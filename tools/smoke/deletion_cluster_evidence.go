// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"

	"github.com/arynyklas/soundpost/internal/model"
)

// dcJournal is what one group's Raft journal file (ready.wal) holds: the index of the snapshot its
// retained history starts after (0 for a journal that was never cut) and the last entry index.
type dcJournal struct {
	Snapshot uint64 `json:"snapshot"`
	Last     uint64 `json:"last"`
}

var dcWALTable = crc32.MakeTable(crc32.Castagnoli)

// dcReadJournal decodes one ready.wal the way the replica package does (frames "SPR1", a JSON
// record per frame carrying protobuf snapshot and entries) and reports the journal's range. A torn
// or unreadable tail ends the read: a live node may be appending while this is called.
func dcReadJournal(path string) (dcJournal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return dcJournal{}, err
	}
	memory := raft.NewMemoryStorage()
	frames := 0
	for off := 0; off+16 <= len(raw); {
		header := raw[off : off+16]
		if string(header[:4]) != "SPR1" || binary.BigEndian.Uint32(header[12:]) != crc32.Checksum(header[:12], dcWALTable) {
			break
		}
		length := int(binary.BigEndian.Uint32(header[4:8]))
		if length == 0 || off+16+length > len(raw) {
			break
		}
		body := raw[off+16 : off+16+length]
		if crc32.Checksum(body, dcWALTable) != binary.BigEndian.Uint32(header[8:12]) {
			break
		}
		var record struct {
			Snapshot []byte   `json:"snapshot"`
			Entries  [][]byte `json:"entries"`
		}
		if json.Unmarshal(body, &record) != nil {
			return dcJournal{}, errors.New("journal record undecodable")
		}
		if len(record.Snapshot) > 0 {
			snap := &pb.Snapshot{}
			if proto.Unmarshal(record.Snapshot, snap) != nil {
				return dcJournal{}, errors.New("journal snapshot undecodable")
			}
			if err = memory.ApplySnapshot(snap); err != nil && !errors.Is(err, raft.ErrSnapOutOfDate) {
				return dcJournal{}, err
			}
		}
		entries := make([]*pb.Entry, 0, len(record.Entries))
		for _, e := range record.Entries {
			entry := &pb.Entry{}
			if proto.Unmarshal(e, entry) != nil {
				return dcJournal{}, errors.New("journal entry undecodable")
			}
			entries = append(entries, entry)
		}
		if len(entries) > 0 {
			if last, _ := memory.LastIndex(); entries[0].GetIndex() > last+1 {
				return dcJournal{}, errors.New("journal has a gap")
			}
			if err = memory.Append(entries); err != nil {
				return dcJournal{}, err
			}
		}
		frames++
		off += 16 + length
	}
	if frames == 0 {
		return dcJournal{}, errors.New("journal holds no frame")
	}
	first, _ := memory.FirstIndex()
	last, _ := memory.LastIndex()
	return dcJournal{Snapshot: first - 1, Last: last}, nil
}

// dcJournals reads every ready.wal under dir, keyed by its slash-separated path relative to dir.
func dcJournals(dir string) (map[string]dcJournal, error) {
	out := map[string]dcJournal{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "ready.wal" {
			return err
		}
		j, err := dcReadJournal(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = j
		return nil
	})
	return out, err
}

// dcStranded names the journals of live in which a snapshot cut lies past everything the lagging
// voter ever journaled: the entries between are gone, so the voter can only be brought up to date
// by installing that snapshot.
func dcStranded(lagging, live map[string]dcJournal) []string {
	var out []string
	for name, l := range live {
		if had, ok := lagging[name]; ok && l.Snapshot > had.Last {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// dcInstalledPast names, of the stranded journals, those the lagging voter's own journal now
// starts beyond the live node's cut: it moved past the gap, which only an installed snapshot can do.
func dcInstalledPast(stranded []string, live, after map[string]dcJournal) []string {
	var out []string
	for _, name := range stranded {
		if now, ok := after[name]; ok && now.Snapshot >= live[name].Snapshot {
			out = append(out, name)
		}
	}
	return out
}

// dcFacts are the erase-protocol facts a stopped node's apply.db holds.
type dcFacts struct {
	NoticeByNode  map[string]uint64 `json:"erase_notice_index_by_node"`
	InstallEpoch  uint64            `json:"install_epoch"`
	NoticeSettled uint64            `json:"notice_settled"`
}

// dcReadFacts opens the apply.db under dir read-only (the node must be stopped) and reads the
// facts of the slot-0 group's erase protocol from the replicated-data bucket: the notices a
// sender committed before announcing a snapshot to a voter (the highest index per node), and this
// voter's own installation epoch and settled-notice counter. Keys are told apart by their names.
func dcReadFacts(dir string) (dcFacts, error) {
	facts := dcFacts{NoticeByNode: map[string]uint64{}}
	var path string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "apply.db" && path == "" {
			path = p
		}
		return err
	})
	if err != nil {
		return facts, err
	}
	if path == "" {
		return facts, errors.New("no apply.db")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return facts, err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if meta == nil {
			return errors.New("no replica_data bucket")
		}
		u64 := func(v []byte) uint64 {
			if len(v) != 8 {
				return 0
			}
			return binary.BigEndian.Uint64(v)
		}
		return meta.ForEach(func(k, v []byte) error {
			if len(k) < 2 || !bytes.Equal(k[:2], []byte{0, 0}) { // slot 0 holds the erase protocol
				return nil
			}
			name := string(k[2:])
			switch {
			case strings.HasPrefix(name, "erase-notice:"):
				if parts := strings.SplitN(name, ":", 3); len(parts) == 3 {
					facts.NoticeByNode[parts[1]] = max(facts.NoticeByNode[parts[1]], u64(v))
				}
			case name == "install-epoch":
				facts.InstallEpoch = u64(v)
			case name == "notice-settled":
				facts.NoticeSettled = u64(v)
			}
			return nil
		})
	})
	return facts, err
}

// dcArtifactName is the artifact file of the run whose lagging voter is node.
func dcArtifactName(node uint64) string {
	return "deletion-cluster-lag-" + strconv.FormatUint(node, 10) + ".json"
}

// dcPlanStep is one full run of the scenario: a fresh cluster, one voter held back, and what
// happens to it (it is restarted, or replaced by a fresh identity).
type dcPlanStep struct {
	Node    uint64
	Replace bool
}

// dcPlan turns --lag-nodes and --replace-nodes into the runs in order: every lagging-node run,
// then every replacement run. "none" names no run for that flag; at least one run is required.
func dcPlan(lag, replace string) ([]dcPlanStep, error) {
	var steps []dcPlanStep
	for _, part := range []struct {
		flag, value string
		replace     bool
	}{{"--lag-nodes", lag, false}, {"--replace-nodes", replace, true}} {
		if strings.TrimSpace(part.value) == "none" {
			continue
		}
		nodes, err := dcParseNodes(part.flag, part.value)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			steps = append(steps, dcPlanStep{Node: n, Replace: part.replace})
		}
	}
	if len(steps) == 0 {
		return nil, errors.New("--lag-nodes and --replace-nodes name no run")
	}
	return steps, nil
}

// dcParseNodes parses a node list flag: distinct node ids among 1, 2 and 3.
func dcParseNodes(flag, s string) ([]uint64, error) {
	var out []uint64
	for _, part := range strings.Split(s, ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil || id < 1 || id > 3 || slices.Contains(out, id) {
			return nil, fmt.Errorf("%s wants distinct node ids among 1, 2, 3 (or none)", flag)
		}
		out = append(out, id)
	}
	return out, nil
}

// dcRunArtifactName is the artifact file of one planned run.
func dcRunArtifactName(s dcPlanStep) string {
	if s.Replace {
		return "deletion-cluster-replace-" + strconv.FormatUint(s.Node, 10) + ".json"
	}
	return dcArtifactName(s.Node)
}

// ---- the restore authority, the backup CLI and the membership CLI ----

// dcAuthority names the files of the restore authority a run configures: a directory of its own,
// outside every node's data directory, with its own signing keys.
type dcAuthority struct {
	Keys       string // full authority keys (a private file): every serve process checkpoints deletions with them
	Restricted string // the restricted keys a restore operator holds: read and verify, never write
	Dir        string // the authority's directory
	KeyDir     string // the backup key-encryption keys
	BackupDir  string // the backup destination
}

// dcServeArgs is the command line of one voter. With an authority every voter gets the same
// --authority-keys and --authority-dir, so each deletion it begins is checkpointed there.
func dcServeArgs(id uint64, nodeFile, data, listen string, a *dcAuthority) []string {
	args := []string{"serve", "--mode=distributed", "--node-id", strconv.FormatUint(id, 10), "--cluster-config", nodeFile, "--data-dir", data, "--listen", listen}
	if a != nil {
		args = append(args, "--authority-keys", a.Keys, "--authority-dir", a.Dir)
	}
	return args
}

// dcSafeLine reduces the last line a command printed to the words that cannot carry a path, a key
// or a token (letters, digits and _ : . ( ) [ ] -, at most 40 characters): the CLI's failure lines
// are static, this keeps them that way in the artifact. Every other word is dropped whole.
func dcSafeLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var kept []string
	for _, word := range strings.Fields(lines[len(lines)-1]) {
		safe := len(word) <= 40
		for _, r := range word {
			safe = safe && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_:.()[]-", r))
		}
		if safe {
			kept = append(kept, word)
		}
	}
	return strings.Join(kept, " ")
}

// dcCLI runs one command of the produced binary and returns its stdout. A failure is the typed
// {stage, command_failed} plus the safe last line the command printed on stderr.
func dcCLI(binary string, env []string, limit time.Duration, args ...string) (stdout []byte, line string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if runErr := cmd.Run(); runErr != nil {
		stage := "cli"
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				break
			}
			stage += "_" + a
		}
		return nil, dcSafeLine(errOut.String()), &smokeFailure{Stage: stage, Code: "command_failed"}
	}
	return out.Bytes(), "", nil
}

// dcNum is a non-negative integer the CLI prints as a JSON number or as a decimal string (the
// product's 64-bit counters are strings in JSON).
type dcNum uint64

func (n *dcNum) UnmarshalJSON(raw []byte) error {
	v, err := strconv.ParseUint(strings.Trim(string(raw), `"`), 10, 64)
	if err != nil {
		return errors.New("not a non-negative integer")
	}
	*n = dcNum(v)
	return nil
}

// dcBackupInfo is what `soundpost backup create` prints.
type dcBackupInfo struct {
	ID                  string `json:"backup_id"`
	ControlRevision     dcNum  `json:"control_revision"`
	AuthoritySequence   dcNum  `json:"authority_sequence"`
	AuthorityGeneration dcNum  `json:"authority_generation"`
	Objects             int    `json:"objects"`
	Voters              dcNum  `json:"voters"`
}

// dcParseBackupCreate reads the report of `backup create`; a report with no backup id or no
// objects is not a backup.
func dcParseBackupCreate(raw []byte) (dcBackupInfo, error) {
	var out dcBackupInfo
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("backup report does not decode")
	}
	if _, err := model.ParseID(out.ID); err != nil || out.Objects == 0 {
		return out, errors.New("backup report names no backup")
	}
	return out, nil
}

// dcRestoreInfo is what `soundpost backup restore` prints.
type dcRestoreInfo struct {
	ID                  string `json:"backup_id"`
	ControlRevision     dcNum  `json:"control_revision"`
	AuthoritySequence   dcNum  `json:"authority_sequence"`
	AuthorityGeneration dcNum  `json:"authority_generation"`
	Tombstones          int    `json:"tombstones"`
	Objects             int    `json:"objects"`
}

func dcParseRestore(raw []byte) (dcRestoreInfo, error) {
	var out dcRestoreInfo
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("restore report does not decode")
	}
	if _, err := model.ParseID(out.ID); err != nil || out.Objects == 0 {
		return out, errors.New("restore report names no backup")
	}
	return out, nil
}

// dcActivateInfo is what `soundpost backup activate` prints.
type dcActivateInfo struct {
	Ready               bool  `json:"ready"`
	Tombstones          int   `json:"tombstones"`
	AuthorityGeneration dcNum `json:"authority_generation"`
}

func dcParseActivate(raw []byte) (dcActivateInfo, error) {
	var out dcActivateInfo
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("activate report does not decode")
	}
	return out, nil
}

// dcTombstoneOf finds the tombstone the authority holds for one deletion operation.
func dcTombstoneOf(tombstones []model.DeletePredicate, op model.ID) (model.DeletePredicate, bool) {
	for _, t := range tombstones {
		if t.Operation == op {
			return t, true
		}
	}
	return model.DeletePredicate{}, false
}

// dcRetiresOnly reports whether a tombstone retires exactly one project of one organization and
// nothing else: the shape of the deletion this smoke begins.
func dcRetiresOnly(t model.DeletePredicate, org, project model.ID) bool {
	return t.Org == org && t.Mode == model.DeleteRetireProject && len(t.Projects) == 1 && t.Projects[0] == project
}

// dcReplacementMembers is the voter set after the lagging voter is replaced by the fresh one.
func dcReplacementMembers(members []uint64, removed, added uint64) []uint64 {
	out := []uint64{added}
	for _, id := range members {
		if id != removed && id != added {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// dcStatusShowsVoters reports whether `soundpost membership status` lists, in at least min
// groups and in every group it lists, exactly the wanted voters (id -> node identity) and no
// learner.
func dcStatusShowsVoters(out string, want map[uint64]string, min int) bool {
	groups := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "group ") {
			continue
		}
		_, members, ok := strings.Cut(line, "members=")
		if !ok {
			return false
		}
		got := map[uint64]string{}
		for _, m := range strings.Split(strings.TrimSpace(members), ",") {
			parts := strings.Split(m, ":")
			if len(parts) != 3 || parts[1] != "voter" {
				return false
			}
			id, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return false
			}
			got[id] = parts[2]
		}
		if len(got) != len(want) {
			return false
		}
		for id, identity := range want {
			if got[id] != identity {
				return false
			}
		}
		groups++
	}
	return groups >= min
}

// dcNotRun is what a run does not cover, stated in its artifact.
func dcNotRun(authority, replace bool) []string {
	out := []string{"three independent physical hosts, disks, power or network paths"}
	if authority {
		out = append(out, "an authority and backup destination on separate hardware or in an S3-compatible store (here directories of this host, outside every node's data directory); no power-loss test of the authority")
	} else {
		out = append(out, "off-host backup authority and restore (run without --authority: no backup authority is configured)")
	}
	if replace {
		out = append(out, "restarting the lagging voter on its own directory (the --lag-nodes runs do it)")
	} else {
		out = append(out, "replacing the lagging voter by a fresh identity (the --replace-nodes runs do it)")
	}
	return append(out, "container host (--binary processes only)")
}
