// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
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

// dcParseLagNodes parses the --lag-nodes list: distinct node ids among 1, 2 and 3.
func dcParseLagNodes(s string) ([]uint64, error) {
	var out []uint64
	for _, part := range strings.Split(s, ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil || id < 1 || id > 3 || slices.Contains(out, id) {
			return nil, fmt.Errorf("--lag-nodes wants distinct node ids among 1, 2, 3")
		}
		out = append(out, id)
	}
	return out, nil
}

// dcArtifactName is the artifact file of the run whose lagging voter is node.
func dcArtifactName(node uint64) string {
	return "deletion-cluster-lag-" + strconv.FormatUint(node, 10) + ".json"
}
