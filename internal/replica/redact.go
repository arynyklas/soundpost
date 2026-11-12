// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

// Redaction crash hooks (see install.go for the semantics of a hook error).
const (
	HookRedactBegin   = "redact_begin"
	HookRedactPins    = "redact_pins"
	HookRedactWrite   = "redact_write"
	HookRedactSync    = "redact_sync"
	HookRedactSwitch  = "redact_switch"
	HookRedactRenamed = "redact_renamed"
	HookRedactMemory  = "redact_memory"
)

// Residue store names reported by Group.Residue.
const (
	ResidueJournal   = "raft_journal"
	ResidueSnapshots = "raft_snapshots"
)

const (
	journalRedactTemp = "ready.wal.redact"
	maxEntryPayload   = 16 << 20
)

// Redaction names one applied command whose payload this group must stop holding, and the
// payload the machine accepts in its place.
type Redaction struct {
	// ApplicationIndex is the C05 application index of the command (the machine's own
	// position for it), the key both the machine and this group know it by.
	ApplicationIndex uint64
	// Replacement is replayed by the machine instead of the original payload: it must be a
	// payload the machine applies to the same state the redacted stored command has, and it
	// must not carry what is being forgotten. It is retained as the command's payload from now
	// on, in the retry table, the journal and every later snapshot.
	Replacement []byte
}

// RedactResult counts what one call changed. A call that finds everything already redacted
// changes and rewrites nothing.
type RedactResult struct {
	Redacted int // commands whose retained payload in the retry table was replaced
	Absent   int // requested application indexes this group holds no applied command for
	Journal  int // journal entries rewritten on disk
	Pins     int // pin archive entries rewritten on disk
}

type redactTarget struct {
	replacement []byte
}

// RedactCompleted replaces the retained payload of the named applied commands by the machine's
// replacement, in every place this group keeps one that it can rewrite:
//
//   - the retry table (completed commands) that every later snapshot serializes;
//   - every entry of the retained Raft journal, on disk (temp file, fsync, atomic rename) and in
//     the in-memory log that is sent to a voter that is behind, so such a voter receives the
//     redacted entry and never stores the original;
//   - the entries of every backup pin archive.
//
// The command keeps its ID, kind, term, physical and application index, reservation and
// outcome, so a retry answers with the original receipt; only the payload changes, and the digest
// of the payload it was proposed with is kept (Entry.Original), so a retry carrying the original
// payload is still recognized and a different payload under the same ID is still a conflict.
//
// What cannot be rewritten in place is a snapshot directory, and the snapshot record the journal
// begins with: they are sealed at an older cut, checksummed and immutable. They carry the old
// payloads until a snapshot cut at a later index replaces them and the journal is compacted onto
// it (CreateSnapshot after the applied index advanced, SnapshotStore.DropSuperseded,
// CompactJournal). Residue reports whether such copies still exist.
//
// The operation is idempotent and re-derivable: every request names a command by application
// index and carries the replacement, so a caller that knows (durably) which commands are
// redacted can repeat the call after any crash, restart or snapshot installation and the group
// converges. The retry table is rebuilt from the selected snapshot on open, so a redaction that
// only reached the table is repeated by the caller after a restart; the journal rewrite is
// atomic (the old or the new journal is in force, never a mix).
//
// An error returned before the journal was replaced (a hook, a read, a temp file or a pin archive
// that could not be written) did not start writing: the group is untouched and still serves, and
// the caller retries the same call. An error after the journal rename, or in the in-memory swap,
// can leave the open journal handle, the retained log and the retry table disagreeing: the group
// fails until a restart rebuilds it from the journal and the caller repeats the redaction.
//
// A request that cannot be honoured is refused whole with ErrInvalid before anything is
// rewritten: an empty or oversized replacement, application index 0, a duplicate application
// index, or a command that is not telemetry payload (barriers, cancellations, control and
// artifact-GC commands are never redacted). An application index the group holds no command for
// is counted in Absent and is not an error.
func (g *Group) RedactCompleted(ctx context.Context, requests []Redaction) (RedactResult, error) {
	if err := ctx.Err(); err != nil {
		return RedactResult{}, err
	}
	wanted := make(map[uint64][]byte, len(requests))
	for _, r := range requests {
		if r.ApplicationIndex == 0 || len(r.Replacement) == 0 || len(r.Replacement) > maxEntryPayload {
			return RedactResult{}, ErrInvalid
		}
		if _, dup := wanted[r.ApplicationIndex]; dup {
			return RedactResult{}, ErrInvalid
		}
		wanted[r.ApplicationIndex] = r.Replacement
	}
	if len(wanted) == 0 {
		return RedactResult{}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return RedactResult{}, ErrUnavailable
	}
	var res RedactResult
	targets := map[model.ID]*redactTarget{}
	found := map[uint64]bool{}
	for id, c := range g.completed {
		replacement, ok := wanted[c.Entry.ApplicationIndex]
		if !ok {
			continue
		}
		if c.Entry.Kind != Data && c.Entry.Kind != Artifact {
			return RedactResult{}, ErrInvalid
		}
		if found[c.Entry.ApplicationIndex] {
			return RedactResult{}, ErrConflict // two retained commands claim one application index
		}
		found[c.Entry.ApplicationIndex] = true
		targets[id] = &redactTarget{replacement: bytes.Clone(replacement)}
	}
	res.Absent = len(wanted) - len(found)
	if len(targets) == 0 {
		return res, nil
	}

	var table []model.ID
	for id, t := range targets {
		if p := g.completed[id].Entry.Payload; len(p) > 0 && !bytes.Equal(p, t.replacement) { // no payload: kept by digest
			table = append(table, id)
		}
	}
	memory, err := g.redactedLogLocked(targets)
	if err != nil {
		return RedactResult{}, err
	}
	if len(table) == 0 && len(memory) == 0 && len(g.pins) == 0 {
		return res, nil
	}
	// An error before the journal was replaced (a hook, a read, a temp file, a pin archive: each
	// replaced whole, atomically, and re-derivable) never started writing: the group is intact,
	// the caller retries, and the pass is idempotent. Only a failure after the journal rename, or
	// in the in-memory swap, can leave the group torn.
	if err = g.trip(HookRedactBegin); err != nil {
		return RedactResult{}, err
	}
	if res.Pins, err = g.redactPinsLocked(targets); err != nil {
		return RedactResult{}, err
	}
	if len(memory) > 0 {
		if res.Journal, err = g.rewriteJournalRedacted(targets); err != nil {
			var torn *tornError
			if errors.As(err, &torn) {
				g.fail()
				return RedactResult{}, torn.error
			}
			return RedactResult{}, err
		}
		if err = g.trip(HookRedactMemory); err != nil {
			g.fail()
			return RedactResult{}, err
		}
		if err = g.swapLogLocked(memory); err != nil {
			g.fail()
			return RedactResult{}, err
		}
	}
	for _, id := range table {
		t := targets[id]
		c := g.completed[id]
		c.Entry = redactedCommand(c.Entry, t.replacement)
		g.completed[id] = c
		if l, ok := g.logCommands[id]; ok {
			l.Entry = redactedCommand(l.Entry, t.replacement)
			g.logCommands[id] = l
		}
		res.Redacted++
	}
	g.sendSnap = nil // built from the retry table
	return res, nil
}

// redactedCommand is e with its payload replaced; Original keeps the digest of the payload the
// command was first proposed with, across any number of redactions.
func redactedCommand(e Entry, replacement []byte) Entry {
	original := e.proposed()
	e.Payload = bytes.Clone(replacement)
	e.Original = &original
	return e
}

// redactedEntry returns the Raft entry that replaces ent, or nil when ent is not one of the
// commands to redact or already carries its replacement.
func redactedEntry(ent *pb.Entry, targets map[model.ID]*redactTarget) (*pb.Entry, error) {
	e, ok := parseEntry(ent)
	if !ok {
		return nil, nil
	}
	t := targets[e.ID]
	if t == nil || bytes.Equal(e.Payload, t.replacement) {
		return nil, nil
	}
	data, err := json.Marshal(redactedCommand(e, t.replacement))
	if err != nil {
		return nil, err
	}
	replaced := proto.Clone(ent).(*pb.Entry)
	replaced.Data = data
	return replaced, nil
}

// redactedLogLocked lists the retained log entries (by physical index) that the redaction
// replaces.
func (g *Group) redactedLogLocked(targets map[model.ID]*redactTarget) (map[uint64]*pb.Entry, error) {
	first, _ := g.memory.FirstIndex()
	last, _ := g.memory.LastIndex()
	out := map[uint64]*pb.Entry{}
	for lo := first; lo <= last; {
		entries, err := g.memory.Entries(lo, last+1, 8<<20)
		if err != nil {
			return nil, err
		}
		for _, ent := range entries {
			lo = ent.GetIndex() + 1
			replaced, err := redactedEntry(ent, targets)
			if err != nil {
				return nil, err
			}
			if replaced != nil {
				out[ent.GetIndex()] = replaced
			}
		}
	}
	return out, nil
}

// swapLogLocked replaces entries of the in-memory log. The Raft state machine reads entries from
// the storage on demand and never caches them, and the entries keep their term and index, so
// the swap changes no Raft state; a voter that is behind is now sent the redacted entries.
func (g *Group) swapLogLocked(replaced map[uint64]*pb.Entry) error {
	last, _ := g.memory.LastIndex()
	lo := ^uint64(0)
	for index := range replaced {
		lo = min(lo, index)
	}
	entries, err := g.memory.Entries(lo, last+1, ^uint64(0))
	if err != nil {
		return err
	}
	suffix := make([]*pb.Entry, len(entries))
	for i, ent := range entries {
		suffix[i] = ent
		if r, ok := replaced[ent.GetIndex()]; ok {
			suffix[i] = r
		}
	}
	return g.memory.Append(suffix)
}

// rewriteJournalRedacted streams the journal into a temporary file with the redacted entries
// substituted, record by record, and atomically renames it over the journal. Records that
// carry nothing to redact are copied byte for byte; the snapshot and HardState records are
// untouched. A crash leaves the complete old or the complete new journal.
func (g *Group) rewriteJournalRedacted(targets map[model.ID]*redactTarget) (int, error) {
	w := g.disk
	dir := filepath.Dir(w.file.Name())
	path := filepath.Join(dir, "ready.wal")
	temp := filepath.Join(dir, journalRedactTemp)
	if err := os.Remove(temp); err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	in, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	fail := func(err error) (int, error) { out.Close(); return 0, err }
	if err = g.trip(HookRedactWrite); err != nil {
		return fail(err)
	}
	rewritten := 0
	for {
		var header [16]byte
		if _, err = io.ReadFull(in, header[:]); err == io.EOF {
			break
		} else if err != nil {
			return fail(err)
		}
		if string(header[:4]) != "SPR1" || binary.BigEndian.Uint32(header[12:]) != crc32.Checksum(header[:12], readyCRC) {
			return fail(ErrInvalid)
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if length == 0 || length > maxReadyBytes {
			return fail(ErrInvalid)
		}
		raw := make([]byte, length)
		if _, err = io.ReadFull(in, raw); err != nil {
			return fail(err)
		}
		if crc32.Checksum(raw, readyCRC) != binary.BigEndian.Uint32(header[8:12]) {
			return fail(ErrInvalid)
		}
		var record readyRecord
		if model.StrictJSON(raw, &record) != nil {
			return fail(ErrInvalid)
		}
		changed := false
		for i, rawEntry := range record.Entries {
			ent := &pb.Entry{}
			if proto.Unmarshal(rawEntry, ent) != nil {
				return fail(ErrInvalid)
			}
			replaced, rerr := redactedEntry(ent, targets)
			if rerr != nil {
				return fail(rerr)
			}
			if replaced == nil {
				continue
			}
			if record.Entries[i], rerr = proto.Marshal(replaced); rerr != nil {
				return fail(rerr)
			}
			changed = true
			rewritten++
		}
		if !changed {
			if err = writeFull(out, header[:]); err == nil {
				err = writeFull(out, raw)
			}
		} else {
			var encoded []byte
			if encoded, err = encodeReady(record); err == nil {
				err = writeFull(out, encoded)
			}
		}
		if err != nil {
			return fail(err)
		}
	}
	if err = g.trip(HookRedactSync); err != nil {
		return fail(err)
	}
	if err = out.Sync(); err != nil {
		return fail(err)
	}
	if err = out.Close(); err != nil {
		return 0, err
	}
	if err = g.trip(HookRedactSwitch); err != nil {
		return 0, err
	}
	if err = os.Rename(temp, path); err != nil {
		return 0, err
	}
	// From here the file on disk is the new journal while the open handle (and the retained
	// in-memory log) still describe the old one: a failure leaves the group torn.
	if err = g.trip(HookRedactRenamed); err != nil {
		return 0, &tornError{err}
	}
	if err = durablefs.SyncDir(dir); err != nil {
		return 0, &tornError{err}
	}
	if err = w.file.Close(); err != nil {
		return 0, &tornError{err}
	}
	reopened, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return 0, &tornError{err}
	}
	if _, err = reopened.Seek(0, io.SeekEnd); err != nil {
		reopened.Close()
		return 0, &tornError{err}
	}
	w.file = reopened
	return rewritten, nil
}

// tornError marks a failure after the journal was replaced: the group's durable log, its open
// handle and its in-memory log may disagree, so the group must stop serving until a restart
// rebuilds it. A failure before that point never started writing the journal.
type tornError struct{ error }

func (e *tornError) Unwrap() error { return e.error }

// redactPinsLocked rewrites every pin archive that holds a command to redact. An archive is
// replaced by temp file, fsync and atomic rename; one that holds nothing to redact is not
// touched.
func (g *Group) redactPinsLocked(targets map[model.ID]*redactTarget) (int, error) {
	if len(g.pins) == 0 {
		return 0, nil
	}
	if err := g.trip(HookRedactPins); err != nil {
		return 0, err
	}
	ids := make([]model.ID, 0, len(g.pins))
	for id := range g.pins {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	total := 0
	for _, id := range ids {
		n, err := redactPinArchive(g.pins[id].path, targets)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func redactPinArchive(path string, targets map[model.ID]*redactTarget) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var out bytes.Buffer
	rewritten := 0
	for len(raw) >= 8 {
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-8) || crc32.Checksum(raw[8:8+n], readyCRC) != binary.BigEndian.Uint32(raw[4:8]) {
			break // torn tail of an interrupted append: the journal still holds those entries
		}
		record := raw[8 : 8+n]
		raw = raw[8+n:]
		var r pinRecord
		if model.StrictJSON(record, &r) != nil {
			return 0, ErrCorrupt
		}
		if r.Entry != nil {
			ent := &pb.Entry{}
			if proto.Unmarshal(r.Entry, ent) != nil {
				return 0, ErrCorrupt
			}
			replaced, rerr := redactedEntry(ent, targets)
			if rerr != nil {
				return 0, rerr
			}
			if replaced != nil {
				if r.Entry, rerr = proto.Marshal(replaced); rerr != nil {
					return 0, rerr
				}
				if record, rerr = json.Marshal(r); rerr != nil {
					return 0, rerr
				}
				rewritten++
			}
		}
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], uint32(len(record)))
		binary.BigEndian.PutUint32(h[4:], crc32.Checksum(record, readyCRC))
		out.Write(h[:])
		out.Write(record)
	}
	if rewritten == 0 {
		return 0, nil
	}
	temp := path + ".tmp"
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	_, err = f.Write(out.Bytes())
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return 0, err
	}
	if err = durablefs.Rename(temp, path); err != nil {
		return 0, err
	}
	return rewritten, durablefs.SyncDir(filepath.Dir(path))
}

// Residue reports where copies of a payload redacted at or before floor (a physical index at
// which the machine had applied the original) can still be: "raft_journal" while the journal
// still begins at, or retains entries at or before, floor; "raft_snapshots" while any snapshot
// directory, selected or not, was cut at or before floor. Both are sealed at their cut and are
// replaced only by a snapshot cut at a later index followed by SnapshotStore.DropSuperseded and
// CompactJournal. It reads state only.
func (g *Group) Residue(floor uint64) ([]string, error) {
	if floor == 0 {
		return nil, nil
	}
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	first, _ := g.memory.FirstIndex()
	snapshot, err := g.memory.Snapshot()
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var out []string
	headAt := snapshot.GetMetadata().GetIndex()
	if first <= floor || headAt != 0 && headAt <= floor {
		out = append(out, ResidueJournal)
	}
	cuts, err := g.snaps.cutIndexes()
	if err != nil {
		return nil, err
	}
	for _, cut := range cuts {
		if cut <= floor {
			out = append(out, ResidueSnapshots)
			break
		}
	}
	return out, nil
}

// cutIndexes returns the physical cut of every snapshot directory, selected or not.
func (s *SnapshotStore) cutIndexes() ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirs, err := s.snapDirs()
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(dirs))
	for _, d := range dirs {
		// snap-<20 digit index>-<checksum prefix>
		parts := strings.SplitN(d, "-", 3)
		if len(parts) != 3 {
			return nil, ErrCorrupt
		}
		index, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, ErrCorrupt
		}
		out = append(out, index)
	}
	return out, nil
}

// DropSuperseded removes every snapshot directory that sorts before the selected one and reports
// how many it removed. The store keeps the selected snapshot and the newest previous one as a
// fallback if the selected one is damaged; after a redaction or an erasure the previous one is a
// copy of the state from before it. Directories that sort after the selection (a cut still being
// published) are never touched. The trade-off is explicit: until the next cut there is no
// previous snapshot to fall back on. Without a selected snapshot nothing is dropped.
func (s *SnapshotStore) DropSuperseded() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.loadCurrent(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	keep := dirName(current.Manifest)
	dirs, err := s.snapDirs()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, d := range dirs {
		if d >= keep {
			continue
		}
		if err = os.RemoveAll(filepath.Join(s.root, d)); err != nil {
			return removed, err
		}
		removed++
	}
	if removed > 0 {
		err = durablefs.SyncDir(s.root)
	}
	return removed, err
}
