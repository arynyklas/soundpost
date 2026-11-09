// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

// Journal crash hooks (see install.go for the semantics of a hook error).
const (
	HookCompactBegin   = "compact_begin"
	HookCompactArchive = "compact_archive"
	HookCompactWrite   = "compact_write"
	HookCompactSync    = "compact_sync"
	HookCompactSwitch  = "compact_switch"
	HookCompactRenamed = "compact_renamed"
	HookCompactMemory  = "compact_memory"
)

const journalCompactTemp = "ready.wal.compact"

// DefaultPinTTL is the lease of a journal pin. A backup that holds a pin for longer fails closed
// when the lease lapses (its Entries return ErrStale); a pin whose holder died is dropped by
// truncation or by the next open once it lapses, and sooner by DropPin.
const DefaultPinTTL = 24 * time.Hour

// repair removes everything an interrupted creation or installation can leave
// behind and re-selects the newest verified directory when the CURRENT pointer
// itself is unusable. A valid CURRENT is never replaced by an orphan, however new.
func (s *SnapshotStore) repair() error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "tmp-") || strings.HasPrefix(name, "install-") || strings.HasSuffix(name, ".tmp") {
			if err = os.RemoveAll(filepath.Join(s.root, name)); err != nil {
				return err
			}
		}
	}
	if cur, err := s.loadCurrent(false); err == nil {
		return s.prune(dirName(cur.Manifest))
	}
	_ = os.Remove(filepath.Join(s.root, currentName))
	dirs, err := s.snapDirs()
	if err != nil {
		return err
	}
	fence := s.fenceLocked()
	for _, d := range dirs {
		snap, err := s.loadDir(filepath.Join(s.root, d), true)
		if err != nil || snap.Manifest.Generation < fence || d != dirName(snap.Manifest) {
			continue
		}
		pointer, err := json.Marshal(currentPointer{Version: 1, Dir: d, Checksum: snap.Manifest.Checksum})
		if err != nil {
			return err
		}
		if err = s.writeAtomic(currentName, pointer, ""); err != nil {
			return err
		}
		return s.prune(d)
	}
	return nil
}

// installedSeed lets a fresh Raft journal start from an installed snapshot.
type installedSeed struct {
	data  []byte
	index uint64
	term  uint64
	conf  *pb.ConfState
}

// loadInstalledSeed deep-verifies the selected snapshot. A directory that does
// not verify is never used: opening the group fails instead.
func loadInstalledSeed(s *SnapshotStore) (*installedSeed, error) {
	snap, err := s.Verify()
	if errors.Is(err, ErrNoSnapshot) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := snap.envelopeBytes()
	if err != nil {
		return nil, err
	}
	seed := &installedSeed{data: data, index: snap.Manifest.Index, term: snap.Manifest.Term}
	if in, err := snap.File(fileConf); err == nil {
		raw, rerr := io.ReadAll(in)
		in.Close()
		conf := &pb.ConfState{}
		if rerr != nil || proto.Unmarshal(raw, conf) != nil {
			return nil, ErrCorrupt
		}
		seed.conf = conf
	}
	return seed, nil
}

// Snapshots exposes the group's snapshot store.
func (g *Group) Snapshots() *SnapshotStore { return g.snaps }

// JournalRange reports the first and last retained physical Raft index.
func (g *Group) JournalRange() (first, last uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	first, _ = g.memory.FirstIndex()
	last, _ = g.memory.LastIndex()
	return first, last
}

// CompactionResult describes one journal truncation.
type CompactionResult struct {
	SnapshotIndex uint64
	FirstIndex    uint64
	Archived      int
}

// CompactJournal truncates the Raft journal up to the verified current snapshot.
// It first re-reads every snapshot byte, requires the machine to have durably
// applied the cut, archives entries still needed by backup pins, writes a new
// journal anchored on the snapshot, and only then renames it over the old one.
// A crash at any hook leaves either the complete old or complete new journal.
func (g *Group) CompactJournal(ctx context.Context) (CompactionResult, error) {
	if err := ctx.Err(); err != nil {
		return CompactionResult{}, err
	}
	snap, err := g.snaps.Verify()
	if err != nil {
		return CompactionResult{}, err
	}
	data, err := snap.envelopeBytes()
	if err != nil {
		return CompactionResult{}, err
	}
	var conf *pb.ConfState
	if in, err := snap.File(fileConf); err == nil {
		raw, rerr := io.ReadAll(in)
		in.Close()
		conf = &pb.ConfState{}
		if rerr != nil || proto.Unmarshal(raw, conf) != nil {
			return CompactionResult{}, ErrCorrupt
		}
	}
	cut := snap.Manifest.Index
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return CompactionResult{}, ErrUnavailable
	}
	if cut > g.applied || g.machine.Applied() < cut || g.application < uint64(snap.Manifest.Cursor.Index) {
		return CompactionResult{}, ErrStale
	}
	first, _ := g.memory.FirstIndex()
	if cut < first {
		return CompactionResult{SnapshotIndex: cut, FirstIndex: first}, nil
	}
	existing, err := g.memory.Snapshot()
	if err != nil {
		return CompactionResult{}, err
	}
	switch {
	case existing.GetMetadata().GetIndex() > cut:
		return CompactionResult{}, ErrStale
	case existing.GetMetadata().GetIndex() < cut:
		if _, err = g.memory.CreateSnapshot(cut, conf, data); err != nil {
			return CompactionResult{}, err
		}
	}
	if err = g.trip(HookCompactBegin); err != nil {
		g.fail()
		return CompactionResult{}, err
	}
	archived, err := g.archivePinsLocked(cut)
	if err != nil {
		g.fail()
		return CompactionResult{}, err
	}
	if err = g.rewriteJournalLocked(cut); err != nil {
		g.fail()
		return CompactionResult{}, err
	}
	if err = g.trip(HookCompactMemory); err != nil {
		g.fail()
		return CompactionResult{}, err
	}
	if err = g.memory.Compact(cut); err != nil && !errors.Is(err, raft.ErrCompacted) {
		g.fail()
		return CompactionResult{}, err
	}
	first, _ = g.memory.FirstIndex()
	return CompactionResult{SnapshotIndex: cut, FirstIndex: first, Archived: archived}, nil
}

func encodeReady(r readyRecord) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > maxReadyBytes {
		return nil, ErrInvalid
	}
	out := make([]byte, 16, 16+len(raw))
	copy(out[:4], "SPR1")
	binary.BigEndian.PutUint32(out[4:8], uint32(len(raw)))
	binary.BigEndian.PutUint32(out[8:12], crc32.Checksum(raw, readyCRC))
	binary.BigEndian.PutUint32(out[12:], crc32.Checksum(out[:12], readyCRC))
	return append(out, raw...), nil
}

func (g *Group) rewriteJournalLocked(cut uint64) error {
	w := g.disk
	dir := filepath.Dir(w.file.Name())
	temp := filepath.Join(dir, journalCompactTemp)
	if err := os.Remove(temp); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	write := func(r readyRecord) error {
		raw, err := encodeReady(r)
		if err != nil {
			return err
		}
		return writeFull(f, raw)
	}
	fail := func(err error) error { f.Close(); return err }
	if err = g.trip(HookCompactWrite); err != nil {
		return fail(err)
	}
	snapshot, err := g.memory.Snapshot()
	if err != nil {
		return fail(err)
	}
	rawSnapshot, err := proto.Marshal(snapshot)
	if err != nil {
		return fail(err)
	}
	base := readyRecord{Group: w.group, Node: w.node, Members: cloneMembers(w.members)}
	head := base
	head.Snapshot = rawSnapshot
	if err = write(head); err != nil {
		return fail(err)
	}
	last, _ := g.memory.LastIndex()
	chunk, size := base, 0
	for index := cut + 1; index <= last; {
		entries, err := g.memory.Entries(index, last+1, 8<<20)
		if err != nil {
			return fail(err)
		}
		for _, ent := range entries {
			raw, err := proto.Marshal(ent)
			if err != nil {
				return fail(err)
			}
			chunk.Entries = append(chunk.Entries, raw)
			size += len(raw)
			index = ent.GetIndex() + 1
		}
		if size > 0 {
			if err = write(chunk); err != nil {
				return fail(err)
			}
			chunk, size = base, 0
		}
	}
	hard, _, err := g.memory.InitialState()
	if err != nil {
		return fail(err)
	}
	tail := base
	if tail.Hard, err = proto.Marshal(hard); err != nil {
		return fail(err)
	}
	if err = write(tail); err != nil {
		return fail(err)
	}
	if err = g.trip(HookCompactSync); err != nil {
		return fail(err)
	}
	if err = f.Sync(); err != nil {
		return fail(err)
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = g.trip(HookCompactSwitch); err != nil {
		return err
	}
	path := filepath.Join(dir, "ready.wal")
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	if err = g.trip(HookCompactRenamed); err != nil {
		return err
	}
	if err = durablefs.SyncDir(dir); err != nil {
		return err
	}
	if err = w.file.Close(); err != nil {
		return err
	}
	reopened, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if _, err = reopened.Seek(0, io.SeekEnd); err != nil {
		reopened.Close()
		return err
	}
	w.file = reopened
	return nil
}

// ReplayEntry is one committed journal entry with its C05 application index.
type ReplayEntry struct {
	Index            uint64
	ApplicationIndex uint64
	ID               model.ID
	Kind             Kind
	Payload          []byte
}

// JournalPin keeps every committed journal entry with application index above
// After available until released, even across journal truncation: truncation
// archives the pinned range durably before it discards anything.
type JournalPin struct {
	g       *Group
	id      model.ID
	after   uint64
	path    string
	next    uint64 // first physical index not yet in the archive
	owner   model.ID
	created int64 // lease, Unix nanoseconds
	expires int64
}

type pinRecord struct {
	Header *pinHeader `json:"header,omitempty"`
	Entry  []byte     `json:"entry,omitempty"`
}
type pinHeader struct {
	ID    model.ID `json:"id"`
	After uint64   `json:"after,string"`
	Next  uint64   `json:"next,string"`
	// Owner is the Group instance that created the pin: a process lifetime, not a node identity.
	// A pin whose Owner is not this instance was left by a process that is gone.
	Owner model.ID `json:"owner"`
	// Created and Expires are the lease, in Unix nanoseconds.
	Created int64 `json:"created,string"`
	Expires int64 `json:"expires,string"`
}

// PinInfo describes one durable journal pin.
type PinInfo struct {
	ID      model.ID
	After   uint64
	Created time.Time
	Expires time.Time
	// Orphaned: created by an earlier instance of this group, a process that is gone. Nothing in
	// this process holds the pin; it only archives until it expires or is dropped.
	Orphaned bool
}

// Pins lists the durable journal pins of this group after dropping every pin whose lease lapsed.
// A backup driver reaps the pins of a backup that died with DropPin; Orphaned says which pins
// no live holder in this process can still be using.
func (g *Group) Pins() ([]PinInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return nil, ErrUnavailable
	}
	if err := g.reapExpiredPinsLocked(); err != nil {
		return nil, err
	}
	out := make([]PinInfo, 0, len(g.pins))
	for _, p := range g.pins {
		out = append(out, PinInfo{ID: p.id, After: p.after, Created: time.Unix(0, p.created), Expires: time.Unix(0, p.expires), Orphaned: p.owner != g.owner})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID[:], out[j].ID[:]) < 0 })
	return out, nil
}

// DropPin removes a pin and its archive, whoever holds it; a missing pin is not an error, so a
// reaper can retry. A backup that still holds the pin fails closed: its Entries return ErrStale.
func (g *Group) DropPin(id model.ID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return ErrUnavailable
	}
	p, ok := g.pins[id]
	if !ok {
		return nil
	}
	if err := durablefs.Remove(p.path); err != nil {
		return err
	}
	delete(g.pins, id)
	return nil
}

// reapExpiredPinsLocked drops every pin whose lease lapsed: nothing archives into a pin that
// can no longer be used, and a backup that holds one fails closed.
func (g *Group) reapExpiredPinsLocked() error {
	now := g.now().UnixNano()
	for id, p := range g.pins {
		if now < p.expires {
			continue
		}
		if err := durablefs.Remove(p.path); err != nil {
			return err
		}
		delete(g.pins, id)
	}
	return nil
}

// After is the processed application index this pin protects evidence beyond.
func (p *JournalPin) After() uint64 { return p.after }

func (g *Group) pinDir() string { return filepath.Join(g.dir, "pins") }

// PinJournal atomically protects the committed journal beyond after. It is a
// crash-durable registration: pins are reloaded on Open and keep archiving.
func (g *Group) PinJournal(after uint64) (*JournalPin, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return nil, ErrUnavailable
	}
	if err := durablefs.MkdirAll(g.pinDir()); err != nil {
		return nil, err
	}
	commit := g.raw.BasicStatus().HardState.GetCommit()
	first, _ := g.memory.FirstIndex()
	created := g.now().UnixNano()
	p := &JournalPin{g: g, id: model.NewID(), after: after, next: first, owner: g.owner, created: created, expires: created + int64(g.pinTTL)}
	p.path = filepath.Join(g.pinDir(), p.id.String()+".pin")
	if err := p.appendLocked(nil, &pinHeader{ID: p.id, After: after, Next: first, Owner: p.owner, Created: p.created, Expires: p.expires}); err != nil {
		return nil, err
	}
	if err := g.archiveRangeLocked(p, commit); err != nil {
		_ = os.Remove(p.path)
		return nil, err
	}
	if g.pins == nil {
		g.pins = map[model.ID]*JournalPin{}
	}
	g.pins[p.id] = p
	return p, nil
}

func (p *JournalPin) appendLocked(entries []*pb.Entry, header *pinHeader) error {
	f, err := os.OpenFile(p.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	var records []pinRecord
	if header != nil {
		records = append(records, pinRecord{Header: header})
	}
	for _, ent := range entries {
		raw, err := proto.Marshal(ent)
		if err != nil {
			return err
		}
		records = append(records, pinRecord{Entry: raw})
	}
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], uint32(len(raw)))
		binary.BigEndian.PutUint32(h[4:], crc32.Checksum(raw, readyCRC))
		if err = writeFull(f, append(h[:], raw...)); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return durablefs.SyncDir(filepath.Dir(p.path))
}

// archiveRangeLocked copies committed entries [p.next, through] whose
// application index is beyond the pin into the pin archive.
func (g *Group) archiveRangeLocked(p *JournalPin, through uint64) error {
	first, _ := g.memory.FirstIndex()
	last, _ := g.memory.LastIndex()
	if through > last {
		through = last
	}
	lo := p.next
	if lo < first {
		lo = first // already truncated before the pin: reported later as a gap
	}
	if lo > through {
		if p.next <= through {
			p.next = through + 1
		}
		return nil
	}
	entries, err := g.memory.Entries(lo, through+1, ^uint64(0))
	if err != nil {
		return err
	}
	var keep []*pb.Entry
	for _, ent := range entries {
		if e, ok := parseEntry(ent); ok && e.ApplicationIndex > p.after {
			keep = append(keep, ent)
		}
	}
	if err = p.appendLocked(keep, nil); err != nil {
		return err
	}
	p.next = through + 1
	return nil
}

func (g *Group) archivePinsLocked(limit uint64) (int, error) {
	if err := g.reapExpiredPinsLocked(); err != nil {
		return 0, err
	}
	if len(g.pins) == 0 {
		return 0, nil
	}
	if err := g.trip(HookCompactArchive); err != nil {
		return 0, err
	}
	total := 0
	ids := make([]model.ID, 0, len(g.pins))
	for id := range g.pins {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	for _, id := range ids {
		p := g.pins[id]
		before := p.next
		if err := g.archiveRangeLocked(p, limit); err != nil {
			return total, err
		}
		if p.next > before {
			total += int(p.next - before)
		}
	}
	return total, nil
}

func parseEntry(ent *pb.Entry) (Entry, bool) {
	if ent.GetType() != pb.EntryNormal || len(ent.GetData()) == 0 {
		return Entry{}, false
	}
	var e Entry
	if model.StrictJSON(ent.GetData(), &e) != nil || !e.valid() {
		return Entry{}, false
	}
	return e, true
}

func replayOf(ent *pb.Entry) (ReplayEntry, bool) {
	e, ok := parseEntry(ent)
	if !ok {
		return ReplayEntry{}, false
	}
	return ReplayEntry{Index: ent.GetIndex(), ApplicationIndex: e.ApplicationIndex, ID: e.ID, Kind: e.Kind, Payload: bytes.Clone(e.Payload)}, true
}

// Entries returns every pinned committed entry with application index in
// (After, through], from the durable archive plus the live journal. The caller
// must prove contiguity; absent entries are simply absent here.
func (p *JournalPin) Entries(through uint64) ([]ReplayEntry, error) {
	g := p.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return nil, ErrUnavailable
	}
	if _, ok := g.pins[p.id]; !ok {
		return nil, ErrStale
	}
	if g.now().UnixNano() >= p.expires {
		if err := g.reapExpiredPinsLocked(); err != nil {
			return nil, err
		}
		return nil, ErrStale
	}
	archived, err := readPinArchive(p.path)
	if err != nil {
		return nil, err
	}
	byApp := map[uint64]ReplayEntry{}
	add := func(r ReplayEntry) {
		if r.ApplicationIndex > p.after && r.ApplicationIndex <= through {
			byApp[r.ApplicationIndex] = r
		}
	}
	for _, ent := range archived.entries {
		if r, ok := replayOf(ent); ok {
			add(r)
		}
	}
	commit := g.raw.BasicStatus().HardState.GetCommit()
	first, _ := g.memory.FirstIndex()
	last, _ := g.memory.LastIndex()
	if commit > last {
		commit = last
	}
	lo := p.next
	if lo < first {
		lo = first
	}
	if lo <= commit {
		live, err := g.memory.Entries(lo, commit+1, ^uint64(0))
		if err != nil {
			return nil, err
		}
		for _, ent := range live {
			if r, ok := replayOf(ent); ok {
				add(r)
			}
		}
	}
	out := make([]ReplayEntry, 0, len(byApp))
	for _, r := range byApp {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApplicationIndex < out[j].ApplicationIndex })
	return out, nil
}

// Release drops the pin and its archive; the evidence is then reclaimable.
func (p *JournalPin) Release() error {
	g := p.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.pins[p.id]; !ok {
		return nil
	}
	delete(g.pins, p.id)
	return durablefs.Remove(p.path)
}

type pinArchive struct {
	header  pinHeader
	entries []*pb.Entry
	lastIdx uint64
}

func readPinArchive(path string) (pinArchive, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return pinArchive{}, err
	}
	var out pinArchive
	headerSeen := false
	for len(raw) >= 8 {
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-8) || crc32.Checksum(raw[8:8+n], readyCRC) != binary.BigEndian.Uint32(raw[4:8]) {
			break // torn tail of an interrupted append: the journal still holds those entries
		}
		var r pinRecord
		if model.StrictJSON(raw[8:8+n], &r) != nil {
			return pinArchive{}, ErrCorrupt
		}
		raw = raw[8+n:]
		switch {
		case r.Header != nil && !headerSeen:
			out.header, headerSeen = *r.Header, true
		case r.Entry != nil && headerSeen:
			ent := &pb.Entry{}
			if proto.Unmarshal(r.Entry, ent) != nil {
				return pinArchive{}, ErrCorrupt
			}
			out.entries = append(out.entries, ent)
			out.lastIdx = ent.GetIndex()
		default:
			return pinArchive{}, ErrCorrupt
		}
	}
	if !headerSeen {
		return pinArchive{}, errPinNoHeader
	}
	return out, nil
}

// errPinNoHeader: the archive holds no complete header record. The header is the first durable
// write of PinJournal, which registers the pin only after it, so such a file never was a pin.
var errPinNoHeader = fmt.Errorf("pin archive has no durable header: %w", ErrCorrupt)

// loadPins re-registers the pins an earlier process left, so a restart cannot silently let
// truncation discard evidence a backup still needs, and validates every one of them: a file whose
// header never became durable was never a pin, and a pin without a lease or whose lease lapsed
// belongs to a backup that is gone; both are dropped. A pin that registered but does not read
// back (corruption in the middle of its archive, a header naming another pin) is refused.
func (g *Group) loadPins() error {
	entries, err := os.ReadDir(g.pinDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	g.pins = map[model.ID]*JournalPin{}
	first, _ := g.memory.FirstIndex()
	now := g.now().UnixNano()
	for _, e := range entries {
		path := filepath.Join(g.pinDir(), e.Name())
		if strings.HasSuffix(e.Name(), ".tmp") { // an interrupted archive rewrite: the .pin is intact
			if err = durablefs.Remove(path); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(e.Name(), ".pin") {
			continue
		}
		archive, err := readPinArchive(path)
		if errors.Is(err, errPinNoHeader) {
			if err = durablefs.Remove(path); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		h := archive.header
		if e.Name() != h.ID.String()+".pin" {
			return ErrCorrupt
		}
		if h.Owner == (model.ID{}) || h.Expires == 0 || now >= h.Expires {
			if err = durablefs.Remove(path); err != nil {
				return err
			}
			continue
		}
		next := h.Next
		if archive.lastIdx >= next {
			next = archive.lastIdx + 1
		}
		if next < first {
			next = first
		}
		g.pins[h.ID] = &JournalPin{g: g, id: h.ID, after: h.After, path: path, next: next, owner: h.Owner, created: h.Created, expires: h.Expires}
	}
	return nil
}
