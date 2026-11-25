// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"slices"
	"time"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// A cadence cut compacts the journal onto the snapshot it just cut, so a member that was away for
// longer than the cut interval has nothing left to be sent but a snapshot of the whole state (60 MB
// per group in the three-node installation: a member that was down for 20 s needed ~50 of them, one
// every 4-5 s over its 100 Mbit/s card, and the startup gave up at 60 s). Cadence.Retain keeps the
// entries a cut compacted, in memory only, for as long as a member can be away and still be offered
// them: raft sees the log from the oldest retained entry, the journal on disk and every other part of
// the group see it as compacted. The tail is a plain contiguous run of committed, applied entries
// ending at the newest cut; it is dropped by whatever makes it untrue (a snapshot installed, an explicit
// journal compaction, a redaction pass) and is not rebuilt after a restart.

// defaultRetainBytes bounds the tail of a group when Cadence.RetainBytes is not set.
const defaultRetainBytes = 24 << 20

// DefaultRetain is how long a cadence cut keeps what it compacts for a member that is away: the startup budget of
// a distributed node (60 s, appcore) and the time its process takes to come back, so that a node that was down for
// the whole budget still finds the entries it missed and rejoins within the budget, instead of being sent the
// state of every group.
const DefaultRetain = 75 * time.Second

// tailMark says how far the group had applied at a time: the age of the entries is judged by the
// newest mark older than the retention window.
type tailMark struct {
	index uint64
	at    time.Time
}

// logTail is the retained run of entries before the in-memory log's first index. base is the index
// and term of the entry just before entries[0], kept for matching an append (raft asks for it).
type logTail struct {
	baseIndex, baseTerm uint64
	entries             []*pb.Entry
	bytes               int64
	marks               []tailMark
	lastMark            time.Time
}

func (t *logTail) empty() bool { return len(t.entries) == 0 }

// firstIndex is the index of the oldest retained entry (0: none).
func (t *logTail) firstIndex() uint64 {
	if t.empty() {
		return 0
	}
	return t.baseIndex + 1
}

// lastIndex is the index of the newest retained entry (0: none).
func (t *logTail) lastIndex() uint64 {
	if t.empty() {
		return 0
	}
	return t.baseIndex + uint64(len(t.entries))
}

// reset forgets the retained entries; the marks go too (they would name entries that are gone).
func (t *logTail) reset() {
	*t = logTail{}
}

// mark records that the group had applied index at now, at most once per every.
func (t *logTail) mark(index uint64, now time.Time, every time.Duration) {
	if !t.lastMark.IsZero() && now.Sub(t.lastMark) < every {
		return
	}
	t.lastMark = now
	t.marks = append(t.marks, tailMark{index: index, at: now})
	if len(t.marks) > 4096 {
		t.marks = slices.Delete(t.marks, 0, len(t.marks)-4096)
	}
}

// term is the term of entry i, which must be in [baseIndex, lastIndex].
func (t *logTail) term(i uint64) uint64 {
	if i == t.baseIndex {
		return t.baseTerm
	}
	return t.entries[i-t.baseIndex-1].GetTerm()
}

// slice returns a copy of the retained entries [lo, hi), at most maxSize bytes of them but at least one
// (what raft's storage does), and their size. lo and hi must lie in (baseIndex, lastIndex+1].
func (t *logTail) slice(lo, hi, maxSize uint64) ([]*pb.Entry, uint64) {
	out := make([]*pb.Entry, 0, min(hi-lo, 64))
	var size uint64
	for i := lo; i < hi; i++ {
		e := t.entries[i-t.baseIndex-1]
		n := uint64(proto.Size(e))
		if len(out) > 0 && size+n > maxSize {
			break
		}
		out = append(out, e)
		size += n
	}
	return out, size
}

// add appends the entries a cut compacted: entries run from index first to the cut. A run that does not
// continue the tail (a snapshot was installed in between, a gap) replaces it. baseTerm is the term of the
// entry before first.
func (t *logTail) add(entries []*pb.Entry, baseTerm uint64) {
	if len(entries) == 0 {
		return
	}
	first := entries[0].GetIndex()
	if t.empty() || t.lastIndex()+1 != first {
		marks, last := t.marks, t.lastMark
		t.reset()
		t.marks, t.lastMark = marks, last
		t.baseIndex, t.baseTerm = first-1, baseTerm
	}
	for _, e := range entries {
		t.entries = append(t.entries, e)
		t.bytes += int64(proto.Size(e))
	}
}

// dropThrough forgets the retained entries up to and including index.
func (t *logTail) dropThrough(index uint64) {
	if t.empty() || index <= t.baseIndex {
		return
	}
	n := int(min(index-t.baseIndex, uint64(len(t.entries))))
	for _, e := range t.entries[:n] {
		t.bytes -= int64(proto.Size(e))
	}
	t.baseIndex, t.baseTerm = t.entries[n-1].GetIndex(), t.entries[n-1].GetTerm()
	t.entries = slices.Clone(t.entries[n:]) // the dropped entries are released, not kept alive by the old array
	// Nothing retained: add starts a new run, so the base means nothing.
	if len(t.entries) == 0 {
		t.entries, t.bytes = nil, 0
	}
}

// trim keeps the entries newer than the window and no more than maxBytes: the floor is the newest mark at least
// window old, and the oldest entries are dropped when the bytes are over the bound.
func (t *logTail) trim(now time.Time, window time.Duration, maxBytes int64) {
	floor := -1
	for i, m := range t.marks {
		if now.Sub(m.at) >= window {
			floor = i
		}
	}
	if floor >= 0 {
		t.dropThrough(t.marks[floor].index)
		t.marks = slices.Clone(t.marks[floor+1:])
	}
	if t.bytes > maxBytes && !t.empty() {
		over := t.bytes - maxBytes
		n := 0
		for n < len(t.entries) && over > 0 {
			over -= int64(proto.Size(t.entries[n]))
			n++
		}
		t.dropThrough(t.entries[n-1].GetIndex())
	}
}

// retainLocked moves the entries the compaction onto cut is about to drop into the tail and trims it to
// the window and the bytes. g.mu is held; the in-memory log still starts at its old first index.
func (g *Group) retainLocked(cut uint64) {
	first, err := g.memory.FirstIndex()
	if err != nil || cut < first {
		return
	}
	baseTerm, err := g.memory.Term(first - 1)
	if err != nil {
		g.tail.reset()
		return
	}
	entries, err := g.memory.Entries(first, cut+1, ^uint64(0))
	if err != nil {
		g.tail.reset()
		return
	}
	g.tail.add(slices.Clone(entries), baseTerm)
	limit := g.cadence.RetainBytes
	if limit <= 0 {
		limit = defaultRetainBytes
	}
	g.tail.trim(g.now(), g.cadence.Retain, limit)
}

// markApplied records the applied index for the retention window (countApplied, g.mu held).
func (g *Group) markApplied() {
	if g.cadence.Retain <= 0 {
		return
	}
	g.tail.mark(g.applied, g.now(), min(time.Second, g.cadence.Retain/32))
}

// FirstIndex is raft's view of the log: the retained tail extends it below what the in-memory log holds.
func (s snapshotSource) FirstIndex() (uint64, error) {
	if first := s.g.tail.firstIndex(); first != 0 {
		return first, nil
	}
	return s.MemoryStorage.FirstIndex()
}

// Term answers from the tail for an index it holds (its base included, which is the term raft matches an append on).
func (s snapshotSource) Term(i uint64) (uint64, error) {
	if t := &s.g.tail; !t.empty() {
		if i < t.baseIndex {
			return 0, raft.ErrCompacted
		}
		if i <= t.lastIndex() {
			return t.term(i), nil
		}
	}
	return s.MemoryStorage.Term(i)
}

// Entries reads from the tail and on into the in-memory log, which begins right after the tail.
func (s snapshotSource) Entries(lo, hi, maxSize uint64) ([]*pb.Entry, error) {
	t := &s.g.tail
	if t.empty() || lo > t.lastIndex() {
		return s.MemoryStorage.Entries(lo, hi, maxSize)
	}
	if lo <= t.baseIndex {
		return nil, raft.ErrCompacted
	}
	out, size := t.slice(lo, min(hi, t.lastIndex()+1), maxSize)
	// The in-memory log is read on only when the tail was read to its end: a run cut short by maxSize must end there,
	// the entries after it are not the ones that follow.
	if hi > t.lastIndex()+1 && lo+uint64(len(out)) == t.lastIndex()+1 && size < maxSize {
		rest, err := s.MemoryStorage.Entries(t.lastIndex()+1, hi, maxSize-size)
		if err != nil {
			return nil, err
		}
		out = append(out, rest...)
	}
	return out, nil
}
