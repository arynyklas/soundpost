// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// The journal of a group is compacted onto every cadence cut, so a member that was down for longer than the
// interval between two cuts could only be given a snapshot of the whole state, for every group it missed (in the
// three-node installation ~50 groups of 60 MB over a 100 Mbit/s card, one every 4-5 s: the node never rejoined within
// the 60 s of its startup budget, reason=stale). A member that is away for less than Cadence.Retain must be caught up
// from the entries the others kept.
func TestAMemberThatWasDownThroughSeveralCutsIsCaughtUpWithoutASnapshot(t *testing.T) {
	memberDownThroughSeveralCuts(t, 400, 512, 0)
}

// The same with entries large enough that what a member needs does not fit one append (256 KiB): the catch-up is
// several appends that run on from the retained entries into the log without a gap. The tick is 100 ms (the product's):
// under the race detector the 10 ms tick of the other test lets a starved leader lose its leadership in the middle of
// 7 MB of proposals.
func TestAMemberThatWasDownThroughSeveralCutsOfLargeEntriesIsCaughtUpWithoutASnapshot(t *testing.T) {
	memberDownThroughSeveralCuts(t, 300, 24<<10, 100*time.Millisecond)
}

func memberDownThroughSeveralCuts(t *testing.T, commands, payload int, tick time.Duration) {
	t.Helper()
	c := newAsyncCluster(t, 1, func(_, _ int, cfg *Config) {
		cfg.Cadence = Cadence{Commands: 20, Retain: time.Minute, RetainBytes: 8 << 20}
		if tick > 0 {
			cfg.TickInterval = tick
		}
	})
	if err := c.groups[0][0].Campaign(); err != nil {
		t.Fatal(err)
	}
	await(t, 10*time.Second, "a leader", func() bool { return c.leader(0) == 1 })
	body := strings.Repeat("x", payload)
	propose := func(i int) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := c.groups[0][0].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("%d %s", i, body))}); err != nil {
			t.Fatalf("proposal %d: %v", i, err)
		}
	}
	for i := range 40 {
		propose(i)
	}
	// Member 3 is killed: its process and its in-memory state are gone, its journal stays.
	c.stop(2)
	downAt := c.groups[0][0].Status().LastIndex
	for i := 40; i < commands; i++ {
		propose(i)
	}
	// The leader and member 2 have cut and compacted past everything member 3 holds.
	for n := range 2 {
		g := c.groups[n][0]
		await(t, 20*time.Second, fmt.Sprintf("member %d compacted past %d", n+1, downAt), func() bool {
			first, _ := g.JournalRange()
			return first > downAt+1
		})
	}
	snapshotsBefore := c.wire.sent(3, pb.MsgSnap)
	began := time.Now()
	c.start(2)
	want := c.groups[0][0].Status().LastIndex
	await(t, 20*time.Second, "member 3 caught up", func() bool {
		g := c.groups[2][0]
		return g != nil && g.Status().Applied >= want
	})
	took := time.Since(began)
	if n := c.wire.sent(3, pb.MsgSnap) - snapshotsBefore; n != 0 {
		t.Fatalf("member 3 was sent %d snapshots after %d commands while it was down: it should have been given the entries the others retained", n, commands-40)
	}
	c.rows[2][0].mu.Lock()
	got := len(c.rows[2][0].rows)
	c.rows[2][0].mu.Unlock()
	if got != commands {
		t.Fatalf("member 3 holds %d of %d commands after catching up", got, commands)
	}
	t.Logf("member 3 caught up on %d commands in %v with no snapshot", commands-40, took)
}

// Retention is bounded: when the tail passes its byte bound the oldest entries go first, and a member that needs
// what went is given a snapshot, which is the same state.
func TestRetainedEntriesAreBoundedByBytes(t *testing.T) {
	var tail logTail
	entry := func(i uint64) *pb.Entry {
		return &pb.Entry{Index: proto.Uint64(i), Term: proto.Uint64(3), Data: make([]byte, 1000)}
	}
	var entries []*pb.Entry
	for i := uint64(11); i <= 50; i++ {
		entries = append(entries, entry(i))
	}
	tail.add(entries, 3)
	size := tail.bytes
	if tail.firstIndex() != 11 || tail.lastIndex() != 50 || tail.baseIndex != 10 {
		t.Fatalf("the tail is %d..%d (base %d), want 11..50 (base 10)", tail.firstIndex(), tail.lastIndex(), tail.baseIndex)
	}
	tail.trim(time.Now(), time.Hour, size/2)
	if tail.bytes > size/2 || tail.lastIndex() != 50 || tail.firstIndex() <= 11 {
		t.Fatalf("after a trim to %d bytes the tail is %d..%d with %d bytes: the oldest entries must go and the newest stay", size/2, tail.firstIndex(), tail.lastIndex(), tail.bytes)
	}
	if got := tail.term(tail.baseIndex); got != 3 {
		t.Fatalf("the term of the entry before the tail is %d", got)
	}
	tail.trim(time.Now(), time.Hour, 0)
	if !tail.empty() || tail.bytes != 0 {
		t.Fatalf("a bound of 0 left %d entries and %d bytes", len(tail.entries), tail.bytes)
	}
}

// The age of an entry is judged by the newest mark older than the window: what was applied before that mark goes,
// what was applied after it stays, and a run that does not continue the tail replaces it.
func TestRetainedEntriesAreKeptForTheWindow(t *testing.T) {
	var tail logTail
	now := time.Unix(1_800_000_000, 0)
	for i := uint64(1); i <= 100; i++ {
		tail.mark(i, now.Add(time.Duration(i)*time.Second), time.Second)
	}
	var entries []*pb.Entry
	for i := uint64(1); i <= 100; i++ {
		entries = append(entries, &pb.Entry{Index: proto.Uint64(i), Term: proto.Uint64(1), Data: []byte("x")})
	}
	tail.add(entries, 1)
	// At t=100 s with a 30 s window, the entries applied at or before t=70 s are older than the window.
	tail.trim(now.Add(100*time.Second), 30*time.Second, 1<<20)
	if tail.firstIndex() != 71 || tail.lastIndex() != 100 {
		t.Fatalf("a 30 s window at t=100 s keeps %d..%d, want 71..100", tail.firstIndex(), tail.lastIndex())
	}
	// A run that does not continue the tail (a snapshot was installed between two cuts) replaces it.
	tail.add([]*pb.Entry{{Index: proto.Uint64(500), Term: proto.Uint64(2), Data: []byte("y")}}, 2)
	if tail.firstIndex() != 500 || tail.lastIndex() != 500 || tail.baseIndex != 499 || tail.term(499) != 2 {
		t.Fatalf("a run after a gap left the tail at %d..%d (base %d)", tail.firstIndex(), tail.lastIndex(), tail.baseIndex)
	}
}

// What raft reads is one run of consecutive entries: a read that the byte limit stops inside the tail ends there. It
// must not go on into the in-memory log, which begins after the end of the tail, not after the entries that were read
// (a leader that did sent a follower entries 271..274 and 452..: the follower, a previous-release binary, panicked in
// raft's log on "applying(452) is out of range", and a member that was down never rejoined).
func TestRetainedEntriesAreReadAsOneRunOfConsecutiveEntries(t *testing.T) {
	const (
		tailFirst, tailLast = 271, 451
		memFirst, memLast   = 452, 470
		size                = 60 << 10
	)
	entry := func(i uint64) *pb.Entry {
		return &pb.Entry{Index: proto.Uint64(i), Term: proto.Uint64(6), Data: make([]byte, size)}
	}
	memory := raft.NewMemoryStorage()
	if err := memory.ApplySnapshot(&pb.Snapshot{Metadata: &pb.SnapshotMetadata{Index: proto.Uint64(tailLast), Term: proto.Uint64(6)}}); err != nil {
		t.Fatal(err)
	}
	var inMemory, retained []*pb.Entry
	for i := uint64(memFirst); i <= memLast; i++ {
		inMemory = append(inMemory, entry(i))
	}
	if err := memory.Append(inMemory); err != nil {
		t.Fatal(err)
	}
	for i := uint64(tailFirst); i <= tailLast; i++ {
		retained = append(retained, entry(i))
	}
	g := &Group{}
	g.tail.add(retained, 6)
	source := snapshotSource{MemoryStorage: memory, g: g}
	for _, c := range []struct {
		what      string
		lo, hi    uint64
		max       uint64
		wantFirst uint64
		wantAll   bool // the run reaches hi-1
	}{
		{"a read the limit stops inside the tail", tailFirst, memLast + 1, 256 << 10, tailFirst, false},
		{"a read of one entry more than the limit allows", tailFirst, memLast + 1, 1, tailFirst, false},
		{"a read that starts in the tail and ends in the log", tailLast - 2, memLast + 1, 1 << 30, tailLast - 2, true},
		{"a read of everything", tailFirst, memLast + 1, 1 << 30, tailFirst, true},
		{"a read inside the log", memFirst, memLast + 1, 1 << 30, memFirst, true},
	} {
		got, err := source.Entries(c.lo, c.hi, c.max)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if len(got) == 0 {
			t.Fatalf("%s: no entries", c.what)
		}
		for i, e := range got {
			if e.GetIndex() != c.wantFirst+uint64(i) {
				t.Fatalf("%s: entry %d of the run has index %d, want %d", c.what, i, e.GetIndex(), c.wantFirst+uint64(i))
			}
		}
		if c.wantAll != (got[len(got)-1].GetIndex() == c.hi-1) {
			t.Fatalf("%s: the run ends at %d (want to reach %d: %v)", c.what, got[len(got)-1].GetIndex(), c.hi-1, c.wantAll)
		}
	}
}
