// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Decision D4: the retry table of a digest machine is bounded by age and by count, and a group
// with a Cadence cuts and compacts on its own.

type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func openBounded(t *testing.T, cfg Config) (*Group, *wholeMachine) {
	t.Helper()
	id := model.NewID()
	machine := newWholeMachine(id)
	transport := NewLoopback()
	cfg.ID, cfg.Group, cfg.Directory, cfg.Transport, cfg.Members, cfg.Machine = 1, id, filepath.Join(t.TempDir(), "raft"), transport, soloMembers(), digestMachine{machine}
	group, err := Open(cfg)
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Close() })
	if err = transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		t.Fatal(err)
	}
	return group, machine
}

func putWhole(t *testing.T, g *Group, m *wholeMachine, i int) wholeRow {
	t.Helper()
	e := wholeEntry(m.current().Rev, bigState(i))
	c, err := g.Propose(t.Context(), e)
	if err != nil {
		t.Fatal(err)
	}
	return wholeRow{entry: e, acked: c}
}

func retryCount(g *Group) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.completed)
}

// A retry inside the window is answered with its original receipt; outside it the command is no
// longer recognized and is proposed afresh, where the revision it expects makes it a conflict
// instead of a second effect.
func TestRetryTableForgetsACommandAfterTheWindowAndKeepsItInside(t *testing.T) {
	clock := &stepClock{t: time.Unix(1_800_000_000, 0)}
	g, m := openBounded(t, Config{Now: clock.now})
	old := putWhole(t, g, m, 0)
	clock.advance(23 * time.Hour)
	recent := putWhole(t, g, m, 1)
	retry, err := g.Propose(t.Context(), old.entry)
	if err != nil {
		t.Fatalf("a retry inside the window: %v", err)
	}
	requireSameReceipt(t, "inside the window", old.acked, retry)
	clock.advance(2 * time.Hour) // old is 25 h behind the next command, recent 2 h
	putWhole(t, g, m, 2)
	if _, err = g.Propose(t.Context(), recent.entry); err != nil {
		t.Fatalf("a retry 2 h old: %v", err)
	}
	before := m.current().Rev
	if _, err = g.Propose(t.Context(), old.entry); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrStale) {
		t.Fatalf("a retry 25 h old was answered %v; it must be proposed afresh and rejected (stale application index or expected revision)", err)
	}
	if m.current().Rev != before {
		t.Fatal("the replayed command took effect a second time")
	}
}

func TestRetryTableKeepsOnlyTheNewestEntriesWhenTheCountIsReached(t *testing.T) {
	g, m := openBounded(t, Config{RetryMax: 5})
	var rows []wholeRow
	for i := range 9 {
		rows = append(rows, putWhole(t, g, m, i))
	}
	if n := retryCount(g); n != 5 {
		t.Fatalf("the retry table holds %d commands, want 5", n)
	}
	for _, r := range rows[4:] {
		retry, err := g.Propose(t.Context(), r.entry)
		if err != nil {
			t.Fatal(err)
		}
		requireSameReceipt(t, "newest", r.acked, retry)
	}
	if _, err := g.Propose(t.Context(), rows[0].entry); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrStale) {
		t.Fatalf("the oldest command is still recognized: %v", err)
	}
}

func TestDefaultRetryBoundsAreTheApprovedOnes(t *testing.T) {
	if DefaultRetryWindow != 24*time.Hour || DefaultRetryMax != 100000 {
		t.Fatalf("D4: 24 h / 100000 entries, have %v / %d", DefaultRetryWindow, DefaultRetryMax)
	}
}

func TestCadenceCutsAndCompactsWithoutAnyDeletion(t *testing.T) {
	g, m := openBounded(t, Config{Cadence: Cadence{Commands: 10}})
	first, _ := g.JournalRange()
	for i := range 25 {
		putWhole(t, g, m, i)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if now, _ := g.JournalRange(); now > first+10 {
			return
		}
		if time.Now().After(deadline) {
			now, _ := g.JournalRange()
			t.Fatalf("25 commands at a cadence of 10 left the journal head at %d (was %d)", now, first)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestNoCadenceNeverCompacts(t *testing.T) {
	g, m := openBounded(t, Config{})
	first, _ := g.JournalRange()
	for i := range 25 {
		putWhole(t, g, m, i)
	}
	time.Sleep(300 * time.Millisecond)
	if now, _ := g.JournalRange(); now != first {
		t.Fatalf("a group without a cadence compacted: head %d -> %d", first, now)
	}
}

// A wake that arrives while a cut is running is still queued when the cut ends, and the cut has
// already counted what made it: the loop must look at the counters again and not cut a second time
// for nothing (measured on three voters: every cut was followed by one more, 10 commands later).
func TestCadenceLoopDoesNotCutAgainOnAWakeThatIsNoLongerDue(t *testing.T) {
	g, m := openBounded(t, Config{Cadence: Cadence{Commands: 1000}})
	first, _ := g.JournalRange()
	for i := range 3 {
		putWhole(t, g, m, i)
	}
	g.cadenceWake <- struct{}{} // what a command applied during an earlier cut left behind
	time.Sleep(500 * time.Millisecond)
	if cuts := g.CadenceCuts(); cuts != 0 {
		t.Fatalf("3 commands at a cadence of 1000 were cut %d times", cuts)
	}
	if now, _ := g.JournalRange(); now != first {
		t.Fatalf("the journal head moved from %d to %d with 3 commands at a cadence of 1000", first, now)
	}
}

// Close stops the cadence loop and waits for a cut in progress: nothing under the group's directory may change after Close
// returned (a cut still writing snapshot files raced the caller's cleanup: `directory not empty` on CI).
func TestCloseWaitsForACadenceCut(t *testing.T) {
	for round := range 20 {
		dir := filepath.Join(t.TempDir(), "raft")
		id := model.NewID()
		machine := newWholeMachine(id)
		transport := NewLoopback()
		g, err := Open(Config{ID: 1, Group: id, Directory: dir, Transport: transport, Members: soloMembers(), Machine: digestMachine{machine}, Cadence: Cadence{Commands: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if err = transport.Register(g); err == nil {
			err = g.Campaign()
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			putWhole(t, g, machine, i)
		}
		_ = g.Close()
		transport.Close()
		before := treeState(t, dir)
		time.Sleep(200 * time.Millisecond)
		if after := treeState(t, dir); after != before {
			t.Fatalf("round %d: the group directory changed after Close returned:\nbefore %s\nafter  %s", round, before, after)
		}
	}
}

// treeState lists every path under dir with its size.
func treeState(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s:%d;", p, info.Size())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A cut of a machine that writes its whole state costs the size of the state: the bounds of an amortizing
// cadence grow with the snapshot of the last cut (half of it in journal), a plain one never does.
func TestAmortizingCadenceScalesWithTheLastSnapshot(t *testing.T) {
	g := &Group{cadence: Cadence{Commands: 100, Bytes: 8 << 20, Amortize: true}}
	g.sinceBytes = 9 << 20
	if !g.cutDue() {
		t.Fatal("9 MiB of journal over an 8 MiB bound is due with no snapshot size known")
	}
	g.cutBytes = 160 << 20 // the last cut wrote 160 MB: 80 MiB of journal may accumulate
	if g.cutDue() {
		t.Fatal("9 MiB of journal is not due after a 160 MB snapshot")
	}
	g.sinceBytes = 81 << 20
	if !g.cutDue() {
		t.Fatal("81 MiB of journal is due after a 160 MB snapshot")
	}
	g.sinceBytes, g.sinceCommands = 0, 900
	if g.cutDue() {
		t.Fatal("900 commands are not due when the command bound grew to 1000 with the snapshot")
	}
	g.sinceCommands = 1000
	if !g.cutDue() {
		t.Fatal("1000 commands are due")
	}
	plain := &Group{cadence: Cadence{Commands: 100, Bytes: 8 << 20}, cutBytes: 160 << 20}
	plain.sinceBytes = 9 << 20
	if !plain.cutDue() {
		t.Fatal("a cadence that does not amortize ignores the snapshot size")
	}
}

// The 64 data groups of a node are loaded alike and cut at the same bound; each is given a share of the bounds
// (Cadence.Stagger) so the cuts of a node fall one after another (L2w20Admission19, L2w20Admission20). A share
// scales both bounds, never below one command or byte, and 0 or the whole base is the whole bound.
func TestStaggeredCadenceCutsAtItsShareOfTheBounds(t *testing.T) {
	due := func(c Cadence, commands uint64, bytes int64) bool {
		g := &Group{cadence: c, sinceCommands: commands, sinceBytes: bytes}
		return g.cutDue()
	}
	base := Cadence{Commands: 2048, Bytes: 16 << 20}
	half := base
	half.Stagger = StaggerBase / 2
	if due(half, 1023, 0) || !due(half, 1024, 0) {
		t.Fatal("a share of 512/1024 cuts at 1024 of 2048 commands, not before")
	}
	if due(half, 0, 8<<20-1) || !due(half, 0, 8<<20) {
		t.Fatal("a share of 512/1024 cuts at 8 MiB of a 16 MiB bound, not before")
	}
	for _, whole := range []uint16{0, StaggerBase, StaggerBase + 7} {
		c := base
		c.Stagger = whole
		if due(c, 2047, 16<<20-1) || !due(c, 2048, 0) || !due(c, 0, 16<<20) {
			t.Fatalf("a share of %d is the whole bound", whole)
		}
	}
	tiny := Cadence{Commands: 1, Bytes: 1, Stagger: 1}
	if due(tiny, 0, 0) || !due(tiny, 1, 0) || !due(tiny, 0, 1) {
		t.Fatal("a share never takes a bound below one command or byte")
	}
	grown := &Group{cadence: Cadence{Commands: 100, Bytes: 8 << 20, Amortize: true, Stagger: StaggerBase / 2}, cutBytes: 160 << 20}
	grown.sinceBytes = 39 << 20
	if grown.cutDue() {
		t.Fatal("the share applies to the grown bound: 80 MiB halved is 40 MiB")
	}
	grown.sinceBytes = 40 << 20
	if !grown.cutDue() {
		t.Fatal("40 MiB is due at half of an 80 MiB amortized bound")
	}
}

// Two groups of one cadence that differ only in their share cut at different points of the same load: the
// smaller share cuts first, the other has not reached its bound.
func TestGroupsWithDifferentSharesCutAtDifferentCommands(t *testing.T) {
	early, em := openBounded(t, Config{Cadence: Cadence{Commands: 20, Stagger: StaggerBase / 2}})
	late, lm := openBounded(t, Config{Cadence: Cadence{Commands: 20, Stagger: StaggerBase * 3 / 4}})
	// 12 commands: past 10 (half of 20), short of 15 (three quarters of 20).
	for i := range 12 {
		putWhole(t, early, em, i)
		putWhole(t, late, lm, i)
	}
	deadline := time.Now().Add(30 * time.Second)
	for early.CadenceCuts() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("12 commands at 512/1024 of a 20 command bound did not cut")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := late.CadenceCuts(); got != 0 {
		t.Fatalf("a group at 768/1024 of a 20 command bound cut %d times at 12 commands", got)
	}
}
