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

// A share places where a group's FIRST cut falls, so that the groups of a node, loaded alike, do not cut together; every cut
// after it is due at the whole bounds. A share that lasted would cut a group at its share of the bound for as long as it
// runs, which is more cuts, and more of the work a cut costs, than the bound the cadence names (the 64 data groups of a
// node cut at an average of three quarters of it), and it keeps the journal a restart replays below the bound only by paying
// for it on every cut.
func TestStaggerIsTheShareOfTheFirstCutOnly(t *testing.T) {
	g := &Group{cadence: Cadence{Commands: 2048, Bytes: 16 << 20, Stagger: StaggerBase / 2}}
	g.sinceCommands = 1024
	if !g.cutDue() {
		t.Fatal("the first cut of a group of share 512/1024 is due at half the command bound")
	}
	g.sinceCommands, g.sinceBytes = 0, 8<<20
	if !g.cutDue() {
		t.Fatal("the first cut of a group of share 512/1024 is due at half the byte bound")
	}
	g.cadenceCuts.Store(1) // its first cut completed
	g.sinceCommands, g.sinceBytes = 1024, 8<<20
	if g.cutDue() {
		t.Fatal("after its first cut a group is due at the whole bound, not at its share")
	}
	g.sinceCommands, g.sinceBytes = 2047, 16<<20-1
	if g.cutDue() {
		t.Fatal("a group is not due short of the whole bounds")
	}
	if g.sinceCommands = 2048; !g.cutDue() {
		t.Fatal("a group is due at the whole command bound")
	}
	if g.sinceCommands, g.sinceBytes = 0, 16<<20; !g.cutDue() {
		t.Fatal("a group is due at the whole byte bound")
	}
}

func sinceCommandsOf(g *Group) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sinceCommands
}

// The same on a running group: the first cut falls at its share of the bound, the next one a whole bound later.
func TestStaggeredGroupCutsAtTheWholeBoundAfterItsFirstCut(t *testing.T) {
	g, m := openBounded(t, Config{Cadence: Cadence{Commands: 20, Stagger: StaggerBase / 2}})
	puts := 0
	put := func() { putWhole(t, g, m, puts); puts++ }
	waitCuts := func(want uint64, what string) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); g.CadenceCuts() < want; time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d cuts after %d commands, want %d", what, g.CadenceCuts(), puts, want)
			}
		}
	}
	for range 12 { // past 10, the share of 20
		put()
	}
	waitCuts(1, "a group at 512/1024 of a bound of 20 commands")
	// What was applied while that cut ran counts toward the next one. Up to 15 since it is short of the bound of 20 and
	// past the share, 10, that the first cut fell at.
	for sinceCommandsOf(g) < 15 {
		put()
	}
	time.Sleep(500 * time.Millisecond)
	if cuts := g.CadenceCuts(); cuts != 1 {
		t.Fatalf("the group cut %d times after %d commands, with %d since its first cut: after the first cut it is due at the whole bound of 20, not at its share of 10", cuts, puts, sinceCommandsOf(g))
	}
	for sinceCommandsOf(g) < 20 && g.CadenceCuts() < 2 {
		put()
	}
	waitCuts(2, "a group at the whole bound of 20 commands since its first cut")
}

// A reader of CadenceCuts that wants every cut the commands it has appended called for must be able to tell a cut that is
// slow from one that is not coming: CadencePending is true from the command that reached the bound, through the cut,
// until the moment the cut is counted (never a moment of neither, or the reader sees the count before it moves).
func TestCadencePendingCoversTheCutFromTheBoundUntilItIsCounted(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once, released sync.Once
	free := func() { released.Do(func() { close(release) }) }
	g, m := openBounded(t, Config{Cadence: Cadence{Commands: 4}, Fault: func(at string) error {
		if at == "snapshot_cut" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}})
	t.Cleanup(free) // a failed check must not leave Close waiting for the held cut (cleanups run last in, first out)
	if g.CadencePending() {
		t.Fatal("pending with no command applied but the election's")
	}
	putWhole(t, g, m, 0)
	if g.CadencePending() {
		t.Fatalf("pending with %d of 4 commands applied", sinceCommandsOf(g))
	}
	for sinceCommandsOf(g) < 4 {
		putWhole(t, g, m, 1)
	}
	if !g.CadencePending() {
		t.Fatal("not pending when the command that reached the bound was answered")
	}
	select { // the cut is running, held inside the snapshot
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the cut the bound called for never began")
	}
	if !g.CadencePending() || g.CadenceCuts() != 0 {
		t.Fatalf("a running cut: pending %v, cuts %d", g.CadencePending(), g.CadenceCuts())
	}
	free()
	deadline := time.Now().Add(30 * time.Second)
	for g.CadencePending() {
		if time.Now().After(deadline) {
			t.Fatal("the cut never ended")
		}
		time.Sleep(time.Millisecond)
	}
	if cuts := g.CadenceCuts(); cuts != 1 {
		t.Fatalf("no longer pending with %d cuts counted, want 1", cuts)
	}
}
