// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"path/filepath"
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
