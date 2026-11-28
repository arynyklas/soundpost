// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// A snapshot cut of one data group derives the windows of its slot, and the open one means decoding every
// command in it: a second of CPU at the single-host load. It did so under the engine lock, the lock every append
// of every slot takes for the index of its command, so each cut stopped the whole engine for that second and the
// 64 cuts that fell together stopped it for a minute: at the gate the p95 of the acknowledgements went from
// 140 ms to 22 s when the groups reached their first cut (L2w20Admission19). The engine lock may be held for
// the engine's own state, not for the derivation.
func TestSnapshotCutDoesNotHoldTheEngineLockWhileItDerivesTheWindows(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4))
	w := newWindowEnv(t)
	w.add(9) // two sealed windows whose records are not persisted yet, one command in the third
	m := &slotMachine{engine: w.e, slot: w.slot}
	held, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- w.e.db.Update(func(*bolt.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	cut := make(chan error, 1)
	go func() { _, err := m.CompactSnapshot(); cut <- err }()
	// The cut has derived the windows and now waits for the write transaction the test holds, to persist the
	// records of the sealed ones.
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-cut:
		t.Fatalf("fixture invalid: the cut finished (%v) while the write transaction that it must wait for was open", err)
	default:
	}
	free := w.e.mu.TryLock()
	if free {
		w.e.mu.Unlock()
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if err := <-cut; err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Fatal("a snapshot cut held the engine lock while it derived the windows of its slot")
	}
}

// The 64 data groups of a node are loaded alike: with one bound for all of them they reach it at the same
// instant, and the cuts that follow fall together. Each group is given a different share of the bound.
func TestDataGroupsAreGivenDifferentSharesOfTheirCadence(t *testing.T) {
	seen := map[uint16]bool{}
	lowest, highest := uint16(1<<15), uint16(0)
	for slot := range uint16(64) {
		s := slotStagger(slot)
		if seen[s] {
			t.Fatalf("slot %d has the share %d of another slot", slot, s)
		}
		seen[s] = true
		lowest, highest = min(lowest, s), max(highest, s)
	}
	if lowest < 512 || highest >= 1024 || highest-lowest < 480 {
		t.Fatalf("the shares of the 64 groups run from %d to %d of 1024, want them spread over the second half of the bound", lowest, highest)
	}
	w := newWindowEnv(t)
	for slot, g := range w.e.repl.groups {
		if got, want := g.Cadence().Stagger, slotStagger(uint16(slot)); got != want {
			t.Fatalf("the group of slot %d runs with the share %d, want %d", slot, got, want)
		}
	}
}

// maxEngineLockStall is the longest the engine lock stayed unavailable while the cuts of all the groups of a
// node ran together. Every append of every slot takes the lock for the index of its command, so this is how long
// all acknowledgements wait for a cut: at the gate a cut that derived its windows under the lock held it for
// ~1 s, and the 64 cuts that fell together for a minute (L2w20Admission19: p95 140 ms -> 22 s). The derivation is
// off the lock now, and what remains of a cut under it is a pointer read: a stall of tens of milliseconds
// is the scheduler's, not the cuts'.
const maxEngineLockStall = 150 * time.Millisecond

// All 64 data groups of a node cut at the same moment (the load is alike, so without a stagger they reach their
// bound together): the engine lock stays available to the appends throughout. The cuts wait together for the
// write transaction that persists the records of the windows they sealed, which the test holds open for
// stallHold; a cut that holds the engine lock across its derivation keeps it for that long, and the others queue
// behind it. The window is 4 commands, so every slot has two sealed windows to persist and one command open.
func TestAllGroupsCuttingAtOnceDoNotStallTheEngineLock(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4))
	const perSlot = 9
	const stallHold = 600 * time.Millisecond
	w := newWindowEnv(t)
	var names [64]string
	for i, found := 0, 0; found < 64; i++ {
		if i == 1<<16 {
			t.Fatalf("series for %d of the 64 slots among the first %d names", found, i)
		}
		name := fmt.Sprintf("cut_series_%d", i)
		if slot := ackPagesSlotOf(t, w.desc, name); names[slot] == "" {
			names[slot] = name
			found++
		}
	}
	for slot := range names {
		producer := model.NewID()
		for j := range perSlot {
			scope, b := settleBatch(t, w.store, w.service, w.cred, w.desc, producer, model.UnixNano(j+1), names[slot])
			if _, err := w.e.Append(context.Background(), scope, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	var (
		derivedBefore = windowCommandsDerived.Load()
		held, release = make(chan struct{}), make(chan struct{})
		writer        = make(chan error, 1)
		stalls        = make(chan time.Duration, 1)
		stopProbe     = make(chan struct{})
		cutErr        = make(chan error, 64)
		started, done sync.WaitGroup
		begin         = make(chan struct{})
	)
	go func() {
		writer <- w.e.db.Update(func(*bolt.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	go func() { // the probe: the longest unbroken time the engine lock was not free
		var worst time.Duration
		var since time.Time
		for {
			select {
			case <-stopProbe:
				stalls <- worst
				return
			default:
			}
			if w.e.mu.TryLock() {
				w.e.mu.Unlock()
				if !since.IsZero() {
					worst, since = max(worst, time.Since(since)), time.Time{}
				}
			} else if since.IsZero() {
				since = time.Now()
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	for slot := range uint16(64) {
		started.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			m := &slotMachine{engine: w.e, slot: slot}
			started.Done()
			<-begin
			_, err := m.CompactSnapshot()
			cutErr <- err
		}()
	}
	started.Wait()
	close(begin)
	time.Sleep(stallHold)
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	done.Wait()
	close(stopProbe)
	worst := <-stalls
	close(cutErr)
	for err := range cutErr {
		if err != nil {
			t.Fatal(err)
		}
	}
	if derived := windowCommandsDerived.Load() - derivedBefore; derived < 64*perSlot {
		t.Fatalf("fixture invalid: the 64 cuts derived %d commands, want at least %d (every window of every slot)", derived, 64*perSlot)
	}
	t.Logf("64 cuts at once, held %v by one write transaction: the engine lock was unavailable for at most %v", stallHold, worst)
	if worst > maxEngineLockStall {
		t.Fatalf("64 cuts at once kept the engine lock from every append for %v, want at most %v", worst, maxEngineLockStall)
	}
}
