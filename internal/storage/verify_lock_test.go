// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// A restart replays the 64 groups' journals from their snapshots, and each snapshot is verified against the
// stored commands by window: the open window of the slot is derived, which decodes every command in it (a second
// of CPU at 4,096 commands of 10 KB). The 64 groups open concurrently, but the check derived under the engine
// lock, so the derivations ran one after the other: 27 s of the 34 s the restart took after 900 s of the
// single-host load (L2w20Admission21). The derivation is excluded against erasure, the one writer that rewrites
// stored commands, by cutMu shared (as a snapshot cut's is), and holds no engine lock.
func TestSnapshotVerificationDerivesTheWindowsOffTheEngineLock(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4))
	w := newWindowEnv(t)
	w.add(9) // two sealed windows and one command open
	m := &slotMachine{engine: w.e, slot: w.slot}
	state, err := m.CompactSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	// Erasure rewrites stored commands under cutMu exclusive: a derivation that read them meanwhile would
	// compare a half-rewritten window.
	w.e.cutMu.Lock()
	verified := make(chan error, 1)
	go func() { verified <- m.VerifySnapshot(state) }()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-verified:
		w.e.cutMu.Unlock()
		t.Fatalf("the verification (%v) derived the windows while erasure held the right to rewrite the commands", err)
	default:
	}
	free := w.e.mu.TryLock()
	if free {
		w.e.mu.Unlock()
	}
	w.e.cutMu.Unlock()
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Fatal("the verification waited for erasure holding the engine lock: every append of every slot waited with it")
	}
}

// The identity check of a compact state hashes the stored bytes of the window's commands and decodes none of them;
// it must give the identity the full derivation gives, for ordinary commands and for the ones physical erasure
// rewrote (a redacted command counts as the original it replaced).
func TestWindowIdentityEqualsTheDerivedWindowsIdentity(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4))
	x := newEraseEnv(t)
	producer := model.NewID()
	var slot uint16
	for range 9 { // two sealed windows and one command open
		slot = x.appendMixedAs(producer, eraseCanary, bothDeadlines).batch.RouteSlot
	}
	check := func(when string) {
		t.Helper()
		table, err := x.e.windowTableOf(slot, 9, false, false, 0)
		if err != nil || len(table) != 3 {
			t.Fatalf("%s: window table %d (%v)", when, len(table), err)
		}
		err = x.e.db.View(func(tx *bolt.Tx) error {
			commands := tx.Bucket([]byte("replica_commands"))
			for _, w := range table {
				got, err := windowIdentity(commands, slot, w.First, w.Count)
				if err != nil || got != w.Identity {
					t.Fatalf("%s: window %d identity %x, derived %x (%v)", when, w.N, got, w.Identity, err)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	check("before the erasure")
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	check("after the erasure")
}
