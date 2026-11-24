// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The settlement pass offers the windows of every data group and derives the ones the engine has not derived
// yet, which decodes every command in them. The 64 groups of a node are loaded alike and seal their first
// window together, so the pass found 64 windows of 4,096 commands to derive; it did so under the engine lock,
// the lock every append of every slot takes for the index of its command, and every acknowledgement waited
// for the minute that took: at the gate the p95 went from 290 ms to 29 s and the goroutines from 349 to 12,000
// at 820 s of the single-host load (L2w20Admission21). The engine lock may be held for the engine's own state,
// not for the derivation.
func TestSettlePassDoesNotHoldTheEngineLockWhileItDerivesTheWindows(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4))
	w := newWindowEnv(t)
	w.add(9) // two sealed windows whose records are not persisted yet, one command in the third
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
	pass := make(chan error, 1)
	go func() { _, err := w.e.SettleCandidates(context.Background()); pass <- err }()
	// The pass has derived the windows and now waits for the write transaction the test holds, to persist
	// the records of the sealed ones.
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-pass:
		t.Fatalf("fixture invalid: the pass finished (%v) while the write transaction that it must wait for was open", err)
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
	if err := <-pass; err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Fatal("the settlement pass held the engine lock while it derived the windows of the slots")
	}
}
