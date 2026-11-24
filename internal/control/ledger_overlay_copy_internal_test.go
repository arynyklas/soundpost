// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The shared copy of the overlay's generations (ovShared) is what every transaction of the ledger reads. A transaction that
// finds it invalid or late loads the generations from the log (inflate and decode of up to two generations of 24 MiB of records:
// a second at the single-host gate), and at the gate dozens of them did so at once, again and again, each time under the lock of
// the next writer: the 2-15 s stalls of the 900 s runs (loads 8-15 and 5-15 s of load time in a two-second sample,
// L2w20Admission30/d3a). These tests are the properties that end that: one load for all the transactions that need the same
// version, a copy that follows commits whose handlers ran out of order, and a wait for a handler that is late.

// fillOverlay writes records (the keys of the reservation table, which do not repeat) in commits of per records into the log of
// the store's overlay, as the generation that never freezes (withSmallOverlay).
func fillOverlay(t *testing.T, s *Store, commits, per int) {
	t.Helper()
	n := 0
	for range commits {
		writeLedger(t, s, func(l *ledgerTx) error {
			for range per {
				key := []byte(fmt.Sprintf("o1:p%02d:s1:pr:%d:batch%06d", n%100, n%3, n/300))
				if err := l.put(tableKeys, key, []byte(fmt.Sprintf("res%08d", n))); err != nil {
					return err
				}
				n++
			}
			return nil
		})
	}
}

// readOnce reads one key of the overlay in a read transaction that is already begun.
func readOnce(t *testing.T, tx *bolt.Tx) {
	t.Helper()
	l, err := openLedger(tx)
	if err != nil {
		t.Error(err)
		return
	}
	l.t[tableKeys].Get([]byte("o1:p00:s1:pr:0:batch000000"))
}

// concurrently runs fn n times at once and waits for all of them.
func concurrently(n int, fn func(i int)) {
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range n {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			fn(i)
		}()
	}
	start.Done()
	done.Wait()
}

// Sixteen readers that find the copy gone each used to load the generations: sixteen loads, and a second of CPU each at the gate's
// size. One of them loads, the others take its copy.
func TestOverlayLoadsOnceForTheReadersThatFindTheCopyInvalid(t *testing.T) {
	withSmallOverlay(t, 1<<30, 256, 1<<14)
	s := newLedgerStore(t)
	fillOverlay(t, s, 50, 2000)
	forgetOverlay(s.db.DB) // the copy is gone, as after a restart or a drop: the log holds 100,000 records
	before := ovStats.loads.Load()
	concurrently(16, func(int) {
		_ = s.db.View(func(tx *bolt.Tx) error { readOnce(t, tx); return nil })
	})
	if got := ovStats.loads.Load() - before; got != 1 {
		t.Fatalf("16 readers of one version loaded the generations %d times, want once", got)
	}
}

// Readers that began before a commit and look at the ledger after it are older than the copy: they used to load a private copy each,
// of the version they share. They share one.
func TestOverlayLoadsOnceForTheReadersOfOneOldVersion(t *testing.T) {
	withSmallOverlay(t, 1<<30, 256, 1<<14)
	s := newLedgerStore(t)
	fillOverlay(t, s, 50, 2000)
	_ = s.db.View(func(tx *bolt.Tx) error { readOnce(t, tx); return nil }) // the copy holds this version
	const readers = 12
	var txs [readers]*bolt.Tx
	for i := range txs {
		tx, err := s.db.Begin(false)
		if err != nil {
			t.Fatal(err)
		}
		txs[i] = tx
	}
	fillOverlay(t, s, 1, 10) // the copy moves on: the readers are older than it
	before := ovStats.loads.Load()
	concurrently(readers, func(i int) { readOnce(t, txs[i]) })
	for _, tx := range txs {
		_ = tx.Rollback()
	}
	if got := ovStats.loads.Load() - before; got != 1 {
		t.Fatalf("%d readers of one old version loaded the generations %d times, want once", readers, got)
	}
}

// ovTestWriter is the commit of version base to base+1 that appends one record to slot 0.
func ovTestWriter(base uint64, key string) *ovWriter {
	ents := newOvMaps()
	ents[0][key] = []byte("v" + key)
	return &ovWriter{base: ovMeta{seq: base}, meta: ovMeta{seq: base + 1}, ops: []ovOp{{kind: ovAppend, ents: ents}}}
}

// The handler of a commit runs after the writer lock is released, so the handler of the next commit can run first. The copy used to
// drop itself at that (it did not hold the version the second commit started from): the next reader loaded it again, and again.
func TestOverlayCopyFollowsCommitsWhoseHandlersRunOutOfOrder(t *testing.T) {
	sh := &ovShared{ok: true, seq: 5, active: newOvGen(1)}
	sh.apply(ovTestWriter(6, "b")) // the handler of 6 -> 7 ahead of the handler of 5 -> 6
	if !sh.ok {
		t.Fatal("the copy dropped itself at a commit whose predecessor's handler had not run")
	}
	sh.apply(ovTestWriter(5, "a"))
	if !sh.ok || sh.seq != 7 {
		t.Fatalf("after both handlers the copy is valid=%v at version %d, want 7", sh.ok, sh.seq)
	}
	for _, k := range []string{"a", "b"} {
		if string(sh.active.m[0][k]) != "v"+k {
			t.Fatalf("the copy lacks the record of commit %q: %q", k, sh.active.m[0][k])
		}
	}
}

// A copy that a reader loaded from its snapshot is behind by the commits that landed during the load; their handlers ran while it
// was not installed and are parked, so installing it brings it up to date without a second load.
func TestOverlayInstalledCopyTakesTheCommitsThatLandedDuringItsLoad(t *testing.T) {
	sh := &ovShared{}
	sh.apply(ovTestWriter(5, "a")) // commits of versions 5 -> 8 land while a reader loads version 5
	sh.apply(ovTestWriter(6, "b"))
	sh.apply(ovTestWriter(7, "c"))
	sh.apply(ovTestWriter(3, "old")) // a commit the load already holds
	sh.mu.Lock()
	sh.install(newOvGen(1), nil, 5)
	sh.mu.Unlock()
	if !sh.ok || sh.seq != 8 {
		t.Fatalf("the installed copy is valid=%v at version %d, want 8", sh.ok, sh.seq)
	}
	for _, k := range []string{"a", "b", "c"} {
		if string(sh.active.m[0][k]) != "v"+k {
			t.Fatalf("the copy lacks the record of commit %q", k)
		}
	}
	if _, ok := sh.active.m[0]["old"]; ok {
		t.Fatal("the copy took a commit its load already held")
	}
	if len(sh.parked) != 0 {
		t.Fatalf("%d commits are still parked", len(sh.parked))
	}
}

// A transaction that began after a commit waits for the handler that brings the copy to its version. A handler that is a fifth of a
// second late (a thread not scheduled at 600 % CPU) is waited for, not replaced by a load that takes longer than the wait.
func TestOverlayWaitsForALateHandlerInsteadOfLoading(t *testing.T) {
	sh := &ovShared{ok: true, seq: 5, active: newOvGen(1)}
	ov := &ovTx{sh: sh, snap: ovMeta{seq: 6}}
	before := ovStats.loads.Load()
	go func() {
		time.Sleep(200 * time.Millisecond)
		sh.apply(ovTestWriter(5, "a"))
	}()
	ov.settle()
	if got := ovStats.loads.Load() - before; got != 0 {
		t.Fatalf("the transaction loaded the generations %d times while the handler of its version was on its way", got)
	}
	if ov.privSet || sh.seq != 6 {
		t.Fatalf("the transaction reads a private copy=%v, the copy is at version %d, want the shared one at 6", ov.privSet, sh.seq)
	}
}
