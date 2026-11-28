// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func recordedTotal(t *testing.T, x *eraseEnv) uint64 {
	t.Helper()
	raw, err := os.ReadFile(x.recordPath())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeVerifiedRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, g := range rec.Groups {
		total += uint64(g.Applied)
	}
	return total
}

// holdBackgroundVerification keeps the background loop (its full pass at the start and its advances) from running, so a test drives the advance itself.
func holdBackgroundVerification(t *testing.T) {
	t.Helper()
	verifyGate = make(chan struct{})
	t.Cleanup(func() { verifyGate = nil })
}

// The verified point of a running node follows what it applies (L2w20Admission22): the record used to be written by the start and by
// the full pass at the start, so a node that ran for an hour under load still held the point of its first second and its first restart
// verified the whole hour (tail lookups of every command and of every page's index entries before readiness), where the restart after a restart,
// whose record is fresh, took a seventh of that. The advance verifies the commands above the record exactly as a start does and moves the point.
func TestVerifiedPointAdvancesWhileTheNodeRuns(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(6, 100)
	if before := recordedTotal(t, x); before != 0 {
		t.Fatalf("the record already covers %d commands before any advance", before)
	}
	if err := x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := recordedTotal(t, x), totalApplied(x.e); got != want || got < 6 {
		t.Fatalf("recorded %d commands after the advance, applied %d", got, want)
	}
	x.closeEngine()
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	if v := x.e.StartupVerification(); v.Full || v.Commands != 0 || v.IndexEntries != 0 || v.SegmentsHashed != 0 {
		t.Fatalf("the start after an advanced point still verified history: %+v", v)
	}
}

// A pass with nothing new writes nothing, and the commands of a later pass are only those above the point.
func TestVerifiedAdvanceVerifiesOnlyWhatIsNew(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(4, 100)
	if err := x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(x.recordPath())
	if err != nil {
		t.Fatal(err)
	}
	if err = x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again, err := os.Stat(x.recordPath()); err != nil || !again.ModTime().Equal(info.ModTime()) {
		t.Fatalf("a pass with nothing new rewrote the record (%v)", err)
	}
	x.appendN(2, 200)
	if err = x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := recordedTotal(t, x), totalApplied(x.e); got != want || got < 6 {
		t.Fatalf("recorded %d commands after the second advance, applied %d", got, want)
	}
}

// The advance is a verification, not a bookmark: damage above the point fails the engine closed and the point stays where it was.
func TestVerifiedAdvanceRefusesDamageAboveThePoint(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	receipts := x.appendN(3, 100)
	slot := slotOf(t, x.e, receipts[0])
	err := x.e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_commands")).Delete(commandKey(slot, uint64(receipts[0].Cursor.Index)))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = x.e.advanceVerified(context.Background()); !isCorruptFault(err) {
		t.Fatalf("advance over a missing command: %v", err)
	}
	if x.e.VerifyFailure() == nil {
		t.Fatal("the engine was not failed closed")
	}
	// failVerify removes the record: the next start verifies in full, and nothing records the damaged history as verified.
	if _, err := os.Stat(x.recordPath()); !os.IsNotExist(err) {
		t.Fatalf("the record of a damaged history survives (%v)", err)
	}
}

// The background loop runs the advance by itself.
func TestBackgroundLoopAdvancesTheVerifiedPoint(t *testing.T) {
	old := verifyAdvanceInterval
	verifyAdvanceInterval = 20 * time.Millisecond
	t.Cleanup(func() { verifyAdvanceInterval = old })
	x := newEraseEnv(t)
	x.appendN(5, 100)
	deadline := time.Now().Add(20 * time.Second)
	for recordedTotal(t, x) != totalApplied(x.e) {
		if time.Now().After(deadline) {
			t.Fatalf("the verified point stayed at %d of %d applied commands", recordedTotal(t, x), totalApplied(x.e))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Writing the verified record does not stop the node (L2w20Admission29). The single-host gate froze every acknowledged request, all ten
// orgs at once, for seconds at a time, once a minute, in growing steps (a 5 s freeze at the first, 25 s with shedding at the 45th minute,
// p95 4.7 s over the hour) while the disk was not saturated: the advance wrote the record (a file fsync, a rename, the directory's fsync,
// each a commit of the file system's journal, which waits for the engine's own dirty pages) with e.mu held, and the 64 slot groups apply
// under e.mu. The record write here is held by the fault hook; an append of the node must complete while it is.
func TestVerifiedRecordWriteDoesNotHoldTheEngine(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(4, 100)
	ctx := context.Background()
	if err := x.e.VerifyFull(ctx); err != nil {
		t.Fatal(err)
	}
	x.appendN(2, 200)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	x.e.setFault(func(at string) error {
		if at == "verify_record_write" {
			once.Do(func() { close(entered) })
			<-release
		}
		return nil
	})
	passed := make(chan error, 1)
	go func() { passed <- x.e.advanceVerified(ctx) }()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("the advance never reached the write of the record")
	}
	appended := make(chan struct{})
	go func() {
		x.appendN(1, 300)
		close(appended)
	}()
	select {
	case <-appended:
	case <-time.After(5 * time.Second):
		t.Error("an append waited for the write of the verified record: the record is written with the engine lock held")
	}
	close(release)
	<-appended
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
	if got := recordedTotal(t, x); got < 6 {
		t.Fatalf("the advance recorded %d commands", got)
	}
}

// The read transaction of the advance (every command applied since the record, 35,000 acks a minute at the gate) does not stop the node
// either: appends commit beside it (bolt's writer does not wait for readers while the file is mapped ahead of its growth), and the engine
// lock is not held by the pass. The pass is held inside its transaction by the fault hook, with a hold bounded by the test.
func TestVerifyAdvanceReadTransactionDoesNotHoldTheEngine(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(4, 100)
	ctx := context.Background()
	if err := x.e.VerifyFull(ctx); err != nil {
		t.Fatal(err)
	}
	x.appendN(2, 200)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	x.e.setFault(func(at string) error {
		if at == "verify_advance_view" {
			once.Do(func() { close(entered) })
			<-release
		}
		return nil
	})
	passed := make(chan error, 1)
	go func() { passed <- x.e.advanceVerified(ctx) }()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("the advance never reached its read transaction")
	}
	start := time.Now()
	for i := range 5 {
		appended := make(chan struct{})
		go func() {
			x.appendN(1, 300+i)
			close(appended)
		}()
		select {
		case <-appended:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("append %d waited for the read transaction of the advance", i)
		}
	}
	t.Logf("5 appends took %v beside an open advance transaction", time.Since(start))
	close(release)
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
}
