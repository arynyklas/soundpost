// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// quiesceReaders waits until no read transaction is open on control.db. The store's own background
// readers (the attestation/withdraw loops and the verification the group starts with) hold short
// read transactions while the fixture starts; the tests below count readers exactly, so they begin
// once those have finished. It waits for the readers to end; it never closes or retries anything.
func (f *installFx) quiesceReaders() {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for f.s.db.openReaders() != 0 || f.s.db.Stats().OpenTxN != 0 {
		if time.Now().After(deadline) {
			f.t.Fatalf("fixture invalid: %d store readers and %d bolt readers never ended", f.s.db.openReaders(), f.s.db.Stats().OpenTxN)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// bolt registers a reader and only then updates Stats().OpenTxN, so a control scrub that trusted
// the stat could zero pages of a reader that is just beginning (internal/storage fixed the same
// hazard for apply.db: TestScrubDefersToAReaderBoltHasNotCountedYet). The store counts its
// readers itself before bolt sees them: a reader caught in that window defers the scrub, and the
// rerun finishes it.
func TestScrubDefersToAReaderBoltHasNotCountedYet(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true)) // this file owes a local scrub: the erased payload sits in free pages
	f.quiesceReaders()
	if !f.dbHolds() || !f.owesState() {
		t.Fatal("fixture invalid: the erased payload is not owed a scrub")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open()
	watchdog := time.AfterFunc(20*time.Second, open) // a failing assertion never leaves the reader held
	defer watchdog.Stop()
	gap := func() { close(entered); <-release }
	f.s.db.viewGap.Store(&gap)
	finished := make(chan error, 1)
	go func() { finished <- f.s.db.View(func(*bolt.Tx) error { return nil }) }()
	<-entered
	if n := f.s.db.Stats().OpenTxN; n != 0 {
		t.Fatalf("fixture invalid: bolt already counts %d readers", n)
	}
	err := f.s.ScrubErased(f.ctx)
	if mutantCode(err) != model.Unavailable {
		t.Fatalf("the scrub ran past a reader that was about to begin (answered %v), want unavailable (the debt is still owed)", err)
	}
	if !f.dbHolds() {
		t.Fatal("pages a beginning reader may read were zeroed")
	}
	if !f.owesState() || !f.local().owed {
		t.Fatalf("a scrub that could not run settled the debt: marker=%+v", f.local())
	}
	open()
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	if err = f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("the rerun after the reader ended: %v", err)
	}
	if f.dbHolds() || f.owesState() {
		t.Fatalf("the rerun left the payload or the debt: holds=%v owes=%v", f.dbHolds(), f.owesState())
	}
}

// bolt's own count stays in the guard: a reader the store did not count (one opened on the bare
// bolt handle, as tx.DB().View would) is registered by bolt and defers the scrub as well.
func TestScrubDefersToAReaderOnTheBareBoltHandle(t *testing.T) {
	f := newInstallFx(t)
	f.quiesceReaders()
	f.install(f.leader(5, true, true))
	f.quiesceReaders()
	held, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(stop) }) }
	defer open()
	watchdog := time.AfterFunc(20*time.Second, open)
	defer watchdog.Stop()
	go func() {
		defer close(done)
		_ = f.s.db.DB.View(func(*bolt.Tx) error {
			close(held)
			<-stop
			return nil
		})
	}()
	<-held
	if f.s.db.openReaders() != 0 || f.s.db.Stats().OpenTxN < 1 {
		t.Fatalf("fixture invalid: the store counts %d readers and bolt %d, want 0 and at least 1", f.s.db.openReaders(), f.s.db.Stats().OpenTxN)
	}
	err := f.s.ScrubErased(f.ctx)
	if mutantCode(err) != model.Unavailable {
		t.Fatalf("the scrub ran past a reader bolt counts (answered %v), want unavailable", err)
	}
	if !f.dbHolds() {
		t.Fatal("pages a reader may read were zeroed")
	}
	open()
	<-done
	if err = f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("the rerun after the reader ended: %v", err)
	}
	if f.dbHolds() || f.owesState() {
		t.Fatalf("the rerun left the payload or the debt: holds=%v owes=%v", f.dbHolds(), f.owesState())
	}
}

// Every read of control.db is counted before bolt sees it: each path below, started with the gap
// armed, is held after its reader was counted here and while bolt counts none. A path that opened
// its transaction on the bare bolt handle would run through the gap and be reported.
func TestEveryControlReadIsCountedBeforeBoltCountsIt(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	f.quiesceReaders() // the store's background readers end first: each path below must be the only reader
	reads := []struct {
		name string
		read func()
	}{
		{"Store.View", func() { _ = f.s.View(f.ctx, func(State) error { return nil }) }},
		{"scrubState", func() { _, _, _ = f.s.scrubState() }},
		{"localState", func() { _, _ = f.s.localState() }},
		{"localStateAt", func() { _, _, _ = f.s.localStateAt() }},
		{"appliedIndex", func() { _, _ = f.s.appliedIndex() }},
		{"staleCutoff", func() { f.s.staleCutoff() }},
		{"ResidualStores", func() { f.s.ResidualStores() }},
		{"ClusterOperationResidual", func() { f.s.ClusterOperationResidual(f.operation) }},
		{"replicatedControl.Applied", func() { f.s.repl.Applied() }},
		{"replicatedControl.Snapshot", func() { _, _ = f.s.repl.Snapshot() }},
	}
	for _, r := range reads {
		t.Run(r.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			open := func() { once.Do(func() { close(release) }) }
			defer open()
			watchdog := time.AfterFunc(20*time.Second, open)
			defer watchdog.Stop()
			gap := func() { close(entered); <-release }
			f.s.db.viewGap.Store(&gap)
			defer f.s.db.viewGap.Store(nil)
			done := make(chan struct{})
			go func() { defer close(done); r.read() }()
			select {
			case <-entered:
			case <-done:
				t.Fatal("the read ran without passing the counting View")
			}
			if f.s.db.openReaders() < 1 {
				t.Error("the held reader is not counted")
			}
			if n := f.s.db.Stats().OpenTxN; n != 0 {
				t.Errorf("fixture invalid: bolt already counts %d readers", n)
			}
			open()
			<-done
		})
	}
}
