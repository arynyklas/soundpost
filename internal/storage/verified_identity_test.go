// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// InstallReplicationIdentity re-binds a fresh engine to the identity of the installation it
// joins (appcore's enableReplication runs it after Open, which has already started the background
// verification). A verified record names the engine's identity and the 64 group ids derived from
// it, so a record that was built from the old identity, or from both, must never be the one the
// engine keeps. These tests install an identity at every point of a verification pass.

// reporter is what the assertion helpers need of *testing.T and *firstFailure.
type reporter interface {
	Errorf(format string, args ...any)
}

// holdVerifyPass holds the background pass of every engine the test opens until release runs.
func holdVerifyPass(t *testing.T) (release func()) {
	t.Helper()
	old := verifyGate
	gate := make(chan struct{})
	verifyGate = gate
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() { release(); verifyGate = old })
	return release
}

// openIdentityEngine opens an engine in dir that is closed with the test (Close is idempotent).
func openIdentityEngine(t *testing.T, dir string) *Engine {
	t.Helper()
	e, err := Open(dir, nopRevalidator{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Errorf("closing the engine: %v", err)
		}
	})
	return e
}

// recordOnDisk is the verified-record file of e, nil when there is none.
func recordOnDisk(t *testing.T, e *Engine) *verifiedRecord {
	t.Helper()
	raw, err := os.ReadFile(e.verifiedPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeVerifiedRecord(raw)
	if err != nil {
		t.Fatalf("the verified record on disk does not decode: %v", err)
	}
	return rec
}

// assertConsistent reports a record whose group ids are not the ones its own identity derives: the
// mark of a record built from two identities.
func assertConsistent(r reporter, what string, rec *verifiedRecord) {
	if rec == nil {
		return
	}
	if len(rec.Groups) != 64 {
		r.Errorf("%s lists %d groups, want 64", what, len(rec.Groups))
		return
	}
	of := &Engine{identity: rec.Identity}
	for slot, g := range rec.Groups {
		if g.Group != of.group(uint16(slot)) {
			r.Errorf("%s names identity %s but group %d of another identity", what, rec.Identity, slot)
			return
		}
	}
}

// assertBoundTo reports a record that is not of identity (nil is no record: nothing is kept).
func assertBoundTo(r reporter, what string, rec *verifiedRecord, identity model.ID) {
	if rec == nil {
		return
	}
	if rec.Identity != identity {
		r.Errorf("%s is bound to identity %s, the engine's is %s", what, rec.Identity, identity)
		return
	}
	assertConsistent(r, what, rec)
}

// waitRecord polls until the engine holds a record (the background pass keeps one) and returns it.
func waitRecord(t *testing.T, e *Engine, what string) *verifiedRecord {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if rec := e.verifiedRec(); rec != nil {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: no verified record within 30s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The deterministic case: the install lands after the pass built its record and before it keeps
// it, on the pass's own goroutine (the fault point verify_built runs with no lock held).
func TestAPassThatBuiltItsRecordBeforeAnIdentityInstallKeepsNoRecordOfTheOldIdentity(t *testing.T) {
	holdVerifyPass(t)
	dir := t.TempDir()
	e := openIdentityEngine(t, dir)
	original := e.identity // the background pass is held: nothing else reads or writes it
	if rec := e.verifiedRec(); rec == nil || rec.Identity != original {
		t.Fatalf("fixture: Open must leave a record of the engine's own identity, has %v", rec)
	}
	joined := model.NewID()
	fired := 0
	e.setFault(func(at string) error {
		if at != "verify_built" {
			return nil
		}
		fired++
		if fired == 1 {
			return e.InstallReplicationIdentity(joined)
		}
		return nil
	})
	if err := e.VerifyFull(context.Background()); err != nil {
		t.Fatalf("VerifyFull across the install: %v", err)
	}
	if fired != 1 {
		t.Fatalf("the fault point verify_built fired %d times, want 1 (fixture)", fired)
	}
	assertBoundTo(t, "the record the pass kept", e.verifiedRec(), joined)
	assertBoundTo(t, "the record file the pass left", recordOnDisk(t, e), joined)

	// The next pass records the new point, and the next start accepts it.
	e.setFault(nil)
	if err := e.VerifyFull(context.Background()); err != nil {
		t.Fatalf("VerifyFull after the install: %v", err)
	}
	rec := e.verifiedRec()
	if rec == nil {
		t.Fatal("a pass after the install recorded nothing")
	}
	if rec.Identity != joined {
		t.Fatalf("the record after the install names identity %s, want %s", rec.Identity, joined)
	}
	assertConsistent(t, "the record after the install", rec)
	if disk := recordOnDisk(t, e); disk == nil || disk.Identity != joined {
		t.Fatalf("the record file after the install is %v, want one of identity %s", disk, joined)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openIdentityEngine(t, dir)
	if got := reopened.StartupVerification(); got.Full {
		t.Fatalf("the restart verified in full (%q): the record after the install was not usable", got.Reason)
	}
}

// The same install, but the background loop itself runs the pass: after the first pass discarded
// its record the loop must run another one on its own.
func TestAnIdentityInstalledDuringTheBackgroundPassIsRecordedByTheLoop(t *testing.T) {
	release := holdVerifyPass(t)
	e := openIdentityEngine(t, t.TempDir())
	joined := model.NewID()
	installed := make(chan struct{})
	var once sync.Once
	e.setFault(func(at string) error {
		if at != "verify_built" {
			return nil
		}
		var err error
		once.Do(func() {
			err = e.InstallReplicationIdentity(joined)
			close(installed)
		})
		return err
	})
	release()
	select {
	case <-installed:
	case <-time.After(30 * time.Second):
		t.Fatal("the background pass never reached verify_built")
	}
	rec := waitRecord(t, e, "after the install")
	assertBoundTo(t, "the record kept after an install during the pass", rec, joined)
	assertBoundTo(t, "the record file after an install during the pass", recordOnDisk(t, e), joined)
}

// An install between two passes (the first record is already kept): the old identity's record is
// gone at once, and the loop, which would otherwise sleep for the whole interval, records again.
func TestAnIdentityInstalledBetweenPassesDropsTheOldRecordAndTheLoopRecordsAgain(t *testing.T) {
	release := holdVerifyPass(t)
	e := openIdentityEngine(t, t.TempDir())
	original := e.identity
	if rec := e.verifiedRec(); rec == nil || rec.Identity != original {
		t.Fatalf("fixture: Open must leave a record of the engine's own identity, has %v", rec)
	}
	joined := model.NewID()
	if err := e.InstallReplicationIdentity(joined); err != nil {
		t.Fatal(err)
	}
	// The pass is still held: whatever stands now is what an engine that crashed here would leave.
	if rec := e.verifiedRec(); rec != nil {
		t.Errorf("the record of identity %s survived the install of %s in memory", rec.Identity, joined)
	}
	if rec := recordOnDisk(t, e); rec != nil {
		t.Errorf("the record file of identity %s survived the install of %s", rec.Identity, joined)
	}
	release()
	rec := waitRecord(t, e, "after the install")
	assertBoundTo(t, "the first record the loop kept after the install", rec, joined)

	// The loop is now waiting out its interval; a second install must wake it.
	again := model.NewID()
	if err := e.InstallReplicationIdentity(again); err != nil {
		t.Fatal(err)
	}
	if got := e.verifiedRec(); got != nil && got.Identity != again {
		t.Errorf("the record of identity %s survived the install of %s in memory", got.Identity, again)
	}
	rec = waitRecord(t, e, "after the second install")
	assertBoundTo(t, "the record the idle loop kept after the second install", rec, again)
	assertBoundTo(t, "the record file after the second install", recordOnDisk(t, e), again)
}

// The race detector's case (see verified_race_test.go for why this detection does not depend on
// timing): installs of one identity after another while passes run on other goroutines. Reading
// the identity in the pass without e.mu is a data race; building the record from two reads of it
// is a record whose groups are not its identity's.
func TestIdentityInstallRacesTheVerificationPass(t *testing.T) {
	holdVerifyPass(t)
	e := openIdentityEngine(t, t.TempDir())
	bad := &firstFailure{t: t}
	ctx := context.Background()
	overlapped(30, func() {
		if err := e.InstallReplicationIdentity(model.NewID()); err != nil {
			bad.Errorf("InstallReplicationIdentity: %v", err)
		}
	}, func() {
		if err := e.VerifyFull(ctx); err != nil {
			bad.Errorf("VerifyFull: %v", err)
		}
	}, func() {
		assertConsistent(bad, "a record kept beside an install", e.verifiedRec())
	})
	if e.VerifyFailure() != nil {
		t.Fatalf("a clean engine failed verification: %v", e.VerifyFailure())
	}
	if err := e.VerifyFull(ctx); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	identity := e.identity
	e.mu.Unlock()
	rec := e.verifiedRec()
	if rec == nil {
		t.Fatal("no record after a pass that no install overlapped")
	}
	if rec.Identity != identity {
		t.Fatalf("the record names identity %s, the engine's is %s", rec.Identity, identity)
	}
	assertConsistent(t, "the final record", rec)
}
