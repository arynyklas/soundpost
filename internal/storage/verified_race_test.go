// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// e.ver.rec, the verified record, is replaced or dropped by the background pass (VerifyFull,
// failVerify) while Open's tail verification reads it through verifiedFrom and recordHasSegment.
// Every access takes e.ver.mu; an earlier version read the field directly and raced with
// failVerify. These tests hold readers and writers in flight together and fail under `go test
// -race` if a single access skips the lock.
//
// Why the detection is deterministic: the race detector reports two accesses that no
// synchronisation orders, whatever the interleaving; it does not need them to collide in time.
// overlapped orders nothing between a reader and the writer except the lock itself, and the
// field has four accessors (the test goroutine that opened the engine, the two readers, the
// writer), which fits the four shadow cells the detector keeps per word, so no earlier access is
// evicted before the conflicting one is checked against it.

// nopRevalidator is the Revalidator of an engine that never serves a request.
type nopRevalidator struct{}

func (nopRevalidator) Revalidate(context.Context, auth.Scope) error { return nil }

const (
	lockTestSlot    uint16 = 5
	lockTestApplied        = 7
)

// lockTestEngine opens a plain engine (no replication) whose background pass is held back, so the
// only writers of e.ver.rec are the ones a test drives. A failed engine closes like any other.
func lockTestEngine(t *testing.T) *Engine {
	t.Helper()
	old := verifyGate
	verifyGate = make(chan struct{})
	t.Cleanup(func() { verifyGate = old })
	e, err := Open(t.TempDir(), nopRevalidator{})
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

func lockTestSegment() SegmentManifest {
	return SegmentManifest{ID: model.ID{0x5e, 0x91}, File: "lock-test.seg", Checksum: sha256.Sum256([]byte("lock test segment")), Bytes: 4096}
}

// lockTestRecord lists seg as verified and states that slot lockTestSlot is verified up to
// command lockTestApplied.
func lockTestRecord(seg SegmentManifest) *verifiedRecord {
	rec := &verifiedRecord{Format: verifiedFormat, Groups: make([]verifiedGroup, 64)}
	rec.Groups[lockTestSlot].Applied = lockTestApplied
	rec.Segments = []verifiedSegment{{ID: seg.ID, File: seg.File, Checksum: seg.Checksum, Bytes: seg.Bytes}}
	return rec
}

// setVerifiedForTest replaces the record the way the loaders and VerifyFull do: under e.ver.mu.
func setVerifiedForTest(e *Engine, r *verifiedRecord) {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	e.ver.rec = r
}

// firstFailure reports only the first failure of a loop that runs thousands of iterations.
type firstFailure struct {
	t    *testing.T
	once sync.Once
}

func (f *firstFailure) Errorf(format string, args ...any) {
	f.once.Do(func() { f.t.Errorf(format, args...) })
}

// overlapped runs write `writes` times on one goroutine while every reader runs in a loop on a
// goroutine of its own, and guarantees by construction that reads and writes are in flight
// together: all goroutines park on a start barrier; the writer starts only after every reader has
// finished a first read and every reader is about to read again; no reader stops before the
// writer has finished. Every write therefore falls inside every reader's loop, and every reader
// reads again after the first write began. Both loops are bounded: the writer's by writes, the
// readers' by the writer.
func overlapped(writes int, write func(), readers ...func()) {
	var parked, seen, finished sync.WaitGroup
	start, writing, written := make(chan struct{}), make(chan struct{}), make(chan struct{})
	for _, read := range readers {
		parked.Add(1)
		seen.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			parked.Done()
			<-start
			read()
			seen.Done()
			<-writing
			for done := false; !done; {
				read()
				select {
				case <-written:
					done = true
				default:
				}
			}
		}()
	}
	parked.Add(1)
	finished.Add(1)
	go func() {
		defer finished.Done()
		defer close(written)
		parked.Done()
		<-start
		seen.Wait()
		close(writing)
		for range writes {
			write()
		}
	}()
	parked.Wait()
	close(start)
	finished.Wait()
}

// verifiedFrom and recordHasSegment answer from the record that is current, and from nothing once
// failVerify dropped it; VerifyFull replaces the record whole.
func TestVerifiedRecordLockFunctional(t *testing.T) {
	e := lockTestEngine(t)
	seg := lockTestSegment()
	rec := lockTestRecord(seg)
	setVerifiedForTest(e, rec)
	if e.verifiedRec() != rec {
		t.Fatal("verifiedRec is not the installed record")
	}

	for _, c := range []struct {
		name    string
		applied uint64
		want    uint64
	}{
		{"database at the verified point", lockTestApplied, lockTestApplied + 1},
		{"database ahead of the verified point", lockTestApplied + 100, lockTestApplied + 1},
		{"database behind the verified point", lockTestApplied - 1, 1},
		{"database empty", 0, 1},
	} {
		if got := e.verifiedFrom(lockTestSlot, c.applied); got != c.want {
			t.Errorf("%s: verifiedFrom(%d, %d) = %d, want %d", c.name, lockTestSlot, c.applied, got, c.want)
		}
	}
	if got := e.verifiedFrom(lockTestSlot+1, lockTestApplied); got != 1 {
		t.Errorf("a slot the record has no progress for must verify from 1, got %d", got)
	}

	if !e.recordHasSegment(seg) {
		t.Error("the segment the record lists is not recognised")
	}
	for name, change := range map[string]func(*SegmentManifest){
		"id":       func(s *SegmentManifest) { s.ID[0] ^= 1 },
		"file":     func(s *SegmentManifest) { s.File += ".x" },
		"checksum": func(s *SegmentManifest) { s.Checksum[0] ^= 1 },
		"bytes":    func(s *SegmentManifest) { s.Bytes++ },
	} {
		other := seg
		change(&other)
		if e.recordHasSegment(other) {
			t.Errorf("a segment with another %s was recognised as verified", name)
		}
	}

	// VerifyFull replaces the record whole: the engine has no segments and has applied nothing,
	// so the installed record's segment and progress are gone.
	if err := e.VerifyFull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if now := e.verifiedRec(); now == nil || now == rec {
		t.Fatalf("VerifyFull did not replace the record: %p (installed %p)", now, rec)
	}
	if e.recordHasSegment(seg) {
		t.Error("the segment of the replaced record is still recognised")
	}
	if got := e.verifiedFrom(lockTestSlot, lockTestApplied); got != 1 {
		t.Errorf("verifiedFrom after VerifyFull = %d, want 1 (nothing applied)", got)
	}

	// failVerify drops the record, removes its file and fails the engine.
	setVerifiedForTest(e, rec)
	if _, err := os.Stat(e.verifiedPath()); err != nil {
		t.Fatalf("no record file to remove: %v", err)
	}
	if err := e.failVerify(errors.New("verified record lock test")); !isCorruptFault(err) {
		t.Fatalf("failVerify returned %v, want a corruption fault", err)
	}
	if e.verifiedRec() != nil {
		t.Error("failVerify left the record")
	}
	if got := e.verifiedFrom(lockTestSlot, lockTestApplied); got != 1 {
		t.Errorf("verifiedFrom after failVerify = %d, want 1", got)
	}
	if e.recordHasSegment(seg) {
		t.Error("recordHasSegment after failVerify recognised a segment")
	}
	if !isCorruptFault(e.VerifyFailure()) {
		t.Errorf("VerifyFailure = %v, want a corruption fault", e.VerifyFailure())
	}
	if _, err := os.Stat(e.verifiedPath()); !os.IsNotExist(err) {
		t.Errorf("the record file survived failVerify: %v", err)
	}
	e.ver.mu.Lock()
	pending := e.ver.pending
	e.ver.mu.Unlock()
	if pending != nil {
		t.Error("failVerify left a pending record")
	}
	e.mu.Lock()
	failed := e.failed
	e.mu.Unlock()
	if !failed {
		t.Error("failVerify did not fail the engine")
	}
}

// The background pass drops the record (failVerify) while verifiedFrom and recordHasSegment read
// it. Each reader and the writer run in a tight loop in the overlapped window; reading e.ver.rec
// without e.ver.mu in either reader, or writing it without e.ver.mu in failVerify, is a data race
// the race detector reports.
func TestVerifiedRecordLockRaceFailVerify(t *testing.T) {
	e := lockTestEngine(t)
	seg := lockTestSegment()
	foreign := seg
	foreign.Checksum[0] ^= 1
	rec := lockTestRecord(seg)
	setVerifiedForTest(e, rec)
	bad := &firstFailure{t: t}
	cause := errors.New("verified record lock test")

	overlapped(200, func() {
		setVerifiedForTest(e, rec)
		if err := e.failVerify(cause); !isCorruptFault(err) {
			bad.Errorf("failVerify returned %v, want a corruption fault", err)
		}
	}, func() {
		if got := e.verifiedFrom(lockTestSlot, lockTestApplied); got != 1 && got != lockTestApplied+1 {
			bad.Errorf("verifiedFrom returned %d: neither the record's point nor a full verification", got)
		}
	}, func() {
		if e.recordHasSegment(foreign) {
			bad.Errorf("a segment the record never listed was recognised as verified")
		}
		e.recordHasSegment(seg) // true or false while the writer flips the record
	})

	if e.verifiedRec() != nil {
		t.Error("the last failVerify left the record")
	}
	if !isCorruptFault(e.VerifyFailure()) {
		t.Errorf("VerifyFailure = %v, want a corruption fault", e.VerifyFailure())
	}
}

// VerifyFull replaces the record while the same readers run. Each write first reinstalls a record
// that lists seg, so every VerifyFull replaces a different record with a new one.
func TestVerifiedRecordLockRaceVerifyFull(t *testing.T) {
	e := lockTestEngine(t)
	seg := lockTestSegment()
	foreign := seg
	foreign.Checksum[0] ^= 1
	rec := lockTestRecord(seg)
	setVerifiedForTest(e, rec)
	bad := &firstFailure{t: t}
	ctx := context.Background()

	overlapped(40, func() {
		setVerifiedForTest(e, rec)
		if err := e.VerifyFull(ctx); err != nil {
			bad.Errorf("VerifyFull: %v", err)
		}
	}, func() {
		if got := e.verifiedFrom(lockTestSlot, lockTestApplied); got != 1 && got != lockTestApplied+1 {
			bad.Errorf("verifiedFrom returned %d: neither the installed record's point nor a full verification", got)
		}
	}, func() {
		if e.recordHasSegment(foreign) {
			bad.Errorf("a segment the record never listed was recognised as verified")
		}
		e.recordHasSegment(seg)
	})

	if now := e.verifiedRec(); now == nil || now == rec {
		t.Errorf("the last VerifyFull left %p (installed %p), want the record it built", now, rec)
	}
	if e.VerifyFailure() != nil {
		t.Errorf("a clean engine failed verification: %v", e.VerifyFailure())
	}
}
