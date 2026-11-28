// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// crashReopen is what a restart after a crash is for the data directory: the engine fails where the hook says, is closed (the
// process is gone), and the directory is opened again.
func (x *eraseEnv) crashReopen() {
	x.t.Helper()
	x.e.setFault(nil)
	_ = x.e.Close()
	e, err := openTestEngine(x.t, x.dir, x.a, x.store)
	if err != nil {
		x.t.Fatal(err)
	}
	x.e = e
	e.stopIndexMerger()
}

// TestEraseZeroesPayloadRecordsOfACrashedApply is the red test of the privacy defect of D89: an append writes its records into the
// payload log before the transaction that references them commits, so a crash in between leaves records no reference names. The
// batch is retried and stored again; the erasure of it zeroed the records the references name and left the first copy in the log
// file. Erasure must reach every copy, whatever number of restarts separates the crash from the erasure.
func TestEraseZeroesPayloadRecordsOfACrashedApply(t *testing.T) {
	withoutPayloadToggle(t)
	for _, c := range []struct {
		hook     string
		restarts int // graceful restarts between the crash and the erasure
	}{
		{"payload_sync", 0},   // the records are written, not synced
		{"payload_synced", 0}, // the records are durable, no reference is committed
		{"receipt_write", 0},  // the references are in a transaction that did not complete
		{"payload_synced", 1}, // a graceful close between must not declare the span clean
		{"receipt_write", 2},
	} {
		t.Run(c.hook+"/"+string(rune('0'+c.restarts))+" restarts", func(t *testing.T) {
			x := newEraseEnv(t)
			if err := x.e.adoptRunsLayout(); err != nil {
				t.Fatal(err)
			}
			if err := x.e.adoptPayloadLayout(); err != nil {
				t.Fatal(err)
			}
			x.e.stopIndexMerger()
			other := x.appendMixed(otherCanary, bothDeadlines)

			producer, secret, keepM, keepL := x.mixedRecords(eraseCanary)
			batch, scope := x.admit(producer, bothDeadlines, secret, keepM, keepL)
			crashed := false
			x.e.setFault(func(at string) error {
				if at == c.hook {
					crashed = true
					return errors.New("crash at " + at)
				}
				return nil
			})
			if _, err := x.e.Append(context.Background(), scope, batch); err == nil || !crashed {
				t.Fatalf("the append was acknowledged although the engine crashed at %s: %v", c.hook, err)
			}
			x.crashReopen()
			if !x.e.payloadDebt.Load() {
				t.Fatal("the log was reopened after a crash and holds no span to sweep")
			}
			if !hasHit(rawHits(t, x.e, eraseCanary), "payload:") {
				t.Fatal("fixture invalid: the crashed append left no record of the batch in the log")
			}
			for range c.restarts {
				x.reopen()
				if !x.e.payloadDebt.Load() {
					t.Fatal("a graceful restart forgot that the log holds a span the crash left")
				}
			}
			receipt, err := x.e.Append(context.Background(), scope, batch) // the client retries what it never saw acknowledged
			if err != nil {
				t.Fatal(err)
			}
			if _, err = x.e.Append(context.Background(), scope, batch); err != nil {
				t.Fatal(err)
			}
			if hits := rawHits(t, x.e, eraseCanary); !hasHit(hits, "replica_commands") || !hasHit(hits, "payload:") {
				t.Fatalf("fixture invalid: the retried batch is not stored, hits %v", hits)
			}

			report, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Records < 1 {
				t.Fatalf("nothing erased: %+v", report)
			}
			if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
				t.Fatalf("erased bytes are still present in %v", hits)
			}
			if x.e.payloadDebt.Load() {
				t.Fatal("the erasure pass left the span unswept")
			}
			// The sweep zeroes what no reference names and nothing else: the kept rows are there and every reference reads.
			if got, want := x.ids(model.Metric), sortedIDs(other.keepM, keepM); !equalIDs(got, want) {
				t.Fatalf("metric rows after the erasure %v, want the kept ones %v", got, want)
			}
			everyReferenceReads(t, x.e)
			x.integrity()
			if r2, err := x.e.Append(context.Background(), scope, batch); err != nil || !bytes.Equal(mustJSON(t, r2), mustJSON(t, receipt)) {
				t.Fatalf("retry after the erasure did not return the receipt: %v", err)
			}

			// The mark moved: a restart of the swept file holds no span, and one more crash leaves only its own.
			x.reopen()
			if x.e.payloadDebt.Load() {
				t.Fatal("the swept log is reopened with a span to sweep")
			}
			everyReferenceReads(t, x.e)
		})
	}
}

func equalIDs(a, b []model.ID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPayloadMarkFollowsGracefulCloseOnly: a process that closes gracefully has nothing unnamed in its log, so the next open has no
// span; a process that failed has, and a process that closes with a span still owed does not forgive it.
func TestPayloadMarkFollowsGracefulCloseOnly(t *testing.T) {
	withoutPayloadToggle(t)
	x := newEraseEnv(t)
	if err := x.e.adoptRunsLayout(); err != nil {
		t.Fatal(err)
	}
	if err := x.e.adoptPayloadLayout(); err != nil {
		t.Fatal(err)
	}
	x.e.stopIndexMerger()
	x.appendMixed(otherCanary, bothDeadlines)
	x.reopen()
	if x.e.payloadDebt.Load() {
		t.Fatal("a graceful restart left a span to sweep")
	}
	x.e.stopIndexMerger()
	x.appendMixed(longCanary, bothDeadlines)
	// A kill: the file is not closed gracefully, so no mark moves.
	x.e.mu.Lock()
	x.e.failLocked()
	x.e.mu.Unlock()
	x.crashReopen()
	if !x.e.payloadDebt.Load() {
		t.Fatal("a process that failed did not leave a span to sweep")
	}
	if err := x.e.sweepPayloadOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if x.e.payloadDebt.Load() {
		t.Fatal("the sweep left the span")
	}
	x.reopen()
	if x.e.payloadDebt.Load() {
		t.Fatal("a swept log is reopened with a span to sweep")
	}
}

// TestPayloadMarkOfAFileOutsideTheLayoutIsNotTrusted is the red test of the privacy defect the legacy-WAL erase tests found: a file
// that is not in the payload layout names no record of the log beside it (the image an upgrade leaves after the layout was dropped
// under a log the process had closed gracefully, an older apply.db restored under the directory), so a mark at the end of the log
// vouches for nothing. The whole log is the span; the erasure pass zeroes it and the mark stays out of the file.
func TestPayloadMarkOfAFileOutsideTheLayoutIsNotTrusted(t *testing.T) {
	withoutPayloadToggle(t)
	x := newEraseEnv(t)
	if x.e.payloadOn.Load() {
		t.Fatal("fixture invalid: the file is in the payload layout")
	}
	if _, err := x.e.payload.append([]byte("record no value names:" + eraseCanary)); err != nil {
		t.Fatal(err)
	}
	if err := x.e.payload.sync(); err != nil {
		t.Fatal(err)
	}
	if err := x.e.putPayloadSwept(x.e.payload.end()); err != nil { // what a process that had the layout left when it closed
		t.Fatal(err)
	}
	x.reopen()
	if x.e.payloadOn.Load() {
		t.Fatal("the reopened file is in the payload layout")
	}
	if !x.e.payloadDebt.Load() {
		t.Fatal("a log beside a file outside the layout was taken for swept because of a stale mark")
	}
	if !hasHit(rawHits(t, x.e, eraseCanary), "payload:") {
		t.Fatal("fixture invalid: the log does not hold the canary")
	}
	markOf := func() []byte {
		var mark []byte
		_ = x.e.db.View(func(tx *bolt.Tx) error {
			mark = bytes.Clone(tx.Bucket([]byte("meta")).Get([]byte(payloadSweptKey)))
			return nil
		})
		return mark
	}
	if markOf() != nil {
		t.Fatal("the stale mark of a file outside the layout was kept")
	}
	if err := x.e.sweepPayloadOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("the sweep left the bytes in %v", hits)
	}
	if x.e.payloadDebt.Load() {
		t.Fatal("the sweep left the span")
	}
	if markOf() != nil {
		t.Fatal("a sweep wrote a mark into a file outside the layout")
	}
}

// TestZeroUnnamedKeepsEveryNamedRecord: the sweep zeroes what no reference covers (a record of a crashed append, bytes of a torn
// tail, anything else) and nothing a reference names.
func TestZeroUnnamedKeepsEveryNamedRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), payloadDirName)
	l, err := openPayloadLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	canary := bytes.Repeat([]byte(eraseCanary), 8)
	refA, err := l.append(append([]byte("A:"), canary...))
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := l.append(append([]byte("orphan:"), canary...))
	if err != nil {
		t.Fatal(err)
	}
	refB, err := l.append(append([]byte("B:"), canary...))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.sync(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, payloadFileName(1))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(append([]byte("SPL1torn"), canary...)); err != nil { // a record that was torn in the middle
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	extent := func(ref []byte) payloadExtent {
		_, off, n, _, _ := parsePayloadRef(ref)
		return payloadExtent{off, off + payloadHeaderLen + int64(n)}
	}
	zeroed, err := l.zeroUnnamed(context.Background(), 1, 0, fi.Size(), []payloadExtent{extent(refB), extent(refA)})
	if err != nil {
		t.Fatal(err)
	}
	if zeroed == 0 {
		t.Fatal("nothing zeroed")
	}
	for _, ref := range [][]byte{refA, refB} {
		if b, err := l.read(ref); err != nil || !bytes.Contains(b, canary) {
			t.Fatalf("a named record was damaged: %v", err)
		}
	}
	if _, err = l.read(orphan); err == nil {
		t.Fatal("the unnamed record still reads")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, canary); n != 2 {
		t.Fatalf("the file holds the canary %d times, want 2 (the two named records)", n)
	}
	// Again: nothing left to write.
	if zeroed, err = l.zeroUnnamed(context.Background(), 1, 0, fi.Size(), []payloadExtent{extent(refA), extent(refB)}); err != nil || zeroed != 0 {
		t.Fatalf("second pass zeroed %d: %v", zeroed, err)
	}
}
