// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

type keptAppend struct {
	scope   auth.Scope
	batch   model.NormalizedBatch
	receipt model.Receipt
}

func appendKept(t *testing.T, e *Engine, fx layoutFixture, n int) []keptAppend {
	t.Helper()
	out := make([]keptAppend, n)
	for i := range out {
		scope, b := settleBatch(t, fx.store, fx.service, fx.cred, fx.desc, model.NewID(), 1, fmt.Sprintf("migrate_%d_%s", i, model.NewID()))
		r, err := e.Append(context.Background(), scope, b)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out[i] = keptAppend{scope, b, r}
	}
	return out
}

// storedState is what the engine returns for every kept append: the stored batch and receipt (resolved through the log when they are
// references), the answer to a retry and the rows of a scan.
type storedState struct {
	batches, receipts [][]byte
	retried           []string
	rows              int
}

func readState(t *testing.T, e *Engine, fx layoutFixture, kept []keptAppend) storedState {
	t.Helper()
	var s storedState
	marks := make([]model.Cursor, len(kept))
	for i, k := range kept {
		b, r := storedBatch(t, e, k.batch)
		s.batches, s.receipts = append(s.batches, b), append(s.receipts, r)
		got, err := e.Append(context.Background(), k.scope, k.batch)
		if err != nil {
			t.Fatalf("retry of append %d: %v", i, err)
		}
		s.retried = append(s.retried, string(mustJSON(t, got)))
		if string(mustJSON(t, got)) != string(mustJSON(t, k.receipt)) {
			t.Fatalf("retry of append %d does not return the original receipt", i)
		}
		marks[i] = k.receipt.Cursor
		if err = e.VerifyFinalization(context.Background(), model.FinalizeAdmission{ReservationID: k.batch.Reservation.ID, Cursor: k.receipt.Cursor}); err != nil {
			t.Fatalf("consumed reservation of append %d: %v", i, err)
		}
	}
	s.rows = scanAllRows(t, e, fx, marks)
	if err := e.db.View(validateIndexIntegrity); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	return s
}

// storedStateWhy says what the last failed equal found different.
var storedStateWhy string

func (s storedState) equal(o storedState) bool {
	if len(s.batches) != len(o.batches) || s.rows < len(o.batches) || o.rows < len(o.batches) { // a scan also returns what was appended after
		storedStateWhy = fmt.Sprintf("%d batches and %d rows against %d and %d", len(s.batches), s.rows, len(o.batches), o.rows)
		return false
	}
	for i := range s.batches {
		if !bytes.Equal(s.batches[i], o.batches[i]) || !bytes.Equal(s.receipts[i], o.receipts[i]) || s.retried[i] != o.retried[i] {
			storedStateWhy = fmt.Sprintf("append %d: batch equal %v (%d vs %d bytes), receipt equal %v, retry equal %v", i, bytes.Equal(s.batches[i], o.batches[i]), len(s.batches[i]), len(o.batches[i]), bytes.Equal(s.receipts[i], o.receipts[i]), s.retried[i] == o.retried[i])
			return false
		}
	}
	return true
}

type inlineCounts struct {
	cmdInline, cmdRef       int // stored commands of payloadMinBytes or more, inline and as references
	finalInline, finalRef   int // blocks of the final runs
	legacyInline, finalRuns int // rows of the legacy buckets that hold payload inline
}

func countInline(t *testing.T, e *Engine) (c inlineCounts) {
	t.Helper()
	if err := e.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("replica_commands")).ForEach(func(_, v []byte) error {
			switch {
			case isPayloadRef(v):
				c.cmdRef++
			case len(v) >= payloadMinBytes:
				c.cmdInline++
			}
			return nil
		}); err != nil {
			return err
		}
		reg := tx.Bucket([]byte(runsRegistry))
		for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
			runs, err := listIndexRuns(reg, name)
			if err != nil {
				return err
			}
			for _, r := range runs {
				if r.meta.State != indexRunReady || r.meta.Bytes < finalRunBytes {
					continue
				}
				c.finalRuns++
				cur := tx.Bucket(indexRunBucketName(name, r.id)).Cursor()
				for k, v := cur.First(); k != nil; k, v = cur.Next() {
					if isPayloadRef(v) {
						c.finalRef++
					} else {
						c.finalInline++
					}
				}
			}
		}
		if err := tx.Bucket([]byte(tblBatches.bucket)).ForEach(func(_, v []byte) error {
			if !isPayloadRef(v) && len(v) >= payloadMinBytes {
				c.legacyInline++
			}
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket([]byte(tblPages.bucket)).ForEach(func(_, v []byte) error {
			if p, err := parsePageRef(v); err == nil && len(p.Hot) > 0 {
				c.legacyInline++
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// quiesce runs the merges and the externalization of the final runs until there is nothing left to do.
func quiesce(t *testing.T, e *Engine) {
	t.Helper()
	for range 40 {
		if cancelled, err := e.mergeIndexRuns(nil); cancelled || err != nil {
			t.Fatalf("merge: cancelled=%v %v", cancelled, err)
		}
		var due bool
		_ = e.db.View(func(tx *bolt.Tx) error {
			reg := tx.Bucket([]byte(runsRegistry))
			for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
				runs, _ := listIndexRuns(reg, name)
				if _, in := planIndexMergeAt(runs, indexRunFanoutAt, finalRunBytes); len(in) > 0 {
					due = true
				}
			}
			return nil
		})
		if !due {
			return
		}
	}
	t.Fatal("the merges never settled")
}

func smallFinalRuns(t *testing.T) {
	t.Helper()
	oldFinal, oldIdx, oldRows, oldEnabled := finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes, payloadLayoutEnabled
	finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes = boltBytesFinalRun, boltBytesBlock, boltBytesBlock
	payloadLayoutEnabled = false // the test adopts the layout itself, when it has built the file it migrates
	t.Cleanup(func() {
		finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes, payloadLayoutEnabled = oldFinal, oldIdx, oldRows, oldEnabled
	})
}

// TestInlineValuesMigrateOnceTheLayoutIsAdopted: a file that holds its commands, its stored records, its hot pages and the blocks of
// its final runs inline (what the rows layout wrote) keeps every one of them readable the whole time its layout moves to the payload
// log, and ends with them in the log: the commands, the rows of the legacy buckets and the blocks of the final runs. The migration is
// resumable (a restart and a crash between the log sync and the commit lose nothing and repeat nothing), runs after the
// installation is contracted only (the layout is adopted only then, so the previous release, which cannot open the file once it
// is adopted, is never a member that needs to read it), and never makes the data unreadable.
func TestInlineValuesMigrateOnceTheLayoutIsAdopted(t *testing.T) {
	withoutPayloadToggle(t)
	smallFinalRuns(t)
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy rows %v", legacy), func(t *testing.T) {
			store, service, cred, desc := fixture(t)
			fx := layoutFixture{store, service, cred, desc}
			dir := t.TempDir()
			e, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.BindAdmissionOwner(e); err != nil {
				t.Fatal(err)
			}
			e.stopIndexMerger()
			const n = 240
			kept := appendKept(t, e, fx, n)
			quiesce(t, e)
			if legacy { // the file of a build that had the runs of the query indexes and no row store
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				editDB(t, dir, func(tx *bolt.Tx) error {
					moveRowRunsToLegacy(t, tx)
					return tx.Bucket([]byte("meta")).Put([]byte("scan_index_version"), []byte{scanIndexRuns})
				})
				if e, err = openTestEngine(t, dir, service, store); err != nil {
					t.Fatal(err)
				}
				e.stopIndexMerger()
			}
			if marker, _ := scanLayoutMarker(t, e); marker == scanIndexPayload {
				t.Fatalf("the fixture is already in the payload layout")
			}
			before := countInline(t, e)
			bytesBefore, _, _ := boltBytes(t, e)
			if before.cmdInline == 0 || before.finalRuns == 0 || before.finalInline == 0 || before.cmdRef != 0 || before.finalRef != 0 {
				t.Fatalf("the fixture is not a file of inline values: %+v", before)
			}
			if legacy && before.legacyInline == 0 {
				t.Fatalf("the legacy buckets hold no inline payload: %+v", before)
			}
			want := readState(t, e, fx, kept)
			if want.rows != n {
				t.Fatalf("a query returns %d rows of the file before the migration, want %d", want.rows, n)
			}
			if err = e.adoptPayloadLayout(); err != nil {
				t.Fatal(err)
			}
			if got := readState(t, e, fx, kept); !got.equal(want) { // both forms are legal the moment the layout is adopted
				t.Fatal("the file reads differently right after the layout was adopted")
			}

			// A crash between the log sync and the commit of a chunk: the records are durable, nothing names them.
			crashed := false
			e.setFault(func(at string) error {
				if at == "payload_migrate" && !crashed {
					crashed = true
					return errors.New("crash after the log sync, before the commit")
				}
				return nil
			})
			if _, err = e.migrateInlinePayload(nil); err == nil || !crashed {
				t.Fatalf("the crash hook did not fire (%v)", err)
			}
			e.setFault(nil)
			if got := readState(t, e, fx, kept); !got.equal(want) {
				t.Fatal("the file reads differently after a chunk that was lost between the sync and the commit")
			}
			// A restart in the middle: the progress is in the file.
			if _, err = e.migrateInlinePayload(nil); err != nil {
				t.Fatal(err)
			}
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			if e, err = openTestEngine(t, dir, service, store); err != nil {
				t.Fatal(err)
			}
			e.stopIndexMerger()
			if !e.payloadOn.Load() {
				t.Fatal("the reopened file lost the layout")
			}
			for range 200 {
				if _, err = e.migrateInlinePayload(nil); err != nil {
					t.Fatal(err)
				}
				quiesce(t, e)
				if e.payloadMigrationDone() {
					break
				}
			}
			if !e.payloadMigrationDone() {
				t.Fatal("the migration never finished")
			}
			quiesce(t, e)
			after := countInline(t, e)
			if after.cmdInline != 0 || after.finalInline != 0 || after.legacyInline != 0 || after.cmdRef == 0 || after.finalRef == 0 {
				t.Fatalf("inline values are left after the migration: %+v (before %+v)", after, before)
			}
			bytesAfter, _, _ := boltBytes(t, e)
			t.Logf("bolt held %d bytes before the migration and %d after it (%d final runs, %d blocks and %d commands moved)", bytesBefore, bytesAfter, after.finalRuns, after.finalRef, after.cmdRef)
			if bytesAfter*2 > bytesBefore {
				t.Errorf("the migration freed little: %d bytes before, %d after", bytesBefore, bytesAfter)
			}
			if got := readState(t, e, fx, kept); !got.equal(want) {
				t.Fatal("the file reads differently after the migration")
			}
			// A new append after the migration is stored the new way, next to the migrated history.
			more := appendKept(t, e, fx, 20)
			quiesce(t, e)
			if got := readState(t, e, fx, append(append([]keptAppend{}, kept...), more...)); got.rows != n+20 {
				t.Fatalf("a query returns %d rows after the new appends, want %d", got.rows, n+20)
			}
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			e, err = openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if got := readState(t, e, fx, kept); !got.equal(want) {
				t.Fatal("the migrated file reads differently after a restart: " + storedStateWhy)
			}
		})
	}
}
