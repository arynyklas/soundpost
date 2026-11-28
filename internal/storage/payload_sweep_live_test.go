// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// uncleanStop is what a power cut leaves of a data directory as far as the sweep is concerned: the process never moved the mark
// (payload_swept) to the end of the log, so the next open owes a sweep of everything past the old mark.
func uncleanStop(t *testing.T, e *Engine) {
	t.Helper()
	e.payloadDirty.Store(true)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestSweepKeepsEveryRecordTheRowStoreNames is the red test of the power-cut defect (a range read answered 503 corrupt from
// payloadLog.read after a voter lost power): the orphan sweep zeroes every record of its span that no reference names, and the
// references it collected were only the values of the bolt buckets. In the runs layout the rows of the pages (the hot page of a
// batch, `Log`) and of the stored batches are pairs inside the BLOCKS of the scan_rows runs, in the file or in a record of the log,
// so the sweep did not see them and zeroed the records of acknowledged data. Every acknowledged record must read back, with its exact
// bytes, after the sweep of an unclean stop, whatever the form of the runs (blocks in bolt, blocks in the log).
func TestSweepKeepsEveryRecordTheRowStoreNames(t *testing.T) {
	withoutPayloadToggle(t)
	for _, c := range []struct {
		name  string
		final bool // the runs are final: their blocks live in the payload log
	}{
		{"blocks in bolt", false},
		{"blocks in the payload log", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.final {
				old := finalRunBytes
				finalRunBytes = 1
				defer func() { finalRunBytes = old }()
			}
			store, service, cred, desc := fixture(t)
			fx := layoutFixture{store, service, cred, desc}
			dir := t.TempDir()
			e := openPayloadEngine(t, dir, store, service)
			if err := store.BindAdmissionOwner(e); err != nil {
				t.Fatal(err)
			}
			e.stopIndexMerger()
			acked := appendKept(t, e, fx, 6)
			if c.final {
				for range 4 {
					if _, err := e.externalizeRuns(nil); err != nil {
						t.Fatal(err)
					}
				}
			}
			want := readState(t, e, fx, acked)
			everyLiveRecordReads(t, e)
			uncleanStop(t, e)

			e2, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			defer e2.Close()
			if !e2.payloadDebt.Load() {
				t.Fatal("the log was reopened after an unclean stop and holds no span to sweep")
			}
			if err = e2.sweepPayloadOrphans(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := readState(t, e2, fx, acked); !got.equal(want) {
				t.Fatalf("an acknowledged record was lost or changed by the sweep: %s", storedStateWhy)
			}
			everyLiveRecordReads(t, e2)
		})
	}
}

// everyLiveRecordReads reads, through the row store (the same merged view of the legacy buckets and of the runs that every reader
// of the engine has), the payload record of every page and of every stored batch, and every reference the bolt file holds itself:
// what the sweep must never zero. It fails on a record that is not what its reference names.
func everyLiveRecordReads(t *testing.T, e *Engine) (records int) {
	t.Helper()
	records = everyReferenceReads(t, e)
	if err := e.db.View(func(tx *bolt.Tx) error {
		read := func(where string, ref []byte) {
			if !isPayloadRef(ref) {
				return
			}
			records++
			if _, err := e.payload.read(ref); err != nil {
				t.Errorf("%s: a live record is not what its reference names: %v", where, err)
			}
		}
		if err := tableForEach(tx, tblPages, func(_, v []byte) error {
			if p, err := parsePageRef(v); err == nil {
				read("scan_pages row (hot page)", p.Log)
			}
			return nil
		}); err != nil {
			return err
		}
		return tableForEach(tx, tblBatches, func(_, v []byte) error {
			read("batches row", v)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return records
}
