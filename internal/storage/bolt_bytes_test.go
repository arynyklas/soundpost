// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// boltBytes is what apply.db holds, as the bytes of the keys and values bolt stores (the physical form: a run bucket counts its
// blocks, or the references that stand for them), by bucket with the run suffix removed, and the size of the file. The run buckets
// of the runs that are not final (they are still to be merged: bounded by the size of the final run, not by the history) are
// counted together as "unmerged".
func boltBytes(t *testing.T, e *Engine) (total int64, byBucket map[string]int64, file int64) {
	t.Helper()
	byBucket = map[string]int64{}
	err := e.db.View(func(tx *bolt.Tx) error {
		final := map[string]bool{}
		if reg := tx.Bucket([]byte(runsRegistry)); reg != nil {
			for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
				runs, err := listIndexRuns(reg, name)
				if err != nil {
					return err
				}
				for _, r := range runs {
					if r.meta.State == indexRunReady && r.meta.Bytes >= finalRunBytes {
						final[string(indexRunBucketName(name, r.id))] = true
					}
				}
			}
		}
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			group := string(name)
			if i := strings.Index(group, ".r"); i > 0 {
				group = group[:i]
				if !final[string(name)] {
					group = "unmerged"
				}
			}
			var walk func(b *bolt.Bucket)
			walk = func(b *bolt.Bucket) {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if v == nil {
						if sub := b.Bucket(k); sub != nil {
							walk(sub)
						}
						continue
					}
					byBucket[group] += int64(len(k) + len(v))
					total += int64(len(k) + len(v))
				}
			}
			walk(b)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(e.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	return total, byBucket, fi.Size()
}

type boltPoint struct {
	batches int
	total   int64
	file    int64
	by      map[string]int64
}

// boltBytesOverHistory appends rounds of batches (one to a commit), merges after each round to quiescence, and records what bolt holds.
func boltBytesOverHistory(t *testing.T, externalize bool, rounds, perRound int) []boltPoint {
	t.Helper()
	oldFinal, oldIdx, oldRows := finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes
	finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes = boltBytesFinalRun, boltBytesBlock, boltBytesBlock
	if !externalize {
		finalRunBytes = 1 << 62
	}
	t.Cleanup(func() { finalRunBytes, indexRunBlockBytes, rowsRunBlockBytes = oldFinal, oldIdx, oldRows })
	store, service, cred, desc := fixture(t)
	e := openPayloadEngine(t, t.TempDir(), store, service)
	if err := store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	batches := make([]preparedAppend, rounds*perRound)
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
	}
	var out []boltPoint
	for r := range rounds {
		pageNodesPerAck(t, e, batches[r*perRound:(r+1)*perRound], 1)
		for { // to quiescence: a merge can make another due
			cancelled, err := e.mergeIndexRuns(nil)
			if err != nil || cancelled {
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
				break
			}
		}
		total, by, file := boltBytes(t, e)
		out = append(out, boltPoint{(r + 1) * perRound, total, file, by})
	}
	return out
}

// The block and the final run of the measurement: small, so that the history of a test reaches many final runs. In production a
// block is 128 KiB (query indexes) or 32 KiB (rows) and a run is final from 64 MiB.
const (
	boltBytesBlock    = 2 << 10
	boltBytesFinalRun = 24 << 10
)

// TestBoltBytesPerBatchAreBoundedAndIndependentOfHistory is the red test of D89 stage 2. After stage 1 an acknowledged batch of one
// record still left about 3.6 KB in bolt, 1.4 KB of it the index bodies of its record (scan_postings, scan_time) and the rest the
// rows of its tables, all of it rewritten by the merges and, for the history, kept: apply.db grows with the history by that much.
//
// What it must leave once the merges have run, whatever the history behind it: the pointer of its command (replica_commands: its key
// and one 21-byte reference: 31 bytes), its logical index (replica_data: 30 bytes), the cursor and the counters (2 bytes), and the
// pointers of the blocks that hold its index bodies and rows: a final run keeps the last key of each block (at most ~110 bytes
// for the rows, 16 for the indexes, whose keys are mostly shared in the run; measured) and a 21-byte reference per block of
// boltBytesBlock bytes, and each batch is ~3 KB of encoded bodies, so ~1.5 blocks and ~190 bytes of pointers; and the registry and
// bloom bytes of its runs, ~25 bytes. The bound is therefore boltBytesPerBatch bytes per batch, and apply.db at most
// boltFilePerBatch bytes of file per batch (bolt's pages are 4 KiB, a pointer that survives a merge sits in a leaf that is ~70 %
// full, and the pages freed by the merges are reused, so the file is ~1.4x the bytes it holds plus the unmerged runs).
//
// The unmerged runs are not history: at most fanout runs per level, below the final size, so they hold at most
// 3 indexes x fanout x boltBytesFinalRun bytes (boltBytesSawtooth), a constant that the history does not move. The test states the
// bound as bytes(N) <= sawtooth + bound x N at every checkpoint, and the slope between the first and the last checkpoint.
//
// The control runs the same history with no run ever final (what the build before this change did): the same bound must FAIL there.
func TestBoltBytesPerBatchAreBoundedAndIndependentOfHistory(t *testing.T) {
	const rounds, perRound = 6, 150
	points := boltBytesOverHistory(t, true, rounds, perRound)
	control := boltBytesOverHistory(t, false, rounds, perRound)
	describe := func(label string, ps []boltPoint) {
		for _, p := range ps {
			names := make([]string, 0, len(p.by))
			for n := range p.by {
				names = append(names, n)
			}
			sort.Strings(names)
			var parts []string
			for _, n := range names {
				parts = append(parts, fmt.Sprintf("%s=%.0f", n, float64(p.by[n])/float64(p.batches)))
			}
			t.Logf("%s: %d batches: %.0f bolt bytes per batch, file %.0f per batch [%s]", label, p.batches, float64(p.total)/float64(p.batches), float64(p.file)/float64(p.batches), strings.Join(parts, " "))
		}
	}
	describe("externalized", points)
	describe("control (no final run)", control)
	within := func(ps []boltPoint) (okBytes, okFile bool) {
		okBytes, okFile = true, true
		for _, p := range ps {
			if p.total > boltBytesSawtooth+int64(boltBytesPerBatch)*int64(p.batches) {
				okBytes = false
			}
			if p.file > boltFileSawtooth+int64(boltFilePerBatch)*int64(p.batches) {
				okFile = false
			}
		}
		return
	}
	okBytes, okFile := within(points)
	if !okBytes {
		t.Errorf("bolt holds more than %d bytes per batch (plus the %d bytes of unmerged runs) after the merges: the index bodies are not out of bolt", boltBytesPerBatch, boltBytesSawtooth)
	}
	if !okFile {
		t.Errorf("apply.db is larger than %d bytes per batch (plus %d)", boltFilePerBatch, boltFileSawtooth)
	}
	first, last := points[1], points[len(points)-1] // the first round pays the unmerged runs the slope is not about
	slope := float64(last.total-first.total) / float64(last.batches-first.batches)
	fileSlope := float64(last.file-first.file) / float64(last.batches-first.batches)
	t.Logf("slope between %d and %d batches: %.0f bolt bytes, %.0f file bytes per batch", first.batches, last.batches, slope, fileSlope)
	if slope > boltBytesPerBatch {
		t.Errorf("what a batch adds to bolt grows with the history: %.0f bytes per batch between %d and %d batches, bound %d", slope, first.batches, last.batches, boltBytesPerBatch)
	}
	if fileSlope > boltFilePerBatch {
		t.Errorf("what a batch adds to the file grows with the history: %.0f bytes per batch between %d and %d batches, bound %d", fileSlope, first.batches, last.batches, boltFilePerBatch)
	}
	cb, cf := within(control)
	cSlope := float64(control[len(control)-1].total-control[1].total) / float64(control[len(control)-1].batches-control[1].batches)
	if cb && cSlope <= boltBytesPerBatch {
		t.Errorf("the control (no final run) is within the bound too (%.0f bytes per batch): the test does not tell the layout apart", cSlope)
	}
	_ = cf
}

const (
	boltBytesPerBatch = 300 // measured 195-230 (31 + 24..48 + 2 fixed, ~125 of block pointers at 2 KiB blocks, ~15-28 of registry and bloom), 30 % headroom; the control holds ~2,770
	boltFilePerBatch  = 2200
	// 3 indexes x fanout (8) x boltBytesFinalRun, and the same for the file in pages (x 1.6); the file also grows in steps of bolt's
	// AllocSize (16 MiB) once it is mapped ahead of its growth (durablefs.BoltInitialMmapSize, D91), so it is up to one step above what it holds
	boltBytesSawtooth = 3 * 8 * boltBytesFinalRun
	boltFileSawtooth  = boltBytesSawtooth*8/5 + 1<<20 + 16<<20
)
