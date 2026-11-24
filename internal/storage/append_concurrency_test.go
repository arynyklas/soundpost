// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

type preparedAppend struct {
	scope auth.Scope
	batch model.NormalizedBatch
}

// appendConcurrently appends every prepared batch with at most width in flight and returns the
// wall time, the receipts and the per-append latencies.
func appendConcurrently(t *testing.T, e *Engine, batches []preparedAppend, width int) (time.Duration, []model.Receipt, []time.Duration) {
	t.Helper()
	receipts := make([]model.Receipt, len(batches))
	latency := make([]time.Duration, len(batches))
	errs := make([]error, len(batches))
	sem := make(chan struct{}, width)
	var wg sync.WaitGroup
	start := time.Now()
	for i := range batches {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			begin := time.Now()
			receipts[i], errs[i] = e.Append(context.Background(), batches[i].scope, batches[i].batch)
			latency[i] = time.Since(begin)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return elapsed, receipts, latency
}

// Concurrent appends must not queue behind one holder that waits out a replication round trip
// and its fsyncs: the engine-wide throughput under concurrency has to be a multiple of the
// throughput of one append at a time. The 6,000 in-flight requests of the live 2,000 records/s
// run all waited on proposalMu while its holder was latency-bound (L2w20Admission3 p4).
func TestAppendThroughputScalesWithConcurrency(t *testing.T) {
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	// Every journal fsync takes 3 ms whatever the file system under the test (a tmpfs makes fsync
	// free): the appends of different slots must overlap that wait, one engine-wide holder must not.
	e.setFault(func(at string) error {
		if at == "wal_sync" {
			time.Sleep(3 * time.Millisecond)
		}
		return nil
	})
	prepare := func(n int) []preparedAppend {
		out := make([]preparedAppend, n)
		for i := range out {
			out[i].scope, out[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d_%d", n, i))
		}
		return out
	}
	serial := prepare(60)
	parallel := prepare(600)
	begin := time.Now()
	for i := range serial {
		if _, err = e.Append(context.Background(), serial[i].scope, serial[i].batch); err != nil {
			t.Fatal(err)
		}
	}
	serialRate := float64(len(serial)) / time.Since(begin).Seconds()
	statsBefore := e.db.Stats()
	elapsed, receipts, latency := appendConcurrently(t, e, parallel, 128)
	statsAfter := e.db.Stats()
	diff := statsAfter.Sub(&statsBefore)
	t.Logf("bolt during the concurrent run: page writes %d, write time %s, spill time %s, rebalance time %s, page allocs %d", diff.TxStats.GetWrite(), diff.TxStats.GetWriteTime(), diff.TxStats.GetSpillTime(), diff.TxStats.GetRebalanceTime(), diff.TxStats.GetPageAlloc())
	parallelRate := float64(len(parallel)) / elapsed.Seconds()
	var worst time.Duration
	for _, l := range latency {
		worst = max(worst, l)
	}
	t.Logf("one at a time: %.0f appends/s; 128 in flight: %.0f appends/s (x%.1f), worst latency %s", serialRate, parallelRate, parallelRate/serialRate, worst)
	if parallelRate < 2.5*serialRate {
		t.Fatalf("128 concurrent appends ran at %.0f/s, one at a time %.0f/s: concurrency buys x%.1f, want at least x2.5", parallelRate, serialRate, parallelRate/serialRate)
	}
	// Every ACK names its own durable row, and the receipts of one slot count its applied
	// indexes without a gap or a repeat.
	seen := map[model.Cursor]bool{}
	slotIndexes := map[uint16][]uint64{}
	for i, r := range receipts {
		if seen[r.Cursor] {
			t.Fatalf("receipt %d repeats the cursor %v", i, r.Cursor)
		}
		seen[r.Cursor] = true
		slotIndexes[parallel[i].batch.RouteSlot] = append(slotIndexes[parallel[i].batch.RouteSlot], uint64(r.Cursor.Index))
	}
	if err = e.db.View(func(tx *bolt.Tx) error {
		for i, p := range parallel {
			if logicalGet(tx, "batches", batchKey(p.batch.Org, p.batch.Project, p.batch.Source, p.batch.Producer, p.batch.RouteSlot, p.batch.ID)) == nil {
				t.Fatalf("append %d was acknowledged without its row", i)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for slot, indexes := range slotIndexes {
		present := map[uint64]bool{}
		for _, ix := range indexes {
			present[ix] = true
		}
		var top uint64
		for _, ix := range indexes {
			top = max(top, ix)
		}
		if top != e.indexes[slot] {
			t.Fatalf("slot %d: highest receipt %d, applied index %d", slot, top, e.indexes[slot])
		}
	}
}
