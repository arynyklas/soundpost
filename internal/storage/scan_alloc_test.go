// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"runtime"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// scanPerRowAllocBound is the ceiling, in heap allocations per additional row, of a scan page
// that projects only ID and time. The pages borrow decoded columns until the next Next/Close, so
// a page of 128 rows must cost the same number of allocations as a page of 16 rows (measured
// slope 0.00-0.07 alone, up to 0.46 beside parallel tests because the counter is process-wide).
// Before the byte-array decode fix the slope was 4.14: one allocation per ID, origin, project
// and source cell. 1.0 separates the two with margin.
const scanPerRowAllocBound = 1.0

// bulkBatch is normalized with rows records instead of one; it reserves admission once.
func bulkBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, rows int) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	ctx := context.Background()
	scope, err := a.SourceScope(ctx, c, false)
	if err != nil {
		t.Fatal(err)
	}
	src, err := a.SourceAuthority(ctx, c, true)
	if err != nil {
		t.Fatal(err)
	}
	res := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1}
	for i := range rows {
		b.Records = append(b.Records, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(i + 1), Resource: res, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}})
	}
	b.RouteSlot, _ = model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	raw := mustJSON(t, b)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(mustJSON(t, src.Policy)).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 1 << 40}}}
	if n.Reservation, err = store.ReserveAdmission(ctx, scope, n); err != nil {
		t.Fatal(err)
	}
	return scope, n
}

// scanMallocs appends one batch of rows records, optionally flushes it to a segment, and returns
// the smallest heap-allocation count of one full ID+time projected Next over several fresh
// iterators. It also checks the page carries every row.
func scanMallocs(t *testing.T, rows int, cold bool) uint64 {
	t.Helper()
	store, a, c, d := fixture(t)
	write, b := bulkBatch(t, store, a, c, d, rows)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if cold {
		if err = e.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	req := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: model.UnixNano(rows + 2), Projection: []Field{FieldID, FieldTime}}
	best := ^uint64(0)
	for range 6 {
		it, err := e.Scan(context.Background(), read, req)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		page, err := it.Next(context.Background())
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		if page.Len() != rows {
			t.Fatalf("page rows = %d, want %d", page.Len(), rows)
		}
		if _, err = it.Next(context.Background()); err != io.EOF {
			t.Fatalf("after the page: %v", err)
		}
		it.Close()
		if m := after.Mallocs - before.Mallocs; m < best {
			best = m
		}
	}
	return best
}

// TestScanPagesBorrowWithoutPerRowAllocation proves the C05 Interfaces clause "iterator pages
// borrow until next Next/Close; no unnecessary per-row allocation": the allocation count of a
// projected Next does not grow with the number of rows in the page, for hot and flushed data.
func TestScanPagesBorrowWithoutPerRowAllocation(t *testing.T) {
	for _, cold := range []bool{false, true} {
		small := scanMallocs(t, 16, cold)
		large := scanMallocs(t, 128, cold)
		var slope float64
		if large > small {
			slope = float64(large-small) / float64(128-16)
		}
		t.Logf("SCAN-ALLOC cold=%v mallocs(16 rows)=%d mallocs(128 rows)=%d per-extra-row=%.3f", cold, small, large, slope)
		if slope > scanPerRowAllocBound {
			t.Fatalf("cold=%v: %.3f allocations per extra row (16 rows: %d, 128 rows: %d), bound %.2f", cold, slope, small, large, scanPerRowAllocBound)
		}
	}
}
