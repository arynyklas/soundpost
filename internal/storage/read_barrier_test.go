// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A scan made one fence over every group of the cut and one control read more than it needed to answer for
// the same cut: the first chunk read the authority again right after the Scan did, the last Next read it
// once to judge a barrier that reads it again, and the cut reported after the end of the rows was
// certified a third time. At the gate these fixed costs were paid by each of the 1,440 Selects of a
// 24 h query. Counted from the start of the Scan to the cut reported after the end: authority reads at most
// 2 (the Scan) + 1 per chunk after the first + 1 per page's barrier + 1 for the barrier at the end of the
// rows, and one fence per page and one at the end.
func TestScanFencesAndReadsAuthorityOnlyWhereTheCutChanged(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 4, 100)
	var calls, fences atomic.Int64
	hook := func() { fences.Add(1) }
	x.e.mu.Lock()
	x.e.validator = countingValidator{inner: x.a, calls: &calls}
	x.e.duringReleaseFence = hook
	x.e.mu.Unlock()
	defer func() { x.e.mu.Lock(); x.e.duringReleaseFence = nil; x.e.mu.Unlock() }()
	it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	rows, pages := 0, 0
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows += page.Len()
		pages++
	}
	marks := it.Watermarks()
	if rows != 400 || pages < 3 {
		t.Fatalf("scan delivered %d rows in %d pages, want 400 rows in at least 3 pages", rows, pages)
	}
	if len(marks) != 64 {
		t.Fatalf("cut after the end of the rows has %d marks, want the 64 the scan was certified at", len(marks))
	}
	if got, limit := calls.Load(), int64(2*pages+2); got > limit {
		t.Fatalf("%d authority reads for %d pages, want at most %d", got, pages, limit)
	}
	if got, limit := fences.Load(), int64(pages+1); got > limit {
		t.Fatalf("%d release fences for %d pages, want at most %d", got, pages, limit)
	}
}
