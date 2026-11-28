// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A chunk holds at most as many rows as the scan allows it (128, then 512, then 1024), and it appended the
// rows one by one from pages of 128 into columns that began at the size of the first page: nine columns grown
// by doubling, 12 CPU-seconds of a 24 h mix. The chunk allocates its columns once, for the rows it may hold.
func TestScanChunkAllocatesItsColumnsOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("needs three chunks of a growing scan")
	}
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	rows := typedRows(base.Records[0].Resource)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	total := pageRows + 4*pageRows + 700 // pages of 128, 512 and 1024 rows allowed; the third holds 700
	for i := range total {
		row := rows[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 1)
		appendTyped(t, e, store, a, c, d, row)
	}
	scope := scanScope(t, store, a, d)
	it, err := e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: model.UnixNano(total + 10), MaxPageRows: MaxScanPageRows})
	if err != nil {
		t.Fatal(err)
	}
	var lens, caps []int
	for {
		p, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			it.Close()
			t.Fatal(err)
		}
		lens = append(lens, p.Len())
		caps = append(caps, cap(p.IDs))
		if cap(p.Times) != cap(p.IDs) || cap(p.Origins) != cap(p.IDs) {
			it.Close()
			t.Fatalf("page %d: columns have capacities %d, %d, %d", len(lens), cap(p.IDs), cap(p.Times), cap(p.Origins))
		}
	}
	if err = it.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("pages of %v rows, column capacities %v", lens, caps)
	sum := 0
	for _, n := range lens {
		sum += n
	}
	if sum != total || len(lens) < 3 {
		t.Fatalf("scan returned %d of %d rows in %d pages, want three or more pages", sum, total, len(lens))
	}
	last := len(lens) - 1
	if lens[last] <= 4*pageRows || caps[last] != MaxScanPageRows {
		t.Fatalf("the last page holds %d rows in columns of capacity %d, want capacity %d (allocated once)", lens[last], caps[last], MaxScanPageRows)
	}
}
