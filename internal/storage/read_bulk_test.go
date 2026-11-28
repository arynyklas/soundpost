// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Every page a scan releases costs a release barrier, an index seek and a transaction, so the 1,430 pages of a
// 24 h query of one organization were 1,430 of each. A scan that reads on to the end asks for larger pages
// (MaxPageRows): the same rows, in the same order, released after the same barrier, in a few pages instead of
// one per 128 rows. A scan that does not ask keeps pages of 128 rows.
func TestScanWithMaxPageRowsReleasesFewerLargerPages(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	rows := typedRows(base.Records[0].Resource)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	batches := 4*pageRows + 8
	if testing.Short() {
		batches = 2*pageRows + 8
	}
	want := map[model.ID]model.UnixNano{}
	var order []model.ID
	for i := range batches {
		row := rows[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 1)
		appendTyped(t, e, store, a, c, d, row)
		want[row.ID] = row.ObservedAt
		order = append(order, row.ID)
	}
	scope := scanScope(t, store, a, d)
	run := func(phase string, ask int) (pages int, lookups uint64, biggest int) {
		before := e.Stats().IndexLookups
		it, err := e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: model.UnixNano(batches + 10), MaxPageRows: ask})
		if err != nil {
			t.Fatal(err)
		}
		var got []model.ID
		for {
			p, err := it.Next(context.Background())
			if err == io.EOF {
				break
			}
			if err != nil {
				it.Close()
				t.Fatal(err)
			}
			pages++
			biggest = max(biggest, p.Len())
			for i, id := range p.IDs {
				if at, ok := want[id]; !ok || at != p.Times[i] {
					it.Close()
					t.Fatalf("%s: row %s is unexpected or mistimed", phase, id)
				}
				got = append(got, id)
			}
		}
		if err = it.Close(); err != nil {
			t.Fatal(err)
		}
		if len(got) != batches {
			t.Fatalf("%s: scan returned %d of %d rows", phase, len(got), batches)
		}
		for i := range got {
			if got[i] != order[i] {
				t.Fatalf("%s: row %d is %s, want %s: the order of the rows changed", phase, i, got[i], order[i])
			}
		}
		return pages, e.Stats().IndexLookups - before, biggest
	}
	for _, phase := range []string{"hot", "cold"} {
		if phase == "cold" {
			if err = e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		pages, lookups, biggest := run(phase+"/default", 0)
		if biggest > pageRows || pages != (batches+pageRows-1)/pageRows {
			t.Fatalf("%s: a scan that did not ask for larger pages released %d pages, the biggest of %d rows", phase, pages, biggest)
		}
		bulkPages, bulkLookups, bulkBiggest := run(phase+"/bulk", MaxScanPageRows)
		t.Logf("%s: %d rows: default %d pages %d index lookups; MaxPageRows %d: %d pages %d lookups, biggest page %d rows", phase, batches, pages, lookups, MaxScanPageRows, bulkPages, bulkLookups, bulkBiggest)
		// 128 rows, then four times as many: the rest of the rows are in the second page.
		if bulkPages > 2 || bulkLookups > 2 {
			t.Fatalf("%s: %d rows took %d pages and %d index lookups with larger pages, want at most 2 of each (default: %d pages)", phase, batches, bulkPages, bulkLookups, pages)
		}
		if bulkBiggest > MaxScanPageRows {
			t.Fatalf("%s: a page of %d rows is over MaxScanPageRows", phase, bulkBiggest)
		}
	}
	// A request above the bound is refused, not clamped.
	if _, err = e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 1, MaxPageRows: MaxScanPageRows + 1}); err == nil {
		t.Fatal("MaxPageRows over MaxScanPageRows was accepted")
	}
	if s := e.Stats(); s.ActiveIterators != 0 || s.BorrowedPages != 0 {
		t.Fatalf("scans leaked: %+v", s)
	}
}
