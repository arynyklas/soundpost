// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Every page a scan releases costs one quorum barrier over every group of its
// cut. A scan over many batches that each hold one row (what a drill that writes
// one series per batch produces) must therefore release chunks of up to 128 rows
// across batch boundaries, not one page per batch.
func TestScanReleasesChunksAcrossBatchesWithinThePageBounds(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	rows := typedRows(base.Records[0].Resource)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Two batches more than a page holds prove the chunk bound; short mode keeps
	// the cheaper proof that a handful of batches share one page.
	batches := pageRows + 2
	if testing.Short() {
		batches = 12
	}
	want := map[model.ID]model.UnixNano{}
	for i := range batches {
		row := rows[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 1)
		appendTyped(t, e, store, a, c, d, row)
		want[row.ID] = row.ObservedAt
	}
	scope := scanScope(t, store, a, d)
	for _, phase := range []string{"hot", "cold"} {
		if phase == "cold" {
			if err = e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		it, err := e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: model.UnixNano(batches + 10)})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[model.ID]bool{}
		var pages int
		var last model.UnixNano
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
			if p.Len() == 0 || p.Len() > pageRows || p.Bytes > pageByteLimit {
				it.Close()
				t.Fatalf("%s: page of %d rows, %d bytes is outside the page bounds", phase, p.Len(), p.Bytes)
			}
			for i, id := range p.IDs {
				if at, ok := want[id]; !ok || at != p.Times[i] || seen[id] {
					it.Close()
					t.Fatalf("%s: row %s is unexpected, mistimed or repeated", phase, id)
				}
				if p.Times[i] < last {
					it.Close()
					t.Fatalf("%s: rows are not in time order", phase)
				}
				last = p.Times[i]
				seen[id] = true
			}
		}
		if err = it.Close(); err != nil {
			t.Fatal(err)
		}
		if len(seen) != batches {
			t.Fatalf("%s: scan returned %d of %d rows", phase, len(seen), batches)
		}
		if limit := (batches + pageRows - 1) / pageRows; pages > limit {
			t.Fatalf("%s: %d batches took %d pages, want at most %d (one release barrier per page)", phase, batches, pages, limit)
		}
	}
	if s := e.Stats(); s.ActiveIterators != 0 || s.BorrowedPages != 0 {
		t.Fatalf("scans leaked: %+v", s)
	}
}
