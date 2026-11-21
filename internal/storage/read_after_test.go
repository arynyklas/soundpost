// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A consumer that has applied every row up to an origin cursor resumes after it:
// ScanRequest.After skips the rows of a group at or below its entry, in the hot and
// the flushed state alike, leaves other groups whole, and never hides a row above it.
func TestScanAfterSkipsAppliedOriginsOnly(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	rows := typedRows(base.Records[0].Resource)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	const total = 6
	for i := range total {
		row := rows[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 1)
		appendTyped(t, e, store, a, c, d, row)
	}
	scope := scanScope(t, store, a, d)
	read := func(after []model.Cursor) (origins []model.Cursor) {
		t.Helper()
		it, err := e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: model.UnixNano(total + 10), After: after})
		if err != nil {
			t.Fatal(err)
		}
		defer it.Close()
		for {
			p, err := it.Next(context.Background())
			if err == io.EOF {
				return origins
			}
			if err != nil {
				t.Fatal(err)
			}
			origins = append(origins, p.Origins[:p.Len()]...)
		}
	}
	for _, phase := range []string{"hot", "cold"} {
		if phase == "cold" {
			if err = e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		all := read(nil)
		if len(all) != total {
			t.Fatalf("%s: a scan without After returned %d of %d rows", phase, len(all), total)
		}
		slices.SortFunc(all, func(x, y model.Cursor) int { return int(x.Index) - int(y.Index) })
		through := all[2]
		got := read([]model.Cursor{through})
		want := all[3:]
		slices.SortFunc(got, func(x, y model.Cursor) int { return int(x.Index) - int(y.Index) })
		if !slices.Equal(got, want) {
			t.Fatalf("%s: after %v the scan returned %v, want %v", phase, through, got, want)
		}
		// Another group's entry skips nothing of this one; the highest entry of a group wins.
		other := model.Cursor{Group: model.ID{0xee}, Index: 1 << 40}
		if got = read([]model.Cursor{other}); len(got) != total {
			t.Fatalf("%s: an entry for another group hid rows: %d of %d", phase, len(got), total)
		}
		if got = read([]model.Cursor{through, all[1]}); len(got) != len(want) {
			t.Fatalf("%s: with two entries for one group the scan returned %d rows, want %d", phase, len(got), len(want))
		}
		if got = read([]model.Cursor{all[total-1]}); len(got) != 0 {
			t.Fatalf("%s: after the newest origin the scan returned %v", phase, got)
		}
	}
}
