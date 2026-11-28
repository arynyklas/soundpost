// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A union scan keeps every row of its window until the steps have read them: a 24 h log query retains a
// million entries in one slice, and append's growth of a large slice (a quarter more each time) copies it
// about five times over; the evaluation of each window grows its points the same way. 18 CPU seconds of a
// 60 s gate-mix profile went to growslice in these two places. The slices double.
func TestRetainedEntriesAndPointsGrowByDoubling(t *testing.T) {
	const n = 200_000
	s := &metricState{}
	allocs := testing.AllocsPerRun(1, func() {
		u := &rangeUnion{sorted: true}
		var previous model.UnixNano
		charge := func(int64) error { return nil }
		for i := range n {
			if err := s.retain(u, &previous, rangeEntry{rangeRow: rangeRow{at: model.UnixNano(i), retained: true}}, charge); err != nil {
				t.Fatal(err)
			}
		}
		if len(u.entries) != n {
			t.Fatalf("%d entries retained, want %d", len(u.entries), n)
		}
	})
	if allocs > 24 {
		t.Fatalf("%.0f allocations to retain %d entries, want at most 24 (doubling)", allocs, n)
	}
	var points []rangePoint
	allocs = testing.AllocsPerRun(1, func() {
		points = nil
		for i := range n {
			points = appendDoubling(points, rangePoint{at: model.UnixNano(i), v: 1, n: 1})
		}
	})
	if len(points) != n || allocs > 24 {
		t.Fatalf("%d points, %.0f allocations, want %d points in at most 24", len(points), allocs, n)
	}
}
