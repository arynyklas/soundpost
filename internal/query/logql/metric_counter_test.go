// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"testing"
)

func TestMetricCounterPinnedAnchorsThresholdAndZeroCap(t *testing.T) {
	// Pinned range_vector.go286-349 uses native raw-ns observations but a
	// range-ms start displacement, then /1000 for both observation durations.
	// These cases distinguish that kernel from evaluation-anchored PromQL math.
	tests := []struct {
		name            string
		firstAt, lastAt int64
		first, last     string
		multiplicity    model.Uint64
		want            float64
	}{
		// elapsed=1e6, start extension2, end0, increase1; zero-point cap0.
		{"zero-point-cap", 500000000, 1500000000, "n=0", "n=1", 1, 0.5},
		// elapsed=1, spacing1, threshold1.1; first value5 keeps the zero
		// intercept beyond start2, which becomes half-spacing0.5.
		{"threshold-half-spacing", 500000000, 500001000, "n=5", "n=6", 1, 0.75},
		// Same elapsed, but four observations make spacing1/3. The half-spacing
		// extension is1/6: factor1+1/6, then divide by selected range2seconds.
		{"multiplicity-changes-spacing", 500000000, 500001000, "n=5", "n=6", 3, (1.0 + 1.0/6.0) / 2.0},
		// Translating both observations inside the same valid window must not
		// alter native first/last-anchored extrapolation.
		{"translated-observations", 750000000, 750001000, "n=5", "n=6", 1, 0.75},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &metricSource{rows: []scan.LogRow{metricRow(1, tc.firstAt, tc.first), metricRow(2, tc.lastAt, tc.last)}}
			src.rows[0].Multiplicity = tc.multiplicity
			got := metricValue(t, `rate_counter({app="api"}|logfmt|unwrap n[2s])`, src)
			if math.Float64bits(got) != math.Float64bits(tc.want) {
				t.Fatalf("pinned counter %s got=%g bits=%016x want=%g bits=%016x", tc.name, got, math.Float64bits(got), tc.want, math.Float64bits(tc.want))
			}
		})
	}
}
