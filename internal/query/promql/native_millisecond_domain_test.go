// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/query/value"
)

// The pinned engines evaluate in milliseconds: evaluation instants and sample
// timestamps floor to a millisecond, the lookback is a whole-millisecond span
// and a sample exactly one lookback before the evaluation time is stale.
func TestNativeMillisecondDomainInstantSelection(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, tc := range []struct {
			name    string
			samples []value.Sample
			at      int64 // nanoseconds
			present bool
			wantAt  int64
			wantF   float64
		}{
			{"just inside the lookback", []value.Sample{sample(0, 1)}, 299_999_000_000, true, 299_999_000_000, 1},
			{"sub-millisecond instant floors to the inside millisecond", []value.Sample{sample(0, 1)}, 299_999_999_999, true, 299_999_000_000, 1},
			{"exact lookback boundary is stale", []value.Sample{sample(0, 1)}, 300_000_000_000, false, 0, 0},
			{"one nanosecond past the boundary floors onto the boundary", []value.Sample{sample(0, 1), msSample(10_000, 2)}, 300_000_000_001, true, 300_000_000_000, 2},
			{"sub-millisecond instant past a newer sample", []value.Sample{sample(0, 1), msSample(10_000, 2)}, 300_000_999_999, true, 300_000_000_000, 2},
			{"next millisecond", []value.Sample{sample(0, 1), msSample(10_000, 2)}, 300_001_000_001, true, 300_001_000_000, 2},
			{"sample inside the lookback keeps its nanosecond precision", []value.Sample{sample(999_999, 5)}, 300_000_000_000, true, 300_000_000_000, 5},
			{"sample at the first millisecond inside", []value.Sample{sample(1_000_000, 5)}, 300_000_000_000, true, 300_000_000_000, 5},
		} {
			r, _, err := evalWith(t, p, "m", value.Evaluation{Instant: true, Time: model.UnixNano(tc.at)}, metricSeries("m", nil, tc.samples...))
			if err != nil {
				t.Fatalf("%s %s: %v", id, tc.name, err)
			}
			if !tc.present {
				if len(r.Vector) != 0 {
					t.Fatalf("%s %s: stale sample returned %+v", id, tc.name, r.Vector)
				}
				continue
			}
			if len(r.Vector) != 1 {
				t.Fatalf("%s %s: got %d series", id, tc.name, len(r.Vector))
			}
			got := floatsOf(t, r.Vector[0])
			if !samePoints(got, []observedPoint{{tc.wantAt, float64(tc.wantF)}}) {
				t.Fatalf("%s %s: %+v want time %d value %v", id, tc.name, got, tc.wantAt, tc.wantF)
			}
		}
	}
}

func TestNativeMillisecondDomainRangeGrid(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.1.0")
	r, _, err := evalWith(t, p, "m", rangeOf(290_000, 310_000, 1000), metricSeries("m", nil, msSample(0, 1)))
	if err != nil || len(r.Matrix) != 1 {
		t.Fatalf("range: %+v %v", r, err)
	}
	if n := len(r.Matrix[0].Samples); n != 10 || r.Matrix[0].Samples[n-1].Time != 299_000_000_000 {
		t.Fatalf("a sample may serve only steps strictly inside the lookback: %d samples, last %v", n, r.Matrix[0].Samples[n-1].Time)
	}
}

// The evaluation instant floors to a millisecond, but window membership and the
// reported timestamps of samples keep their nanosecond precision.
func TestNativeMillisecondDomainWindowKeepsSampleTimestamps(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.1.0")
	r, _, err := evalWith(t, p, "m[10s]", value.Evaluation{Instant: true, Time: 20_000_500_000}, metricSeries("m", nil, sample(10_000_000_000, 2), sample(15_000_700_000, 3)))
	if err != nil || len(r.Matrix) != 1 {
		t.Fatalf("window: %+v %v", r, err)
	}
	// 10 000 ms is not inside the left-open window (10 000, 20 000].
	got := floatsOf(t, r.Matrix[0])
	if !samePoints(got, []observedPoint{{15_000_700_000, 3}}) {
		t.Fatalf("window samples %+v", got)
	}
}
