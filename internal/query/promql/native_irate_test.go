// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"
)

// After a counter reset irate assigns the post-reset value directly; it is not
// rebuilt as (last-previous)+previous, which loses bits.
func TestNativeIrateResetUsesPostResetValueExactly(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, tc := range []struct {
			name    string
			samples []float64 // spaced 10 s apart from t=0
			atMS    int64
			want    float64
		}{
			{"reset to 0.05 over 10s", []float64{0.1, 0.3, 0.05}, 30_000, 0.005},
			{"reset from 1e16 loses nothing", []float64{1e16, 1}, 20_000, 0.1},
		} {
			series := metricSeries("m", nil)
			for i, f := range tc.samples {
				series.Samples = append(series.Samples, msSample(int64(i)*10_000, f))
			}
			r, _, err := evalWith(t, p, "irate(m[1m])", instantAt(tc.atMS), series)
			if err != nil || len(r.Vector) != 1 {
				t.Fatalf("%s %s: %+v %v", id, tc.name, r, err)
			}
			got := floatsOf(t, r.Vector[0])
			if len(got) != 1 || got[0].Float != tc.want {
				t.Fatalf("%s %s: got %v want %v", id, tc.name, got, tc.want)
			}
		}
	}
}
