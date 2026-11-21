// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

const (
	profile310  = "promql-prometheus-3.1.0"
	profile3135 = "promql-prometheus-3.13.5"
)

func bitsSamples(base int64, step int64, bits ...uint64) []value.Sample {
	out := make([]value.Sample, len(bits))
	for i, b := range bits {
		out[i] = sample(base+int64(i)*step, math.Float64frombits(b))
	}
	return out
}

func singleFloatBits(t *testing.T, p string, q string, at int64, series ...value.Series) uint64 {
	t.Helper()
	r, _, err := evalWith(t, featureProfile(t, p), q, instantAt(at), series...)
	if err != nil || len(r.Vector) != 1 {
		t.Fatalf("%s: %+v %v", q, r, err)
	}
	return uint64(r.Vector[0].Samples[0].Float)
}

// Recorded native observations (pv-0109/pv-0110): variance and deviation over a
// window use a Kahan-compensated incremental mean and a Kahan-compensated sum of
// squared deviations, on both pinned releases. Plain Welford differs in the last bits.
func TestVarianceOverTimeUsesCompensatedIncrementalAccumulation(t *testing.T) {
	m := metricSeries("m", nil, bitsSamples(59_125_000_000, 1_000_000_000,
		0x40fe240c9fbe76c9, 0x40be5a0000000000, 0x3f76872b020c49ba, 0x409f420000000000,
		0x0000000000000000, 0x3fa11105e1c15098, 0x41169b0977ced917, 0x3f35d2d01c0ca601)...)
	for _, p := range []string{profile310, profile3135} {
		if got, want := singleFloatBits(t, p, "stdvar_over_time(m[15m])", 823_875, m), uint64(0x420c1efabac417cb); got != want {
			t.Errorf("%s stdvar_over_time = %016x, want %016x", p, got, want)
		}
		if got, want := singleFloatBits(t, p, "stddev_over_time(m[15m])", 823_875, m), uint64(0x40fdff74a69c69bc); got != want {
			t.Errorf("%s stddev_over_time = %016x, want %016x", p, got, want)
		}
	}
}

// Recorded pv-0081: avg_over_time on 3.13.5 divides the sum and its compensation
// separately (sum/n + c/n); 3.1.0 divides the combined (sum+c)/n. The `avg`
// aggregation follows the same per-profile split.
func TestAverageDividesSumAndCompensationPerProfile(t *testing.T) {
	values := []uint64{0x3fc999999999999a, 0x0000000000000000, 0x4040aaaa8eb46349}
	m := metricSeries("m", nil, bitsSamples(583_500_000_000, 1_000_000_000, values...)...)
	const at = 661_500
	want := map[string]uint64{profile310: 0x40265b058b12a684, profile3135: 0x40265b058b12a683}
	for _, p := range []string{profile310, profile3135} {
		if got := singleFloatBits(t, p, "avg_over_time(m[90s])", at, m); got != want[p] {
			t.Errorf("%s avg_over_time = %016x, want %016x", p, got, want[p])
		}
		var series []value.Series
		for i, v := range values {
			series = append(series, metricSeries("m", model.Labels{{Name: "i", Value: string(rune('a' + i))}}, sample(at*1_000_000, math.Float64frombits(v))))
		}
		if got := singleFloatBits(t, p, "avg(m)", at, series...); got != want[p] {
			t.Errorf("%s avg = %016x, want %016x", p, got, want[p])
		}
	}
}
