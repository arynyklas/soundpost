// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

// Recorded native observations (po-0112/po-0116 and po-0248/po-0252, both pinned
// releases, avg_over_time and the avg aggregation): when the compensated running
// sum of finite inputs overflows, both releases switch mid-stream into an
// incremental mean that keeps the Kahan compensation. 3.1.0 folds
// f/n - (mean+c)/n into the mean; 3.13.5 scales mean and compensation by
// (n-1)/n and folds f/n. A restarted plain mean matches neither.
func TestAverageSwitchesToCompensatedIncrementalMeanWhenSumOverflows(t *testing.T) {
	cases := []struct {
		name   string
		values []uint64
		want   map[string]uint64
	}{
		{
			name: "overflow at the third value",
			values: []uint64{
				0xffe005419221015d, 0x4004000000000000, 0xffe005419221015d,
				0x7fdfaf5f8d197479, 0x3ff0000000000000, 0x7fd1ccf385ebc8a0,
			},
			want: map[string]uint64{profile310: 0xffa376444753b5cf, profile3135: 0xffa376444753b5ce},
		},
		{
			name: "overflow after several finite values",
			values: []uint64{
				0x7fc55c576d815726, 0x7fd1ccf385ebc8a0, 0x7fe1ccf385ebc8a0,
				0x7feab36d48e1acf0, 0x7fee42d130773b76, 0x7fcf543bf5f0e638,
				0x7feab36d48e1acf0, 0xffee42d130773b76, 0x7fdfaf5f8d197479,
			},
			want: map[string]uint64{profile310: 0x7fd83f948ce6bc88, profile3135: 0x7fd83f948ce6bc87},
		},
	}
	const at = 553_000
	for _, tc := range cases {
		m := metricSeries("m", nil, bitsSamples(500_000_000_000, 1_000_000_000, tc.values...)...)
		var series []value.Series
		for i, v := range tc.values {
			series = append(series, metricSeries("m", model.Labels{{Name: "i", Value: string(rune('a' + i))}}, sample(at*1_000_000, math.Float64frombits(v))))
		}
		for _, p := range []string{profile310, profile3135} {
			if got := singleFloatBits(t, p, "avg_over_time(m[10m])", at, m); got != tc.want[p] {
				t.Errorf("%s %s: avg_over_time = %016x, want %016x", tc.name, p, got, tc.want[p])
			}
			if got := singleFloatBits(t, p, "avg(m)", at, series...); got != tc.want[p] {
				t.Errorf("%s %s: avg = %016x, want %016x", tc.name, p, got, tc.want[p])
			}
		}
	}
}
