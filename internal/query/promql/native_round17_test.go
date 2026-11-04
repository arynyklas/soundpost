// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"math"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/query/syntax"
)

// 3.13.5 rejects the largest binary64 below 2^63 (and every value from there
// up); 3.1.0 accepts it and rejects from 2^63. 9223372036854775000 and
// ...775295 round to that same binary64.
func TestNativeTopkParameterJustBelowTwoPow63(t *testing.T) {
	for _, tc := range []struct {
		id, text string
		fails    bool
	}{
		{"promql-prometheus-3.1.0", "9223372036854774784", false},
		{"promql-prometheus-3.1.0", "9223372036854775000", false},
		{"promql-prometheus-3.1.0", "9223372036854775296", true},
		{"promql-prometheus-3.13.5", "4611686018427387904", false},
		{"promql-prometheus-3.13.5", "9223372036854774784", true},
		{"promql-prometheus-3.13.5", "9223372036854775000", true},
		{"promql-prometheus-3.13.5", "9223372036854775295", true},
		{"promql-prometheus-3.13.5", "9223372036854775296", true},
	} {
		p := featureProfile(t, tc.id, "promql-experimental-functions")
		for _, name := range []string{"topk", "bottomk", "limitk"} {
			r, _, err := evalWith(t, p, name+"("+tc.text+", m)", instantAt(10_000),
				metricSeries("m", model.Labels{{Name: "i", Value: "1"}}, msSample(0, 1)),
				metricSeries("m", model.Labels{{Name: "i", Value: "2"}}, msSample(0, 2)))
			if tc.fails {
				var language *syntax.LanguageError
				if !errors.As(err, &language) || language.Code != "aggregation.parameter-range" {
					t.Fatalf("%s %s(%s): want parameter-range, got %+v %v", tc.id, name, tc.text, r, err)
				}
				continue
			}
			if err != nil || len(r.Vector) != 2 {
				t.Fatalf("%s %s(%s): want both series, got %+v %v", tc.id, name, tc.text, r, err)
			}
		}
	}
}

func exponentialHistogram(schema int32, threshold float64, zero, count uint64, sum float64, offset int32, counts ...uint64) model.NativeHistogram {
	absolute := make([]model.AbsoluteBucket, len(counts))
	for i, c := range counts {
		absolute[i] = model.AbsoluteBucket(c)
	}
	return model.NativeHistogram{Integer: &model.IntegerHistogram{
		Flavor: "counter", Schema: schema, ZeroThreshold: model.FloatBits(math.Float64bits(threshold)),
		Sum: model.FloatBits(math.Float64bits(sum)), Count: model.Uint64(count), ZeroCount: model.Uint64(zero),
		PositiveSpans: []model.HistogramSpan{{Offset: offset, Length: uint32(len(counts))}}, PositiveCounts: absolute, ResetHint: "unknown",
	}}
}

// Expected values below are recorded observations of both pinned engines.
// A bound that is never placed takes the whole observation count (11), not the
// bucket total (10), and so does a bound above every bucket.
func TestNativeFractionUnplacedBoundTakesObservationCount(t *testing.T) {
	for _, tc := range []struct {
		name         string
		h            model.NativeHistogram
		lower, upper float64
		want         float64
	}{
		{"count above buckets", exponentialHistogram(2, 0.001, 0, 11, 15, 1, 1, 3, 0, 6), 0, 2, 1},
		// schema -2: buckets (2^-16,2^-12] .. (2^-4,1]; the lower bound 0.5 is
		// interpolated in the log domain inside (2^-4,1], the upper bound is
		// above all buckets, so the 2 observations in no bucket count as below it.
		{"unplaced upper", exponentialHistogram(-2, 0.001, 0, 19, 28.9, -3, 4, 6, 2, 5), 0.5, 1e9, 0.17105263157894737},
		// every bucket lies under the zero threshold 0.5 and is still walked.
		{"buckets under threshold", exponentialHistogram(-2, 0.5, 3, 17, 28.9, -6, 7, 1, 3, 3), 0, 1, 1},
	} {
		got, _ := histogramNativeFraction(tc.lower, tc.upper, tc.h, "promql-prometheus-3.1.0")
		if math.Float64bits(got) != math.Float64bits(tc.want) {
			t.Errorf("%s: fraction(%v, %v) = %v, want %v", tc.name, tc.lower, tc.upper, got, tc.want)
		}
	}
}

// Buckets entirely below the zero threshold keep their upper bound while the
// lower bound is raised to the threshold, so their representative value is
// sqrt(upper*threshold), not the bucket's geometric centre.
func TestNativeVarianceUsesThresholdClampedBuckets(t *testing.T) {
	h := exponentialHistogram(-4, 0.001, 1, 11, 18.7, -6, 4, 4, 2)
	variance := histogramNativeVariance(h, "promql-prometheus-3.1.0")
	if math.Float64bits(variance) != math.Float64bits(2.8899999999954122) {
		t.Fatalf("variance %v", variance)
	}
	if deviation := math.Sqrt(variance); math.Float64bits(deviation) != math.Float64bits(1.6999999999986506) {
		t.Fatalf("deviation %v", deviation)
	}
}

// Bounds of schema < 0 are exact powers of two; those of schema >= 0 come from
// the precalculated upstream mantissa table (1/sqrt(2) is stored as
// 0.7071067811865475, not ...476).
func TestExponentialBoundTable(t *testing.T) {
	if got := exponentialBound(-2, 3); got != 4096 {
		t.Fatalf("schema -2 index 3: %v", got)
	}
	if got := exponentialBound(-4, -1); got != math.Ldexp(1, -16) {
		t.Fatalf("schema -4 index -1: %v", got)
	}
	if got := exponentialBound(0, -3); got != 0.125 {
		t.Fatalf("schema 0 index -3: %v", got)
	}
	for _, tc := range []struct {
		schema, index int32
		want          float64
	}{
		{1, 0, 1}, {2, 4, 2}, {8, 256, 2}, {3, -8, 0.5}, {5, 32, 2},
	} {
		if got := exponentialBound(tc.schema, tc.index); got != tc.want {
			t.Fatalf("schema %d index %d: %v want %v", tc.schema, tc.index, got, tc.want)
		}
	}
	if got := exponentialBound(1, -1); got != 0.7071067811865475 {
		t.Fatalf("schema 1 index -1: %v", got)
	}
	if got := exponentialBound(1, 1); got != 0.7071067811865475*2 {
		t.Fatalf("schema 1 index 1: %v", got)
	}
	for schema, index := range map[int32]int32{0: 1024, 1: 2048, -2: 256, 8: 1024 << 8} {
		if got := exponentialBound(schema, index); got != math.MaxFloat64 {
			t.Fatalf("schema %d index %d: %v want MaxFloat64", schema, index, got)
		}
	}
	if got := exponentialBound(0, 1023); got != math.Ldexp(1, 1023) {
		t.Fatalf("schema 0 index 1023: %v", got)
	}
	if got := exponentialBound(9, 1); !math.IsNaN(got) {
		t.Fatalf("schema 9 has no table, got %v", got)
	}
	h := exponentialHistogram(8, 0, 0, 3, 1, 0, 1, 0)
	if got, _ := histogramNativeQuantile(0.01, h, "promql-prometheus-3.1.0"); got != 0.9973770679244123 {
		t.Fatalf("quantile %v", got)
	}
}

// Recorded observations (ids pz-0507, pz-0239, pn-0004): with a NaN sum the
// observations that are in no bucket are NaNs; 3.13.5 counts them in no
// fraction but keeps them in the denominator, 3.1.0 still places an unplaced
// bound at the whole observation count. A finite sum keeps the count rule on
// both profiles.
func TestNativeFractionNaNObservationsPerProfile(t *testing.T) {
	nan := math.NaN()
	const old, current = "promql-prometheus-3.1.0", "promql-prometheus-3.13.5"
	for _, tc := range []struct {
		name         string
		h            model.NativeHistogram
		lower, upper float64
		wantOld      float64
		wantNew      float64
	}{
		{"bucket total 7 of count 10", exponentialHistogram(1, 0, 0, 10, nan, 0, 0, 7), 0.5, 4, 1, 0.7},
		{"buckets under zero threshold", exponentialHistogram(8, 1, 0, 8, nan, -8, 5), 0.1, 500, 1, 0.625},
		{"zero count and one bucket", exponentialHistogram(3, 0, 3, 13, nan, -1, 9), 0.1, 1e8, 0.7692307692307693, 0.6923076923076923},
		{"finite sum keeps count", exponentialHistogram(1, 0, 0, 10, 5, 0, 0, 7), 0.5, 4, 1, 1},
	} {
		for profile, want := range map[string]float64{old: tc.wantOld, current: tc.wantNew} {
			got, _ := histogramNativeFraction(tc.lower, tc.upper, tc.h, profile)
			if math.Float64bits(got) != math.Float64bits(want) {
				t.Errorf("%s %s: fraction(%v, %v) = %v, want %v", tc.name, profile, tc.lower, tc.upper, got, want)
			}
		}
	}
}
