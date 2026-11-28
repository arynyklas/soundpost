// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Observations of the lock-pinned Prometheus 3.13.5 oracle for native histograms
// under the anchored and smoothed modifiers (the extsel/* probe rows; the
// recorded rows replay in internal/conformance/query). Series samples sit at
// 5s, 10s, 15s and 20s; the evaluation instants are 7.5s, 12s and 17.5s.

func extHistogram(flavor, hint string, sum float64, zero uint64, positive ...uint64) *model.NativeHistogram {
	h := &model.IntegerHistogram{Flavor: flavor, Schema: 0, Sum: model.FloatBits(math.Float64bits(sum)), ZeroCount: model.Uint64(zero), ResetHint: hint}
	count := zero
	for _, c := range positive {
		h.PositiveCounts = append(h.PositiveCounts, model.AbsoluteBucket(c))
		count += c
	}
	h.PositiveSpans = []model.HistogramSpan{{Offset: 0, Length: uint32(len(positive))}}
	h.Count = model.Uint64(count)
	return &model.NativeHistogram{Integer: h}
}

func extCustomHistogram(sum float64, bounds []float64, positive ...uint64) *model.NativeHistogram {
	h := &model.IntegerHistogram{Flavor: "counter", Schema: -53, Sum: model.FloatBits(math.Float64bits(sum)), ResetHint: "unknown"}
	var count uint64
	for _, c := range positive {
		h.PositiveCounts = append(h.PositiveCounts, model.AbsoluteBucket(c))
		count += c
	}
	for _, b := range bounds {
		h.CustomBounds = append(h.CustomBounds, model.FloatBits(math.Float64bits(b)))
	}
	h.PositiveSpans = []model.HistogramSpan{{Offset: 0, Length: uint32(len(positive))}}
	h.Count = model.Uint64(count)
	return &model.NativeHistogram{Integer: h}
}

func extSampleAt(milliseconds int64, h *model.NativeHistogram) value.Sample {
	return value.Sample{Time: model.UnixNano(milliseconds * 1_000_000), Histogram: h}
}

func extEval(t *testing.T, query string, at int64, samples ...value.Sample) (value.Result, []string) {
	t.Helper()
	p := featureProfile(t, "promql-prometheus-3.13.5", extendedGate)
	r, notes, err := evalWith(t, p, query, instantAt(at), metricSeries("h", nil, samples...))
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return r, diagnosticKeys(notes)
}

func extOnlyFloat(t *testing.T, r value.Result) float64 {
	t.Helper()
	if len(r.Vector) != 1 || len(r.Vector[0].Samples) != 1 || r.Vector[0].Samples[0].Histogram != nil {
		t.Fatalf("result is not one float: %+v", r.Vector)
	}
	return math.Float64frombits(uint64(r.Vector[0].Samples[0].Float))
}

// histogram_count/sum over a selector see statistics only: the counter-reset
// test of a gauge-hinted sample compares counts alone, so a falling zero bucket
// (a reset for the full histogram) is none (extsel/mixed-flavor/q01..q03).
func TestStatsOnlyDecodingFollowsTheSelectorPath(t *testing.T) {
	counter := extHistogram("counter", "unknown", 10, 2, 1, 2, 3) // count 8
	gauge := extHistogram("gauge", "gauge", 9, 1, 2, 3, 3)        // count 9, zero bucket fell
	samples := []value.Sample{extSampleAt(5000, counter), extSampleAt(10000, gauge)}
	for _, tc := range []struct {
		query string
		want  float64
	}{
		{`histogram_count(h smoothed)`, 8.5}, // statistics only: no reset, linear
		{`histogram_sum(h smoothed)`, 9.5},
		{`histogram_sum(increase(h[10s] smoothed))`, -0.5}, // right boundary 9.5 minus left 10
	} {
		r, _ := extEval(t, tc.query, 7500, samples...)
		if got := extOnlyFloat(t, r); got != tc.want {
			t.Fatalf("%s = %g, want %g", tc.query, got, tc.want)
		}
	}
	// The same selector as a whole histogram detects the falling zero bucket as a
	// reset and restarts the interpolation from zero (extsel/mixed-flavor/q00).
	r, _ := extEval(t, `h smoothed`, 7500, samples...)
	if len(r.Vector) != 1 || r.Vector[0].Samples[0].Histogram == nil {
		t.Fatalf("whole histogram: %+v", r.Vector)
	}
	if count := math.Float64frombits(uint64(r.Vector[0].Samples[0].Histogram.Float.Count)); count != 4.5 {
		t.Fatalf("whole-histogram interpolation count = %g, want 4.5", count)
	}
}

// An interpolation of custom-bounds histograms that differ in their bounds
// reports the reconciliation of its subtraction and of its addition as two
// annotations; without buckets (histogram_count) there is none
// (extsel/nhcb-diff/q00, q01).
func TestInterpolationReportsSubtractionAndAdditionReconciliation(t *testing.T) {
	a := extCustomHistogram(5, []float64{1, 2}, 1, 2, 3)
	b := extCustomHistogram(10, []float64{1, 3}, 2, 4, 6)
	samples := []value.Sample{extSampleAt(5000, a), extSampleAt(10000, b)}
	_, notes := extEval(t, `h smoothed`, 7500, samples...)
	want := []string{"MismatchedCustomBucketsHistogramsInfo@0-1", "MismatchedCustomBucketsHistogramsInfo@0-1"}
	if !reflect.DeepEqual(notes, want) {
		t.Fatalf("annotations %v, want %v", notes, want)
	}
	_, notes = extEval(t, `histogram_count(h smoothed)`, 7500, samples...)
	if len(notes) != 0 {
		t.Fatalf("statistics-only decoding reconciled buckets: %v", notes)
	}
}

// A carried-forward histogram (no later sample) is no longer a gauge: its hint
// is unknown and its flavor follows (extsel/gauge/q08/t22).
func TestCarriedForwardGaugeHistogramBecomesCounter(t *testing.T) {
	gauge := extHistogram("gauge", "gauge", 3, 0, 1, 1)
	r, _ := extEval(t, `h smoothed`, 22000, extSampleAt(5000, gauge), extSampleAt(20000, gauge))
	if len(r.Vector) != 1 {
		t.Fatalf("carry forward: %+v", r.Vector)
	}
	h := r.Vector[0].Samples[0].Histogram.Float
	if h.Flavor != "counter" || h.ResetHint != "unknown" {
		t.Fatalf("carried histogram flavor=%s hint=%s", h.Flavor, h.ResetHint)
	}
}
