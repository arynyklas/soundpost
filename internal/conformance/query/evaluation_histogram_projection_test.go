// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func histogramProjectionObservation(h *model.NativeHistogram) EvaluationObservation {
	return EvaluationObservation{ID: "hist", Type: "vector", Complete: true, Series: []EvaluationSeries{{Samples: []EvaluationSample{{Time: 1, Histogram: h}}}}}
}
func TestEvaluationHistogramEmptyAllocationProjectionRetainsRawObservations(t *testing.T) {
	want := histogramProjectionObservation(&model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", Schema: 0, ResetHint: "gauge"}})
	got := histogramProjectionObservation(&model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", Schema: 0, ResetHint: "gauge", PositiveSpans: []model.HistogramSpan{}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.FloatBits{}, NegativeBuckets: []model.FloatBits{}, CustomBounds: []model.FloatBits{}}})
	beforeWant, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	beforeGot, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeWant, beforeGot) {
		t.Fatal("literal raw fixture failed to distinguish null from []")
	}
	if mismatches := CompareEvaluation(want, got); len(mismatches) != 0 {
		t.Fatalf("zero-length allocator forms compared: %+v", mismatches)
	}
	afterWant, _ := json.Marshal(want)
	afterGot, _ := json.Marshal(got)
	if !bytes.Equal(beforeWant, afterWant) || !bytes.Equal(beforeGot, afterGot) {
		t.Fatal("comparison mutated raw observations")
	}
	integerWant := histogramProjectionObservation(&model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, ResetHint: "unknown", Count: 9_007_199_254_740_993, ZeroCount: 9_007_199_254_740_993}})
	integerGot := histogramProjectionObservation(&model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, ResetHint: "unknown", Count: 9_007_199_254_740_993, ZeroCount: 9_007_199_254_740_993, PositiveSpans: []model.HistogramSpan{}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.DeltaBucket{}, NegativeBuckets: []model.DeltaBucket{}, PositiveCounts: []model.AbsoluteBucket{}, NegativeCounts: []model.AbsoluteBucket{}, CustomBounds: []model.FloatBits{}}})
	if mismatches := CompareEvaluation(integerWant, integerGot); len(mismatches) != 0 {
		t.Fatalf("integer zero-length allocator forms compared: %+v", mismatches)
	}
	integerGot.Series[0].Samples[0].Histogram.Integer.Count++
	if len(CompareEvaluation(integerWant, integerGot)) == 0 {
		t.Fatal("uint64 count >2^53 normalized")
	}
}
func TestEvaluationHistogramProjectionNeverChangesNonemptyLayoutOrBits(t *testing.T) {
	base := &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "counter", Schema: -53, ResetHint: "unknown", Count: model.FloatBits(0x3ff0000000000000), Sum: model.FloatBits(0x3ff0000000000000), PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 1}}, PositiveBuckets: []model.FloatBits{0x3ff0000000000000}, CustomBounds: []model.FloatBits{0x3ff0000000000000}}}
	want := histogramProjectionObservation(base)
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model.NativeHistogram){
		func(h *model.NativeHistogram) { h.Float.PositiveSpans[0].Offset++ },
		func(h *model.NativeHistogram) { h.Float.PositiveBuckets[0]++ },
		func(h *model.NativeHistogram) { h.Float.CustomBounds[0]++ },
		func(h *model.NativeHistogram) { h.Float.Count++ },
		func(h *model.NativeHistogram) { h.Float.Sum = model.FloatBits(0x8000000000000000) },
		func(h *model.NativeHistogram) { h.Float.ResetHint = "reset" },
		func(h *model.NativeHistogram) { h.Float.Flavor = "gauge" },
		func(h *model.NativeHistogram) { h.Float.Schema++ },
	} {
		var changed model.NativeHistogram
		if err = json.Unmarshal(raw, &changed); err != nil {
			t.Fatal(err)
		}
		change(&changed)
		if len(CompareEvaluation(want, histogramProjectionObservation(&changed))) == 0 {
			t.Fatal("nonempty layout, scalar or FloatBits changed without mismatch")
		}
	}
	if len(CompareEvaluation(want, histogramProjectionObservation(nil))) == 0 {
		t.Fatal("histogram union nil equated to non-nil variant")
	}
	if len(CompareEvaluation(histogramProjectionObservation(&model.NativeHistogram{Float: &model.FloatHistogram{}}), histogramProjectionObservation(&model.NativeHistogram{Integer: &model.IntegerHistogram{}}))) == 0 {
		t.Fatal("integer and float variants equated")
	}
}
