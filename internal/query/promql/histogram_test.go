// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"testing"
)

func nativeTestHistogram(count uint64) *model.NativeHistogram {
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: model.Uint64(count), Sum: model.FloatBits(math.Float64bits(float64(count))), PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 1}}, PositiveCounts: []model.AbsoluteBucket{model.AbsoluteBucket(count)}, ResetHint: "unknown"}}
}
func TestNativeIntegerPrecisionRetained(t *testing.T) {
	h := nativeTestHistogram(9007199254740993)
	s := value.Sample{Histogram: h}
	r, keep, _, e := histogramBinary("==", s, value.CloneSample(s))
	if e != nil || !keep || r.Histogram.Integer.Count != 9007199254740993 {
		t.Fatal("equality rounded integer histogram")
	}
	if h.Integer.Count != 9007199254740993 {
		t.Fatal("mutated original")
	}
	scaled := value.ScaleHistogram(*h, -1)
	if h.Integer.Count != 9007199254740993 || scaled.Float == nil || scaled.Float.Flavor != "gauge" {
		t.Fatal("scale mutates/flavor")
	}
}
func TestHistogramClassicQuantileRepair(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	var v []value.Series
	for _, b := range []struct {
		le string
		n  float64
	}{{"1", 3}, {"2", 2}, {"+Inf", 5}} {
		s := functionTestSeries(b.n)
		s.Labels = value.SetLabel(s.Labels, "le", b.le)
		v = append(v, s)
	}
	r, d, e := EvalFunction(context.Background(), functionTestCall("histogram_quantile"), []value.Result{functionTestScalar(.5), {Type: "vector", Vector: v}}, f)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("classic: %v", e)
	}
	if len(d) == 0 {
		t.Fatal("missing monotonic repair info")
	}
	if x := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)); math.Abs(x-5.0/6) > 1e-14 {
		t.Fatalf("quantile %v", x)
	}
}
func TestHistogramNativeInterpolation(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	s := functionTestSeries()
	s.Samples = []value.Sample{{Histogram: nativeTestHistogram(4)}}
	r, _, e := EvalFunction(context.Background(), functionTestCall("histogram_quantile"), []value.Result{functionTestScalar(.5), {Type: "vector", Vector: []value.Series{s}}}, f)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("native %v", e)
	}
	if x := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)); math.Abs(x-math.Sqrt2) > 1e-14 {
		t.Fatalf("exponential interpolation %v", x)
	}
}
func TestHistogramMixedLayoutsRemoved(t *testing.T) {
	a := value.Sample{Histogram: nativeTestHistogram(2)}
	b := value.Sample{Histogram: &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: -53, Count: 1, CustomBounds: []model.FloatBits{model.FloatBits(math.Float64bits(1))}, PositiveSpans: []model.HistogramSpan{{Length: 1}}, PositiveCounts: []model.AbsoluteBucket{1}, ResetHint: "unknown"}}}
	_, keep, d, e := histogramBinary("+", a, b)
	if e != nil || keep || len(d) == 0 {
		t.Fatalf("incompatible retained %v %#v", e, d)
	}
}
func TestHistogramCounterResetExactCounts(t *testing.T) {
	a := nativeTestHistogram(9007199254740993)
	b := nativeTestHistogram(9007199254740992)
	if !value.HistogramReset(*a, *b) {
		t.Fatal("uint64 reset rounded away")
	}
}
func TestMixedHistogramAnnotationSurvivesPlanRewrite(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	series := functionTestSeries(1)
	series.Samples = append(series.Samples, value.Sample{Time: 10_000_000_000, Histogram: nativeTestHistogram(1)})
	expression, err := Parse("sum by(job) (sum_over_time(requests_total[20s]))", frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(expression, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, frame.Evaluation, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	result, diagnostics, err := Evaluate(context.Background(), plan, seriesSource{series}, frame.Account)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Vector) != 0 {
		t.Fatal("plan invented zero-valued replacement for removed mixed window")
	}
	found := false
	for _, diagnostic := range diagnostics {
		if diagnostic.Category == "MixedFloatsHistogramsWarning" {
			found = true
		}
	}
	if !found {
		t.Fatal("grouped plan lost the source mixed-window warning")
	}
}
