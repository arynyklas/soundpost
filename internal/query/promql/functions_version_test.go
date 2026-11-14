// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

func TestFunctionStartTimestampResetBoundaries(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	frame.Profile.ActiveFeatureSet.Enabled = append(frame.Profile.ActiveFeatureSet.Enabled, "use-start-timestamps")
	ns := func(seconds int64) *model.UnixNano { v := model.UnixNano(seconds * 1_000_000_000); return &v }
	for _, test := range []struct {
		name              string
		previous, current *model.UnixNano
		want              bool
	}{{"positive", ns(1), ns(6), true}, {"future", ns(1), ns(11), false}, {"zero", ns(1), ns(0), false}, {"absent", ns(1), nil, false}, {"equal-known", ns(1), ns(5), true}, {"equal-unknown", nil, ns(5), false}, {"equal-invalid-previous", ns(7), ns(5), false}, {"negative", ns(-2), ns(-1), false}} {
		t.Run(test.name, func(t *testing.T) {
			a := functionSample(10, 5_000_000_000)
			b := functionSample(20, 10_000_000_000)
			a.StartTimestamp = test.previous
			b.StartTimestamp = test.current
			if got := functionStartTimestampReset(a, b, frame); got != test.want {
				t.Fatalf("reset=%v want%v", got, test.want)
			}
			off := frame
			off.Profile.ActiveFeatureSet.Enabled = nil
			if functionStartTimestampReset(a, b, off) {
				t.Fatal("disabled gate reset")
			}
			old := functionTestFrame("promql-prometheus-3.1.0")
			if functionStartTimestampReset(a, b, old) {
				t.Fatal("old pin used start timestamp")
			}
		})
	}
}
func TestFunctionStartTimestampAffectsActualResets(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	frame.Profile.ActiveFeatureSet.Enabled = append(frame.Profile.ActiveFeatureSet.Enabled, "use-start-timestamps")
	series := functionTestSeries(10, 20, 30)
	previous, current := model.UnixNano(1_000_000_000), model.UnixNano(6_000_000_000)
	series.Samples[0].StartTimestamp = &previous
	series.Samples[1].StartTimestamp = &current
	series.Samples[2].StartTimestamp = &current
	result, _, err := EvalFunction(context.Background(), functionTestCall("resets"), []value.Result{{Type: "matrix", Matrix: []value.Series{series}}}, frame)
	if err != nil || len(result.Vector) != 1 || functionFloat(result.Vector[0].Samples[0]) != 1 {
		t.Fatalf("start reset not evaluated: %v", err)
	}
	if *series.Samples[0].StartTimestamp != previous || *series.Samples[1].StartTimestamp != current {
		t.Fatal("start metadata mutated")
	}
}
func TestFunctionPinnedScalarAndInstantHistogramDifferences(t *testing.T) {
	hist := functionTestSeries()
	hist.Samples = []value.Sample{{Histogram: nativeTestHistogram(4)}}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		frame := functionTestFrame(id)
		r, _, err := EvalFunction(context.Background(), functionTestCall("scalar"), []value.Result{{Type: "vector", Vector: []value.Series{hist}}}, frame)
		if err != nil {
			t.Fatal(err)
		}
		if id == "promql-prometheus-3.1.0" && functionFloat(r.Scalar) != 0 || id == "promql-prometheus-3.13.5" && !math.IsNaN(functionFloat(r.Scalar)) {
			t.Fatal("scalar pin difference lost")
		}
		series := functionTestSeries(1)
		series.Samples = append(series.Samples, value.Sample{Time: 10_000_000_000, Histogram: nativeTestHistogram(4)}, functionSample(8, 15_000_000_000))
		r, d, err := EvalFunction(context.Background(), functionTestCall("irate"), []value.Result{{Type: "matrix", Matrix: []value.Series{series}}}, frame)
		if err != nil {
			t.Fatal(err)
		}
		if id == "promql-prometheus-3.1.0" {
			if len(r.Vector) != 1 || functionFloat(r.Vector[0].Samples[0]) != .7 {
				t.Fatal("old instant rate must use last two floats")
			}
		} else if len(r.Vector) != 0 || len(d) == 0 {
			t.Fatal("new instant rate must remove mixed global last pair")
		}
	}
}
func TestFunctionModernUTF8Destination(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	input := value.Result{Type: "vector", Vector: []value.Series{functionTestSeries(1)}}
	arguments := []value.Result{input, {Type: "string", String: "温度"}, {Type: "string", String: "$1"}, {Type: "string", String: "job"}, {Type: "string", String: "(.*)"}}
	result, _, err := EvalFunction(context.Background(), functionTestCall("label_replace"), arguments, frame)
	if err != nil || value.Label(result.Vector[0].Labels, "温度") != "generic" {
		t.Fatalf("UTF8 destination: %v", err)
	}
}
func TestNativeConversionPreservesZeroSpans(t *testing.T) {
	histogram := model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: 9007199254740993, PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 2}}, PositiveCounts: []model.AbsoluteBucket{0, 9007199254740993}, ResetHint: "not_reset"}}
	converted := value.FloatHistogram(histogram)
	if len(converted.PositiveSpans) != 1 || converted.PositiveSpans[0].Length != 2 || len(converted.PositiveBuckets) != 2 || converted.PositiveBuckets[0] != 0 || converted.ResetHint != "not_reset" {
		t.Fatal("semantic conversion compacted or changed metadata")
	}
	if histogram.Integer.PositiveCounts[1] != 9007199254740993 {
		t.Fatal("native input rounded")
	}
}
func TestFunctionInstantRateDivisionBits(t *testing.T) {
	const want model.FloatBits = 0x3fe6666666666666 // The binary64 result of 7/10, not 7*(1/10).
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		frame := functionTestFrame(id)
		series := functionTestSeries()
		series.Samples = []value.Sample{functionSample(1, 5_000_000_000), functionSample(8, 15_000_000_000)}
		result, _, err := EvalFunction(context.Background(), functionTestCall("irate"), []value.Result{{Type: "matrix", Matrix: []value.Series{series}}}, frame)
		if err != nil || len(result.Vector) != 1 || result.Vector[0].Samples[0].Float != want {
			t.Fatalf("%s instant division bits: result=%+v err=%v", id, result, err)
		}
	}
	frame := functionTestFrame("promql-prometheus-3.13.5")
	series := functionTestSeries()
	series.Samples = []value.Sample{{Time: 5_000_000_000, Histogram: nativeTestHistogram(1)}, {Time: 15_000_000_000, Histogram: nativeTestHistogram(8)}}
	result, _, err := EvalFunction(context.Background(), functionTestCall("irate"), []value.Result{{Type: "matrix", Matrix: []value.Series{series}}}, frame)
	if err != nil || len(result.Vector) != 1 || result.Vector[0].Samples[0].Histogram.Float.Count != want {
		t.Fatalf("native instant division bits: result=%+v err=%v", result, err)
	}
	divided, keep, diagnostics, err := histogramBinary("/", value.Sample{Histogram: nativeTestHistogram(7)}, functionSample(10, 0))
	if err != nil || !keep || len(diagnostics) != 0 || divided.Histogram.Float.Count != want {
		t.Fatalf("native binary division bits: result=%+v keep=%v diagnostics=%+v err=%v", divided, keep, diagnostics, err)
	}
}
func TestFunctionExtendedRateDivisionBits(t *testing.T) {
	const want model.FloatBits = 0x3fe6666666666666
	frame := functionTestFrame("promql-prometheus-3.13.5")
	frame.Profile.ActiveFeatureSet.Enabled = append(frame.Profile.ActiveFeatureSet.Enabled, "promql-extended-range-selectors")
	frame.HasWindow, frame.WindowStart, frame.WindowEnd = true, 5_000_000_000, 15_000_000_000
	call := functionTestCall("rate")
	call.Expr.Expr.(*Node).Children[0].(*Node).Extension = "anchored"
	for _, histograms := range []bool{false, true} {
		series := functionTestSeries()
		series.Samples = []value.Sample{functionSample(1, 5_000_000_000), functionSample(8, 15_000_000_000)}
		if histograms {
			series.Samples = []value.Sample{{Time: 5_000_000_000, Histogram: nativeTestHistogram(1)}, {Time: 15_000_000_000, Histogram: nativeTestHistogram(8)}}
		}
		result, _, err := EvalFunction(context.Background(), call, []value.Result{{Type: "matrix", Matrix: []value.Series{series}}}, frame)
		if err != nil || len(result.Vector) != 1 {
			t.Fatalf("extended division result: %+v %v", result, err)
		}
		got := result.Vector[0].Samples[0].Float
		if histograms {
			got = result.Vector[0].Samples[0].Histogram.Float.Count
		}
		if got != want {
			t.Fatalf("extended histogram=%v division bits=%016x want=%016x", histograms, got, want)
		}
	}
}
