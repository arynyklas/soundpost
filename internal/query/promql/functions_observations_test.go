// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"testing"
)

func TestNativeObservedTrimBitsAndLayout(t *testing.T) {
	histogram := value.FloatHistogram(*nativeTestHistogram(4))
	if len(histogram.NegativeSpans) != 0 || len(histogram.NegativeBuckets) != 0 {
		t.Fatal("absent native side gained buckets at selector conversion")
	}
	input := model.NativeHistogram{Float: &histogram}
	for _, bound := range []float64{0, 1, 1.5, 2} {
		result, keep, _, err := histogramBinary("</", value.Sample{Histogram: &input}, functionSample(bound, 0))
		if err != nil || !keep {
			t.Fatalf("trim %v: %v", bound, err)
		}
		if len(result.Histogram.Float.NegativeSpans) != 0 || len(result.Histogram.Float.NegativeBuckets) != 0 {
			t.Fatalf("trim %v gained negative buckets", bound)
		}
		if bound <= 1 && (len(result.Histogram.Float.PositiveSpans) != 0 || len(result.Histogram.Float.PositiveBuckets) != 0) {
			t.Fatalf("trim %v retained discarded positive buckets", bound)
		}
		if bound == 1.5 && (result.Histogram.Float.Count != 0x4002b803473f7ad2 || result.Histogram.Float.Sum != 0x4006ecfe3c4e07a8) {
			t.Fatal("observed crossing population/sum bits changed")
		}
	}
}
func TestHistogramObservedProfileFlavor(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, op := range []string{"-", "*", "/"} {
			left := value.Sample{Histogram: nativeTestHistogram(4)}
			right := functionSample(-2, 0)
			if op == "-" {
				right = value.CloneSample(left)
			}
			result, keep, _, err := histogramBinaryProfile(op, left, right, functionTestFrame(id).Profile)
			if err != nil || !keep {
				t.Fatalf("%s %s: %v", id, op, err)
			}
			flavor, hint := "counter", "unknown"
			if id == "promql-prometheus-3.13.5" {
				flavor, hint = "gauge", "gauge"
			}
			if result.Histogram.Float.Flavor != flavor || result.Histogram.Float.ResetHint != hint {
				t.Fatalf("%s %s flavor/hint=%s/%s", id, op, result.Histogram.Float.Flavor, result.Histogram.Float.ResetHint)
			}
		}
	}
}
func TestAggregationObservedProfileHashEncoding(t *testing.T) {
	labels := model.Labels{{Name: "__name__", Value: "metric_total"}, {Name: "instance", Value: "generic-a"}, {Name: "job", Value: "generic"}}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		result, _, err := EvalAggregation(context.Background(), AggregationPlan{Name: "limit_ratio", Parameter: functionTestScalar(.5)}, value.Result{Type: "vector", Vector: []value.Series{{Project: model.ID{1}, Labels: labels, Samples: []value.Sample{functionSample(8, 20_000_000_000)}}}}, functionTestFrame(id))
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if id == "promql-prometheus-3.13.5" {
			want = 0
		}
		if len(result.Vector) != want {
			t.Fatalf("%s observed ratio selection=%d want%d", id, len(result.Vector), want)
		}
	}
}
func TestFunctionObservedAnnotationRanges(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	query := "quantile_over_time(.5,metric_total[20s])"
	expression, err := Parse(query, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(expression, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	series := functionTestSeries(1)
	series.Samples = append(series.Samples, value.Sample{Time: 15_000_000_000, Histogram: nativeTestHistogram(4)})
	_, diagnostics, err := EvalFunction(context.Background(), CallPlan{Name: "quantile_over_time", Expr: typed}, []value.Result{functionTestScalar(.5), {Type: "matrix", Matrix: []value.Series{series}}}, frame)
	if err != nil || len(diagnostics) != 1 || diagnostics[0].Range.StartByte != 19 || diagnostics[0].Range.EndByte != 21 {
		t.Fatalf("observed mixed quantile range: %+v %v", diagnostics, err)
	}
	query = "sort(metric_total)"
	expression, err = Parse(query, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err = Check(expression, frame.Profile)
	if err != nil {
		t.Fatal(err)
	}
	frame.Evaluation.Instant = false
	_, diagnostics, err = EvalFunction(context.Background(), CallPlan{Name: "sort", Expr: typed}, []value.Result{{Type: "vector", Vector: []value.Series{functionTestSeries(8)}}}, frame)
	if err != nil || len(diagnostics) != 1 || diagnostics[0].Range.StartByte != 0 || diagnostics[0].Range.EndByte != 18 {
		t.Fatalf("observed range sort annotation: %+v %v", diagnostics, err)
	}
}
func TestFunctionSemanticErrorCodes(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	for _, test := range []struct {
		name      string
		arguments []value.Result
		code      string
	}{
		{"not_registered", nil, "function.unknown"},
		{"pi", []value.Result{functionTestScalar(1)}, "function.arity"},
		{"abs", []value.Result{{Type: "string", String: "invalid"}}, "function.argument-type"},
	} {
		_, _, err := EvalFunction(context.Background(), functionTestCall(test.name), test.arguments, frame)
		var languageError *syntax.LanguageError
		if !errors.As(err, &languageError) || languageError.Code != test.code {
			t.Fatalf("%s code: %+v", test.name, err)
		}
	}
	frame.Profile.ActiveFeatureSet.Enabled = nil
	_, _, err := EvalFunction(context.Background(), functionTestCall("mad_over_time"), []value.Result{{Type: "matrix"}}, frame)
	var languageError *syntax.LanguageError
	if !errors.As(err, &languageError) || languageError.Code != "function.feature-disabled" {
		t.Fatalf("gate code: %+v", err)
	}
	_, _, err = EvalAggregation(context.Background(), AggregationPlan{Name: "count_values", Parameter: functionTestScalar(1)}, value.Result{Type: "vector"}, frame)
	if !errors.As(err, &languageError) || languageError.Code != "aggregation.parameter-type" {
		t.Fatalf("aggregation parameter code: %+v", err)
	}
}
