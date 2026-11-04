// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"strings"
	"testing"
)

func TestEveryFunctionEmptyBoundary(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		f := functionTestFrame(id)
		for name, sig := range signatures[id] {
			t.Run(id+"/"+name, func(t *testing.T) {
				args := make([]value.Result, len(sig.args))
				for i, typ := range sig.args {
					args[i].Type = string(typ)
					switch typ {
					case Scalar:
						args[i] = functionTestScalar(.5)
					case String:
						args[i].String = "label"
					}
				}
				if name == "label_replace" {
					args[4].String = ".*"
				}
				r, _, e := EvalFunction(context.Background(), functionTestCall(name), args, f)
				if e != nil {
					t.Fatal(e)
				}
				if r.Type != string(sig.result) {
					t.Fatalf("result type %q", r.Type)
				}
				bad := append([]value.Result(nil), args...)
				bad = append(bad, value.Result{Type: "invalid"})
				if _, _, e = EvalFunction(context.Background(), functionTestCall(name), bad, f); e == nil {
					t.Fatal("bad count/type accepted")
				}
			})
		}
	}
}
func TestEveryMathNonfiniteBoundary(t *testing.T) {
	frame := functionTestFrame("promql-prometheus-3.13.5")
	expected := map[string]func(float64) float64{"abs": math.Abs, "acos": math.Acos, "acosh": math.Acosh, "asin": math.Asin, "asinh": math.Asinh, "atan": math.Atan, "atanh": math.Atanh, "ceil": math.Ceil, "cos": math.Cos, "cosh": math.Cosh, "deg": func(x float64) float64 { return x * 180 / math.Pi }, "exp": math.Exp, "floor": math.Floor, "ln": math.Log, "log10": math.Log10, "log2": math.Log2, "rad": func(x float64) float64 { return x * math.Pi / 180 }, "sgn": func(x float64) float64 {
		if x < 0 {
			return -1
		}
		if x > 0 {
			return 1
		}
		return x
	}, "sin": math.Sin, "sinh": math.Sinh, "sqrt": math.Sqrt, "tan": math.Tan, "tanh": math.Tanh}
	for name, reference := range expected {
		for _, input := range []float64{math.Copysign(0, -1), math.Inf(1), math.Inf(-1), math.NaN(), -1, 1} {
			series := functionTestSeries(input)
			result, _, err := EvalFunction(context.Background(), functionTestCall(name), []value.Result{{Type: "vector", Vector: []value.Series{series}}}, frame)
			if err != nil || len(result.Vector) != 1 {
				t.Fatalf("%s %v", name, err)
			}
			got, want := functionFloat(result.Vector[0].Samples[0]), reference(input)
			if math.IsNaN(want) {
				if !math.IsNaN(got) {
					t.Fatalf("%s NaN became %v", name, got)
				}
			} else if math.Float64bits(got) != math.Float64bits(want) {
				t.Fatalf("%s bits changed", name)
			}
		}
	}
}
func TestFunctionMetadataSurvivesRemoval(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	s := functionTestSeries(1)
	s.Samples = append(s.Samples, value.Sample{Histogram: nativeTestHistogram(1)})
	group := model.ID{1}
	input := value.Result{Type: "matrix", Matrix: []value.Series{s}, Partial: true, Watermarks: []model.Cursor{{Group: group, Index: 17}}}
	r, d, e := EvalFunction(context.Background(), functionTestCall("sum_over_time"), []value.Result{input}, f)
	if e != nil || len(r.Vector) != 0 || len(d) == 0 || !r.Partial || len(r.Watermarks) != 1 || r.Watermarks[0].Index != 17 {
		t.Fatalf("removed partial metadata: %#v %v", r, e)
	}
	r, _, e = EvalAggregation(context.Background(), AggregationPlan{Name: "sum"}, r, f)
	if e != nil || !r.Partial || len(r.Watermarks) != 1 {
		t.Fatal("aggregation lost metadata")
	}
}
func TestFunctionAccountAndCancellation(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	account := value.NewBoundedAccount(1)
	f.Account = account
	if _, _, e := EvalFunction(context.Background(), functionTestCall("vector"), []value.Result{functionTestScalar(1)}, f); e == nil {
		t.Fatal("scratch escaped quota")
	}
	if account.Used() != 0 {
		t.Fatal("failed reservation leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.Account = value.NewBoundedAccount(1 << 20)
	if _, _, e := EvalFunction(ctx, functionTestCall("time"), nil, f); e == nil {
		t.Fatal("cancelled evaluation succeeded")
	}
	if f.Account.(*value.BoundedAccount).Used() != 0 {
		t.Fatal("cancel leaked")
	}
}
func TestFunctionLabelsPreserveHistogram(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	s := functionTestSeries()
	s.Samples = []value.Sample{{Histogram: nativeTestHistogram(9007199254740993)}}
	s.Labels = value.SetLabel(s.Labels, "source", "one\ntwo")
	args := []value.Result{{Type: "vector", Vector: []value.Series{s}}, {Type: "string", String: "destination"}, {Type: "string", String: "$1"}, {Type: "string", String: "source"}, {Type: "string", String: "(.*)"}}
	r, _, e := EvalFunction(context.Background(), functionTestCall("label_replace"), args, f)
	if e != nil || value.Label(r.Vector[0].Labels, "destination") != "one\ntwo" || r.Vector[0].Samples[0].Histogram.Integer.Count != 9007199254740993 {
		t.Fatal("newline replacement or histogram changed")
	}
}
func TestHistogramTrimPopulationAndNaN(t *testing.T) {
	h := nativeTestHistogram(4)
	r, keep, d, e := histogramBinary("</", value.Sample{Histogram: h}, functionSample(math.Sqrt2, 0))
	if e != nil || !keep || len(d) != 0 || r.Histogram.Float == nil {
		t.Fatal("trim removed")
	}
	if count := math.Float64frombits(uint64(r.Histogram.Float.Count)); math.Abs(count-2) > 1e-14 {
		t.Fatalf("crossing count %v", count)
	}
	r, keep, _, e = histogramBinary("</", value.Sample{Histogram: h}, functionSample(math.NaN(), 0))
	if e != nil || !keep || math.Float64frombits(uint64(r.Histogram.Float.Count)) != 0 {
		t.Fatal("NaN ordinary buckets not discarded")
	}
	if h.Integer.Count != 4 {
		t.Fatal("trim mutated input")
	}
}
func TestHistogramCustomReconciliationAndFlavor(t *testing.T) {
	makeH := func(bounds []float64, counts []model.AbsoluteBucket) *model.NativeHistogram {
		h := &model.IntegerHistogram{Flavor: "counter", Schema: -53, Count: 4, PositiveSpans: []model.HistogramSpan{{Length: uint32(len(counts))}}, PositiveCounts: counts, ResetHint: "unknown"}
		for _, b := range bounds {
			h.CustomBounds = append(h.CustomBounds, model.FloatBits(math.Float64bits(b)))
		}
		return &model.NativeHistogram{Integer: h}
	}
	a, b := makeH([]float64{1, 2}, []model.AbsoluteBucket{1, 1, 2}), makeH([]float64{2}, []model.AbsoluteBucket{2, 2})
	r, keep, d, e := histogramBinary("+", value.Sample{Histogram: a}, value.Sample{Histogram: b})
	if e != nil || !keep || len(d) != 1 || d[0].Category != "MismatchedCustomBucketsHistogramsInfo" || len(r.Histogram.Float.CustomBounds) != 1 {
		t.Fatal("custom common boundaries")
	}
	if value.HistogramReset(*a, *b) {
		t.Fatal("compatible custom rollup is reset")
	}
	clone := value.CloneHistogram(*a)
	clone.Integer.Flavor = "gauge"
	clone.Integer.ResetHint = "gauge"
	if !histogramEquivalent(*a, clone) {
		t.Fatal("flavor-only change")
	}
}
func TestFunctionDiagnosticIdentityAndRange(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	call := functionTestCall("quantile_over_time")
	n := call.Expr.Expr.(*Node)
	n.Children = []Expr{&Node{Kind: "number"}, &Node{Kind: "range"}}
	r, d, e := EvalFunction(context.Background(), call, []value.Result{functionTestScalar(2), {Type: "matrix", Matrix: []value.Series{functionTestSeries(1, 2)}}}, f)
	if e != nil || len(r.Vector) != 1 || len(d) != 1 || d[0].Category != "InvalidQuantileWarning" || !strings.Contains(d[0].SafeMessage, "between 0 and 1") {
		t.Fatal("invalid quantile annotation")
	}
}
