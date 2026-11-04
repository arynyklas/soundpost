// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/value"
	"strings"
	"testing"
)

func functionTestFrame(id string) Frame {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		panic(err)
	}
	raw, err := os.ReadFile("../../../profiles/query/" + id + ".json")
	if err != nil {
		panic(err)
	}
	var manifest profile.Profile
	if err = json.Unmarshal(raw, &manifest); err != nil {
		panic(err)
	}
	wanted := 1
	if id == "promql-prometheus-3.13.5" {
		wanted = 2
	}
	var selected string
	for _, set := range manifest.FeatureSets {
		if len(set.Enabled) != wanted {
			continue
		}
		foundExperimental, foundDuration := false, false
		for _, gate := range set.Enabled {
			foundExperimental = foundExperimental || gate == "promql-experimental-functions"
			foundDuration = foundDuration || gate == "promql-duration-expr"
		}
		if foundExperimental && (wanted == 1 || foundDuration) {
			selected = set.ID
			break
		}
	}
	resolved, err := registry.Resolve(id, selected)
	if err != nil {
		panic(err)
	}
	return Frame{Profile: resolved, Project: model.ID{1}, Time: 20_000_000_000, Evaluation: value.Evaluation{Instant: true, Time: 20_000_000_000, Start: 0, End: 20_000_000_000, Step: 1_000_000_000}, Account: value.NewBoundedAccount(16 << 20)}
}
func functionTestScalar(x float64) value.Result {
	return value.Result{Type: "scalar", Scalar: value.Sample{Float: model.FloatBits(math.Float64bits(x))}}
}
func functionTestSeries(xs ...float64) value.Series {
	s := value.Series{Labels: model.Labels{{Name: "__name__", Value: "requests_total"}, {Name: "job", Value: "generic"}}}
	for i, x := range xs {
		s.Samples = append(s.Samples, value.Sample{Time: model.UnixNano((i + 1) * 5_000_000_000), Float: model.FloatBits(math.Float64bits(x))})
	}
	return s
}
func functionTestCall(name string) CallPlan {
	return CallPlan{Name: name, Expr: TypedExpr{Expr: &Node{Kind: "call", Text: name, Children: []Expr{&Node{Kind: "selector", RangeText: "20s"}}}, Children: []TypedExpr{{Expr: &Node{Kind: "matrix", RangeText: "20s"}, Type: Matrix}}}}
}
func TestCatalogEqualsProfileInventory(t *testing.T) {
	b, e := os.ReadFile("../../../conformance/query/audits/promql.json")
	if e != nil {
		t.Fatal(e)
	}
	var audit struct {
		Entries     []struct{ ID, Kind, Profile, Gate, Signature string } `json:"entries"`
		Obligations []struct{ ID, Kind, Profile, Gate, Signature string } `json:"obligations"`
	}
	if e = json.Unmarshal(b, &audit); e != nil {
		t.Fatal(e)
	}
	rows := audit.Entries
	if rows == nil {
		rows = audit.Obligations
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := functionTestFrame(id).Profile
		got := FunctionCatalog(p)
		want := map[string]string{}
		for _, r := range rows {
			if r.Profile == id && (r.Kind == "function-signature" || r.Kind == "aggregation") {
				want[r.ID] = r.Signature
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s catalog=%d inventory=%d", id, len(got), len(want))
		}
		previous := ""
		for _, s := range got {
			if s.ObligationID <= previous {
				t.Fatal("catalog not sorted")
			}
			previous = s.ObligationID
			if want[s.ObligationID] != s.Signature {
				t.Fatalf("unbound or wrong signature: %#v", s)
			}
			if s.Eval == nil {
				t.Fatal("nil evaluator")
			}
		}
		if _, _, e = EvalFunction(context.Background(), functionTestCall("not_registered"), nil, functionTestFrame(id)); e == nil {
			t.Fatal("unknown function accepted")
		}
	}
}
func TestMixedWindowKinds(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		f := functionTestFrame(id)
		s := functionTestSeries(4)
		s.Samples = append(s.Samples, value.Sample{Time: 10_000_000_000, Histogram: &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 9007199254740993, ResetHint: "unknown"}}})
		input := value.Result{Type: "matrix", Matrix: []value.Series{s}}
		for _, c := range []struct {
			name       string
			count      int
			number     float64
			diagnostic string
		}{{"count_over_time", 1, 2, ""}, {"sum_over_time", 0, 0, "MixedFloatsHistogramsWarning"}, {"min_over_time", 1, 4, ""}} {
			r, d, e := EvalFunction(context.Background(), functionTestCall(c.name), []value.Result{input}, f)
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Vector) != c.count {
				t.Fatalf("%s %s outputs=%d", id, c.name, len(r.Vector))
			}
			if c.count > 0 && math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)) != c.number {
				t.Fatalf("%s wrong value", c.name)
			}
			if c.diagnostic != "" && (len(d) == 0 || !strings.Contains(d[0].Category, c.diagnostic)) {
				t.Fatalf("%s missing warning: %#v", c.name, d)
			}
		}
		if s.Samples[1].Histogram.Integer.Count != 9007199254740993 {
			t.Fatal("integer rounded")
		}
	}
}
func TestEveryFunctionOverload(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		f := functionTestFrame(id)
		for name, sig := range signatures[id] {
			t.Run(id+"/"+name, func(t *testing.T) {
				args := make([]value.Result, len(sig.args))
				for i, typ := range sig.args {
					switch typ {
					case Scalar:
						args[i] = functionTestScalar(.5)
					case String:
						args[i] = value.Result{Type: "string", String: "label"}
					case Vector:
						s := functionTestSeries(2)
						args[i] = value.Result{Type: "vector", Vector: []value.Series{s}}
					case Matrix:
						args[i] = value.Result{Type: "matrix", Matrix: []value.Series{functionTestSeries(1, 2, 3)}}
					}
				}
				if name == "label_replace" {
					args[4].String = ".*"
				}
				if name == "double_exponential_smoothing" {
					args[1] = functionTestScalar(.3)
					args[2] = functionTestScalar(.4)
				}
				if _, _, e := EvalFunction(context.Background(), functionTestCall(name), args, f); e != nil {
					t.Fatalf("normal overload: %v", e)
				}
				bad := append([]value.Result(nil), args...)
				if len(bad) > 0 {
					bad[0] = value.Result{Type: "invalid"}
					if _, _, e := EvalFunction(context.Background(), functionTestCall(name), bad, f); e == nil {
						t.Fatal("invalid argument accepted")
					}
				}
				if sig.gate != "" {
					off := f
					off.Profile.ActiveFeatureSet.Enabled = nil
					if _, _, e := EvalFunction(context.Background(), functionTestCall(name), args, off); e == nil {
						t.Fatal("gate ignored")
					}
				}
			})
		}
	}
}
func TestFunctionMathLabelsAndTime(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	for _, name := range []string{"time", "start", "end", "step", "range", "pi"} {
		r, _, e := EvalFunction(context.Background(), functionTestCall(name), nil, f)
		if e != nil || r.Type != "scalar" {
			t.Fatalf("%s: %v", name, e)
		}
	}
	s := functionTestSeries(-0.0)
	s.Samples[0].Float = 0x8000000000000000
	r, _, e := EvalFunction(context.Background(), functionTestCall("sgn"), []value.Result{{Type: "vector", Vector: []value.Series{s}}}, f)
	if e != nil || r.Vector[0].Samples[0].Float != 0x8000000000000000 {
		t.Fatal("sgn signed zero")
	}
	if value.Label(r.Vector[0].Labels, "__name__") != "" && !r.Vector[0].DropName {
		t.Fatal("math retained metric name")
	}
}
func TestFunctionCounterResetExtrapolation(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	r, _, e := EvalFunction(context.Background(), functionTestCall("increase"), []value.Result{{Type: "matrix", Matrix: []value.Series{functionTestSeries(10, 3, 8)}}}, f)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("reset removed %v", e)
	}
	x := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float))
	if x != 16 {
		t.Fatalf("extrapolated increase=%v want16", x)
	}
}
func TestAggregationSemantics(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	for _, name := range []string{"sum", "avg", "count", "group", "min", "max", "stddev", "stdvar", "quantile", "topk", "bottomk", "limitk", "limit_ratio", "count_values"} {
		t.Run(name, func(t *testing.T) {
			a := AggregationPlan{Name: name, Parameter: functionTestScalar(1)}
			if name == "count_values" {
				a.Parameter = value.Result{Type: "string", String: "number"}
			}
			r, _, e := EvalAggregation(context.Background(), a, value.Result{Type: "vector", Vector: []value.Series{functionTestSeries(2), functionTestSeries(4)}}, f)
			if e != nil || r.Type != "vector" {
				t.Fatalf("%s: %v", name, e)
			}
			if name == "sum" && math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)) != 6 {
				t.Fatal("sum")
			}
		})
	}
}
func TestCatalogNamesDeterministic(t *testing.T) {
	f := functionTestFrame("promql-prometheus-3.13.5")
	a, _ := functionEvaluators(f.Profile)
	names := make([]string, 0, len(a))
	for n := range a {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) != len(signatures[f.Profile.ID]) {
		t.Fatal("constructor catalog differs")
	}
}
