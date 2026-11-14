// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"os"
	"testing"
)

func TestEveryPromQLOperator(t *testing.T) {
	for _, tc := range []struct {
		q    string
		want float64
	}{{"5+2", 7}, {"5-2", 3}, {"5*2", 10}, {"5/2", 2.5}, {"5%2", 1}, {"5^2", 25}, {"5 atan2 2", math.Atan2(5, 2)}, {"5 == bool 2", 0}, {"5 != bool 2", 1}, {"5 > bool 2", 1}, {"5 < bool 2", 0}, {"5 >= bool 5", 1}, {"5 <= bool 5", 1}, {"-5", -5}, {"+5", 5}} {
		t.Run(tc.q, func(t *testing.T) {
			r, e := executeExpr(t, tc.q, value.Evaluation{Instant: true}, nil)
			if e != nil || math.Float64frombits(uint64(r.Scalar.Float)) != tc.want {
				t.Fatalf("%+v %v", r, e)
			}
		})
	}
	s := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 4)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 2)}}}
	for _, q := range []string{"a+b", "a-b", "a*b", "a/b", "a%b", "a^b", "a atan2 b", "a == bool b", "a != b", "a > b", "a >= b", "a < bool b", "a <= bool b", "a+2", "2+a", "a and b", "a or b", "a unless b"} {
		t.Run(q, func(t *testing.T) {
			r, e := executeExpr(t, q, value.Evaluation{Instant: true}, s)
			if e != nil {
				t.Fatal(e)
			}
			want := 1
			if q == "a unless b" {
				want = 0
			}
			if len(r.Vector) != want {
				t.Fatalf("%s: %+v", q, r)
			}
		})
	}
	for _, q := range []string{"a+b", "a+2", "2+a", "a > bool b", "-a"} {
		r, e := executeExpr(t, q, value.Evaluation{Instant: true}, s)
		if e != nil {
			t.Fatal(e)
		}
		if value.Label(r.Vector[0].Labels, "__name__") != "" {
			t.Fatalf("metric name retained %s", q)
		}
	}
	many := append(seriesSource(nil), s...)
	many = append(many, value.Series{Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "instance", Value: "2"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 3)}})
	if _, e := executeExpr(t, "a + on(job) b", value.Evaluation{Instant: true}, many); e == nil {
		t.Fatal("many-to-one arithmetic without explicit grouping accepted")
	}
	r, e := executeExpr(t, "a + on(job) group_right b", value.Evaluation{Instant: true}, many)
	if e != nil || len(r.Vector) != 2 {
		t.Fatalf("group_right %+v %v", r, e)
	}
	duplicate := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}}, Samples: []value.Sample{sample(0, 1)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}}, Samples: []value.Sample{sample(0, 2)}}}
	if _, e := executeExpr(t, "{__name__=~\"a|b\"}+1", value.Evaluation{Instant: true}, duplicate); e == nil {
		t.Fatal("duplicate output labels accepted")
	}
}
func TestGroupingInfrastructure(t *testing.T) {
	ls := model.Labels{{Name: "__name__", Value: "m"}, {Name: "a", Value: "1"}, {Name: "b", Value: "2"}}
	if g := GroupingLabels(ls, []string{"a"}, false); len(g) != 1 || g[0].Name != "a" {
		t.Fatalf("by labels %v", g)
	}
	if g := GroupingLabels(ls, []string{"a"}, true); len(g) != 1 || g[0].Name != "b" {
		t.Fatalf("without labels %v", g)
	}
}
func TestVectorOperatorValuesAndNameRules(t *testing.T) {
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 4)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 2)}}}
	for _, tc := range []struct {
		q    string
		want float64
		name string
	}{
		{"a+b", 6, ""}, {"a-b", 2, ""}, {"a*b", 8, ""}, {"a/b", 2, ""}, {"a%b", 0, ""}, {"a^b", 16, ""},
		{"a > b", 4, "a"}, {"a > ignoring(instance) b", 4, "a"}, {"a > bool b", 1, ""},
		{"2 < a", 4, "a"}, {"2 > bool a", 0, ""}, {"+a", 4, "a"}, {"-a", -4, ""},
		{"a and b", 4, "a"}, {"a or b", 4, "a"},
	} {
		t.Run(tc.q, func(t *testing.T) {
			r, e := executeExpr(t, tc.q, value.Evaluation{Instant: true}, src)
			if e != nil || len(r.Vector) != 1 {
				t.Fatalf("vector %+v %v", r, e)
			}
			if got := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)); got != tc.want {
				t.Fatalf("value %v want %v", got, tc.want)
			}
			if name := value.Label(r.Vector[0].Labels, "__name__"); name != tc.name {
				t.Fatalf("name %q want %q", name, tc.name)
			}
		})
	}
}
func TestMetricProjectIdentityDoesNotJoin(t *testing.T) {
	src := seriesSource{{Project: model.ID{1}, Labels: model.Labels{{Name: "__name__", Value: "a"}}, Samples: []value.Sample{sample(0, 4)}}, {Project: model.ID{2}, Labels: model.Labels{{Name: "__name__", Value: "b"}}, Samples: []value.Sample{sample(0, 2)}}}
	state := &evaluationState{plan: Plan{Profile: executionProfile(t)}}
	n := &Node{Kind: "binary", Text: "+"}
	a, b := value.Result{Type: "vector", Vector: []value.Series{src[0]}}, value.Result{Type: "vector", Vector: []value.Series{src[1]}}
	r, _, e := state.binary(n, a, b, 0)
	if e != nil || len(r.Vector) != 0 {
		t.Fatalf("cross-project join %+v %v", r, e)
	}
	n.Text = "or"
	r, _, e = state.binary(n, a, b, 0)
	if e != nil || len(r.Vector) != 2 {
		t.Fatalf("project-local union %+v %v", r, e)
	}
	for _, series := range r.Vector {
		if value.Label(series.Labels, "project") != "" {
			t.Fatal("hidden project label injected")
		}
	}
}
func TestVectorMissingEmptyLabelsAndGroupingUniqueness(t *testing.T) {
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}}, Samples: []value.Sample{sample(0, 4)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "x", Value: ""}}, Samples: []value.Sample{sample(0, 2)}}}
	r, e := executeExpr(t, "a and on(x) b", value.Evaluation{Instant: true}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("missing/empty matching %+v %v", r, e)
	}
	many := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}, {Name: "instance", Value: "1"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 4)}}, {Labels: model.Labels{{Name: "__name__", Value: "a"}, {Name: "instance", Value: "2"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 5)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "instance", Value: "3"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 2)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "instance", Value: "4"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 3)}}}
	for _, q := range []string{"a+on(job)b", "a+on(job)group_left b", "a+on(job)group_right b"} {
		if _, e := executeExpr(t, q, value.Evaluation{Instant: true}, many); e == nil {
			t.Fatalf("many-to-many join accepted: %s", q)
		}
	}
	r, e = executeExpr(t, "a and on(job) b", value.Evaluation{Instant: true}, many)
	if e != nil || len(r.Vector) != 2 {
		t.Fatalf("set many-to-many %+v %v", r, e)
	}
}
func TestAggregationExecutionPartitionsProjectAndGroup(t *testing.T) {
	src := seriesSource{{Project: model.ID{1}, Labels: model.Labels{{Name: "__name__", Value: "m"}, {Name: "instance", Value: "1"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 2)}}, {Project: model.ID{1}, Labels: model.Labels{{Name: "__name__", Value: "m"}, {Name: "instance", Value: "2"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 3)}}, {Project: model.ID{2}, Labels: model.Labels{{Name: "__name__", Value: "m"}, {Name: "instance", Value: "1"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 7)}}}
	p := executionProfile(t)
	expr, e := Parse("sum by(job)(m)", p)
	if e != nil {
		t.Fatal(e)
	}
	typed, _, e := Check(expr, p)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
	if e != nil {
		t.Fatal(e)
	}
	account := value.NewBoundedAccount(1 << 20)
	state := &evaluationState{ctx: context.Background(), plan: plan, account: account, src: seriesSource{}}
	r, e := state.aggregate(typed, []value.Result{{Type: "vector", Vector: src}}, Frame{Profile: p, Evaluation: plan.Evaluation, Project: model.ID{1}, Account: account}, plan.Aggregations["sum"])
	if e != nil || len(r.Vector) != 2 {
		t.Fatalf("grouped aggregation %+v %v", r, e)
	}
	for _, series := range r.Vector {
		want := float64(5)
		if series.Project == (model.ID{2}) {
			want = 7
		}
		if len(series.Labels) != 1 || value.Label(series.Labels, "job") != "x" || math.Float64frombits(uint64(series.Samples[0].Float)) != want {
			t.Fatalf("project grouping %+v", series)
		}
	}
}
func TestProfileMetadataSchemaRemovalAndDelayedCleanup(t *testing.T) {
	registry, e := profile.Load(os.DirFS("../../../profiles/query"))
	if e != nil {
		t.Fatal(e)
	}
	oldDelayed, e := registry.Resolve("promql-prometheus-3.1.0", "promql-prometheus-3.1.0/semantic-sha256-eed774ed7a008d3c41ad55fb64303cbf5ee52ba038aa248470ffebebb73e0ac6")
	if e != nil {
		t.Fatal(e)
	}
	newDelayed, e := registry.Resolve("promql-prometheus-3.13.5", "promql-prometheus-3.13.5/semantic-sha256-8ad079e960c8ad104842c3b8265e66603480e2103a5e6e8b3546eb997ef226b1")
	if e != nil {
		t.Fatal(e)
	}
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}, {Name: "__type__", Value: "gauge"}, {Name: "__unit__", Value: "seconds"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 4)}}}
	for _, p := range []profile.Profile{executionProfile(t), oldDelayed, trimProfile(t), newDelayed} {
		for _, q := range []string{"-m", "m+1", "m > bool 1", "abs(m)"} {
			expr, e := Parse(q, p)
			if e != nil {
				t.Fatal(e)
			}
			typed, _, e := Check(expr, p)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := Evaluate(context.Background(), plan, src, value.NewBoundedAccount(1<<20))
			if e != nil || len(r.Vector) != 1 {
				t.Fatalf("%s/%s %+v %v", p.ID, q, r, e)
			}
			labels := r.Vector[0].Labels
			if value.Label(labels, "__name__") != "" {
				t.Fatal("transformed metric name retained")
			}
			if p.ID == "promql-prometheus-3.13.5" {
				if len(labels) != 1 || value.Label(labels, "job") != "x" {
					t.Fatalf("modern schema labels retained %+v", labels)
				}
			} else {
				if len(labels) != 3 || value.Label(labels, "__type__") != "gauge" || value.Label(labels, "__unit__") != "seconds" {
					t.Fatalf("old profile schema metadata removed %+v", labels)
				}
			}
		}
	}
}
func TestVectorGroupIncludeAfterSchemaTransform(t *testing.T) {
	registry, e := profile.Load(os.DirFS("../../../profiles/query"))
	if e != nil {
		t.Fatal(e)
	}
	delayed, e := registry.Resolve("promql-prometheus-3.13.5", "promql-prometheus-3.13.5/semantic-sha256-8ad079e960c8ad104842c3b8265e66603480e2103a5e6e8b3546eb997ef226b1")
	if e != nil {
		t.Fatal(e)
	}
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "a"}, {Name: "__type__", Value: "gauge"}, {Name: "__unit__", Value: "seconds"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 4)}}, {Labels: model.Labels{{Name: "__name__", Value: "b"}, {Name: "__type__", Value: "counter"}, {Name: "__unit__", Value: "bytes"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 2)}}}
	for _, p := range []profile.Profile{trimProfile(t), delayed} {
		for _, q := range []string{"a + on(job) group_left(__unit__) b", "a + on(job) group_left(__name__) b", "a > bool on(job) group_left(__unit__) b"} {
			expr, e := Parse(q, p)
			if e != nil {
				t.Fatal(e)
			}
			typed, _, e := Check(expr, p)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := Evaluate(context.Background(), plan, src, value.NewBoundedAccount(1<<20))
			if e != nil || len(r.Vector) != 1 {
				t.Fatalf("%s %+v %v", q, r, e)
			}
			ls := r.Vector[0].Labels
			switch q {
			case "a + on(job) group_left(__unit__) b":
				if value.Label(ls, "__unit__") != "bytes" || value.Label(ls, "__name__") != "" {
					t.Fatalf("explicit unit include lost %+v", ls)
				}
			case "a + on(job) group_left(__name__) b":
				if value.Label(ls, "__name__") != "b" {
					t.Fatalf("explicit name include lost %+v", ls)
				}
			default:
				want := "bytes"
				if enabled(p, "promql-delayed-name-removal") {
					want = ""
				}
				if value.Label(ls, "__unit__") != want {
					t.Fatalf("bool delayed cleanup %+v", ls)
				}
			}
			if value.Label(ls, "__type__") != "" {
				t.Fatal("transformed type metadata retained")
			}
		}
	}
}
