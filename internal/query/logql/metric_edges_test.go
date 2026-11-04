// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"math"
	"os"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"testing"
)

func TestMetricGroupingAndBinaryModifiers(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "n=2"), metricRow(2, 2e9, "n=6")}}
	s.rows[0].Record.StreamLabels = append(s.rows[0].Record.StreamLabels, model.Label{Name: "host", Value: "a"})
	s.rows[1].Record.StreamLabels = append(s.rows[1].Record.StreamLabels, model.Label{Name: "host", Value: "b"})
	for _, q := range []string{`avg_over_time({app="api"}|logfmt|unwrap n[2s]) by(app)`, `avg_over_time({app="api"}|logfmt|unwrap n[2s]) without(host)`} {
		if got := metricValue(t, q, s); got != 4 {
			t.Fatalf("grouped average %g", got)
		}
	}
	q := `count_over_time({app="api"}[2s]) / on(app) group_left sum by(app)(count_over_time({app="api"}[2s]))`
	a := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), metricPlan(t, q, value.Evaluation{Instant: true, Time: 2e9}), s, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Vector) != 2 {
		t.Fatalf("group-left result=%+v", r.Vector)
	}
	for _, v := range r.Vector {
		if value.Label(v.Labels, "host") == "" || math.Float64frombits(uint64(v.Samples[0].Float)) != 0.5 {
			t.Fatalf("group-left sample=%+v", v)
		}
	}
}
func TestMetricQuantileCounterAndIEEE(t *testing.T) {
	for _, tc := range []struct {
		name    string
		points  []rangePoint
		q, want float64
	}{{"rate_counter", []rangePoint{{at: 1e9, v: 3, n: 1}}, 0, 0}, {"quantile_over_time", []rangePoint{{v: 1, n: 3}, {v: 4, n: 1}}, 0.5, 1}, {"quantile_over_time", []rangePoint{{v: 1, n: 1}}, -1, math.Inf(-1)}, {"quantile_over_time", []rangePoint{{v: 1, n: 1}}, 2, math.Inf(1)}, {"avg_over_time", []rangePoint{{v: math.Inf(1), n: 1}, {v: math.Inf(1), n: 1}}, 0, math.Inf(1)}, {"sum_over_time", []rangePoint{{v: math.Copysign(0, -1), n: 1}}, 0, 0}} {
		got, ok, err := rangeStatistic(tc.name, tc.points, tc.q, 0, 2e9, 2e9)
		if err != nil || !ok || got != tc.want {
			t.Fatalf("%s got=%g ok=%v error=%v", tc.name, got, ok, err)
		}
	}
}
func TestMetricGatedApproxAndVariants(t *testing.T) {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for _, gate := range []string{"approx_topk", "multi-variant-queries"} {
		var p profile.Profile
		for _, set := range base.FeatureSets {
			if len(set.Enabled) == 1 && set.Enabled[0] == gate {
				p, err = registry.Resolve(base.ID, set.ID)
				break
			}
		}
		if err != nil || p.ID == "" {
			t.Fatal("registered gate unavailable", err)
		}
		q := `approx_topk(1,vector(2))`
		want := 1
		if gate == "multi-variant-queries" {
			q = `variants(vector(2),vector(3)) of ({app="api"}[2s])`
			want = 2
		}
		expr, err := Parse(q, p)
		if err != nil {
			t.Fatal(err)
		}
		typed, _, err := Check(expr, p)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
		if err != nil {
			t.Fatal(err)
		}
		a := value.NewBoundedAccount(32 << 20)
		r, _, err := Evaluate(context.Background(), plan, &metricSource{}, a)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Vector) != want {
			t.Fatalf("gate=%s vector=%+v", gate, r.Vector)
		}
		if gate == "multi-variant-queries" && (value.Label(r.Vector[0].Labels, "__variant__") != "0" || value.Label(r.Vector[1].Labels, "__variant__") != "1") {
			t.Fatalf("variant identity lost: %+v", r.Vector)
		}
		a.Release(value.ResultBytes(r))
		if a.Used() != 0 {
			t.Fatalf("gate memory leaked: %d", a.Used())
		}
	}
}
func TestMetricBudgetAndCancellationRelease(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "n=2")}}
	p := metricPlan(t, `sum_over_time({app="api"}|logfmt|unwrap n[2s])`, value.Evaluation{Instant: true, Time: 2e9})
	for _, limit := range []int64{0, 100, 500} {
		a := value.NewBoundedAccount(limit)
		if _, _, err := Evaluate(context.Background(), p, s, a); err == nil {
			t.Fatal("budget became success")
		}
		if a.Used() != 0 {
			t.Fatalf("quota leaked=%d", a.Used())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := value.NewBoundedAccount(32 << 20)
	if _, _, err := Evaluate(ctx, p, s, a); err == nil {
		t.Fatal("cancellation became success")
	}
	if a.Used() != 0 {
		t.Fatalf("cancel leaked=%d", a.Used())
	}
}
func TestLogIntervalAcrossStreamsAndMultiplicity(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 0, "a"), metricRow(2, 5e8, "b"), metricRow(3, 1e9, "c"), metricRow(4, 2e9, "d")}}
	s.rows[0].Multiplicity = 5
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogsInterval(context.Background(), metricPlan(t, `{app="api"}`, value.Evaluation{Start: 0, End: 3e9}), s, Forward, 2, 1e9, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Logs) != 2 || r.Logs[0].Timestamp != 0 || r.Logs[1].Timestamp != 1e9 || r.Logs[0].Multiplicity != 1 {
		t.Fatalf("global interval/limit result=%+v", r.Logs)
	}
}
