// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"os"
	"testing"
)

func TestMetricVariantsShareOneReadCut(t *testing.T) {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	var p profile.Profile
	for _, set := range base.FeatureSets {
		if len(set.Enabled) == 1 && set.Enabled[0] == "multi-variant-queries" {
			p, err = registry.Resolve(base.ID, set.ID)
			break
		}
	}
	if err != nil || p.ID == "" {
		t.Fatal("missing registered variants profile", err)
	}
	q := `variants(count_over_time({app="api"}[2s]),bytes_over_time({app="api"}[2s])) of ({app="api"}[2s])`
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
	src := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "one"), metricRow(2, 2e9, "two")}, partial: true}
	a := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), plan, src, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.selections) != 1 || len(r.Vector) != 2 || !r.Partial || len(r.Watermarks) != 1 {
		t.Fatalf("shared source/variant identity/metadata changed: reads=%d result=%+v", len(src.selections), r)
	}
	a.Release(value.ResultBytes(r))
	if a.Used() != 0 {
		t.Fatalf("variant source leaked=%d", a.Used())
	}
}
func TestMetricSketchPublicHashAndLabels(t *testing.T) {
	for _, tc := range []struct {
		text string
		hash uint64
	}{{"", 0xef46db3751d8e999}, {"a", 0xd24ec4f1a98c6e5b}, {"hello", 0x26c7827d889f6da3}} {
		if got := metricXXH64([]byte(tc.text)); got != tc.hash {
			t.Fatalf("XXH64(%q)=%016x want %016x", tc.text, got, tc.hash)
		}
	}
	got := metricLabelBytes(model.Labels{{Name: "a", Value: "b"}, {Name: "c", Value: "d"}})
	if string(got) != string([]byte{254, 'a', 255, 'b', 255, 'c', 255, 'd'}) {
		t.Fatalf("pinned label byte identity=%x", got)
	}
	positions := metricSketchPositions(got)
	for row, index := range positions {
		if index < uint32(row*metricSketchWidth) || index >= uint32((row+1)*metricSketchWidth) {
			t.Fatalf("row %d position %d", row, index)
		}
	}
}
func TestMetricSortPolicyFailure(t *testing.T) {
	input := []int{5, 4, 3, 2, 1}
	failure := model.Fail(model.Forbidden)
	err := metricSort(input, func(i, j int) bool { return input[i] < input[j] }, func() error { return failure })
	if err != failure {
		t.Fatalf("sort swallowed policy error: %v", err)
	}
}

func variantsProfile(t *testing.T) profile.Profile {
	t.Helper()
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for _, set := range base.FeatureSets {
		if len(set.Enabled) == 1 && set.Enabled[0] == "multi-variant-queries" {
			p, err := registry.Resolve(base.ID, set.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatal("missing registered variants profile")
	return profile.Profile{}
}

func variantHostRow(id byte, at int64, multiplicity model.Uint64, host, line string) scan.LogRow {
	r := metricRow(id, at, line)
	r.Multiplicity = multiplicity
	r.Record.StreamLabels = model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: host}}
	return r
}

// Each variant reads ITS OWN range and offset, not the range of `of (...)`.
// Every row restates a recorded native observation (vr-*, vq-*) over the data
// set of those rows: a@0 x1, b@0.5s x2, a@1s, b@3s, a@5s x3, b@8s.
func TestVariantsEvaluateEachVariantOverItsOwnRange(t *testing.T) {
	p := variantsProfile(t)
	rows := func() []scan.LogRow {
		return []scan.LogRow{
			variantHostRow(1, 0, 1, "a", "n=1"), variantHostRow(2, 5e8, 2, "b", "n=22"), variantHostRow(3, 1e9, 1, "a", "n=3"),
			variantHostRow(4, 3e9, 1, "b", "n=4"), variantHostRow(5, 5e9, 3, "a", "n=555"), variantHostRow(6, 8e9, 1, "b", "n=6"),
		}
	}
	for _, c := range []struct {
		id    string
		query string
		at    int64
		want  map[string]float64 // variant/host -> value
	}{
		{"vr-0000", `variants(count_over_time({app="api"}[1s])) of ({app="api"}[1s])`, 6e9, map[string]float64{}},
		{"vr-0001", `variants(count_over_time({app="api"}[1s] offset 1s)) of ({app="api"}[1s])`, 6e9, map[string]float64{"0/a": 3}},
		{"vr-0006", `variants(count_over_time({app="api"}[2s])) of ({app="api"}[1s])`, 6e9, map[string]float64{"0/a": 3}},
		{"vr-0013", `variants(count_over_time({app="api"}[3s] offset 1s)) of ({app="api"}[1s])`, 6e9, map[string]float64{"0/a": 3}},
		{"vr-0017", `variants(count_over_time({app="api"}[3s] offset 1s)) of ({app="api"}[5s])`, 6e9, map[string]float64{"0/a": 3, "0/b": 1}},
		{"vr-0125", `variants(count_over_time({app="api"}[5s]), bytes_over_time({app="api"}[2s])) of ({app="api"}[2s])`, 8e9, map[string]float64{"0/b": 1, "1/b": 3}},
		{"vr-0127", `variants(count_over_time({app="api"}[5s]), bytes_over_time({app="api"}[5s])) of ({app="api"}[5s])`, 8e9, map[string]float64{"0/a": 3, "0/b": 1, "1/a": 15, "1/b": 3}},
		{"vq-8", `variants(count_over_time({app="api"}[5s])) of ({app="api"}[2s])`, 2e9, map[string]float64{"0/a": 2, "0/b": 2}},
		{"vq-9", `variants(count_over_time({app="api"}[1s])) of ({app="api"}[2s])`, 2e9, map[string]float64{}},
	} {
		plan, err := BuildPlan(mustTyped(t, p, c.query), value.Evaluation{Instant: true, Time: model.UnixNano(c.at)}, p)
		if err != nil {
			t.Fatal(err)
		}
		src := &metricSource{rows: rows()}
		a := value.NewBoundedAccount(32 << 20)
		r, _, err := Evaluate(context.Background(), plan, src, a)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		got := map[string]float64{}
		for _, s := range r.Vector {
			got[value.Label(s.Labels, "__variant__")+"/"+value.Label(s.Labels, "host")] = math.Float64frombits(uint64(s.Samples[0].Float))
		}
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %v want %v", c.id, got, c.want)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: got %v want %v", c.id, got, c.want)
			}
		}
		if len(src.selections) != 1 {
			t.Fatalf("%s: %d reads, want one shared read cut", c.id, len(src.selections))
		}
		a.Release(value.ResultBytes(r))
		if a.Used() != 0 {
			t.Fatalf("%s leaked %d", c.id, a.Used())
		}
	}
}

func mustTyped(t *testing.T, p profile.Profile, q string) TypedExpr {
	t.Helper()
	expr, err := Parse(q, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(expr, p)
	if err != nil {
		t.Fatal(err)
	}
	return typed
}
