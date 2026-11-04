// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"os"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
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
