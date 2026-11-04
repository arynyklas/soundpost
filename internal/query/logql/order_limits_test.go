// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"testing"
)

func TestLogZeroLimitRetainsPartialCuts(t *testing.T) {
	src := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "one")}, partial: true}
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogs(context.Background(), metricPlan(t, `{app="api"}`, value.Evaluation{Start: 0, End: 2e9}), src, Forward, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Logs) != 0 || !r.Partial || len(r.Watermarks) != 1 {
		t.Fatalf("zero limit fabricated complete empty: %+v", r)
	}
	a.Release(value.ResultBytes(r))
	if a.Used() != 0 {
		t.Fatalf("zero limit leaked=%d", a.Used())
	}
}
func TestLogOriginalCategoriesSurviveFormatting(t *testing.T) {
	row := metricRow(1, 1e9, "safe original")
	src := &metricSource{rows: []scan.LogRow{row}}
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogs(context.Background(), metricPlan(t, `{app="api"}|label_format app="changed"|line_format "rendered"`, value.Evaluation{Start: 0, End: 2e9}), src, Forward, 1, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Logs) != 1 || r.Logs[0].Line != "rendered" || value.Label(r.Logs[0].Labels, "app") != "changed" || value.Label(r.Logs[0].StreamLabels, "app") != "api" || r.Logs[0].ID != row.ID || r.Logs[0].Source != row.Source {
		t.Fatalf("query view overwrote original identity: %+v", r.Logs)
	}
}
