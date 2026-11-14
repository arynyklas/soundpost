// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

func TestMetricBottomKFinalInstantLabelOrder(t *testing.T) {
	rows := []scan.LogRow{metricRow(1, 500000000, "one"), metricRow(2, 1000000000, "two"), metricRow(3, 1500000000, "three")}
	for i := range rows {
		host := "a"
		if i == 2 {
			host = "b"
		}
		rows[i].Record.StreamLabels = append(rows[i].Record.StreamLabels, model.Label{Name: "host", Value: host})
	}
	tests := []struct {
		query  string
		hosts  []string
		values []float64
	}{
		// Engine483-489 label-sorts final instant vectors unless Sortable says
		// there is sort/sort_desc anywhere in a sample expression. Bottom-k
		// itself does not opt out. This is distinct from choosing smallest k.
		{`bottomk(2,count_over_time({app="api"}[2s]))`, []string{"a", "b"}, []float64{2, 1}},
		{`bottomk(1,count_over_time({app="api"}[2s]))`, []string{"b"}, []float64{1}},
		{`sort(bottomk(2,count_over_time({app="api"}[2s])))`, []string{"b", "a"}, []float64{1, 2}},
		{`sort_desc(bottomk(2,count_over_time({app="api"}[2s])))`, []string{"a", "b"}, []float64{2, 1}},
		// Native Sortable traverses descendants; it does not inspect only root.
		{`bottomk(2,sort_desc(count_over_time({app="api"}[2s])))`, []string{"b", "a"}, []float64{1, 2}},
	}
	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			a := value.NewBoundedAccount(32 << 20)
			r, _, err := Evaluate(context.Background(), metricPlan(t, tc.query, value.Evaluation{Instant: true, Time: 2e9}), &metricSource{rows: rows}, a)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Release(value.ResultBytes(r))
			if len(r.Vector) != len(tc.hosts) {
				t.Fatalf("result length=%d want=%d", len(r.Vector), len(tc.hosts))
			}
			for i, series := range r.Vector {
				got := math.Float64frombits(uint64(series.Samples[0].Float))
				if value.Label(series.Labels, "host") != tc.hosts[i] || got != tc.values[i] {
					t.Fatalf("sample%d labels=%+v value=%g want host%s value%g", i, series.Labels, got, tc.hosts[i], tc.values[i])
				}
			}
		})
	}
}
