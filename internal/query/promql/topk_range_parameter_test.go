// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The 3.13.5 topk-family parameter is evaluated at every step, but the engine
// validates all of the steps together: it answers empty only when every
// parameter is below one, and otherwise rejects NaN, <= minInt64 or >= the
// largest binary64 below 2^63 at ANY step before truncating a single step
// (conformance/query/audits/promql.json, obligation 354). A step whose own
// parameter is below one must therefore not hide an overflowing sibling step.
func TestTopkFamilyRangeParameterIsValidatedAcrossAllSteps(t *testing.T) {
	var m []value.Series
	for _, c := range []struct {
		name string
		v    float64
	}{{"a", 4}, {"b", 3}, {"c", 2}} {
		m = append(m, metricSeries("tk_m", model.Labels{{Name: "case", Value: c.name}}, msSample(5_000, c.v)))
	}
	minInt64 := -math.Ldexp(1, 63)
	for _, c := range []struct {
		name        string
		parameters  [2]float64
		fails343    bool // 3.13.5 verdict; 3.1.0 only ever sees the first step's value
		fails310    bool
		wantSeries  int // series returned when nothing fails on 3.13.5
		wantSeries1 int // series returned when nothing fails on 3.1.0
	}{
		{"low-overflow-then-valid", [2]float64{-1e30, 2}, true, true, 0, 0},
		{"minint64-then-valid", [2]float64{minInt64, 2}, true, false, 0, 0},
		{"neg-inf-then-valid", [2]float64{math.Inf(-1), 2}, true, true, 0, 0},
		{"valid-then-low-overflow", [2]float64{2, -1e30}, true, false, 0, 2},
		{"all-below-one-never-errors", [2]float64{-1e30, -5}, false, true, 0, 0},
		{"below-one-then-valid", [2]float64{-1, 2}, false, false, 2, 0},
		{"zero-then-valid", [2]float64{0, 2}, false, false, 2, 0},
	} {
		query := "topk(scalar(tk_k), tk_m)"
		for _, id := range []string{"promql-prometheus-3.13.5", "promql-prometheus-3.1.0"} {
			k := metricSeries("tk_k", nil, msSample(10_000, c.parameters[0]), msSample(20_000, c.parameters[1]))
			p := featureProfile(t, id)
			r, _, err := evalWith(t, p, query, rangeOf(10_000, 20_000, 10_000), append(append([]value.Series(nil), m...), k)...)
			failsWant, seriesWant := c.fails343, c.wantSeries
			if id == "promql-prometheus-3.1.0" {
				failsWant, seriesWant = c.fails310, c.wantSeries1
			}
			if failsWant {
				if err == nil || !strings.Contains(err.Error(), "outside int64 range") {
					t.Errorf("%s %s: want the parameter-range error, got %v %v", id, c.name, err, r)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s %s: unexpected error %v", id, c.name, err)
				continue
			}
			if len(r.Matrix) != seriesWant {
				t.Errorf("%s %s: %d series, want %d", id, c.name, len(r.Matrix), seriesWant)
			}
		}
	}
}
