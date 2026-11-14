// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// validateRangeAggregationParameters applies the 3.13.5 whole-range rule for
// topk, bottomk and limitk. The parameter is evaluated at every step, but the
// reference answers empty early only when every step's parameter is below one;
// otherwise a NaN, a value <= minInt64 or one >= the largest binary64 below
// 2^63 at ANY step fails the whole query before any step is truncated. EvalAggregation
// sees one step only, and a step whose own parameter is below one returns empty
// without range checking, so the cross-step rule runs here, once, before the grid.
// 3.1.0 evaluates the parameter once and validates it at its single use.
// Aggregations inside a subquery run on that subquery's own grid, evaluated
// separately, and are not reachable from the outer grid.
func (s *evaluationState) validateRangeAggregationParameters(grid []model.UnixNano) error {
	if s.plan.Profile.ID != "promql-prometheus-3.13.5" || len(grid) < 2 {
		return nil
	}
	var aggregations []TypedExpr
	collectTruncatingAggregations(s.plan.Expr, enabled(s.plan.Profile, "promql-experimental-functions"), &aggregations)
	upper := math.Nextafter(value.Exp2(63), 0)
	lower := -value.Exp2(63)
	for _, aggregation := range aggregations {
		parameter := aggregation.Children[0]
		anyAtLeastOne, anyInvalid := false, false
		for _, at := range grid {
			mark, markUnits, loaded, annotations := s.reserved, s.units, s.loaded, len(s.annotations)
			r, err := s.eval(parameter, at)
			s.account.Release(s.reserved - mark)
			s.reserved, s.units, s.loaded, s.annotations = mark, markUnits, loaded, s.annotations[:annotations]
			if err != nil {
				return err
			}
			if r.Type != "scalar" {
				return nil // the typed aggregation reports the parameter type at its own step
			}
			v := functionFloat(r.Scalar)
			anyAtLeastOne = anyAtLeastOne || v >= 1
			anyInvalid = anyInvalid || math.IsNaN(v) || v <= lower || v >= upper
		}
		if anyAtLeastOne && anyInvalid {
			return functionError(aggregation, "aggregation.parameter-range", "aggregation parameter is outside int64 range")
		}
	}
	return nil
}

func collectTruncatingAggregations(e TypedExpr, experimental bool, out *[]TypedExpr) {
	n, ok := e.Expr.(*Node)
	if !ok || n.Kind == "subquery" {
		return
	}
	if n.Kind == "aggregate" && len(e.Children) == 2 && (n.Text == "topk" || n.Text == "bottomk" || (n.Text == "limitk" && experimental)) {
		*out = append(*out, e)
	}
	for _, c := range e.Children {
		collectTruncatingAggregations(c, experimental, out)
	}
}
