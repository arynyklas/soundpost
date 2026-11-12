// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
)

func floatOperator(op string, a, b float64) (float64, bool, bool) {
	switch op {
	case "+":
		return value.Add(a, b), true, true
	case "-":
		return value.Sub(a, b), true, true
	case "*":
		return value.Mul(a, b), true, true
	case "/":
		return value.Div(a, b), true, true
	case "%":
		return math.Mod(a, b), true, true
	case "^":
		return math.Pow(a, b), true, true
	case "atan2":
		return math.Atan2(a, b), true, true
	case "==":
		return a, a == b, true
	case "!=":
		return a, a != b, true
	case ">":
		return a, a > b, true
	case "<":
		return a, a < b, true
	case ">=":
		return a, a >= b, true
	case "<=":
		return a, a <= b, true
	}
	return 0, false, false
}
func comparison(op string) bool {
	return op == "==" || op == "!=" || op == ">" || op == "<" || op == ">=" || op == "<="
}
func dropsMetricName(op string) bool {
	return op == "+" || op == "-" || op == "*" || op == "/" || op == "%" || op == "^" || op == "atan2"
}

// GroupingLabels is shared by all aggregation evaluators. Metric names are
// excluded from without grouping, but may be explicitly retained by by(__name__).
func GroupingLabels(ls model.Labels, names []string, without bool) model.Labels {
	out := make(model.Labels, 0, len(ls))
	for _, l := range ls {
		if l.Value == "" {
			continue
		}
		found := false
		for _, name := range names {
			if name == l.Name {
				found = true
				break
			}
		}
		if without && !found && l.Name != "__name__" || !without && found {
			out = append(out, l)
		}
	}
	return out
}
func matchingKey(series value.Series, m *VectorMatching) string {
	if m == nil {
		return series.Project.String() + value.LabelKey(GroupingLabels(series.Labels, nil, true))
	}
	if m.On {
		return series.Project.String() + value.LabelKey(GroupingLabels(series.Labels, m.Labels, false))
	}
	return series.Project.String() + value.LabelKey(GroupingLabels(series.Labels, m.Labels, true))
}
func checkDuplicates(series []value.Series) error {
	seen := make(map[string]bool, len(series))
	for _, s := range series {
		key := s.Project.String() + value.LabelKey(s.Labels)
		if seen[key] {
			return &syntax.LanguageError{Code: "result.duplicate-labelset", Category: "execution", SafeMessage: "vector contains duplicate output label sets"}
		}
		seen[key] = true
	}
	return nil
}
func (s *evaluationState) sampleBinary(n *Node, a, b value.Sample, at model.UnixNano) (value.Sample, bool, []syntax.Diagnostic, error) {
	if a.Histogram != nil || b.Histogram != nil || n.Text == "</" || n.Text == ">/" {
		p, keep, ds, e := histogramBinaryProfile(n.Text, a, b, s.plan.Profile)
		for i := range ds {
			ds[i].Range = n.OperatorRange
		}
		if n.Bool && comparison(n.Text) && e == nil && len(ds) == 0 {
			p.Histogram = nil
			p.Float = 0
			if keep {
				p.Float = model.FloatBits(math.Float64bits(1))
			}
			keep = true
		}
		p.Time = at
		return p, keep, ds, e
	}
	v, keep, valid := floatOperator(n.Text, math.Float64frombits(uint64(a.Float)), math.Float64frombits(uint64(b.Float)))
	if !valid {
		return value.Sample{}, false, nil, operatorError(n, "binary.operator-invalid", "invalid binary operator")
	}
	if n.Bool {
		if keep {
			v = 1
		} else {
			v = 0
		}
		keep = true
	}
	return value.Sample{Time: at, Float: model.FloatBits(math.Float64bits(v))}, keep, nil, nil
}
func (s *evaluationState) binary(n *Node, a, b value.Result, at model.UnixNano) (value.Result, []syntax.Diagnostic, error) {
	if a.Type == "scalar" && b.Type == "scalar" {
		if n.Text == "</" || n.Text == ">/" {
			return value.Result{}, nil, operatorError(n, "binary.operand-type", "histogram trimming is not allowed for scalar operations")
		}
		p, _, ds, e := s.sampleBinary(n, a.Scalar, b.Scalar, at)
		return value.Result{Type: "scalar", Scalar: p}, ds, e
	}
	if n.Text == "and" || n.Text == "or" || n.Text == "unless" {
		return setBinary(n, a, b), nil, nil
	}
	out := value.Result{Type: "vector"}
	var annotations []syntax.Diagnostic
	if a.Type == "scalar" || b.Type == "scalar" {
		v, scalar := a.Vector, b.Scalar
		leftScalar := a.Type == "scalar"
		if leftScalar {
			v, scalar = b.Vector, a.Scalar
		}
		for _, series := range v {
			if len(series.Samples) != 1 {
				return out, annotations, operatorError(n, "execution.invalid-vector", "invalid instant-vector sample count")
			}
			x, y := series.Samples[0], scalar
			if leftScalar {
				x, y = scalar, x
			}
			p, keep, ds, e := s.sampleBinary(n, x, y, at)
			annotations = appendAnnotations(annotations, ds...)
			if e != nil {
				return out, annotations, e
			}
			if !keep {
				continue
			}
			if comparison(n.Text) && !n.Bool {
				p = series.Samples[0]
				p.Time = at
			}
			p.StartTimestamp = series.Samples[0].StartTimestamp
			series.Samples = []value.Sample{p}
			if dropsMetricName(n.Text) || n.Bool {
				s.dropName(&series)
			}
			out.Vector = append(out.Vector, series)
		}
		return out, annotations, checkDuplicates(out.Vector)
	}
	left := map[string][]int{}
	right := map[string][]int{}
	for i, series := range a.Vector {
		key := matchingKey(series, n.Matching)
		left[key] = append(left[key], i)
	}
	for i, series := range b.Vector {
		key := matchingKey(series, n.Matching)
		right[key] = append(right[key], i)
	}
	card := ""
	if n.Matching != nil {
		card = n.Matching.Cardinality
	}
	seenRight := make([]bool, len(b.Vector))
	if len(a.Vector) > 0 && len(b.Vector) > 0 {
		one := right
		if card == "group_right" {
			one = left
		}
		for _, matches := range one {
			if len(matches) > 1 {
				return out, annotations, operatorError(n, "binary.many-to-many", "grouping requires unique samples on the one side")
			}
		}
	}
	emit := func(lhs, rhs value.Series) error {
		if len(lhs.Samples) != 1 || len(rhs.Samples) != 1 {
			return operatorError(n, "execution.invalid-vector", "invalid instant-vector sample count")
		}
		p, keep, ds, e := s.sampleBinary(n, lhs.Samples[0], rhs.Samples[0], at)
		annotations = appendAnnotations(annotations, ds...)
		if e != nil {
			return e
		}
		if !keep {
			return nil
		}
		result, one := lhs, rhs
		if card == "group_right" {
			result, one = rhs, lhs
		}
		if comparison(n.Text) && !n.Bool {
			p = lhs.Samples[0]
			p.Time = at
		}
		p.StartTimestamp = nil // Derived vector/vector samples do not carry native ST.
		modern := s.plan.Profile.ID == "promql-prometheus-3.13.5"
		delayed := enabled(s.plan.Profile, "promql-delayed-name-removal")
		result.DropName = n.Bool && delayed // Never inherit a vector input's deferred flag.
		if dropsMetricName(n.Text) || modern && n.Bool && !delayed {
			result.Labels = dropMetricSchemaLabels(result.Labels, s.plan.Profile)
		} else {
			result.Labels = append(model.Labels(nil), result.Labels...)
		}
		result.Samples = []value.Sample{p}
		if card == "" && n.Matching != nil {
			if n.Matching.On {
				result.Labels = GroupingLabels(result.Labels, n.Matching.Labels, false)
			} else {
				retained := make(model.Labels, 0, len(result.Labels))
				for _, label := range result.Labels {
					ignored := false
					for _, name := range n.Matching.Labels {
						ignored = ignored || name == label.Name
					}
					if !ignored {
						retained = append(retained, label)
					}
				}
				result.Labels = retained
			}
		}
		if n.Matching != nil {
			for _, name := range n.Matching.Include {
				result.Labels = value.SetLabel(result.Labels, name, value.Label(one.Labels, name))
			}
		}
		// 3.1.0 deletes bool names after include; 3.13.5 deletes its schema before
		// include. A delayed bool result instead removes schema at final cleanup.
		if n.Bool && !modern && !delayed {
			result.Labels = dropMetricSchemaLabels(result.Labels, s.plan.Profile)
		}
		out.Vector = append(out.Vector, result)
		return nil
	}
	for _, lhs := range a.Vector {
		key := matchingKey(lhs, n.Matching)
		matches := right[key]
		if len(matches) == 0 {
			if n.FillRight != nil {
				rhs := lhs
				rhs.Samples = []value.Sample{{Time: at, Float: model.FloatBits(*n.FillRight)}}
				if e := emit(lhs, rhs); e != nil {
					return out, annotations, e
				}
			}
			continue
		}
		if len(matches) > 1 && card != "group_right" || len(left[key]) > 1 && card != "group_left" {
			return out, annotations, operatorError(n, "binary.matching-cardinality", "many-to-many or ambiguous vector matching is not allowed")
		}
		if card == "group_left" && len(matches) != 1 || card == "group_right" && len(left[key]) != 1 {
			return out, annotations, operatorError(n, "binary.matching-cardinality", "grouping requires unique samples on the one side")
		}
		for _, j := range matches {
			seenRight[j] = true
			if e := emit(lhs, b.Vector[j]); e != nil {
				return out, annotations, e
			}
		}
	}
	if n.FillLeft != nil {
		for j, rhs := range b.Vector {
			if seenRight[j] {
				continue
			}
			lhs := rhs
			lhs.Samples = []value.Sample{{Time: at, Float: model.FloatBits(*n.FillLeft)}}
			if e := emit(lhs, rhs); e != nil {
				return out, annotations, e
			}
		}
	}
	return out, annotations, checkDuplicates(out.Vector)
}
func setBinary(n *Node, a, b value.Result) value.Result {
	out := value.Result{Type: "vector"}
	left := map[string]bool{}
	right := map[string]bool{}
	for _, series := range a.Vector {
		left[matchingKey(series, n.Matching)] = true
	}
	for _, series := range b.Vector {
		right[matchingKey(series, n.Matching)] = true
	}
	for _, series := range a.Vector {
		match := right[matchingKey(series, n.Matching)]
		if n.Text == "or" || n.Text == "and" && match || n.Text == "unless" && !match {
			out.Vector = append(out.Vector, series)
		}
	}
	if n.Text == "or" {
		for _, series := range b.Vector {
			if !left[matchingKey(series, n.Matching)] {
				out.Vector = append(out.Vector, series)
			}
		}
	}
	return out
}
