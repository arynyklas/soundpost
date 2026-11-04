// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
)

type evaluationState struct {
	ctx         context.Context
	plan        Plan
	src         scan.MetricSource
	account     value.Account
	reserved    int64
	annotations []syntax.Diagnostic
	metadata    value.Result
	regexScope  *regexcompat.Scope
}

func (s *evaluationState) reserve(n int64) error {
	if e := s.account.Check(s.ctx); e != nil {
		return e
	}
	if e := s.account.Reserve(n); e != nil {
		return e
	}
	s.reserved += n
	return nil
}

// Evaluate retains no borrowed pages. Account bounds retained values; pinned
// regex caches have separate query-local caps for C06 admission to account for.
// Returned values transfer to the caller's response-lifetime accounting.
func Evaluate(ctx context.Context, plan Plan, src scan.MetricSource, account value.Account) (result value.Result, diagnostics []syntax.Diagnostic, err error) {
	if account == nil || plan.Expr.Expr == nil || src == nil || src.ProjectID() == (model.ID{}) {
		return result, nil, model.Fail(model.Invalid)
	}
	plan, err = millisecondDomain(plan)
	if err != nil {
		return result, nil, err
	}
	s := &evaluationState{ctx: ctx, plan: plan, src: src, account: account}
	defer func() {
		value.InheritMetadata(&result, s.metadata)
		account.Release(s.reserved)
		err = engineBoundaryError(err)
	}()
	count, e := gridCount(plan.Evaluation)
	if e != nil {
		return result, nil, e
	}
	if e = s.reserve(count * 8); e != nil {
		return result, nil, e
	}
	grid, e := EvaluationGrid(plan.Evaluation)
	if e != nil {
		return result, nil, e
	}
	if plan.Evaluation.Instant {
		result, err = s.eval(plan.Expr, grid[0])
		if err == nil {
			err = finalizeNames(&result, plan.Profile)
		}
		return result, s.annotations, err
	}
	result.Type = "matrix"
	index := map[string]int{}
	for _, at := range grid {
		mark := s.reserved
		r, e := s.eval(plan.Expr, at)
		if e != nil {
			return value.Result{}, s.annotations, e
		}
		if e = finalizeNames(&r, plan.Profile); e != nil {
			return value.Result{}, s.annotations, e
		}
		if r.Type == "scalar" {
			r.Vector = []value.Series{{Project: src.ProjectID(), Samples: []value.Sample{r.Scalar}}}
		}
		transient := s.reserved - mark
		for _, series := range r.Vector {
			key := series.Project.String() + value.LabelKey(series.Labels)
			i, ok := index[key]
			cost := int64(0)
			if !ok {
				cost = value.SeriesBytes(value.Series{Labels: series.Labels})
			}
			for _, sample := range series.Samples {
				cost += value.SampleBytes(sample)
			}
			if e = s.reserve(cost); e != nil {
				return value.Result{}, s.annotations, e
			}
			if !ok {
				i = len(result.Matrix)
				index[key] = i
				result.Matrix = append(result.Matrix, value.Series{Project: series.Project, Labels: series.Labels})
			}
			result.Matrix[i].Samples = append(result.Matrix[i].Samples, series.Samples...)
		}
		s.account.Release(transient)
		s.reserved -= transient
	}
	return result, s.annotations, nil
}
func (s *evaluationState) eval(expr TypedExpr, at model.UnixNano) (value.Result, error) {
	mark := s.reserved
	r, err := s.evalNode(expr, at)
	// Child results and selector buffers are dead after their parent is produced.
	// Charge only the retained parent on return, rather than cumulative work.
	s.account.Release(s.reserved - mark)
	s.reserved = mark
	if err == nil {
		err = s.reserve(value.ResultBytes(r))
	}
	return r, err
}
func (s *evaluationState) evalNode(expr TypedExpr, at model.UnixNano) (value.Result, error) {
	if e := s.account.Check(s.ctx); e != nil {
		return value.Result{}, e
	}
	n := expr.Expr.(*Node)
	switch n.Kind {
	case "number":
		return value.Result{Type: "scalar", Scalar: value.Sample{Time: at, Float: model.FloatBits(n.FloatBits)}}, nil
	case "string":
		return value.Result{Type: "string", String: n.Text}, nil
	case "paren":
		return s.eval(expr.Children[0], at)
	case "selector":
		return s.selectMetric(n, nil, at, selectOptions{})
	case "range":
		return s.selectMetric(n.Children[0].(*Node), n, at, selectOptions{})
	case "subquery":
		return s.subquery(expr, at)
	case "unary":
		r, e := s.eval(expr.Children[0], at)
		if e != nil {
			return r, e
		}
		if n.Text == "+" {
			return r, nil
		}
		if r.Type == "scalar" {
			r.Scalar.Float ^= 1 << 63
			return r, nil
		}
		for i := range r.Vector {
			if len(r.Vector[i].Samples) != 1 {
				return r, operatorError(n, "execution.invalid-vector", "invalid instant-vector sample count")
			}
			p := &r.Vector[i].Samples[0]
			if p.Histogram != nil {
				h := histogramScaleForProfile(*p.Histogram, -1, s.plan.Profile.ID)
				p.Histogram = &h
			} else {
				p.Float ^= 1 << 63
			}
			s.dropName(&r.Vector[i])
		}
		return r, checkDuplicates(r.Vector)
	case "binary":
		a, e := s.eval(expr.Children[0], at)
		if e != nil {
			return a, e
		}
		b, e := s.eval(expr.Children[1], at)
		if e != nil {
			return b, e
		}
		r, ds, e := s.binary(n, a, b, at)
		value.InheritMetadata(&r, a, b)
		s.annotations = appendAnnotations(s.annotations, ds...)
		return r, e
	case "call", "aggregate":
		args := make([]value.Result, len(expr.Children))
		for i, c := range expr.Children {
			var r value.Result
			var e error
			raw := c
			for raw.Expr.(*Node).Kind == "paren" {
				raw = raw.Children[0]
			}
			if n.Text == "timestamp" && i == 0 && raw.Expr.(*Node).Kind == "selector" {
				r, e = s.selectMetric(raw.Expr.(*Node), nil, at, selectOptions{preserveTime: true})
			} else if n.Text == "info" && i == 1 {
				selector := *c.Expr.(*Node)
				hasName := selector.Text != ""
				for _, m := range selector.Matchers {
					hasName = hasName || m.Name == "__name__"
				}
				if !hasName {
					selector.Text = "target_info"
				}
				r, e = s.selectMetric(&selector, nil, at, selectOptions{})
			} else {
				if raw.Expr.(*Node).Kind == "range" {
					r, e = s.evalFunctionWindow(raw, at)
				} else {
					r, e = s.eval(c, at)
				}
			}
			if e != nil {
				return r, e
			}
			args[i] = r
		}
		if n.Text == "info" && len(args) == 1 {
			r, e := s.selectMetric(&Node{Kind: "selector", Text: "target_info"}, nil, at, selectOptions{})
			if e != nil {
				return r, e
			}
			args = append(args, r)
		}
		functions := s.plan.Functions
		if n.Kind == "aggregate" {
			functions = s.plan.Aggregations
		}
		fn := functions[n.Text]
		if fn == nil {
			return value.Result{}, &syntax.LanguageError{Code: "execution.invalid-plan", Category: "execution", Range: n.Range, SafeMessage: "planned evaluator is missing"}
		}
		frame, e := s.functionFrame(expr, at)
		if e != nil {
			return value.Result{}, e
		}
		if n.Kind == "aggregate" {
			return s.aggregate(expr, args, frame, fn)
		}
		r, ds, e := fn(s.ctx, expr, args, frame)
		s.annotations = appendAnnotations(s.annotations, ds...)
		return r, e
	}
	return value.Result{}, operatorError(n, "execution.invalid-plan", "invalid executable expression")
}
func (s *evaluationState) functionFrame(expr TypedExpr, at model.UnixNano) (Frame, error) {
	f := Frame{Profile: s.plan.Profile, Evaluation: s.plan.Evaluation, Time: at, Account: s.account}
	f.Project = s.src.ProjectID()
	f.RegexScope = s.regexScope
	if expr.Expr.(*Node).Text == "label_replace" {
		scope, e := s.matcherScope()
		if e != nil {
			return f, e
		}
		f.RegexScope = scope
	}
	for _, child := range expr.Children {
		if child.Type != Matrix {
			continue
		}
		n := child.Expr.(*Node)
		for n.Kind == "paren" {
			n = n.Children[0].(*Node)
		}
		if n.Kind != "range" && n.Kind != "subquery" {
			continue
		}
		end, e := selectorTime(n, at, s.plan)
		if e != nil {
			return f, e
		}
		width, e := durationNS(n.RangeExpr, n.RangeText, s.plan.Evaluation)
		if e != nil {
			return f, e
		}
		start, e := checkedSub(end, width)
		if e != nil {
			return f, e
		}
		f.HasWindow = true
		f.WindowStart = model.UnixNano(start)
		f.WindowEnd = model.UnixNano(end)
		f.WindowRange = width
		if n.Kind == "subquery" {
			f.WindowStep = s.plan.SubqueryStep
			if n.StepExpr != nil || n.Step != "" {
				f.WindowStep, e = durationNS(n.StepExpr, n.Step, s.plan.Evaluation)
				if e != nil {
					return f, e
				}
			}
		}
		break
	}
	return f, nil
}
func (s *evaluationState) aggregate(expr TypedExpr, args []value.Result, frame Frame, fn FunctionEvaluator) (value.Result, error) {
	n := expr.Expr.(*Node)
	out := value.Result{Type: "vector"}
	value.InheritMetadata(&out, args...)
	if len(args) == 0 {
		return out, operatorError(n, "aggregation.arity", "aggregation has no input")
	}
	vi := len(args) - 1
	names := n.Labels
	if n.Text == "count_values" && len(args) == 2 {
		// The generated count label replaces any old destination value before
		// grouping; an existing value must not split otherwise identical groups.
		names = make([]string, 0, len(n.Labels)+1)
		for _, name := range n.Labels {
			if name != args[0].String {
				names = append(names, name)
			}
		}
		if n.GroupWithout {
			names = append(names, args[0].String)
		}
	}
	groups := make([][]value.Series, 0)
	indices := map[string]int{}
	for _, series := range args[vi].Vector {
		key := series.Project.String() + value.LabelKey(GroupingLabels(series.Labels, names, n.GroupWithout))
		index, ok := indices[key]
		if !ok {
			index = len(groups)
			indices[key] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], series)
	}
	for _, group := range groups {
		if e := s.account.Check(s.ctx); e != nil {
			return out, e
		}
		grouped := append([]value.Result(nil), args...)
		grouped[vi].Vector = group
		frame.Project = group[0].Project
		r, ds, e := fn(s.ctx, expr, grouped, frame)
		s.annotations = appendAnnotations(s.annotations, ds...)
		if e != nil {
			return out, e
		}
		value.InheritMetadata(&out, r)
		out.Vector = append(out.Vector, r.Vector...)
	}
	return out, checkDuplicates(out.Vector)
}
func (s *evaluationState) dropName(series *value.Series) {
	if enabled(s.plan.Profile, "promql-delayed-name-removal") {
		series.DropName = true
	} else {
		series.Labels = dropMetricSchemaLabels(series.Labels, s.plan.Profile)
	}
}
func (s *evaluationState) matcherScope() (*regexcompat.Scope, error) {
	if s.regexScope == nil {
		scope, e := scan.NewMatcherScope(s.plan.Profile)
		if e != nil {
			return nil, e
		}
		s.regexScope = scope
	}
	return s.regexScope, nil
}
func (s *evaluationState) subquery(expr TypedExpr, at model.UnixNano) (value.Result, error) {
	n := expr.Expr.(*Node)
	target, e := selectorTime(n, at, s.plan)
	if e != nil {
		return value.Result{}, e
	}
	width, e := durationNS(n.RangeExpr, n.RangeText, s.plan.Evaluation)
	if e != nil || width <= 0 {
		return value.Result{}, timeError()
	}
	step := s.plan.SubqueryStep
	if n.StepExpr != nil || n.Step != "" {
		step, e = durationNS(n.StepExpr, n.Step, s.plan.Evaluation)
		if e != nil {
			return value.Result{}, e
		}
	}
	left, e := checkedSub(target, width)
	if e != nil {
		return value.Result{}, e
	}
	start, e := firstSubqueryPoint(left, step)
	if e != nil {
		return value.Result{}, e
	}
	r := value.Result{Type: "matrix"}
	if start > target {
		return r, nil
	}
	ev := value.Evaluation{Start: model.UnixNano(start), End: model.UnixNano(target), Step: step}
	count, e := gridCount(ev)
	if e != nil {
		return r, e
	}
	if e = s.reserve(count * 8); e != nil {
		return r, e
	}
	grid, e := EvaluationGrid(ev)
	if e != nil {
		return r, e
	}
	index := map[string]int{}
	for _, t := range grid {
		mark := s.reserved
		part, e := s.eval(expr.Children[0], t)
		if e != nil {
			return r, e
		}
		value.InheritMetadata(&r, part)
		transient := s.reserved - mark
		for _, series := range part.Vector {
			key := series.Project.String() + value.LabelKey(series.Labels)
			i, ok := index[key]
			cost := int64(0)
			if !ok {
				cost = value.SeriesBytes(value.Series{Labels: series.Labels})
			}
			for _, sample := range series.Samples {
				sample.StartTimestamp = nil
				cost += value.SampleBytes(sample)
			}
			if e = s.reserve(cost); e != nil {
				return r, e
			}
			if !ok {
				i = len(r.Matrix)
				index[key] = i
				r.Matrix = append(r.Matrix, value.Series{Project: series.Project, Labels: series.Labels, DropName: series.DropName})
			}
			for _, sample := range series.Samples {
				sample.StartTimestamp = nil
				r.Matrix[i].Samples = append(r.Matrix[i].Samples, sample)
			}
		}
		s.account.Release(transient)
		s.reserved -= transient
	}
	return r, nil
}
func dropMetricSchemaLabels(labels model.Labels, p profile.Profile) model.Labels {
	modern := p.ID == "promql-prometheus-3.13.5"
	out := make(model.Labels, 0, len(labels))
	for _, label := range labels {
		if label.Name == "__name__" || modern && (label.Name == "__type__" || label.Name == "__unit__") {
			continue
		}
		out = append(out, label)
	}
	return out
}
func finalizeNames(r *value.Result, p profile.Profile) error {
	for i := range r.Vector {
		if r.Vector[i].DropName {
			r.Vector[i].Labels = dropMetricSchemaLabels(r.Vector[i].Labels, p)
			r.Vector[i].DropName = false
		}
	}
	for i := range r.Matrix {
		if r.Matrix[i].DropName {
			r.Matrix[i].Labels = dropMetricSchemaLabels(r.Matrix[i].Labels, p)
			r.Matrix[i].DropName = false
		}
	}
	if e := checkDuplicates(r.Vector); e != nil {
		return e
	}
	return checkDuplicates(r.Matrix)
}
