// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"strconv"
)

type pipelineEntries struct {
	input   scan.LogIterator
	plan    PipelinePlan
	account value.Account
}

func (i *pipelineEntries) Next(ctx context.Context) (PipelineResult, error) {
	for {
		row, e := i.input.Next(ctx)
		if e != nil {
			return PipelineResult{}, e
		}
		r, e := RunLogRow(ctx, i.plan, row, i.account)
		if e != nil {
			return PipelineResult{}, e
		}
		if r.Retained {
			return r, nil
		}
		i.account.Release(r.Bytes)
	}
}
func (i *pipelineEntries) Watermarks() []model.Cursor { return i.input.Watermarks() }
func (i *pipelineEntries) Partial() bool              { return i.input.Partial() }
func (i *pipelineEntries) Close() error               { return i.input.Close() }

type metricState struct {
	ctx          context.Context
	plan         Plan
	src          scan.LogSource
	account      value.Account
	held         int64
	metadata     value.Result
	variantInput bool
	regexScope   *regexcompat.Scope
}

func (s *metricState) reserve(n int64) error {
	if e := s.account.Check(s.ctx); e != nil {
		return e
	}
	if e := s.account.Reserve(n); e != nil {
		return e
	}
	s.held += n
	return nil
}

// Evaluate returns retained owned results. The consumer releases
// value.ResultBytes(result), including successful empty/partial results.
func Evaluate(ctx context.Context, plan Plan, src scan.LogSource, account value.Account) (result value.Result, diagnostics []syntax.Diagnostic, err error) {
	if ctx == nil || account == nil || src == nil || src.ProjectID() == (model.ID{}) || plan.Expression.Expr == nil {
		return result, nil, model.Fail(model.Invalid)
	}
	checked, ds, e := Check(plan.Expression.Expr, plan.Profile)
	if e != nil {
		return result, ds, e
	}
	if checked.Type != plan.Expression.Type {
		return result, nil, model.Fail(model.Invalid)
	}
	if checked.Type == TypeLogs {
		result, err = EvaluateLogs(ctx, plan, src, Backward, 5000000, account)
		return result, nil, err
	}
	s := &metricState{ctx: ctx, plan: plan, src: src, account: account}
	defer func() {
		value.InheritMetadata(&result, s.metadata)
		account.Release(s.held)
		if err == nil {
			err = account.Check(ctx)
		}
		if err == nil {
			err = account.Reserve(value.ResultBytes(result))
		}
	}()
	start, end := plan.Evaluation.Start, plan.Evaluation.End
	step := plan.Evaluation.Step
	if plan.Evaluation.Instant {
		start = plan.Evaluation.Time
		end = start
		step = 1
	} else if step <= 0 || end < start {
		return result, nil, model.Fail(model.Invalid)
	}
	count := (uint64(end) - uint64(start)) / uint64(step)
	if count >= 5000000 {
		return result, nil, model.Fail(model.Quota)
	}
	if !plan.Evaluation.Instant {
		result.Type = "matrix"
	}
	index := map[string]int{}
	for at := start; ; {
		mark := s.held
		r, e := s.eval(plan.Expression.Expr, at)
		if e != nil {
			return result, nil, e
		}
		floorSampleTimes(&r)
		if plan.Evaluation.Instant {
			if r.Type == "vector" && !metricPreservesValueOrder(plan.Expression.Expr) {
				if e = metricSort(r.Vector, func(i, j int) bool { return value.CompareLabels(r.Vector[i].Labels, r.Vector[j].Labels) < 0 }, func() error { return account.Check(ctx) }); e != nil {
					return r, nil, e
				}
			}
			return r, nil, nil
		}
		transient := s.held - mark
		if r.Type == "scalar" {
			r.Vector = []value.Series{metricSeries(src.ProjectID(), nil, at, math.Float64frombits(uint64(r.Scalar.Float)))}
		}
		floorSampleTimes(&r)
		for _, series := range r.Vector {
			key := value.LabelKey(series.Labels)
			i, ok := index[key]
			cost := int64(48)
			if !ok {
				cost += value.SeriesBytes(value.Series{Labels: series.Labels}) + int64(len(key)) + 64
			}
			if e = s.reserve(cost); e != nil {
				return result, nil, e
			}
			if !ok {
				i = len(result.Matrix)
				index[key] = i
				result.Matrix = append(result.Matrix, value.Series{Project: src.ProjectID(), Labels: value.CloneLabels(series.Labels)})
			}
			result.Matrix[i].Samples = append(result.Matrix[i].Samples, series.Samples...)
		}
		s.account.Release(transient)
		s.held -= transient
		if uint64(end)-uint64(at) < uint64(step) {
			break
		}
		at = model.UnixNano(int64(at) + step)
	}
	if e := metricSort(result.Matrix, func(i, j int) bool { return value.CompareLabels(result.Matrix[i].Labels, result.Matrix[j].Labels) < 0 }, func() error { return account.Check(ctx) }); e != nil {
		return result, nil, e
	}
	return result, nil, nil
}
func (s *metricState) eval(e Expr, at model.UnixNano) (r value.Result, err error) {
	if err = s.account.Check(s.ctx); err != nil {
		return r, err
	}
	mark := s.held
	r, err = s.node(e, at)
	s.account.Release(s.held - mark)
	s.held = mark
	if err == nil {
		err = s.reserve(value.ResultBytes(r))
	}
	return r, err
}
func (s *metricState) node(e Expr, at model.UnixNano) (value.Result, error) {
	switch n := e.(type) {
	case *LiteralExpr:
		return value.Result{Type: "scalar", Scalar: value.Sample{Time: at, Float: model.FloatBits(math.Float64bits(n.Value))}}, nil
	case *UnaryExpr:
		r, err := s.eval(n.Expr, at)
		if err != nil {
			return r, err
		}
		if n.Op == "-" {
			if r.Type == "scalar" {
				r.Scalar.Float ^= 1 << 63
			} else {
				for i := range r.Vector {
					r.Vector[i].Samples[0].Float ^= 1 << 63
				}
			}
		}
		return r, nil
	case *BinaryExpr:
		a, err := s.eval(n.Left, at)
		if err != nil {
			return a, err
		}
		b, err := s.eval(n.Right, at)
		if err != nil {
			return b, err
		}
		if err = s.reserve((value.ResultBytes(a) + value.ResultBytes(b)) * 4); err != nil {
			return value.Result{}, err
		}
		return binaryMetric(n, a, b, at, s.src.ProjectID(), func() error { return s.account.Check(s.ctx) })
	case *CallExpr:
		if rangeNames[n.Name] {
			idx := 0
			parameter := 0.0
			if n.Name == "quantile_over_time" {
				idx = 1
				r, err := s.eval(n.Args[0], at)
				if err != nil {
					return r, err
				}
				parameter = math.Float64frombits(uint64(r.Scalar.Float))
			}
			rg := n.Args[idx].(*RangeExpr)
			p, err := s.pipeline(rg.Log)
			if err != nil {
				return value.Result{}, err
			}
			if s.variantInput {
				p.Matchers = nil
				p.selectors = nil
			}
			right, err := metricSub(int64(at), rg.Offset)
			if err != nil {
				return value.Result{}, err
			}
			left, err := metricSub(right, rg.Interval)
			if err != nil || right == math.MaxInt64 {
				return value.Result{}, model.Fail(model.Invalid)
			}
			it, err := s.selectEntries(p, model.UnixNano(left+1), model.UnixNano(right+1))
			if err != nil {
				return value.Result{}, err
			}
			r, err := EvaluateRange(s.ctx, RangePlan{Function: n.Name, Range: rg, Pipeline: p, Parameter: parameter, Grouping: n.Grouping, Without: n.Without, checked: true}, it, Frame{Time: at, Profile: s.plan.Profile, Project: s.src.ProjectID(), Account: s.account})
			value.InheritMetadata(&s.metadata, r)
			if err == nil {
				s.held += value.ResultBytes(r)
			}
			return r, err
		}
		if n.Name == "vector" {
			r, err := s.eval(n.Args[0], at)
			if err != nil {
				return r, err
			}
			return value.Result{Type: "vector", Vector: []value.Series{metricSeries(s.src.ProjectID(), nil, at, math.Float64frombits(uint64(r.Scalar.Float)))}}, nil
		}
		if n.Name == "label_replace" {
			r, err := s.eval(n.Args[0], at)
			if err != nil {
				return r, err
			}
			return s.labelReplace(n, r)
		}
		args := make([]value.Result, len(n.Args))
		for i, x := range n.Args {
			r, err := s.eval(x, at)
			if err != nil {
				return r, err
			}
			args[i] = r
		}
		if n.Name == "approx_topk" && !s.plan.Evaluation.Instant {
			return value.Result{}, typeError(n, "approx_topk supports only instant queries")
		}
		scratch := value.ResultBytes(args[len(args)-1]) * 6
		if n.Name == "approx_topk" {
			scratch += metricSketchWidth * metricSketchDepth * 8
		}
		if err := s.reserve(scratch); err != nil {
			return value.Result{}, err
		}
		return aggregateMetric(n, args, at, s.src.ProjectID(), s.plan.Profile, func() error { return s.account.Check(s.ctx) })
	case *VariantsExpr:
		return s.variants(n, at)
	}
	return value.Result{}, model.Fail(model.Invalid)
}
func (s *metricState) pipeline(log *LogExpr) (PipelinePlan, error) {
	for _, p := range s.plan.Pipelines {
		if samePipeline(p, log) {
			return p, nil
		}
	}
	p := PipelinePlan{Matchers: log.Matchers, Stages: log.Stages, Profile: s.plan.Profile, Evaluation: s.plan.Evaluation, Templates: defaultTemplateRuntime()}
	err := p.compile(s.ctx)
	return p, err
}
func samePipeline(p PipelinePlan, l *LogExpr) bool {
	if len(p.Matchers) != len(l.Matchers) || len(p.Stages) != len(l.Stages) {
		return false
	}
	for i := range p.Matchers {
		if p.Matchers[i] != l.Matchers[i] {
			return false
		}
	}
	for i := range p.Stages {
		if p.Stages[i].Span() != l.Stages[i].Span() {
			return false
		}
	}
	return true
}
func (s *metricState) selectEntries(p PipelinePlan, start, end model.UnixNano) (EntryIterator, error) {
	ms := make([]scan.LabelMatcher, len(p.Matchers))
	for i, m := range p.Matchers {
		ms[i] = scan.LabelMatcher{Name: m.Name, Op: m.Op, Value: m.Value}
	}
	it, err := s.src.Select(s.ctx, scan.LogSelection{Start: start, End: end, Matchers: ms, Profile: s.plan.Profile, Account: s.account, RegexScope: p.RegexScope})
	if err != nil {
		return nil, err
	}
	if it == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return &pipelineEntries{it, p, s.account}, nil
}

// EvaluateLogs applies the requested raw-log order and user-visible limit; a
// budget violation remains an error and is never turned into that limit.
func EvaluateLogs(ctx context.Context, plan Plan, src scan.LogSource, order LogOrder, limit uint64, account value.Account) (value.Result, error) {
	return EvaluateLogsInterval(ctx, plan, src, order, limit, 0, account)
}
func EvaluateLogsInterval(ctx context.Context, plan Plan, src scan.LogSource, order LogOrder, limit uint64, interval int64, account value.Account) (result value.Result, err error) {
	if ctx == nil || src == nil || account == nil || src.ProjectID() == (model.ID{}) || interval < 0 {
		return result, model.Fail(model.Invalid)
	}
	log, ok := plan.Expression.Expr.(*LogExpr)
	if !ok {
		return result, model.Fail(model.Invalid)
	}
	if _, _, err = Check(log, plan.Profile); err != nil {
		return result, err
	}
	start, end := plan.Evaluation.Start, plan.Evaluation.End
	if plan.Evaluation.Instant {
		end = plan.Evaluation.Time
		lookback := int64(30000000000)
		if raw, present := plan.Profile.Configuration["instant_log_lookback_ns"]; present {
			lookback, err = configInt64(raw)
			if err != nil || lookback <= 0 {
				return result, model.Fail(model.Invalid)
			}
		}
		left, e := metricSub(int64(end), lookback)
		if e != nil {
			return result, e
		}
		start = model.UnixNano(left)
	}
	if start >= end {
		return result, model.Fail(model.Invalid)
	}
	s := &metricState{ctx: ctx, plan: plan, src: src, account: account}
	p, err := s.pipeline(log)
	if err != nil {
		return result, err
	}
	input, err := s.selectEntries(p, start, end)
	if err != nil {
		return result, err
	}
	mergeLimit := limit
	if interval > 0 {
		mergeLimit = math.MaxUint64
	}
	merged, err := MergeLogs(ctx, []EntryIterator{input}, order, mergeLimit, account)
	if err != nil {
		return result, err
	}
	result.Type = "streams"
	held := int64(0)
	var emitted uint64
	var previous model.UnixNano
	havePrevious := false
	defer func() {
		closeErr := merged.Close()
		if err == nil {
			err = closeErr
		}
		value.InheritMetadata(&result, value.Result{Partial: merged.Partial(), Watermarks: merged.Watermarks()})
		account.Release(held)
		if err == nil {
			err = account.Check(ctx)
		}
		if err == nil {
			err = account.Reserve(value.ResultBytes(result))
		}
	}()
	if limit == 0 {
		return result, nil
	}
	for {
		r, e := merged.Next(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return result, e
		}
		if interval > 0 && havePrevious {
			distance := uint64(r.Entry.Timestamp) - uint64(previous)
			if order == Backward {
				distance = uint64(previous) - uint64(r.Entry.Timestamp)
			}
			if distance < uint64(interval) {
				account.Release(r.Bytes)
				continue
			}
		}
		if interval > 0 {
			r.Entry.Multiplicity = 1
		}
		if limit > 0 && uint64(r.Entry.Multiplicity) > limit-emitted {
			r.Entry.Multiplicity = model.Uint64(limit - emitted)
		}
		l := value.Log{Project: src.ProjectID(), ID: r.Entry.ID, Source: r.Entry.Source, Timestamp: r.Entry.Timestamp, Multiplicity: r.Entry.Multiplicity, Line: r.Entry.Line, Labels: r.Labels, StreamLabels: r.OriginalStreamLabels, StructuredMetadata: r.OriginalStructuredMetadata}
		cost := value.LogBytes(l) + 64
		if e = account.Reserve(cost); e != nil {
			account.Release(r.Bytes)
			return result, e
		}
		held += cost
		l.Labels = value.CloneLabels(l.Labels)
		l.StreamLabels = value.CloneLabels(l.StreamLabels)
		l.StructuredMetadata = value.CloneLabels(l.StructuredMetadata)
		result.Logs = append(result.Logs, l)
		account.Release(r.Bytes)
		previous = l.Timestamp
		havePrevious = true
		emitted += uint64(l.Multiplicity)
		if limit > 0 && emitted == limit {
			break
		}
	}
	return result, nil
}

// The pinned engine label-orders final instant vectors except sample trees
// containing sort/sort_desc anywhere. Variants never opt out of final ordering.
func metricPreservesValueOrder(expr Expr) bool {
	if _, variants := expr.(*VariantsExpr); variants {
		return false
	}
	var visit func(Expr) bool
	visit = func(e Expr) bool {
		switch n := e.(type) {
		case *CallExpr:
			if n.Name == "sort" || n.Name == "sort_desc" {
				return true
			}
			for _, arg := range n.Args {
				if visit(arg) {
					return true
				}
			}
		case *BinaryExpr:
			return visit(n.Left) || visit(n.Right)
		case *UnaryExpr:
			return visit(n.Expr)
		}
		return false
	}
	return visit(expr)
}

// configInt64 reads an integer profile setting written either as a JSON string
// ("30000000000") or as a JSON number (30000000000).
func configInt64(raw json.RawMessage) (int64, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strconv.ParseInt(text, 10, 64)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, err
	}
	return strconv.ParseInt(number.String(), 10, 64)
}

// floorSampleTimes reports every sample of a metric result at millisecond
// precision, as the reference does (its samples carry a millisecond
// timestamp): a query evaluated at t=2000000500ns returns the sample time
// 2000000000. The evaluation itself, window edges included, keeps the exact
// nanosecond time.
func floorSampleTimes(r *value.Result) {
	floor := func(t model.UnixNano) model.UnixNano {
		const ms = int64(1000000)
		v := int64(t)
		if v%ms == 0 {
			return t
		}
		q := v / ms
		if v < 0 {
			q--
		}
		return model.UnixNano(q * ms)
	}
	if r.Type == "scalar" {
		r.Scalar.Time = floor(r.Scalar.Time)
	}
	for i := range r.Vector {
		for j := range r.Vector[i].Samples {
			r.Vector[i].Samples[j].Time = floor(r.Vector[i].Samples[j].Time)
		}
	}
}
