// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"io"
	"math"
	"sort"

	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
)

// selectOptions refine how selectMetric returns a selector's samples.
type selectOptions struct {
	// preserveTime keeps each sample's own timestamp (timestamp()).
	preserveTime bool
	// functionArg marks a matrix selector consumed directly by a range
	// function. With an extension modifier the function receives the raw
	// samples of the extended window and applies the extension itself.
	functionArg bool
}

// selectionBounds is the span of nanosecond timestamps a selector may read:
// timestamps in (from, through]. The bounds are whole milliseconds, see
// millisecondDomain.
type selectionBounds struct {
	target, from, through int64
	// left is the start of the nominal range of a matrix selector.
	left int64
}

func (s *evaluationState) selectionBounds(node *Node, window *Node, target int64) (selectionBounds, error) {
	b := selectionBounds{target: target, through: target}
	var err error
	if b.from, err = checkedSub(target, s.plan.Lookback); err != nil {
		return b, err
	}
	switch {
	case window == nil:
		if node.Extension == "smoothed" {
			b.through, err = checkedAdd(target, s.plan.Lookback)
		}
	default:
		width, e := durationNS(window.RangeExpr, window.RangeText, s.plan.Evaluation)
		if e != nil || width <= 0 {
			return b, timeError()
		}
		if b.left, err = checkedSub(target, width); err != nil {
			return b, err
		}
		b.from = b.left
		switch window.Extension {
		case "anchored":
			b.from, err = checkedSub(b.left, s.plan.Lookback)
		case "smoothed":
			if b.from, err = checkedSub(b.left, s.plan.Lookback); err == nil {
				b.through, err = checkedAdd(target, s.plan.Lookback)
			}
		}
	}
	return b, err
}

func (s *evaluationState) selectMetric(sel, window *Node, at model.UnixNano, opts selectOptions) (r value.Result, err error) {
	node := sel
	if window != nil {
		node = window
	}
	target, e := selectorTime(node, at, s.plan)
	if e != nil {
		return r, e
	}
	bounds, e := s.selectionBounds(node, window, target)
	if e != nil {
		return r, e
	}
	// The lower bound is exclusive: the storage request starts right after it.
	start, e := checkedAdd(bounds.from, 1)
	if e != nil {
		return r, e
	}
	end, e := checkedAdd(bounds.through, 1)
	if e != nil {
		return r, e
	}
	req := scan.MetricSelection{Start: model.UnixNano(start), End: model.UnixNano(end), Profile: s.plan.Profile, Account: s.account}
	if sel.Text != "" {
		req.Matchers = append(req.Matchers, scan.LabelMatcher{Name: "__name__", Op: "=", Value: sel.Text})
	}
	for _, m := range sel.Matchers {
		req.Matchers = append(req.Matchers, scan.LabelMatcher{Name: m.Name, Op: m.Op, Value: m.Value})
	}
	for _, m := range req.Matchers {
		if m.Op == "=~" || m.Op == "!~" {
			req.RegexScope, e = s.matcherScope()
			if e != nil {
				return r, e
			}
			break
		}
	}
	matchers, e := scan.CompileMatchers(s.ctx, req)
	if e != nil {
		return r, e
	}
	if s.src == nil {
		return r, model.Fail(model.Invalid)
	}
	it, e := s.src.Select(s.ctx, req)
	if e != nil {
		return r, e
	}
	defer func() {
		metadata := value.Result{Partial: it.Partial(), Watermarks: it.Watermarks()}
		value.InheritMetadata(&r, metadata)
		value.InheritMetadata(&s.metadata, metadata)
		if e := it.Close(); err == nil && e != nil {
			err = e
		}
	}()
	r.Type = "vector"
	if window != nil {
		r.Type = "matrix"
	}
	for {
		series, e := it.Next(s.ctx)
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return r, e
		}
		if e = s.account.Check(s.ctx); e != nil {
			return r, e
		}
		if series.Project != s.src.ProjectID() {
			return r, model.Fail(model.Corrupt)
		}
		ok, e := matchers.Match(s.ctx, series.Labels)
		if e != nil {
			return r, e
		}
		if !ok {
			continue
		}
		for i := 1; i < len(series.Samples); i++ {
			if series.Samples[i].Time <= series.Samples[i-1].Time {
				return r, model.Fail(model.Corrupt)
			}
		}
		picked, e := s.pickSamples(series, node, window, bounds, at, opts)
		if e != nil {
			return r, e
		}
		if len(picked) == 0 {
			continue
		}
		retained := value.Series{Project: series.Project, Labels: value.CloneLabels(series.Labels), Samples: picked}
		if window == nil {
			r.Vector = append(r.Vector, retained)
		} else {
			r.Matrix = append(r.Matrix, retained)
		}
	}
	if e = s.account.Check(s.ctx); e != nil {
		return r, e
	}
	if e = checkDuplicates(r.Vector); e != nil {
		return r, e
	}
	return r, checkDuplicates(r.Matrix)
}

// stamped locates one raw sample of a series by timestamp.
type stamped struct {
	t     int64
	index int
}

// windowSamples lists the non-stale samples with a timestamp in (from, through].
func windowSamples(samples []value.Sample, from, through int64) []stamped {
	var out []stamped
	for i, p := range samples {
		if t := int64(p.Time); t > from && t <= through && !p.Stale() {
			out = append(out, stamped{t, i})
		}
	}
	return out
}

// pickSamples applies the selector semantics to one series and returns the
// retained samples (nil when the series contributes nothing).
func (s *evaluationState) pickSamples(series value.Series, node, window *Node, b selectionBounds, at model.UnixNano, opts selectOptions) ([]value.Sample, error) {
	samples := series.Samples
	switch {
	case window == nil && node.Extension == "smoothed":
		return s.smoothInstant(series, node, b, at)
	case window == nil:
		// The newest sample at or before the evaluation time stands in for the
		// series unless it is stale or a full lookback (exclusive) old.
		for i := len(samples) - 1; i >= 0; i-- {
			t := int64(samples[i].Time)
			if t > b.target {
				continue
			}
			if t <= b.from || samples[i].Stale() {
				break
			}
			out, err := s.retain(series, []stamped{{t, i}}, 0)
			if err != nil {
				return nil, err
			}
			if !opts.preserveTime {
				out[0].Time = at
			}
			return out, nil
		}
		return nil, nil
	}
	picked := windowSamples(samples, b.from, b.through)
	if len(picked) == 0 {
		return nil, nil
	}
	if window.Extension == "" || opts.functionArg {
		return s.retain(series, picked, 0)
	}
	return s.extendWindow(series, window, picked, b)
}

// retain copies the picked samples into the result, with cloned start
// timestamps and float histograms. spare is the number of additional samples
// the caller will add; their accounting is reserved here.
func (s *evaluationState) retain(series value.Series, picked []stamped, spare int) ([]value.Sample, error) {
	cost := value.SeriesBytes(value.Series{Labels: series.Labels}) + int64(spare)*value.SampleBytes(value.Sample{})
	for _, p := range picked {
		cost += value.SampleBytes(series.Samples[p.index])
	}
	if e := s.reserve(cost); e != nil {
		return nil, e
	}
	out := make([]value.Sample, len(picked), len(picked)+spare)
	for i, p := range picked {
		sample := series.Samples[p.index]
		if sample.StartTimestamp != nil {
			start := *sample.StartTimestamp
			sample.StartTimestamp = &start
		}
		if sample.Histogram != nil {
			if (sample.Histogram.Integer == nil) == (sample.Histogram.Float == nil) {
				return nil, model.Fail(model.Corrupt)
			}
			// Both pinned language profiles materialize AtFloatHistogram here.
			// Native scans retain exact integers; this is the explicit semantic
			// conversion boundary, not an unsupported-kind fallback or raw rewrite.
			histogram := value.FloatHistogram(*sample.Histogram)
			sample.Histogram = &model.NativeHistogram{Float: &histogram}
		}
		out[i] = sample
	}
	return out, nil
}

// interpolateFloat is linear interpolation between two samples at nanosecond
// times. A counter that decreased between them is modelled as restarting from
// zero. The time fractions are taken in milliseconds, the unit of the pinned
// engines, so the rounding of the product matches theirs.
func interpolateFloat(t1 int64, y1 float64, t2 int64, y2 float64, t int64, counter bool) float64 {
	if counter && y2 < y1 {
		y1 = 0
	}
	return y1 + (y2-y1)*(float64(t-t1)/1e6)/(float64(t2-t1)/1e6)
}

// smoothInstant evaluates an instant selector with the smoothed modifier: the
// value at the evaluation time is interpolated between the samples around it.
func (s *evaluationState) smoothInstant(series value.Series, node *Node, b selectionBounds, at model.UnixNano) ([]value.Sample, error) {
	picked := windowSamples(series.Samples, b.from, b.through)
	if len(picked) == 0 {
		return nil, nil
	}
	histograms := 0
	for _, p := range picked {
		if series.Samples[p.index].Histogram != nil {
			histograms++
		}
	}
	if histograms > 0 && histograms < len(picked) {
		s.annotations = appendAnnotations(s.annotations, rangeDiagnostic(node.Range, "MixedFloatsHistogramsWarning"))
		return nil, nil
	}
	next := sort.Search(len(picked), func(i int) bool { return picked[i].t >= b.target })
	var chosen []stamped
	switch {
	case next < len(picked) && picked[next].t == b.target:
		chosen = []stamped{picked[next]}
	case next > 0 && next < len(picked):
		chosen = []stamped{picked[next-1], picked[next]}
	case next > 0:
		chosen = []stamped{picked[next-1]}
	default:
		return nil, nil
	}
	out, err := s.retain(series, chosen, 0)
	if err != nil {
		return nil, err
	}
	result := out[len(out)-1]
	if len(chosen) == 2 {
		result = out[0]
	}
	if histograms == 0 {
		if len(chosen) == 2 {
			f := interpolateFloat(chosen[0].t, functionFloat(out[0]), chosen[1].t, functionFloat(out[1]), b.target, false)
			result.Float = floatBitsOf(f)
		}
	} else if len(chosen) == 2 {
		counter := histogramHint(*out[0].Histogram) != "gauge" || histogramHint(*out[1].Histogram) != "gauge"
		h, reasons, ok := interpolateHistogram(out[0], chosen[0].t, out[1], chosen[1].t, b.target, counter, s.plan.Profile.ID)
		for _, reason := range reasons {
			s.annotations = appendAnnotations(s.annotations, rangeDiagnostic(node.Range, reason))
		}
		if !ok {
			return nil, nil
		}
		result.Histogram = &h
	} else if chosen[0].t != b.target {
		// Carried forward: the hint described the step to a sample no longer used.
		carried := value.CloneHistogram(*result.Histogram)
		carried.Float.ResetHint = "unknown"
		result.Histogram = &carried
	}
	result.Time = at
	result.StartTimestamp = nil
	return []value.Sample{result}, nil
}

// extendWindow builds the boundary samples of a bare matrix selector with the
// anchored or smoothed modifier. The result starts at the (left-open) range
// start and ends at the range end, both synthesized from the neighbouring
// samples; interior samples are kept as they are.
func (s *evaluationState) extendWindow(series value.Series, window *Node, picked []stamped, b selectionBounds) ([]value.Sample, error) {
	for _, p := range picked {
		if series.Samples[p.index].Histogram != nil {
			return nil, &syntax.LanguageError{Code: "range.extension-histogram", Category: "execution", SafeMessage: window.Extension + " modifier is not supported with histograms"}
		}
	}
	smoothed := window.Extension == "smoothed"
	lo, hi := b.left, b.target
	valueOf := func(i int) float64 { return functionFloat(series.Samples[picked[i].index]) }
	first, last := extendedBounds(func(i int) int64 { return picked[i].t }, len(picked), lo, hi, smoothed)
	if picked[last].t <= lo {
		return nil, nil
	}
	left, right := valueOf(first), valueOf(last)
	if smoothed && picked[first].t < lo {
		left = interpolateFloat(picked[first].t, valueOf(first), picked[first+1].t, valueOf(first+1), lo, false)
	}
	if smoothed && last > 0 && picked[last].t > hi {
		right = interpolateFloat(picked[last-1].t, valueOf(last-1), picked[last].t, valueOf(last), hi, false)
	}
	if picked[first].t <= lo {
		first++
	}
	if picked[last].t >= hi {
		last--
	}
	interior := []stamped{}
	if first <= last {
		interior = picked[first : last+1]
	}
	retained, err := s.retain(series, interior, 2)
	if err != nil {
		return nil, err
	}
	out := make([]value.Sample, 0, len(retained)+2)
	out = append(out, value.Sample{Time: model.UnixNano(lo), Float: floatBitsOf(left)})
	out = append(out, retained...)
	return append(out, value.Sample{Time: model.UnixNano(hi), Float: floatBitsOf(right)}), nil
}

func floatBitsOf(f float64) model.FloatBits { return model.FloatBits(math.Float64bits(f)) }

// rangeDiagnostic is an annotation attached to an explicit source range.
func rangeDiagnostic(r syntax.SourceRange, id string) syntax.Diagnostic {
	return syntax.Diagnostic{Category: id, Range: r, SafeMessage: functionAnnotationText(id)}
}

// evalFunctionWindow evaluates a range selector that is the argument of a
// function; see selectOptions.functionArg.
func (s *evaluationState) evalFunctionWindow(expr TypedExpr, at model.UnixNano) (value.Result, error) {
	if e := s.account.Check(s.ctx); e != nil {
		return value.Result{}, e
	}
	mark := s.reserved
	n := expr.Expr.(*Node)
	r, err := s.selectMetric(n.Children[0].(*Node), n, at, selectOptions{functionArg: true})
	s.account.Release(s.reserved - mark)
	s.reserved = mark
	if err == nil {
		err = s.reserve(value.ResultBytes(r))
	}
	return r, err
}
