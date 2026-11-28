// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"io"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// A range evaluation asks every selector the same question once per grid step,
// each time about a window that overlaps its neighbours'. Answering each from
// its own storage scan reads every stored sample (window / step) times over. The
// scope below reads the union of the windows of one selector once, keeps the
// samples in memory and lets selectMetric cut each step's window out of them.
//
// The sharing is an optimisation of the reads only: the cut is exactly what the
// scan of that step's window would have delivered (the scan is half-open
// [from+1, through+1) and so is the cut), every check, budget and diagnostic of
// the per-step path still runs per step on that cut, and whenever the shared
// read is not provably the same thing the selector is evaluated the per-step way
// (a failed or oversized union read, a gap between consecutive windows, a
// selector evaluated off the grid). The union read is charged to the memory
// account like the scan it replaces, and is released in favour of the per-step
// path the moment any other reservation would otherwise fail, so a query that
// fitted its account before still fits it.

// rangeScope is the grid whose selectors share reads: the query's grid, or the
// grid of one subquery invocation.
type rangeScope struct {
	first, last model.UnixNano
	step        int64
	entries     map[*Node]*rangeEntry
	// subqueries are the scopes of the subqueries evaluated at the steps of this
	// scope, one per subquery node: nil when their invocations do not form a
	// single contiguous grid.
	subqueries map[*Node]*rangeScope
}

// rangeEntry is the shared read of one selector node. A dead entry sends the
// selector down the per-step path.
type rangeEntry struct {
	dead bool
	// from and through bound the timestamps held: (from, through].
	from, through int64
	series        []value.Series
	meta          value.Result
	bytes         int64
}

func newRangeScope(first, last model.UnixNano, step int64) *rangeScope {
	return &rangeScope{first: first, last: last, step: step, entries: map[*Node]*rangeEntry{}, subqueries: map[*Node]*rangeScope{}}
}

// enterScope makes the grid [first, last] the scope of the selectors evaluated
// until the returned function runs. Fewer than two steps share nothing: one
// evaluation reads each selector once already.
func (s *evaluationState) enterScope(first, last model.UnixNano, step int64) (leave func()) {
	outer, mark := s.scope, len(s.scopes)
	if !s.shareScans || first == last {
		s.scope = nil
	} else {
		s.scope = newRangeScope(first, last, step)
		s.scopes = append(s.scopes, s.scope)
	}
	return func() {
		s.dropScopes(mark)
		s.scope = outer
	}
}

// enterSubquery is enterScope for one invocation of the subquery node n, whose
// inner grid is [first, last] with the given step. The invocations at the steps of
// the enclosing scope evaluate the same selectors over inner grids that overlap
// or abut when the enclosing step is not longer than the subquery range, so
// together they form one grid and one shared read serves all of them.
func (s *evaluationState) enterSubquery(n *Node, first, last model.UnixNano, step, width int64) (leave func()) {
	outer := s.scope
	if outer != nil && s.shareScans && s.unshared == 0 {
		inner, known := outer.subqueries[n]
		if !known {
			inner = s.subquerySpan(outer, n, step, width)
			outer.subqueries[n] = inner
			if inner != nil {
				s.scopes = append(s.scopes, inner)
			}
		}
		if inner != nil && first >= inner.first && last <= inner.last && inner.step == step {
			s.scope = inner
			return func() { s.scope = outer }
		}
	}
	return s.enterScope(first, last, step)
}

// subquerySpan is the grid of every inner evaluation of the subquery n over the
// steps of outer: the points of the subquery's step multiples in
// (first target - width, last target]. It is nil unless the invocations touch.
func (s *evaluationState) subquerySpan(outer *rangeScope, n *Node, step, width int64) *rangeScope {
	firstTarget, err := selectorTime(n, outer.first, s.plan)
	if err != nil {
		return nil
	}
	lastTarget, err := selectorTime(n, outer.last, s.plan)
	if err != nil || firstTarget != lastTarget && outer.step > width {
		return nil
	}
	left, err := checkedSub(firstTarget, width)
	if err != nil {
		return nil
	}
	first, err := firstSubqueryPoint(left, step)
	if err != nil {
		return nil
	}
	last := lastTarget - ((lastTarget%step)+step)%step
	if last <= first {
		return nil
	}
	return newRangeScope(model.UnixNano(first), model.UnixNano(last), step)
}

// dropScopes releases the scopes entered since the stack had the given length.
func (s *evaluationState) dropScopes(mark int) {
	for _, sc := range s.scopes[mark:] {
		for _, e := range sc.entries {
			s.dropEntry(e)
		}
	}
	s.scopes = s.scopes[:mark]
}

func (s *evaluationState) dropEntry(e *rangeEntry) {
	e.dead = true
	e.series = nil
	if e.bytes > 0 {
		s.rawAccount.Release(e.bytes)
		e.bytes = 0
	}
}

// releaseScans drops every shared read held; it reports whether any held memory.
func (s *evaluationState) releaseScans() bool {
	released := false
	for _, sc := range s.scopes {
		for _, e := range sc.entries {
			if e.bytes > 0 {
				released = true
				s.dropEntry(e)
			}
		}
	}
	return released
}

// scanAccount is the account the evaluation and everything it calls charges. A
// quota failure first gives back the memory of the shared reads, which the
// per-step path never held, and retries once.
type scanAccount struct {
	value.Account
	s *evaluationState
}

func (a scanAccount) Reserve(n int64) error {
	err := a.Account.Reserve(n)
	var fault *model.Fault
	if err != nil && errors.As(err, &fault) && fault.Code == model.Quota && a.s.releaseScans() {
		err = a.Account.Reserve(n)
	}
	return err
}

// sharedScan returns the shared read that serves the selector at the evaluation
// time, building it on first use, or nil when the selector must be evaluated
// the per-step way.
func (s *evaluationState) sharedScan(sel, node, window *Node, at model.UnixNano, b selectionBounds, opts selectOptions) *rangeEntry {
	sc := s.scope
	if sc == nil || s.unshared > 0 || opts.unshared || at < sc.first || at > sc.last || (int64(at)-int64(sc.first))%sc.step != 0 {
		return nil
	}
	e := sc.entries[node]
	if e == nil {
		e = &rangeEntry{}
		sc.entries[node] = e
		s.buildShared(e, sc, sel, node, window)
	}
	if e.dead || b.from < e.from || b.through > e.through {
		return nil
	}
	return e
}

// sharedGapFactor bounds the gap between the windows of consecutive steps that a shared read still covers, as a
// multiple of the width of a window: the union then holds at most that many times the rows the steps read, one
// scan instead of one per step. Windows further apart than that are read the per-step way, where the rows are
// the steps' own.
const sharedGapFactor = 8

// buildShared reads the union of the selector's windows over the scope's grid.
// Any irregularity (an error, a quota failure, data the per-step path would
// reject) leaves the entry dead: the per-step path then meets and reports it at
// the very step it belongs to.
func (s *evaluationState) buildShared(e *rangeEntry, sc *rangeScope, sel, node, window *Node) {
	e.dead = true
	firstTime, err := selectorTime(node, sc.first, s.plan)
	if err != nil {
		return
	}
	lastTime, err := selectorTime(node, sc.last, s.plan)
	if err != nil {
		return
	}
	first, err := s.selectionBounds(node, window, firstTime)
	if err != nil {
		return
	}
	last, err := s.selectionBounds(node, window, lastTime)
	if err != nil {
		return
	}
	// The windows of consecutive steps must touch, or be close enough that the union costs less than a scan
	// per step (sharedGapFactor): a union that read data no step does would charge for it. A selector with a
	// fixed time (@) has one window for all steps.
	span, err := checkedSub(first.through, first.from)
	if err != nil || firstTime != lastTime && sc.step/sharedGapFactor > span {
		return
	}
	e.from, e.through = min(first.from, last.from), max(first.through, last.through)
	req, matchers, err := s.selectionRequest(sel, e.from, e.through)
	if err != nil {
		return
	}
	it, err := s.src.Select(s.ctx, req)
	if err != nil {
		return
	}
	closed := false
	defer func() {
		if !closed {
			_ = it.Close()
		}
	}()
	var series []value.Series
	var bytes int64
	for {
		next, err := it.Next(s.ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return
		}
		if s.account.Check(s.ctx) != nil || next.Project != s.src.ProjectID() {
			return
		}
		ok, err := matchers.Match(s.ctx, next.Labels)
		if err != nil {
			return
		}
		if !ok {
			continue
		}
		samples := next.Samples
		for i := range samples {
			if i > 0 && samples[i].Time <= samples[i-1].Time {
				return
			}
			if samples[i].Histogram != nil && value.CheckHistogramLayout(*samples[i].Histogram) != nil {
				return
			}
		}
		// A source that ignores the window is cut to it: nothing else is ever read.
		lo := sort.Search(len(samples), func(i int) bool { return int64(samples[i].Time) > e.from })
		hi := lo + sort.Search(len(samples)-lo, func(i int) bool { return int64(samples[lo+i].Time) > e.through })
		if lo == hi {
			continue
		}
		next.Samples = samples[lo:hi]
		bytes += value.SeriesBytes(value.Series{Labels: next.Labels})
		for _, p := range next.Samples {
			bytes += value.SampleBytes(p)
		}
		series = append(series, next)
	}
	meta := value.Result{Partial: it.Partial(), Watermarks: it.Watermarks()}
	closed = true
	if it.Close() != nil {
		return
	}
	// The scan released its own charge on Close; the shared read is charged for as
	// long as it is held.
	if s.account.Reserve(bytes) != nil {
		return
	}
	e.dead, e.series, e.meta, e.bytes = false, series, meta, bytes
}

// selectShared answers one step from a shared read: for every series, the samples
// of the step's window, picked and retained exactly as for a per-step scan.
func (s *evaluationState) selectShared(e *rangeEntry, node, window *Node, at model.UnixNano, b selectionBounds, opts selectOptions) (r value.Result, err error) {
	// The entry may be dropped by a reservation made while this step runs; the
	// slice it hands out stays valid for the step.
	series, meta := e.series, e.meta
	defer func() {
		value.InheritMetadata(&r, meta)
		value.InheritMetadata(&s.metadata, meta)
	}()
	r.Type = "vector"
	if window != nil {
		r.Type = "matrix"
	}
	for i := range series {
		held := &series[i]
		lo := sort.Search(len(held.Samples), func(i int) bool { return int64(held.Samples[i].Time) > b.from })
		hi := lo + sort.Search(len(held.Samples)-lo, func(i int) bool { return int64(held.Samples[lo+i].Time) > b.through })
		if lo == hi {
			continue // the per-step scan would not have delivered this series
		}
		if err = s.account.Check(s.ctx); err != nil {
			return r, err
		}
		cut := value.Series{Project: held.Project, Labels: held.Labels, Samples: held.Samples[lo:hi]}
		picked, err := s.pickSamples(cut, node, window, b, at, opts)
		if err != nil {
			return r, err
		}
		if len(picked) == 0 {
			continue
		}
		retained := value.Series{Project: cut.Project, Labels: value.CloneLabels(cut.Labels), Samples: picked}
		if window == nil {
			r.Vector = append(r.Vector, retained)
		} else {
			r.Matrix = append(r.Matrix, retained)
		}
	}
	if err = s.account.Check(s.ctx); err != nil {
		return r, err
	}
	if err = checkDuplicates(r.Vector); err != nil {
		return r, err
	}
	return r, checkDuplicates(r.Matrix)
}

// selectionRequest builds the storage request for the timestamps in (from, through]
// and the matchers the selector's series are filtered with.
func (s *evaluationState) selectionRequest(sel *Node, from, through int64) (scan.MetricSelection, *scan.MatcherSet, error) {
	var req scan.MetricSelection
	// The lower bound is exclusive: the storage request starts right after it.
	start, e := checkedAdd(from, 1)
	if e != nil {
		return req, nil, e
	}
	end, e := checkedAdd(through, 1)
	if e != nil {
		return req, nil, e
	}
	req = scan.MetricSelection{Start: model.UnixNano(start), End: model.UnixNano(end), Profile: s.plan.Profile, Account: s.account}
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
				return req, nil, e
			}
			break
		}
	}
	matchers, e := scan.CompileMatchers(s.ctx, req)
	return req, matchers, e
}
