// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package traces

import (
	"bytes"
	"cmp"
	"errors"
	"math"
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
)

// Analysis bounds. Input past either bound is refused with a typed error, never
// truncated into a plausible shorter trace.
const (
	MaxSpans = 100_000
	MaxDepth = 10_000
)

// Typed refusals of CriticalPath.
var (
	ErrNoSpans      = errors.New("traces: no spans")
	ErrTooManySpans = errors.New("traces: too many spans")
	ErrTooDeep      = errors.New("traces: trace too deep")
	ErrMixedTraces  = errors.New("traces: spans belong to more than one trace")
	ErrInvalidSpan  = errors.New("traces: span without trace or span identity")
)

// Bounds is an observed duration interval in nanoseconds. It is evidence, not a
// measurement: Min <= Max always and Known is false when no interval could be
// derived (open span, end before start).
type Bounds struct {
	Known bool        `json:"known"`
	Min   model.Int64 `json:"min_ns"`
	Max   model.Int64 `json:"max_ns"`
	// Basis is "same_domain_monotonic" (exact elapsed within one clock domain) or
	// "wall_clock_with_uncertainty" (the two stamps are in unlike domains).
	Basis string `json:"basis,omitempty"`
}

// SpanReport is one span as recorded plus what the analysis can and cannot say
// about it.
type SpanReport struct {
	ID         model.SpanID  `json:"span_id"`
	Parent     *model.SpanID `json:"parent_id"`
	Kind       string        `json:"span_kind"`
	Operation  string        `json:"operation"`
	Status     string        `json:"status"`
	Dependency string        `json:"dependency_alias,omitempty"`
	StartWall  model.Int64   `json:"start_wall_ns"`
	EndWall    *model.Int64  `json:"end_wall_ns"`
	Duration   Bounds        `json:"duration"`
	// Flags is a sorted closed vocabulary: open, end_before_start,
	// cross_domain_duration, dependency_boundary, cancelled, incomplete, async,
	// duplicate_id, in_cycle, orphan.
	Flags             []string     `json:"flags"`
	SampleProbability float64      `json:"sample_probability"`
	SampleDecision    string       `json:"sample_decision"`
	Job               *model.ID    `json:"job_id,omitempty"`
	Replay            *model.ID    `json:"replay_id,omitempty"`
	Profile           *model.ID    `json:"profile_id,omitempty"`
	Links             []LinkReport `json:"links"`
}

// LinkReport is an explicit span link. A link is an asynchronous causal
// reference: it never extends a synchronous duration. Resolved is true only when
// the linked span is in this trace's analyzed set.
type LinkReport struct {
	Trace     model.ID     `json:"trace_id"`
	Span      model.SpanID `json:"span_id"`
	SameTrace bool         `json:"same_trace"`
	Resolved  bool         `json:"resolved"`
}

// Segment is one span on a critical path. Self is the part of the span's own
// duration not covered by path children. Ambiguous marks a span that is one of
// several indistinguishable candidates under clock uncertainty.
type Segment struct {
	Span      model.SpanID `json:"span_id"`
	Depth     int          `json:"depth"`
	Self      Bounds       `json:"self"`
	Ambiguous bool         `json:"ambiguous"`
	Parallel  int          `json:"parallel_siblings_off_path"`
	Async     int          `json:"async_children_off_path"`
}

// TreePath is the analysis of one causal tree: a real root, or an orphan whose
// parent is missing, ambiguous or corrupt.
type TreePath struct {
	Root     model.SpanID `json:"root_span_id"`
	Orphan   bool         `json:"orphan"`
	Duration Bounds       `json:"duration"`
	Segments []Segment    `json:"segments"`
}

// EdgeIssue is a missing or ambiguous causal edge. Kind is closed:
// missing_parent, parent_ambiguous, parent_in_cycle, cycle, duplicate_span_id,
// multiple_roots, no_root, sequential_order_uncertain, critical_branch_ambiguous,
// link_unresolved, link_foreign_trace.
type EdgeIssue struct {
	Kind  string         `json:"kind"`
	Span  *model.SpanID  `json:"span_id,omitempty"`
	Other []model.SpanID `json:"other_span_ids,omitempty"`
	Count int            `json:"count,omitempty"`
}

// ClockIssue reports a child whose recorded times fall outside its parent's.
// Kind is starts_before_parent | ends_after_parent. Certain is true only when no
// clock uncertainty could explain it; a possible one is cross-host skew. Wall
// clocks never reorder causality: the parent edge stays the parent edge.
type ClockIssue struct {
	Span          model.SpanID `json:"span_id"`
	Parent        model.SpanID `json:"parent_id"`
	Kind          string       `json:"kind"`
	Certain       bool         `json:"certain"`
	CrossDomain   bool         `json:"cross_domain"`
	UncertaintyNS model.Int64  `json:"uncertainty_ns"`
}

// Sampling summarizes head-sampling evidence of the spans that are present.
type Sampling struct {
	Kept           int     `json:"kept"`
	Dropped        int     `json:"dropped"`
	MinProbability float64 `json:"min_probability"`
	Sampled        bool    `json:"sampled"` // some span carries probability < 1
	Invalid        int     `json:"invalid_probability"`
}

// PathResult is the full analysis. Observed is a bound over the whole trace,
// never an authoritative total.
type PathResult struct {
	Trace        model.ID     `json:"trace_id"`
	SpanCount    int          `json:"span_count"`
	Spans        []SpanReport `json:"spans"`
	Trees        []TreePath   `json:"trees"`
	Observed     Bounds       `json:"observed"`
	Edges        []EdgeIssue  `json:"edges"`
	Clock        []ClockIssue `json:"clock_issues"`
	UnlikeDomain bool         `json:"unlike_clock_domains"`
	MaxUncertain model.Int64  `json:"max_uncertainty_ns"`
	Sampling     Sampling     `json:"sampling"`
	Complete     bool         `json:"complete"`
	Reasons      []string     `json:"reasons"`
}

// iv is a closed interval of nanosecond offsets.
type iv struct{ lo, hi int64 }

const maxClampedNS = int64(1) << 62

func clampU(v uint64) int64 {
	if v > uint64(maxClampedNS) {
		return maxClampedNS
	}
	return int64(v)
}

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

func satSub(a, b int64) int64 {
	if b == math.MinInt64 {
		return satAdd(satAdd(a, math.MaxInt64), 1)
	}
	return satAdd(a, -b)
}

func monoDiff(t, base uint64) int64 {
	if t >= base {
		return clampU(t - base)
	}
	return -clampU(base - t)
}

// offset places stamp t relative to base. Inside one clock domain the monotonic
// readings give an exact elapsed time; across domains monotonic readings are
// unrelated, so only the wall clocks can be compared and both stamps' declared
// uncertainty widens the interval. No wall reading is ever used inside a domain.
func offset(t, base model.TraceClock) iv {
	if t.Domain == base.Domain {
		d := monoDiff(uint64(t.Mono), uint64(base.Mono))
		return iv{d, d}
	}
	d := satSub(int64(t.Wall), int64(base.Wall))
	u := satAdd(clampU(uint64(t.Uncertainty)), clampU(uint64(base.Uncertainty)))
	return iv{satSub(d, u), satAdd(d, u)}
}

type node struct {
	span     *model.Span
	parent   int // >=0 tree parent; -1 true root; -2 ambiguous parent; -3 missing parent; -4 parent in a cycle
	inCycle  bool
	dur      Bounds
	durIV    iv
	valid    bool // a measured, non-reversed duration exists
	reversed bool
	crossDur bool
	async    bool
}

func spanLess(a, b *model.Span) int {
	if c := cmp.Compare(a.Start.Wall, b.Start.Wall); c != 0 {
		return c
	}
	if c := bytes.Compare(a.ID[:], b.ID[:]); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Start.Mono, b.Start.Mono); c != 0 {
		return c
	}
	switch {
	case a.End == nil && b.End != nil:
		return -1
	case a.End != nil && b.End == nil:
		return 1
	case a.End != nil:
		if c := cmp.Compare(a.End.Wall, b.End.Wall); c != 0 {
			return c
		}
		if c := cmp.Compare(a.End.Mono, b.End.Mono); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(a.Operation, b.Operation); c != 0 {
		return c
	}
	return cmp.Compare(a.Status, b.Status)
}

func spanDuration(s *model.Span) (n struct {
	b        Bounds
	i        iv
	valid    bool
	reversed bool
	cross    bool
}) {
	if s.End == nil {
		return n
	}
	if s.End.Domain == s.Start.Domain {
		if s.End.Mono < s.Start.Mono {
			n.reversed = true
			return n
		}
		d := monoDiff(uint64(s.End.Mono), uint64(s.Start.Mono))
		n.i, n.valid = iv{d, d}, true
		n.b = Bounds{Known: true, Min: model.Int64(d), Max: model.Int64(d), Basis: "same_domain_monotonic"}
		return n
	}
	n.cross = true
	n.i = offset(*s.End, s.Start)
	if n.i.hi < 0 {
		n.reversed = true
		return n
	}
	n.valid = true
	n.b = Bounds{Known: true, Min: model.Int64(max(0, n.i.lo)), Max: model.Int64(n.i.hi), Basis: "wall_clock_with_uncertainty"}
	return n
}

func spanIDPtr(id model.SpanID) *model.SpanID { return &id }

func sampleProb(s *model.Span) (float64, bool) {
	p := math.Float64frombits(uint64(s.SampleProbability))
	return p, !math.IsNaN(p) && p > 0 && p <= 1
}

// cand is one synchronous child eligible for the backward critical-path walk,
// positioned relative to its parent's start.
type cand struct {
	node int
	s, e iv
}

const groupScanLimit = 1024

// CriticalPath analyzes the spans of exactly one trace. It never mutates its
// input, never recurses, and never reads wall-clock order as causality: the
// parent edge decides who is whose child; times only bound durations and report
// disagreement. Spans whose parent is absent, ambiguous or corrupt form their
// own orphan trees; they never lengthen a real root.
func CriticalPath(spans []model.Span) (PathResult, error) {
	if len(spans) == 0 {
		return PathResult{}, ErrNoSpans
	}
	if len(spans) > MaxSpans {
		return PathResult{}, ErrTooManySpans
	}
	trace := spans[0].Trace
	for i := range spans {
		if spans[i].Trace == (model.ID{}) || spans[i].ID == (model.SpanID{}) {
			return PathResult{}, ErrInvalidSpan
		}
		if spans[i].Trace != trace {
			return PathResult{}, ErrMixedTraces
		}
	}
	sorted := make([]*model.Span, len(spans))
	for i := range spans {
		sorted[i] = &spans[i]
	}
	slices.SortFunc(sorted, spanLess)

	counts := make(map[model.SpanID]int, len(sorted))
	for _, s := range sorted {
		counts[s.ID]++
	}
	res := PathResult{Trace: trace, SpanCount: len(sorted), Spans: make([]SpanReport, 0, len(sorted)), Trees: []TreePath{}, Edges: []EdgeIssue{}, Clock: []ClockIssue{}, Reasons: []string{}}
	reasons := map[string]bool{}
	nodeOf := make(map[model.SpanID]int, len(sorted))
	var nodes []node
	var dupSeen = map[model.SpanID]bool{}
	reportIdx := make([]int, 0, len(sorted)) // SpanReport index per node
	domains := map[model.ClockDomain]bool{}

	// Sampling and clock inventory over every span present, duplicates included.
	res.Sampling.MinProbability = 1
	stampSeen := func(c model.TraceClock) {
		domains[c.Domain] = true
		res.MaxUncertain = max(res.MaxUncertain, model.Int64(clampU(uint64(c.Uncertainty))))
	}
	for _, s := range sorted {
		stampSeen(s.Start)
		if s.End != nil {
			stampSeen(*s.End)
		}
		if s.SampleDecision == "drop" {
			res.Sampling.Dropped++
			reasons["head_sampled"] = true
		} else {
			res.Sampling.Kept++
		}
		if p, ok := sampleProb(s); !ok {
			res.Sampling.Invalid++
			reasons["sample_probability_invalid"] = true
		} else if p < 1 {
			res.Sampling.Sampled = true
			res.Sampling.MinProbability = min(res.Sampling.MinProbability, p)
			reasons["head_sampled"] = true
		}
	}
	res.UnlikeDomain = len(domains) > 1

	reports := make([]SpanReport, 0, len(sorted))
	for _, s := range sorted {
		r := SpanReport{ID: s.ID, Kind: s.Kind, Operation: s.Operation, Status: s.Status, Dependency: s.Dependency, StartWall: model.Int64(s.Start.Wall),
			SampleDecision: s.SampleDecision, Flags: []string{}, Links: make([]LinkReport, 0, len(s.Links))}
		if s.Parent != nil {
			p := *s.Parent
			r.Parent = &p
		}
		if s.End != nil {
			w := model.Int64(s.End.Wall)
			r.EndWall = &w
		}
		r.SampleProbability = math.Float64frombits(uint64(s.SampleProbability))
		if math.IsNaN(r.SampleProbability) || math.IsInf(r.SampleProbability, 0) {
			r.SampleProbability = 0
		}
		for _, p := range []struct {
			dst **model.ID
			src *model.ID
		}{{&r.Job, s.Job}, {&r.Replay, s.Replay}, {&r.Profile, s.Profile}} {
			if p.src != nil {
				v := *p.src
				*p.dst = &v
			}
		}
		for _, l := range s.Links {
			lr := LinkReport{Trace: l.Trace, Span: l.Span, SameTrace: l.Trace == trace}
			if lr.SameTrace {
				_, lr.Resolved = counts[l.Span]
			}
			switch {
			case !lr.SameTrace:
				res.Edges = append(res.Edges, EdgeIssue{Kind: "link_foreign_trace", Span: spanIDPtr(s.ID), Other: []model.SpanID{l.Span}})
				reasons["link_foreign_trace"] = true
			case !lr.Resolved:
				res.Edges = append(res.Edges, EdgeIssue{Kind: "link_unresolved", Span: spanIDPtr(s.ID), Other: []model.SpanID{l.Span}})
				reasons["link_unresolved"] = true
			}
			r.Links = append(r.Links, lr)
		}
		switch s.Status {
		case "cancelled":
			r.Flags = append(r.Flags, "cancelled")
		case "incomplete":
			r.Flags = append(r.Flags, "incomplete")
			reasons["span_incomplete"] = true
		}
		d := spanDuration(s)
		r.Duration = d.b
		switch {
		case s.End == nil:
			r.Flags = append(r.Flags, "open")
			reasons["span_open"] = true
		case d.reversed:
			r.Flags = append(r.Flags, "end_before_start")
			reasons["end_before_start"] = true
		case d.cross:
			r.Flags = append(r.Flags, "cross_domain_duration")
		}
		reports = append(reports, r)
		if counts[s.ID] > 1 {
			reports[len(reports)-1].Flags = append(reports[len(reports)-1].Flags, "duplicate_id")
			if !dupSeen[s.ID] {
				dupSeen[s.ID] = true
				res.Edges = append(res.Edges, EdgeIssue{Kind: "duplicate_span_id", Span: spanIDPtr(s.ID), Count: counts[s.ID]})
				reasons["duplicate_span_id"] = true
			}
			continue
		}
		nodeOf[s.ID] = len(nodes)
		reportIdx = append(reportIdx, len(reports)-1)
		nodes = append(nodes, node{span: s, parent: -1, dur: d.b, durIV: d.i, valid: d.valid, reversed: d.reversed, crossDur: d.cross})
	}

	// Resolve parents.
	for i := range nodes {
		p := nodes[i].span.Parent
		switch {
		case p == nil:
		case counts[*p] > 1:
			nodes[i].parent = -2
		default:
			if j, ok := nodeOf[*p]; ok {
				nodes[i].parent = j
			} else {
				nodes[i].parent = -3
			}
		}
	}

	// Cycles: iterative colouring of the parent pointers.
	color := make([]uint8, len(nodes))
	var path []int
	for i := range nodes {
		if color[i] != 0 {
			continue
		}
		path = path[:0]
		cur := i
		for cur >= 0 && color[cur] == 0 {
			color[cur] = 1
			path = append(path, cur)
			cur = nodes[cur].parent
		}
		if cur >= 0 && color[cur] == 1 {
			k := slices.Index(path, cur)
			members := slices.Clone(path[k:])
			slices.Sort(members)
			ids := make([]model.SpanID, 0, min(len(members), 32))
			for _, m := range members {
				nodes[m].inCycle = true
				if len(ids) < 32 {
					ids = append(ids, nodes[m].span.ID)
				}
			}
			res.Edges = append(res.Edges, EdgeIssue{Kind: "cycle", Other: ids, Count: len(members)})
			reasons["cycle"] = true
		}
		for _, p := range path {
			color[p] = 2
		}
	}

	// Tree structure: children of healthy parents; everything else is a root or an
	// orphan root.
	kidCount := make([]int, len(nodes)+1)
	var roots, orphans []int
	for i := range nodes {
		n := &nodes[i]
		if n.inCycle {
			continue
		}
		switch {
		case n.parent == -1:
			roots = append(roots, i)
		case n.parent >= 0 && nodes[n.parent].inCycle:
			n.parent = -4
			orphans = append(orphans, i)
		case n.parent >= 0:
			kidCount[n.parent]++
		default:
			orphans = append(orphans, i)
		}
	}
	kidStart := make([]int, len(nodes)+1)
	for i := range nodes {
		kidStart[i+1] = kidStart[i] + kidCount[i]
	}
	kids := make([]int, kidStart[len(nodes)])
	fill := slices.Clone(kidStart[:len(nodes)])
	for i := range nodes {
		if nodes[i].parent >= 0 && !nodes[i].inCycle {
			kids[fill[nodes[i].parent]] = i
			fill[nodes[i].parent]++
		}
	}
	kidsOf := func(i int) []int { return kids[kidStart[i]:kidStart[i+1]] }

	for _, o := range orphans {
		n := &nodes[o]
		kind := "missing_parent"
		switch n.parent {
		case -2:
			kind = "parent_ambiguous"
		case -4:
			kind = "parent_in_cycle"
		}
		res.Edges = append(res.Edges, EdgeIssue{Kind: kind, Span: spanIDPtr(n.span.ID), Other: []model.SpanID{*n.span.Parent}})
		reasons[map[string]string{"missing_parent": "missing_parent", "parent_ambiguous": "parent_ambiguous", "parent_in_cycle": "cycle"}[kind]] = true
		reports[reportIdx[o]].Flags = append(reports[reportIdx[o]].Flags, "orphan")
	}
	switch {
	case len(roots) > 1:
		ids := make([]model.SpanID, 0, min(len(roots), 32))
		for _, r := range roots[:min(len(roots), 32)] {
			ids = append(ids, nodes[r].span.ID)
		}
		res.Edges = append(res.Edges, EdgeIssue{Kind: "multiple_roots", Other: ids, Count: len(roots)})
		reasons["multiple_roots"] = true
	case len(roots) == 0:
		res.Edges = append(res.Edges, EdgeIssue{Kind: "no_root"})
		reasons["no_root"] = true
	}
	for i := range nodes {
		if nodes[i].inCycle {
			reports[reportIdx[i]].Flags = append(reports[reportIdx[i]].Flags, "in_cycle")
		}
	}

	// Depth (iterative breadth-first walk) and child bookkeeping.
	treeRoots := append(slices.Clone(roots), orphans...)
	depth := make([]int, len(nodes))
	queue := slices.Clone(treeRoots)
	for head := 0; head < len(queue); head++ {
		i := queue[head]
		if depth[i] >= MaxDepth {
			return PathResult{}, ErrTooDeep
		}
		for _, k := range kidsOf(i) {
			depth[k] = depth[i] + 1
			queue = append(queue, k)
		}
	}
	for _, i := range queue {
		n := &nodes[i]
		if n.parent >= 0 {
			par := &nodes[n.parent]
			n.async = n.span.Kind == "consumer" || par.span.Kind == "producer"
			if n.async {
				reports[reportIdx[i]].Flags = append(reports[reportIdx[i]].Flags, "async")
			}
			res.Clock = append(res.Clock, clockIssues(n, par)...)
		}
		if n.span.Kind == "client" && n.span.Dependency != "" && kidStart[i] == kidStart[i+1] {
			reports[reportIdx[i]].Flags = append(reports[reportIdx[i]].Flags, "dependency_boundary")
		}
	}
	for _, c := range res.Clock {
		if c.Certain {
			reasons["clock_violation"] = true
		} else {
			reasons["clock_uncertain"] = true
		}
	}

	// Critical path per tree: explicit stack, pre-order, chronological children.
	type frame struct {
		node, depth int
		ambiguous   bool
	}
	for _, root := range treeRoots {
		tp := TreePath{Root: nodes[root].span.ID, Orphan: nodes[root].parent != -1, Duration: nodes[root].dur, Segments: []Segment{}}
		stack := []frame{{node: root}}
		for len(stack) > 0 {
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			seg, chosen := walkChildren(&nodes[f.node], nodes, kidsOf(f.node), &res, reasons)
			seg.Span, seg.Depth, seg.Ambiguous = nodes[f.node].span.ID, f.depth, f.ambiguous
			tp.Segments = append(tp.Segments, seg)
			for i := len(chosen) - 1; i >= 0; i-- {
				stack = append(stack, frame{node: chosen[i].node, depth: f.depth + 1, ambiguous: chosen[i].ambiguous})
			}
		}
		res.Trees = append(res.Trees, tp)
	}

	res.Observed = observed(res.Trees, nodes, treeRoots)

	for i := range reports {
		slices.Sort(reports[i].Flags)
	}
	res.Spans = reports
	for r := range reasons {
		res.Reasons = append(res.Reasons, r)
	}
	slices.Sort(res.Reasons)
	res.Complete = len(res.Reasons) == 0
	return res, nil
}

func clockIssues(child, parent *node) []ClockIssue {
	cross := child.span.Start.Domain != parent.span.Start.Domain
	var out []ClockIssue
	s := offset(child.span.Start, parent.span.Start)
	if s.lo < 0 {
		u := int64(0)
		if cross {
			u = satAdd(clampU(uint64(child.span.Start.Uncertainty)), clampU(uint64(parent.span.Start.Uncertainty)))
		}
		out = append(out, ClockIssue{Span: child.span.ID, Parent: parent.span.ID, Kind: "starts_before_parent", Certain: s.hi < 0, CrossDomain: cross, UncertaintyNS: model.Int64(u)})
	}
	if child.valid && parent.valid {
		e := offset(*child.span.End, parent.span.Start)
		pe := parent.durIV
		if e.hi > pe.hi {
			cross := child.span.End.Domain != parent.span.Start.Domain
			u := int64(0)
			if cross {
				u = satAdd(clampU(uint64(child.span.End.Uncertainty)), clampU(uint64(parent.span.Start.Uncertainty)))
			}
			if parent.span.End.Domain != parent.span.Start.Domain {
				u = satAdd(u, clampU(uint64(parent.span.End.Uncertainty)))
			}
			out = append(out, ClockIssue{Span: child.span.ID, Parent: parent.span.ID, Kind: "ends_after_parent", Certain: e.lo > pe.hi, CrossDomain: cross || child.span.End.Domain != parent.span.End.Domain, UncertaintyNS: model.Int64(u)})
		}
	}
	return out
}

type chosenChild struct {
	node      int
	ambiguous bool
}

// walkChildren runs the backward walk over one span's synchronous children: the
// child that (provably) ends last is on the path, then the latest-ending child
// that provably ended before that one started, and so on. Children that overlap
// are parallel work off the path; children whose order is only ambiguous under
// clock uncertainty are all kept as ambiguous candidates, never silently ranked.
func walkChildren(n *node, nodes []node, kids []int, res *PathResult, reasons map[string]bool) (Segment, []chosenChild) {
	seg := Segment{}
	var cands []cand
	var width int64
	for _, k := range kids {
		c := &nodes[k]
		if c.async {
			seg.Async++
			continue
		}
		if !c.valid {
			continue
		}
		cd := cand{node: k, s: offset(c.span.Start, n.span.Start), e: offset(*c.span.End, n.span.Start)}
		width = max(width, satSub(cd.e.hi, cd.e.lo))
		cands = append(cands, cd)
	}
	slices.SortStableFunc(cands, func(a, b cand) int { return cmp.Compare(b.e.lo, a.e.lo) })
	used := make([]bool, len(cands))
	cursor := int64(math.MaxInt64)
	var groups [][]int // indexes into cands, reverse chronological
	for p := 0; p < len(cands); {
		for p < len(cands) && (used[p] || cands[p].e.hi > cursor) {
			p++
		}
		if p == len(cands) {
			break
		}
		best := cands[p]
		group := []int{p}
		used[p] = true
		scanned := 0
		for q := p + 1; q < len(cands) && satAdd(cands[q].e.lo, width) >= best.e.lo; q++ {
			if scanned++; scanned > groupScanLimit {
				break
			}
			if used[q] || cands[q].e.hi > cursor || cands[q].e.hi < best.e.lo {
				continue
			}
			used[q] = true
			group = append(group, q)
		}
		next := cands[group[0]].s.lo
		for _, g := range group[1:] {
			next = min(next, cands[g].s.lo)
		}
		cursor = next
		groups = append(groups, group)
		p++
	}

	var chosen []chosenChild
	var coverLo, coverHi int64
	for gi := len(groups) - 1; gi >= 0; gi-- {
		g := groups[gi]
		slices.SortFunc(g, func(a, b int) int { return cmp.Compare(cands[a].node, cands[b].node) })
		lo, hi := int64(math.MaxInt64), int64(0)
		for _, ci := range g {
			d := nodes[cands[ci].node].dur
			lo, hi = min(lo, int64(d.Min)), max(hi, int64(d.Max))
			chosen = append(chosen, chosenChild{node: cands[ci].node, ambiguous: len(g) > 1})
		}
		coverLo, coverHi = satAdd(coverLo, lo), satAdd(coverHi, hi)
		if len(g) > 1 {
			ids := make([]model.SpanID, 0, min(len(g), 16))
			for _, ci := range g[:min(len(g), 16)] {
				ids = append(ids, nodes[cands[ci].node].span.ID)
			}
			res.Edges = append(res.Edges, EdgeIssue{Kind: "critical_branch_ambiguous", Span: spanIDPtr(n.span.ID), Other: ids, Count: len(g)})
			reasons["critical_branch_ambiguous"] = true
		}
	}
	off, uncertain := 0, 0
	for i, c := range cands {
		if used[i] {
			continue
		}
		off++
		if c.e.lo <= cursor && c.e.hi > cursor {
			uncertain++
		}
	}
	seg.Parallel = off
	if uncertain > 0 {
		res.Edges = append(res.Edges, EdgeIssue{Kind: "sequential_order_uncertain", Span: spanIDPtr(n.span.ID), Count: uncertain})
		reasons["sequential_order_uncertain"] = true
	}
	if n.valid {
		seg.Self = Bounds{Known: true, Min: model.Int64(max(0, satSub(int64(n.dur.Min), coverHi))), Max: model.Int64(max(0, satSub(int64(n.dur.Max), coverLo))), Basis: n.dur.Basis}
	}
	return seg, chosen
}

// observed bounds the whole trace. One tree: that tree's own interval. Several
// trees (several roots, orphans): the longest tree is a lower bound and the
// wall-clock envelope, widened by every stamp's uncertainty, an upper bound. An
// unmeasured tree makes the trace unbounded rather than guessed.
func observed(trees []TreePath, nodes []node, roots []int) Bounds {
	if len(trees) == 0 {
		return Bounds{}
	}
	if len(trees) == 1 {
		return trees[0].Duration
	}
	var lo int64
	first, last := int64(math.MaxInt64), int64(math.MinInt64)
	for i, t := range trees {
		if !t.Duration.Known {
			return Bounds{}
		}
		lo = max(lo, int64(t.Duration.Min))
		r := nodes[roots[i]].span
		su := clampU(uint64(r.Start.Uncertainty))
		eu := clampU(uint64(r.End.Uncertainty))
		first = min(first, satSub(int64(r.Start.Wall), su))
		last = max(last, satAdd(int64(r.End.Wall), eu))
	}
	hi := max(lo, satSub(last, first))
	return Bounds{Known: true, Min: model.Int64(lo), Max: model.Int64(hi), Basis: "wall_clock_with_uncertainty"}
}
