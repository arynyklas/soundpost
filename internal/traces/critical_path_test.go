// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package traces_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"runtime/debug"
	"slices"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/traces"
)

const ms = int64(1_000_000)

var testTrace = model.ID{0: 0xAA, 15: 1}

func sid(n uint64) model.SpanID {
	var s model.SpanID
	binary.BigEndian.PutUint64(s[:], n)
	return s
}

func domain(d int) model.ClockDomain {
	return model.ClockDomain{Host: model.ID{0: byte(d), 15: 7}, Boot: model.ID{0: 1}, Runtime: model.ID{0: 2}}
}

// stamp builds a clock stamp. Monotonic readings of unlike domains are
// deliberately unrelated (a different origin per domain), wall clocks are shared.
func stamp(dom int, atMs int64, uncertaintyMs int64) model.TraceClock {
	return model.TraceClock{
		Wall:        model.UnixNano(1_700_000_000_000_000_000 + atMs*ms),
		Mono:        model.MonoNano(uint64(dom+1)*7_000_000_000_000 + uint64(atMs*ms)),
		Domain:      domain(dom),
		Uncertainty: model.MonoNano(uncertaintyMs * ms),
	}
}

func span(id, parent uint64, start, end int64, dom int) model.Span {
	e := stamp(dom, end, 0)
	s := model.Span{Trace: testTrace, ID: sid(id), Kind: "internal", Operation: "op", Start: stamp(dom, start, 0), End: &e, Status: "ok", SampleProbability: model.FloatBits(math.Float64bits(1)), SampleDecision: "keep"}
	if parent != 0 {
		p := sid(parent)
		s.Parent = &p
	}
	return s
}

func must(t *testing.T, spans []model.Span) traces.PathResult {
	t.Helper()
	r, err := traces.CriticalPath(spans)
	if err != nil {
		t.Fatalf("CriticalPath: %v", err)
	}
	return r
}

func pathIDs(tp traces.TreePath) []model.SpanID {
	out := make([]model.SpanID, len(tp.Segments))
	for i, s := range tp.Segments {
		out[i] = s.Span
	}
	return out
}

func wantPath(t *testing.T, tp traces.TreePath, ids ...uint64) {
	t.Helper()
	want := make([]model.SpanID, len(ids))
	for i, id := range ids {
		want[i] = sid(id)
	}
	if !slices.Equal(pathIDs(tp), want) {
		t.Fatalf("critical path = %x, want %x", pathIDs(tp), want)
	}
}

func hasEdge(r traces.PathResult, kind string) bool {
	return slices.ContainsFunc(r.Edges, func(e traces.EdgeIssue) bool { return e.Kind == kind })
}
func hasReason(r traces.PathResult, reason string) bool { return slices.Contains(r.Reasons, reason) }
func report(t *testing.T, r traces.PathResult, id uint64) traces.SpanReport {
	t.Helper()
	for _, s := range r.Spans {
		if s.ID == sid(id) {
			return s
		}
	}
	t.Fatalf("no span report %d", id)
	return traces.SpanReport{}
}
func flagged(s traces.SpanReport, f string) bool { return slices.Contains(s.Flags, f) }

func TestCriticalPathConcurrentAndUncertain(t *testing.T) {
	// 100 ms root, concurrent 70 ms and 40 ms branches: never summed to 110 ms.
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 70, 0), span(3, 1, 0, 40, 0)})
	if len(r.Trees) != 1 {
		t.Fatalf("trees = %d", len(r.Trees))
	}
	tp := r.Trees[0]
	wantPath(t, tp, 1, 2)
	if tp.Duration != (traces.Bounds{Known: true, Min: model.Int64(100 * ms), Max: model.Int64(100 * ms), Basis: "same_domain_monotonic"}) {
		t.Fatalf("root duration = %+v", tp.Duration)
	}
	if got := tp.Segments[0].Self; !got.Known || got.Min != model.Int64(30*ms) || got.Max != model.Int64(30*ms) {
		t.Fatalf("root self = %+v, want exactly 30 ms (100-70), not 100-110", got)
	}
	if tp.Segments[0].Parallel != 1 {
		t.Fatalf("parallel off-path = %d, want 1", tp.Segments[0].Parallel)
	}
	if r.Observed.Min != model.Int64(100*ms) || r.Observed.Max != model.Int64(100*ms) || !r.Complete || len(r.Reasons) != 0 {
		t.Fatalf("observed=%+v complete=%v reasons=%v", r.Observed, r.Complete, r.Reasons)
	}
}

func TestCriticalPathSequentialChildrenChain(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 30, 0), span(3, 1, 30, 100, 0)})
	wantPath(t, r.Trees[0], 1, 2, 3)
	if s := r.Trees[0].Segments[0].Self; s.Min != 0 || s.Max != 0 {
		t.Fatalf("root self = %+v, want 0 (children cover the root)", s)
	}
}

func TestCriticalPathOverlappingSiblings(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 50, 0), span(3, 1, 20, 100, 0)})
	wantPath(t, r.Trees[0], 1, 3)
	if r.Trees[0].Segments[0].Parallel != 1 {
		t.Fatalf("overlapping sibling must be off-path parallel work: %+v", r.Trees[0].Segments[0])
	}
	if s := r.Trees[0].Segments[0].Self; s.Min != model.Int64(20*ms) || s.Max != model.Int64(20*ms) {
		t.Fatalf("root self = %+v, want 20 ms", s)
	}
}

func TestCriticalPathAsyncFanOutFanInAndLinks(t *testing.T) {
	consumer := span(5, 1, 20, 300, 0) // outlives the request
	consumer.Kind = "consumer"
	other := span(6, 0, 400, 500, 1) // asynchronous job in its own tree
	other.Links = []model.SpanLink{{Trace: testTrace, Span: sid(1)}, {Trace: testTrace, Span: sid(99)}, {Trace: model.ID{0: 9}, Span: sid(1)}}
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 10, 60, 0), span(3, 1, 10, 90, 0), span(4, 1, 10, 50, 0), consumer, other})
	wantPath(t, r.Trees[0], 1, 3)
	if r.Trees[0].Segments[0].Async != 1 || r.Trees[0].Segments[0].Parallel != 2 {
		t.Fatalf("segment = %+v, want 1 async and 2 parallel off path", r.Trees[0].Segments[0])
	}
	if r.Trees[0].Duration.Max != model.Int64(100*ms) {
		t.Fatalf("async consumer extended the synchronous request: %+v", r.Trees[0].Duration)
	}
	if !flagged(report(t, r, 5), "async") {
		t.Fatalf("consumer child not flagged async: %v", report(t, r, 5).Flags)
	}
	links := report(t, r, 6).Links
	if len(links) != 3 || !links[0].Resolved || links[1].Resolved || links[2].Resolved || links[2].SameTrace {
		t.Fatalf("links = %+v", links)
	}
	if !hasEdge(r, "link_unresolved") || !hasEdge(r, "link_foreign_trace") {
		t.Fatalf("edges = %+v", r.Edges)
	}
}

func TestCriticalPathOrphanAndMissingParent(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 70, 0), span(3, 77, 10, 30, 0)})
	if !hasEdge(r, "missing_parent") || r.Complete || !hasReason(r, "missing_parent") {
		t.Fatalf("edges=%+v complete=%v reasons=%v", r.Edges, r.Complete, r.Reasons)
	}
	if len(r.Trees) != 2 || r.Trees[0].Orphan || !r.Trees[1].Orphan || r.Trees[1].Root != sid(3) {
		t.Fatalf("trees = %+v", r.Trees)
	}
	if !flagged(report(t, r, 3), "orphan") {
		t.Fatalf("orphan not flagged")
	}
	// An orphan never joins the root's path or lengthens the root.
	wantPath(t, r.Trees[0], 1, 2)
	// Missing root: only orphans exist.
	r = must(t, []model.Span{span(2, 1, 0, 70, 0), span(3, 1, 10, 30, 0)})
	if !hasEdge(r, "no_root") || !hasEdge(r, "missing_parent") || r.Complete {
		t.Fatalf("edges=%+v", r.Edges)
	}
}

func TestCriticalPathCycleIsCorruptNotInfinite(t *testing.T) {
	// 2 -> 3 -> 2 cycle; 4 hangs below the cycle; 5 parents itself; 1 is a healthy root.
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 3, 0, 10, 0), span(3, 2, 0, 10, 0), span(4, 3, 0, 5, 0), span(5, 5, 0, 5, 0)})
	if !hasEdge(r, "cycle") || !hasEdge(r, "parent_in_cycle") || r.Complete || !hasReason(r, "cycle") {
		t.Fatalf("edges=%+v reasons=%v", r.Edges, r.Reasons)
	}
	for _, id := range []uint64{2, 3, 5} {
		if !flagged(report(t, r, id), "in_cycle") {
			t.Fatalf("span %d not flagged in_cycle", id)
		}
	}
	for _, tp := range r.Trees {
		for _, s := range tp.Segments {
			for _, id := range []uint64{2, 3, 5} {
				if s.Span == sid(id) {
					t.Fatalf("cycle member %d is on a critical path", id)
				}
			}
		}
	}
	if r.Trees[0].Root != sid(1) {
		t.Fatalf("healthy root lost: %+v", r.Trees)
	}
}

func TestCriticalPathSkewedClocksAreUncertaintyNotReordering(t *testing.T) {
	// Child on another host appears 5 ms before the parent started and 8 ms after
	// it ended, with 10 ms uncertainty on each stamp.
	child := span(2, 1, -5, 108, 1)
	child.Start.Uncertainty = model.MonoNano(10 * ms)
	e := *child.End
	e.Uncertainty = model.MonoNano(10 * ms)
	child.End = &e
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), child})
	wantPath(t, r.Trees[0], 1, 2) // causality is the parent edge, not wall time
	if len(r.Clock) != 2 {
		t.Fatalf("clock issues = %+v", r.Clock)
	}
	for _, c := range r.Clock {
		if c.Certain || !c.CrossDomain || c.UncertaintyNS != model.Int64(10*ms) {
			t.Fatalf("skew must be uncertain and cross-domain with 10 ms: %+v", c)
		}
	}
	if !r.UnlikeDomain || r.MaxUncertain != model.Int64(10*ms) {
		t.Fatalf("unlike=%v max=%d", r.UnlikeDomain, r.MaxUncertain)
	}
	d := report(t, r, 2).Duration
	if !d.Known || d.Min < 0 || d.Min > d.Max || d.Basis != "same_domain_monotonic" {
		t.Fatalf("child duration (own domain) = %+v", d)
	}
	// Root duration stays the observed 100 ms.
	if r.Trees[0].Duration.Min != model.Int64(100*ms) {
		t.Fatalf("root = %+v", r.Trees[0].Duration)
	}
}

// Inside one clock domain only the monotonic readings order time. A wall-clock step (NTP, manual change) must neither create a
// clock issue nor change a duration, even one that makes a span's end wall time precede its start wall time.
func TestCriticalPathWallClockStepInsideOneDomainIsIgnored(t *testing.T) {
	child := span(2, 1, 10, 60, 0)
	child.Start.Wall -= model.UnixNano(5_000_000_000) // the wall clock was stepped back 5 s before the child began
	e := *child.End
	e.Wall -= model.UnixNano(9_000_000_000) // and further back before it ended: end wall < start wall
	child.End = &e
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), child})
	if len(r.Clock) != 0 {
		t.Fatalf("a wall step inside one domain produced clock issues: %+v", r.Clock)
	}
	d := report(t, r, 2).Duration
	if !d.Known || d.Min != model.Int64(50*ms) || d.Max != model.Int64(50*ms) || d.Basis != "same_domain_monotonic" || flagged(report(t, r, 2), "end_before_start") {
		t.Fatalf("child duration = %+v flags=%v, want exactly 50 ms from the monotonic readings", d, report(t, r, 2).Flags)
	}
	wantPath(t, r.Trees[0], 1, 2)
	if s := r.Trees[0].Segments[0].Self; s.Min != model.Int64(50*ms) || s.Max != model.Int64(50*ms) {
		t.Fatalf("root self = %+v, want exactly 50 ms", s)
	}
}

func TestCriticalPathCertainClockViolationSameDomain(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 10, 100, 0), span(2, 1, 5, 50, 0)})
	if len(r.Clock) != 1 || !r.Clock[0].Certain || r.Clock[0].Kind != "starts_before_parent" || r.Clock[0].CrossDomain {
		t.Fatalf("clock = %+v", r.Clock)
	}
}

func TestCriticalPathUncertainSiblingsStayAmbiguous(t *testing.T) {
	// Two branches on different hosts end at 70 and 75 ms, 10 ms uncertainty each.
	a, b := span(2, 1, 0, 70, 1), span(3, 1, 0, 75, 2)
	for _, s := range []*model.Span{&a, &b} {
		e := *s.End
		e.Uncertainty = model.MonoNano(10 * ms)
		s.End = &e
	}
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), a, b})
	segs := r.Trees[0].Segments
	if len(segs) != 3 || !segs[1].Ambiguous || !segs[2].Ambiguous || segs[0].Ambiguous {
		t.Fatalf("segments = %+v, want both branches ambiguous", segs)
	}
	if !hasEdge(r, "critical_branch_ambiguous") || r.Complete {
		t.Fatalf("edges=%+v", r.Edges)
	}
	// Same ends in ONE domain are exactly ordered: no ambiguity.
	r = must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 70, 0), span(3, 1, 0, 75, 0)})
	wantPath(t, r.Trees[0], 1, 3)
	if r.Trees[0].Segments[1].Ambiguous || hasEdge(r, "critical_branch_ambiguous") {
		t.Fatalf("exact order reported ambiguous")
	}
}

func TestCriticalPathDuplicateIDsExcludedAndDeterministic(t *testing.T) {
	spans := []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 0, 70, 0), span(2, 1, 0, 90, 0), span(3, 2, 0, 10, 0)}
	r := must(t, spans)
	if !hasEdge(r, "duplicate_span_id") || !hasEdge(r, "parent_ambiguous") || r.Complete {
		t.Fatalf("edges=%+v", r.Edges)
	}
	for _, tp := range r.Trees {
		for _, s := range tp.Segments {
			if s.Span == sid(2) {
				t.Fatalf("duplicate id on a path: %+v", tp)
			}
		}
	}
	rev := slices.Clone(spans)
	slices.Reverse(rev)
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(must(t, rev))
	if string(a) != string(b) {
		t.Fatalf("input order changed the result:\n%s\n%s", a, b)
	}
}

func TestCriticalPathDeterministicUnderShuffle(t *testing.T) {
	var spans []model.Span
	spans = append(spans, span(1, 0, 0, 100, 0))
	for i := uint64(2); i < 60; i++ {
		spans = append(spans, span(i, 1+i%3*0+1-1, int64(i%7)*3, 50+int64(i%11)*4, int(i%3)))
	}
	spans = append(spans, span(300, 77, 1, 2, 0))
	want, _ := json.Marshal(must(t, spans))
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 5; n++ {
		s := slices.Clone(spans)
		rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
		got, _ := json.Marshal(must(t, s))
		if string(got) != string(want) {
			t.Fatalf("shuffle %d changed the result", n)
		}
	}
}

func TestCriticalPathSamplingAndLoss(t *testing.T) {
	lost := span(2, 1, 0, 50, 0)
	lost.SampleProbability = model.FloatBits(math.Float64bits(0.25))
	dropped := span(3, 1, 0, 40, 0)
	dropped.SampleProbability = model.FloatBits(math.Float64bits(0.5))
	dropped.SampleDecision = "drop"
	bad := span(4, 1, 0, 10, 0)
	bad.SampleProbability = model.FloatBits(math.Float64bits(math.NaN()))
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), lost, dropped, bad})
	s := r.Sampling
	if !s.Sampled || s.MinProbability != 0.25 || s.Kept != 3 || s.Dropped != 1 || s.Invalid != 1 {
		t.Fatalf("sampling = %+v", s)
	}
	if r.Complete || !hasReason(r, "head_sampled") || !hasReason(r, "sample_probability_invalid") {
		t.Fatalf("reasons = %v", r.Reasons)
	}
	clean := must(t, []model.Span{span(1, 0, 0, 100, 0)})
	if clean.Sampling.Sampled || clean.Sampling.MinProbability != 1 || hasReason(clean, "head_sampled") {
		t.Fatalf("unsampled trace reported sampled: %+v", clean.Sampling)
	}
}

func TestCriticalPathModerateSamplingIsStillSampling(t *testing.T) {
	kept := span(2, 1, 0, 50, 0)
	kept.SampleProbability = model.FloatBits(math.Float64bits(0.75)) // kept, but only one in 1.33 such spans were
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), kept})
	if !r.Sampling.Sampled || r.Sampling.MinProbability != 0.75 || r.Sampling.Dropped != 0 || !hasReason(r, "head_sampled") || r.Complete {
		t.Fatalf("sampling = %+v reasons=%v", r.Sampling, r.Reasons)
	}
}

func TestCriticalPathZeroLengthSpanIsMeasuredNotReversed(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 40, 40, 0)})
	s := report(t, r, 2)
	if !s.Duration.Known || s.Duration.Min != 0 || s.Duration.Max != 0 || flagged(s, "end_before_start") || hasReason(r, "end_before_start") {
		t.Fatalf("zero-length span = %+v reasons=%v", s, r.Reasons)
	}
}

// A wide-interval sibling widens the scan window; a sibling that provably ended before the latest one must still stay out of the
// ambiguous group.
func TestCriticalPathProvablyEarlierSiblingIsNotAnAmbiguousCandidate(t *testing.T) {
	withUncertainty := func(s model.Span, endUncertaintyMs int64) model.Span {
		e := *s.End
		e.Uncertainty = model.MonoNano(endUncertaintyMs * ms)
		s.End = &e
		return s
	}
	best := span(2, 1, 0, 70, 1)                        // ends at exactly 70 ms
	earlier := withUncertainty(span(3, 1, 0, 50, 2), 5) // ends within [45, 55]: provably before 70
	wide := withUncertainty(span(4, 1, 0, 30, 3), 20)   // [10, 50]: makes the scan window wide
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), best, earlier, wide})
	wantPath(t, r.Trees[0], 1, 2)
	if r.Trees[0].Segments[1].Ambiguous || hasEdge(r, "critical_branch_ambiguous") {
		t.Fatalf("a sibling that provably ended earlier was treated as a candidate: %+v", r.Edges)
	}
}

func TestCriticalPathReversedAndOpenSpansAreReportedNotRepaired(t *testing.T) {
	rev := span(2, 1, 50, 20, 0) // end precedes start in the same domain
	open := span(3, 1, 10, 0, 0)
	open.End = nil
	cancelled := span(4, 1, 0, 20, 0)
	cancelled.Status = "cancelled"
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), rev, open, cancelled})
	rs := report(t, r, 2)
	if rs.Duration.Known || !flagged(rs, "end_before_start") || rs.EndWall == nil || *rs.EndWall != model.Int64(rev.End.Wall) {
		t.Fatalf("reversed span = %+v", rs)
	}
	os := report(t, r, 3)
	if os.Duration.Known || !flagged(os, "open") || os.EndWall != nil {
		t.Fatalf("open span = %+v", os)
	}
	if !flagged(report(t, r, 4), "cancelled") || !hasReason(r, "span_open") || !hasReason(r, "end_before_start") || r.Complete {
		t.Fatalf("reasons = %v", r.Reasons)
	}
	for _, s := range r.Trees[0].Segments {
		if s.Span == sid(2) || s.Span == sid(3) {
			t.Fatalf("unmeasured span on the path: %+v", r.Trees[0].Segments)
		}
		if s.Self.Min < 0 {
			t.Fatalf("negative self time %+v", s)
		}
	}
	// An open root has no duration at all.
	o := span(1, 0, 0, 0, 0)
	o.End = nil
	r = must(t, []model.Span{o})
	if r.Trees[0].Duration.Known || r.Observed.Known {
		t.Fatalf("open root got a duration: %+v / %+v", r.Trees[0].Duration, r.Observed)
	}
}

func TestCriticalPathCrossDomainDurationUsesWallWithUncertainty(t *testing.T) {
	s := span(1, 0, 0, 100, 0)
	e := stamp(1, 100, 4) // end stamped in another domain: monotonic subtraction is meaningless
	s.End = &e
	s.Start.Uncertainty = model.MonoNano(3 * ms)
	r := must(t, []model.Span{s})
	d := r.Spans[0].Duration
	if !d.Known || d.Basis != "wall_clock_with_uncertainty" || d.Min != model.Int64(93*ms) || d.Max != model.Int64(107*ms) || !flagged(r.Spans[0], "cross_domain_duration") {
		t.Fatalf("duration = %+v flags=%v", d, r.Spans[0].Flags)
	}
	if r.Observed.Min == r.Observed.Max {
		t.Fatalf("differing bounds must not collapse to a single total: %+v", r.Observed)
	}
}

func TestCriticalPathMultipleRootsGiveBoundsNotOneTotal(t *testing.T) {
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), span(2, 0, 30, 130, 1)})
	if !hasEdge(r, "multiple_roots") || r.Complete || len(r.Trees) != 2 {
		t.Fatalf("edges=%+v trees=%d", r.Edges, len(r.Trees))
	}
	if r.Observed.Min != model.Int64(100*ms) || r.Observed.Max != model.Int64(130*ms) || !r.Observed.Known {
		t.Fatalf("observed = %+v, want [100ms,130ms]", r.Observed)
	}
}

func TestCriticalPathDependencyBoundary(t *testing.T) {
	dep := span(2, 1, 0, 60, 0)
	dep.Kind, dep.Dependency = "client", "payments"
	inside := span(3, 1, 0, 60, 0)
	inside.Kind, inside.Dependency = "client", "ledger"
	r := must(t, []model.Span{span(1, 0, 0, 100, 0), dep, inside, span(4, 3, 5, 50, 1)})
	if !flagged(report(t, r, 2), "dependency_boundary") || flagged(report(t, r, 3), "dependency_boundary") {
		t.Fatalf("boundary flags: %v / %v", report(t, r, 2).Flags, report(t, r, 3).Flags)
	}
}

func TestCriticalPathHugeFanOut(t *testing.T) {
	const n = 50_000
	spans := make([]model.Span, 0, n+1)
	spans = append(spans, span(1, 0, 0, 1_000_000, 0))
	for i := uint64(2); i <= n; i++ {
		spans = append(spans, span(i, 1, int64(i%1000), int64(i%1000)+1+int64(i%5000), int(i%4)))
	}
	late := span(n+1, 1, 0, 999_999, 0)
	spans = append(spans, late)
	start := time.Now()
	r := must(t, spans)
	if time.Since(start) > 20*time.Second {
		t.Fatalf("fan-out analysis too slow: %v", time.Since(start))
	}
	if r.SpanCount != n+1 || len(r.Trees[0].Segments) < 2 || r.Trees[0].Segments[1].Span != late.ID {
		t.Fatalf("latest-ending child must be on the path: %d segments, second=%x", len(r.Trees[0].Segments), r.Trees[0].Segments[1].Span)
	}
}

func chain(depth int) []model.Span {
	spans := make([]model.Span, depth)
	for i := range spans {
		parent := uint64(i)
		spans[i] = span(uint64(i+1), parent, 0, int64(depth-i), 0)
	}
	return spans
}

func TestCriticalPathDeepChainIsIterative(t *testing.T) {
	old := debug.SetMaxStack(512 << 10) // a recursive walk at this depth would abort the process
	defer debug.SetMaxStack(old)
	r := must(t, chain(traces.MaxDepth))
	if got := len(r.Trees[0].Segments); got != traces.MaxDepth {
		t.Fatalf("segments = %d", got)
	}
	if r.Trees[0].Segments[traces.MaxDepth-1].Depth != traces.MaxDepth-1 {
		t.Fatalf("depth = %d", r.Trees[0].Segments[traces.MaxDepth-1].Depth)
	}
}

func TestCriticalPathBoundsAreTypedErrors(t *testing.T) {
	if _, err := traces.CriticalPath(chain(traces.MaxDepth + 1)); !errors.Is(err, traces.ErrTooDeep) {
		t.Fatalf("deep chain err = %v", err)
	}
	many := make([]model.Span, traces.MaxSpans+1)
	for i := range many {
		many[i] = span(uint64(i+1), 0, 0, 1, 0)
	}
	if _, err := traces.CriticalPath(many); !errors.Is(err, traces.ErrTooManySpans) {
		t.Fatalf("many spans err = %v", err)
	}
	// The cap is on the span count: exactly MaxSpans is accepted.
	if _, err := traces.CriticalPath(many[:traces.MaxSpans]); err != nil {
		t.Fatalf("MaxSpans err = %v", err)
	}
	if _, err := traces.CriticalPath(nil); !errors.Is(err, traces.ErrNoSpans) {
		t.Fatalf("empty err = %v", err)
	}
	other := span(2, 1, 0, 1, 0)
	other.Trace = model.ID{0: 5}
	if _, err := traces.CriticalPath([]model.Span{span(1, 0, 0, 1, 0), other}); !errors.Is(err, traces.ErrMixedTraces) {
		t.Fatalf("mixed err = %v", err)
	}
	zero := span(1, 0, 0, 1, 0)
	zero.ID = model.SpanID{}
	if _, err := traces.CriticalPath([]model.Span{zero}); !errors.Is(err, traces.ErrInvalidSpan) {
		t.Fatalf("zero id err = %v", err)
	}
}

func TestCriticalPathDoesNotMutateInput(t *testing.T) {
	child := span(2, 1, 0, 70, 1)
	child.Links = []model.SpanLink{{Trace: testTrace, Span: sid(1)}}
	spans := []model.Span{span(3, 1, 0, 40, 0), span(1, 0, 0, 100, 0), child, span(9, 77, 0, 1, 0)}
	before, _ := json.Marshal(spans)
	r := must(t, spans)
	after, _ := json.Marshal(spans)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
	// The result owns its data: mutating it cannot reach the input.
	r.Spans[0].Links = append(r.Spans[0].Links, traces.LinkReport{})
	if spans[0].ID != sid(3) {
		t.Fatal("input order changed")
	}
}
