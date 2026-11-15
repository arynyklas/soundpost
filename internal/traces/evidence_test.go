// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package traces_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/traces"
)

func wall(atMs int64) int64 { return 1_700_000_000_000_000_000 + atMs*ms }

func TestLateSpansAreReportedAfterTheyEndedNotRepaired(t *testing.T) {
	// root 0-100 ms, child 10-60 ms; the child was reported 30 s after it ended, the root on time.
	spans := []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 10, 60, 0)}
	r, err := traces.Analyze(spans, traces.Evidence{Reported: []int64{wall(100), wall(60) + 30_000*ms}})
	if err != nil {
		t.Fatal(err)
	}
	child := report(t, r, 2)
	if !flagged(child, "late") || child.ReportedWall == nil || int64(*child.ReportedWall) != wall(60)+30_000*ms {
		t.Fatalf("the late child is not flagged with its report time: %+v", child)
	}
	if flagged(report(t, r, 1), "late") {
		t.Fatal("a span reported on time is flagged late")
	}
	if len(r.Late) != 1 || r.Late[0].Span != sid(2) || int64(r.Late[0].LateBy) != 30_000*ms {
		t.Fatalf("late list = %+v, want the child 30 s late", r.Late)
	}
	if !hasReason(r, "late_spans") || r.Complete {
		t.Fatalf("a trace with a late span must say so: reasons %v complete %v", r.Reasons, r.Complete)
	}
	// The late span stays in the analysis exactly as recorded.
	wantPath(t, r.Trees[0], 1, 2)
	// Nothing late: nothing is said.
	on, err := traces.Analyze(spans, traces.Evidence{Reported: []int64{wall(100), wall(60) + 4_999*ms}})
	if err != nil || len(on.Late) != 0 || hasReason(on, "late_spans") || flagged(report(t, on, 2), "late") {
		t.Fatalf("a span reported 4.999 s after it ended is late: %+v err %v", on.Late, err)
	}
	// The boundary itself (exactly LateAfterNS) is not late; one nanosecond more is.
	edge := wall(60) + traces.LateAfterNS
	atEdge, _ := traces.Analyze(spans, traces.Evidence{Reported: []int64{wall(100), edge}})
	past, _ := traces.Analyze(spans, traces.Evidence{Reported: []int64{wall(100), edge + 1}})
	if len(atEdge.Late) != 0 || len(past.Late) != 1 {
		t.Fatalf("boundary: at %d late spans, past %d, want 0 and 1", len(atEdge.Late), len(past.Late))
	}
}

func TestOpenAndReversedSpansAreNeverCalledLate(t *testing.T) {
	open := span(2, 1, 10, 60, 0)
	open.End = nil
	rev := span(3, 1, 80, 20, 0)
	r, err := traces.Analyze([]model.Span{span(1, 0, 0, 100, 0), open, rev}, traces.Evidence{Reported: []int64{wall(100), wall(1_000_000), wall(1_000_000)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Late) != 0 || flagged(report(t, r, 2), "late") || flagged(report(t, r, 3), "late") {
		t.Fatalf("a span with no end, or an end before its start, has no lateness to measure: %+v", r.Late)
	}
	if report(t, r, 2).ReportedWall == nil {
		t.Fatal("the report time of an open span is dropped")
	}
}

func TestUnknownReportTimeIsNotLate(t *testing.T) {
	r, err := traces.Analyze([]model.Span{span(1, 0, 0, 100, 0), span(2, 1, 10, 60, 0)}, traces.Evidence{Reported: []int64{0, 0}})
	if err != nil || len(r.Late) != 0 || report(t, r, 2).ReportedWall != nil || !r.Complete {
		t.Fatalf("no reported time must mean no claim: late %v reported %v complete %v err %v", r.Late, report(t, r, 2).ReportedWall, r.Complete, err)
	}
}

func TestReportedTimesMustLineUpWithTheSpans(t *testing.T) {
	spans := []model.Span{span(1, 0, 0, 100, 0), span(2, 1, 10, 60, 0)}
	for _, reported := range [][]int64{{1}, {1, 2, 3}} {
		if _, err := traces.Analyze(spans, traces.Evidence{Reported: reported}); !errors.Is(err, traces.ErrInvalidEvidence) {
			t.Fatalf("%d reported times for %d spans: err = %v, want ErrInvalidEvidence", len(reported), len(spans), err)
		}
	}
}

func TestLateIsTiedToTheInputPositionNotTheSortOrder(t *testing.T) {
	// The input is deliberately not in the analysis' own order: the late one is listed first.
	spans := []model.Span{span(3, 1, 70, 90, 0), span(1, 0, 0, 100, 0), span(2, 1, 10, 60, 0)}
	r, err := traces.Analyze(spans, traces.Evidence{Reported: []int64{wall(90), wall(100), wall(60) + 10_000*ms}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Late) != 1 || r.Late[0].Span != sid(2) {
		t.Fatalf("late = %+v, want only span 2", r.Late)
	}
}

func gap(src, prod byte, start, end int64, reason string, n uint64) traces.ProducerLoss {
	return traces.ProducerLoss{Source: model.ID{0: src}, Producer: model.ID{0: prod}, Start: model.Int64(wall(start)), End: model.Int64(wall(end)), Reason: reason, Count: model.Uint64(n)}
}

func TestProducerGapsOverlappingTheTraceAreReportedAndMakeItIncomplete(t *testing.T) {
	spans := []model.Span{span(1, 0, 100, 200, 0), span(2, 1, 120, 180, 0)}
	losses := []traces.ProducerLoss{
		gap(1, 1, 150, 170, "transport", 7), // inside
		gap(1, 1, 190, 400, "shutdown", 2),  // straddles the end
		gap(1, 1, 0, 99, "queue_full", 5),   // before the trace
		gap(1, 1, 201, 300, "expired", 9),   // after the trace
	}
	r, err := traces.Analyze(spans, traces.Evidence{Losses: losses})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Gaps) != 2 || r.Gaps[0].Reason != "transport" || r.Gaps[0].Count != 7 || r.Gaps[1].Reason != "shutdown" {
		t.Fatalf("gaps = %+v, want the transport and shutdown ones in time order", r.Gaps)
	}
	if !hasReason(r, "producer_loss") || r.Complete {
		t.Fatalf("a trace read across a producer loss must say so: %v complete %v", r.Reasons, r.Complete)
	}
	// Touching the edge counts: loss ending exactly at the first start, or starting exactly at the last end.
	edge, _ := traces.Analyze(spans, traces.Evidence{Losses: []traces.ProducerLoss{gap(1, 1, 0, 100, "transport", 1), gap(1, 1, 200, 300, "transport", 1)}})
	if len(edge.Gaps) != 2 {
		t.Fatalf("edge-touching gaps = %d, want 2", len(edge.Gaps))
	}
	none, _ := traces.Analyze(spans, traces.Evidence{})
	if len(none.Gaps) != 0 || hasReason(none, "producer_loss") || !none.Complete {
		t.Fatalf("no loss records must mean no gap: %+v %v", none.Gaps, none.Reasons)
	}
	if none.Gaps == nil || none.Late == nil {
		t.Fatal("late_spans and producer_gaps must serialize as empty lists, not null")
	}
}

func TestProducerGapsAreBoundedAndSaySoWhenCut(t *testing.T) {
	spans := []model.Span{span(1, 0, 0, 1000, 0)}
	var losses []traces.ProducerLoss
	for i := range traces.MaxGaps + 5 {
		losses = append(losses, gap(1, 1, int64(i), int64(i)+1, "transport", 1))
	}
	r, err := traces.Analyze(spans, traces.Evidence{Losses: losses})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Gaps) != traces.MaxGaps || !hasReason(r, "producer_loss_truncated") {
		t.Fatalf("%d gaps, reasons %v: a cut list must say it was cut", len(r.Gaps), r.Reasons)
	}
	if int64(r.Gaps[0].Start) != wall(0) || !slices.IsSortedFunc(r.Gaps, func(a, b traces.ProducerLoss) int { return int(int64(a.Start) - int64(b.Start)) }) {
		t.Fatal("the kept gaps are not the earliest, in order")
	}
}

func TestProducerGapsComeOutInTimeOrderWhateverTheInputOrder(t *testing.T) {
	spans := []model.Span{span(1, 0, 0, 1000, 0)}
	in := []traces.ProducerLoss{gap(2, 1, 300, 310, "transport", 1), gap(1, 1, 100, 110, "shutdown", 2), gap(1, 1, 100, 105, "expired", 3), gap(1, 2, 100, 105, "expired", 3)}
	r, err := traces.Analyze(spans, traces.Evidence{Losses: in})
	if err != nil {
		t.Fatal(err)
	}
	var starts, ends []int64
	for _, g := range r.Gaps {
		starts, ends = append(starts, int64(g.Start)), append(ends, int64(g.End))
	}
	if len(r.Gaps) != 4 || !slices.IsSorted(starts) || starts[0] != wall(100) || starts[3] != wall(300) || ends[0] != wall(105) || ends[2] != wall(110) {
		t.Fatalf("gaps = %+v, want (start, end, source, producer) order", r.Gaps)
	}
	if r.Gaps[0].Producer != (model.ID{0: 1}) || r.Gaps[1].Producer != (model.ID{0: 2}) {
		t.Fatalf("ties are not broken by source then producer: %+v", r.Gaps)
	}
	// The caller's slice is not reordered.
	if in[0].Source != (model.ID{0: 2}) {
		t.Fatal("the input losses were sorted in place")
	}
}
