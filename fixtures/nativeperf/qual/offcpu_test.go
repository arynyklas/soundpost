// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// These tests exercise the comparator arithmetic with hand-made intervals. They
// are NOT scheduler evidence: no native scheduler capture exists on this host.

func truthSet(n int) []BlockedTruth {
	var out []BlockedTruth
	for i := 0; i < n; i++ {
		start := uint64(1_000_000_000 + i*400_000_000)
		out = append(out, BlockedTruth{TID: 77, Start: start, End: start + 200_000_000})
	}
	return out
}

func nativeFor(truth []BlockedTruth, scale float64, kind nativeperf.IntervalKind) []nativeperf.Interval {
	var out []nativeperf.Interval
	for _, g := range truth {
		d := uint64(float64(g.End-g.Start) * scale)
		out = append(out, nativeperf.Interval{Kind: kind, Task: nativeperf.TaskKey{TID: 77}, Start: model.MonoNano(g.Start), End: model.MonoNano(g.Start + d)})
	}
	return out
}

func TestCompareBlockedToleranceBoundaries(t *testing.T) {
	truth := truthSet(24)
	for _, tc := range []struct {
		scale float64
		want  string
	}{{1.0, VerdictPass}, {0.8, VerdictPass}, {0.76, VerdictPass}, {0.70, VerdictFail}, {0.0, VerdictUnknown}} {
		got := CompareBlocked(truth, nativeFor(truth, tc.scale, nativeperf.IntervalBlocked))
		if got.Verdict != tc.want {
			t.Errorf("scale %.2f: %s (%s), want %s", tc.scale, got.Verdict, got.Reason, tc.want)
		}
	}
	// over-reporting is held to the same window: 1.30x is outside, 1.2x inside
	// (end clipped by the overlap rule, so use a widened ground truth instead)
	wide := nativeFor(truth, 1.0, nativeperf.IntervalBlocked)
	for i := range wide {
		wide[i].End += 60_000_000 // 30% of 200 ms: overlap is clipped to the truth interval
	}
	if CompareBlocked(truth, wide).Verdict != VerdictPass {
		t.Error("native time beyond the truth window must be clipped, not scored")
	}
}

func TestCompareBlockedMissingEvidenceIsUnknownNeverPass(t *testing.T) {
	truth := truthSet(24)
	native := nativeFor(truth, 1.0, nativeperf.IntervalBlocked)
	if v := CompareBlocked(truth, native[:23]).Verdict; v != VerdictUnknown {
		t.Errorf("one interval without evidence: %s", v)
	}
	unk := append([]nativeperf.Interval(nil), native...)
	unk[5].Kind = nativeperf.IntervalUnknown
	if v := CompareBlocked(truth, unk).Verdict; v != VerdictUnknown {
		t.Errorf("unknown split inside a ground-truth interval: %s", v)
	}
	cen := append([]nativeperf.Interval(nil), native...)
	cen[7].Kind = nativeperf.IntervalCensored
	if v := CompareBlocked(truth, cen).Verdict; v != VerdictUnknown {
		t.Errorf("censored interval: %s", v)
	}
	if v := CompareBlocked(truth[:19], native[:19]).Verdict; v != VerdictUnknown {
		t.Errorf("19 intervals: %s", v)
	}
	other := append([]nativeperf.Interval(nil), native...)
	for i := range other {
		other[i].Task.TID = 99 // intervals of a different thread must not match
	}
	if v := CompareBlocked(truth, other).Verdict; v != VerdictUnknown {
		t.Errorf("foreign thread evidence: %s", v)
	}
}

func TestCompareRunnableNeedsNonzeroDistinctEvidence(t *testing.T) {
	if v, _ := CompareRunnable(500, nil); v != VerdictUnknown {
		t.Errorf("no runnable evidence: %s", v)
	}
	r := []nativeperf.Interval{{Kind: nativeperf.IntervalRunnable, Start: 10, End: 490}}
	if v, n := CompareRunnable(500, r); v != VerdictPass || n != 480 {
		t.Errorf("runnable evidence: %s %d", v, n)
	}
	if v, _ := CompareRunnable(0, r); v != VerdictUnknown {
		t.Errorf("no ground-truth contention: %s", v)
	}
}

// A sliver of runnable delay against seconds of ground-truth contention is not
// a measurement of it; the native runnable time has to match the workload's own
// wall-minus-CPU truth within the approved tolerance, in both directions.
func TestCompareRunnableMustMatchTheGroundTruthWithinTheTolerance(t *testing.T) {
	runnable := func(ns uint64) []nativeperf.Interval {
		return []nativeperf.Interval{{Kind: nativeperf.IntervalRunnable, Start: 0, End: model.MonoNano(ns)}}
	}
	for name, tc := range map[string]struct {
		ns   uint64
		want string
	}{"lower edge": {750, VerdictPass}, "upper edge": {1250, VerdictPass}, "below": {749, VerdictFail}, "a sliver": {30, VerdictFail}, "above": {1251, VerdictFail}} {
		if v, n := CompareRunnable(1000, runnable(tc.ns)); v != tc.want || n != tc.ns {
			t.Errorf("%s: %s %d, want %s", name, v, n, tc.want)
		}
	}
}

func TestCompareRunnableFailsWhenBlockedTimeOfTheSameThreadsIsNotSmaller(t *testing.T) {
	in := []nativeperf.Interval{
		{Kind: nativeperf.IntervalRunnable, Start: 0, End: 900},
		{Kind: nativeperf.IntervalBlocked, Start: 1000, End: 1900},
	}
	if v, _ := CompareRunnable(1000, in); v != VerdictFail {
		t.Errorf("blocked >= runnable: %s", v)
	}
	in[1].End = 1100
	if v, _ := CompareRunnable(1000, in); v != VerdictPass {
		t.Errorf("blocked << runnable: %s", v)
	}
}

// A collector that never reports run-queue delay while the workload measured the
// threads waiting is wrong, not "without evidence": it fails. Missing or
// unknown-split evidence stays unknown, and the censored tail of a capture does
// not make the evidence unknown.
func TestCompareRunnableFailsAZeroRunnableReportWithCompleteBlockedEvidence(t *testing.T) {
	blocked := nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Start: 0, End: 900}
	if v, n := CompareRunnable(1000, []nativeperf.Interval{blocked}); v != VerdictFail || n != 0 {
		t.Errorf("complete blocked evidence, zero runnable: %s %d", v, n)
	}
	censored := nativeperf.Interval{Kind: nativeperf.IntervalCensored, Start: 900, End: 1000, Reason: nativeperf.ReasonUnmeasured}
	if v, _ := CompareRunnable(1000, []nativeperf.Interval{blocked, censored}); v != VerdictFail {
		t.Errorf("a censored tail hid a zero-runnable collector: %s", v)
	}
	unknown := nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Start: 900, End: 1000, Reason: nativeperf.ReasonUnmeasured}
	if v, _ := CompareRunnable(1000, []nativeperf.Interval{blocked, unknown}); v != VerdictUnknown {
		t.Errorf("an unknown split is not evidence of zero runnable delay: %s", v)
	}
	if v, _ := CompareRunnable(1000, []nativeperf.Interval{{Kind: nativeperf.IntervalCPU}}); v != VerdictUnknown {
		t.Errorf("no scheduler evidence at all: %s", v)
	}
}

// The sleeper's runnable delay cannot exceed what its sleeps overshot (the
// workload's measurement) by more than the approved tolerance.
func TestCompareSleeperRunnableIsBoundedByTheMeasuredOvershoot(t *testing.T) {
	in := func(runnable, blocked uint64) []nativeperf.Interval {
		return []nativeperf.Interval{
			{Kind: nativeperf.IntervalRunnable, Start: 0, End: model.MonoNano(runnable)},
			{Kind: nativeperf.IntervalBlocked, Start: 0, End: model.MonoNano(blocked)},
		}
	}
	for name, tc := range map[string]struct {
		run, blocked, bound uint64
		want                string
	}{
		"within the bound":                  {80, 5000, 100, VerdictPass},
		"upper edge":                        {125, 5000, 100, VerdictPass},
		"blocked time reported as runnable": {5000, 0, 100, VerdictFail},
		"just above":                        {126, 5000, 100, VerdictFail},
		"no ground truth":                   {80, 5000, 0, VerdictUnknown},
		"sleeper never seen":                {0, 0, 100, VerdictUnknown},
	} {
		if v, _, _ := CompareSleeperRunnable(tc.bound, in(tc.run, tc.blocked)); v != tc.want {
			t.Errorf("%s: %s, want %s", name, v, tc.want)
		}
	}
}
