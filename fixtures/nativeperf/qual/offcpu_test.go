// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
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
	r := []nativeperf.Interval{{Kind: nativeperf.IntervalRunnable, Start: 10, End: 40}}
	if v, n := CompareRunnable(500, r); v != VerdictPass || n != 30 {
		t.Errorf("runnable evidence: %s %d", v, n)
	}
	if v, _ := CompareRunnable(0, r); v != VerdictUnknown {
		t.Errorf("no ground-truth contention: %s", v)
	}
}
