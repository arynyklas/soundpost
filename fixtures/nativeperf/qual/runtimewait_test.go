// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// A runtime that served `requests` loopback HTTP requests, each held server-side for 50 ms, inside a 3.2 s window: its
// event-loop thread (TID 4242) was idle for about requests*50 ms of it, and the round trips it observed add up to a
// little more than that (the loop also does work). These are hand-made intervals, not scheduler evidence.
func waitTruth(requests int) RuntimeWaitTruth {
	return RuntimeWaitTruth{
		TID: 4242, StartNs: 10_000_000_000, EndNs: 13_200_000_000,
		Requests: requests, ServerDelayNs: 50_000_000, WaitTotalNs: uint64(requests) * 56_000_000,
	}
}

func loopIntervals(kind nativeperf.IntervalKind, tid uint32, requests int, each uint64) []nativeperf.Interval {
	var out []nativeperf.Interval
	start := uint64(10_000_000_000)
	for range requests {
		out = append(out, nativeperf.Interval{Kind: kind, Task: nativeperf.TaskKey{TID: tid}, Start: model.MonoNano(start), End: model.MonoNano(start + each)})
		start += 60_000_000
	}
	return out
}

func TestCompareRuntimeWaitAcceptsTheBlockedTimeTheRuntimeRecorded(t *testing.T) {
	for _, each := range []uint64{50_000_000, 52_000_000, 56_000_000} {
		got := CompareRuntimeWait(waitTruth(53), loopIntervals(nativeperf.IntervalBlocked, 4242, 53, each))
		if got.Verdict != VerdictPass {
			t.Errorf("blocked %d ns per request: %s (%s)", each, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitRejectsCollectorsThatMisreportTheWait(t *testing.T) {
	truth := waitTruth(53)
	for name, native := range map[string][]nativeperf.Interval{
		"every wait reported as run-queue delay (blocked never reported)": loopIntervals(nativeperf.IntervalRunnable, 4242, 53, 50_000_000),
		"waits cut to 30%":  loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 15_000_000),
		"waits inflated 2x": loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 110_000_000),
	} {
		got := CompareRuntimeWait(truth, native)
		if got.Verdict != VerdictFail {
			t.Errorf("%s: %s (%s), want fail", name, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitIsUnknownWithoutEvidence(t *testing.T) {
	truth := waitTruth(53)
	good := loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)
	for name, c := range map[string]struct {
		truth  RuntimeWaitTruth
		native []nativeperf.Interval
	}{
		"no interval of the loop thread at all":             {truth, loopIntervals(nativeperf.IntervalBlocked, 9999, 53, 52_000_000)},
		"too few requests":                                  {waitTruth(5), loopIntervals(nativeperf.IntervalBlocked, 4242, 5, 52_000_000)},
		"no server delay recorded":                          {RuntimeWaitTruth{TID: 4242, StartNs: truth.StartNs, EndNs: truth.EndNs, Requests: 53, WaitTotalNs: truth.WaitTotalNs}, good},
		"empty window":                                      {RuntimeWaitTruth{TID: 4242, Requests: 53, ServerDelayNs: 50_000_000, WaitTotalNs: truth.WaitTotalNs}, good},
		"an unknown split inside the window":                {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Task: nativeperf.TaskKey{TID: 4242}, Start: 10_100_000_000, End: 10_200_000_000})},
		"a censored interval inside the window":             {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalCensored, Task: nativeperf.TaskKey{TID: 4242}, Start: 12_000_000_000, End: 12_500_000_000})},
		"a correction of the loop thread inside the window": {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4242}, Start: 11_000_000_000, End: 11_100_000_000})},
		"a domain-wide correction inside the window":        {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Start: 11_000_000_000, End: 11_100_000_000})},
	} {
		got := CompareRuntimeWait(c.truth, c.native)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%s: %s (%s), want unknown", name, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitIgnoresOtherThreadsAndCorrectionsAndTimeOutsideTheWindow(t *testing.T) {
	truth := waitTruth(53)
	native := loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)
	// a helper thread of the runtime that slept the whole window must not add to the loop thread's wait
	native = append(native, nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4243}, Start: 10_000_000_000, End: 13_200_000_000})
	// blocked time before and after the window (startup, shutdown) is not part of the measured phase
	native = append(native, nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 5_000_000_000, End: 9_900_000_000},
		nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 13_300_000_000, End: 19_000_000_000})
	// a coverage correction outside the window, or of another thread, is not this window's evidence
	native = append(native,
		nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4242}, Start: 5_000_000_000, End: 9_000_000_000},
		nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4243}, Start: 10_000_000_000, End: 13_200_000_000})
	got := CompareRuntimeWait(truth, native)
	if got.Verdict != VerdictPass {
		t.Fatalf("%s (%s)", got.Verdict, got.Reason)
	}
	if got.NativeNs != 53*52_000_000 {
		t.Errorf("native blocked %d ns, want the loop thread's own %d ns inside the window", got.NativeNs, 53*52_000_000)
	}
}

func TestCompareRuntimeWaitBoundaryIsTheApprovedTolerance(t *testing.T) {
	truth := waitTruth(53) // lower bound 53*50 ms*0.75 = 1.9875 s, upper bound 53*56 ms*1.25 = 3.71 s
	lower := uint64(float64(53*50_000_000) * (1 - BlockedTolerance))
	upper := uint64(float64(truth.WaitTotalNs) * (1 + BlockedTolerance))
	one := func(total uint64) []nativeperf.Interval {
		return []nativeperf.Interval{{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 10_000_000_000, End: model.MonoNano(10_000_000_000 + total)}}
	}
	for _, c := range []struct {
		ns   uint64
		want string
	}{{lower + 1_000, VerdictPass}, {lower - 1_000_000, VerdictFail}, {upper - 1_000, VerdictPass}, {upper + 1_000_000, VerdictFail}} {
		wide := truth
		wide.EndNs = 20_000_000_000 // keep the whole interval inside the window so only the totals decide
		if got := CompareRuntimeWait(wide, one(c.ns)); got.Verdict != c.want {
			t.Errorf("%d ns: %s (%s), want %s", c.ns, got.Verdict, got.Reason, c.want)
		}
	}
}
