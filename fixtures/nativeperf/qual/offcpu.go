// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// BlockedTolerance is the approved +-25 percent window and MinBlockedIntervals
// the approved minimum number of independently recorded intervals.
const (
	BlockedTolerance    = 0.25
	MinBlockedIntervals = 20
)

// BlockedTruth is one blocking interval the workload measured itself.
type BlockedTruth struct {
	TID        uint32
	Start, End uint64
}

// Verdict values of the scheduler comparators. Missing evidence is "unknown",
// never a numeric pass.
const (
	VerdictPass    = "pass"
	VerdictFail    = "fail"
	VerdictUnknown = "unknown"
)

// BlockedComparison is the result of comparing native blocked intervals with
// the workload's monotonic ground truth.
type BlockedComparison struct {
	Verdict     string
	Reason      string
	Intervals   int
	Matched     int
	TruthNs     uint64
	NativeNs    uint64
	Deviation   float64 // |native-truth|/truth over the summed intervals
	MaxInterval float64 // worst single-interval relative deviation
}

func overlap(a0, a1, b0, b1 uint64) uint64 {
	lo, hi := a0, a1
	if b0 > lo {
		lo = b0
	}
	if b1 < hi {
		hi = b1
	}
	if hi <= lo {
		return 0
	}
	return hi - lo
}

// CompareBlocked compares the sum of native blocked time against the sum of the
// independently recorded blocking ground truth. An interval with no native
// blocked evidence, or whose evidence is an unknown/censored interval, makes the
// whole comparison unknown instead of passing a numeric tolerance; fewer than
// MinBlockedIntervals recorded intervals is also unknown.
func CompareBlocked(truth []BlockedTruth, native []nativeperf.Interval) BlockedComparison {
	c := BlockedComparison{Intervals: len(truth)}
	if len(truth) < MinBlockedIntervals {
		c.Verdict, c.Reason = VerdictUnknown, fmt.Sprintf("only %d ground-truth intervals, need %d", len(truth), MinBlockedIntervals)
		return c
	}
	for _, g := range truth {
		var got, uncertain uint64
		for _, iv := range native {
			if iv.Correction || uint32(iv.Task.TID) != g.TID {
				continue
			}
			o := overlap(g.Start, g.End, uint64(iv.Start), uint64(iv.End))
			switch iv.Kind {
			case nativeperf.IntervalBlocked:
				got += o
			case nativeperf.IntervalUnknown, nativeperf.IntervalCensored:
				uncertain += o
			}
		}
		want := g.End - g.Start
		c.TruthNs += want
		if got == 0 || uncertain > 0 {
			c.Verdict, c.Reason = VerdictUnknown, "an interval has no complete blocked evidence (missing, unknown split or censored)"
			return c
		}
		c.Matched++
		c.NativeNs += got
		if want > 0 {
			d := float64(diff(got, want)) / float64(want)
			if d > c.MaxInterval {
				c.MaxInterval = d
			}
		}
	}
	c.Deviation = float64(diff(c.NativeNs, c.TruthNs)) / float64(c.TruthNs)
	if c.Deviation <= BlockedTolerance {
		c.Verdict = VerdictPass
	} else {
		c.Verdict, c.Reason = VerdictFail, fmt.Sprintf("summed deviation %.1f%% exceeds %.0f%%", c.Deviation*100, BlockedTolerance*100)
	}
	return c
}

func diff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// CompareRunnable judges the intervals of the threads that contended for the
// CPU (the caller passes only those): the native runnable delay must be nonzero,
// match the workload's own wall-minus-CPU ground truth within BlockedTolerance
// in both directions, and exceed the blocked time those same threads show, so the
// two are visibly separate. Without any runnable evidence or ground truth it is
// unknown, EXCEPT a split that reports complete blocked intervals (no interval
// whose blocked/runnable split is unknown; the still-open intervals censored at
// the end of every capture do not count) and still no runnable delay at all for
// threads the workload measured as waiting: that is a collector that never
// reports run-queue delay, so it fails instead of passing as "no evidence".
func CompareRunnable(truthNs uint64, native []nativeperf.Interval) (verdict string, nativeNs uint64) {
	var blocked, uncertain uint64
	for _, iv := range native {
		if iv.Correction {
			continue
		}
		switch iv.Kind {
		case nativeperf.IntervalRunnable:
			nativeNs += uint64(iv.End - iv.Start)
		case nativeperf.IntervalBlocked:
			blocked += uint64(iv.End - iv.Start)
		case nativeperf.IntervalUnknown:
			uncertain += uint64(iv.End - iv.Start)
		}
	}
	switch {
	case truthNs == 0:
		return VerdictUnknown, nativeNs
	case nativeNs == 0 && blocked > 0 && uncertain == 0:
		return VerdictFail, nativeNs // a complete split that never reports the run-queue delay the workload measured
	case nativeNs == 0:
		return VerdictUnknown, nativeNs
	case blocked >= nativeNs:
		return VerdictFail, nativeNs // contention that is not clearly distinct from blocked time
	case float64(diff(nativeNs, truthNs))/float64(truthNs) > BlockedTolerance:
		return VerdictFail, nativeNs // not the contention the workload measured
	}
	return VerdictPass, nativeNs
}

// CompareSleeperRunnable judges the threads that did NOT contend for the CPU but
// slept (the workload's coordinator, which sleeps in 1 ms polls). A sleeper is
// blocked, not waiting for a CPU: its run-queue delay is bounded by the time its
// sleeps overshot what it asked for, which the workload measured itself
// (boundNs). Native runnable delay beyond that bound (plus the approved
// tolerance) is blocked time reported as run-queue delay, and fails. A sleeper
// with no blocked and no runnable evidence, or no ground-truth bound, is unknown.
func CompareSleeperRunnable(boundNs uint64, native []nativeperf.Interval) (verdict string, runnableNs, blockedNs uint64) {
	for _, iv := range native {
		if iv.Correction {
			continue
		}
		switch iv.Kind {
		case nativeperf.IntervalRunnable:
			runnableNs += uint64(iv.End - iv.Start)
		case nativeperf.IntervalBlocked:
			blockedNs += uint64(iv.End - iv.Start)
		}
	}
	switch {
	case boundNs == 0 || runnableNs == 0 && blockedNs == 0:
		return VerdictUnknown, runnableNs, blockedNs
	case float64(runnableNs) > float64(boundNs)*(1+BlockedTolerance):
		return VerdictFail, runnableNs, blockedNs
	}
	return VerdictPass, runnableNs, blockedNs
}
