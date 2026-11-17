// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// ParseWaitBegin reads the "wait_begin <ns>" line a runtime fixture prints when its wait phase starts (CLOCK_MONOTONIC
// nanoseconds, the clock of the scheduler events). A line that is not complete yet (no newline), not a number or zero
// is not an announcement.
func ParseWaitBegin(output string) (uint64, bool) {
	for _, line := range strings.SplitAfter(output, "\n") {
		rest, ok := strings.CutPrefix(line, "wait_begin ")
		if !ok || !strings.HasSuffix(rest, "\n") {
			continue
		}
		if ns, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64); err == nil && ns != 0 {
			return ns, true
		}
	}
	return 0, false
}

// KeepWaitWindow is the interval filter of a runtime column's wait row, applied where the correlator returns an
// interval so that nothing outside the evidence ever reaches the consumer's allowance: coverage corrections always (they
// say where evidence was revoked), the event-loop thread's intervals that end at or after the announced start of the
// wait phase, and nothing else; before the announcement nothing but corrections is kept (the CPU phase of the fixture
// is not wait evidence). output is the workload's output so far.
func KeepWaitWindow(loopTID uint32, output func() string) func(nativeperf.Interval) bool {
	var begin uint64
	return func(iv nativeperf.Interval) bool {
		if iv.Correction {
			return true
		}
		if iv.Task.TID != loopTID {
			return false
		}
		if begin == 0 {
			begin, _ = ParseWaitBegin(output())
		}
		return begin != 0 && uint64(iv.End) >= begin
	}
}

// MinRuntimeWaitRequests is the fewest loopback requests a runtime column has to
// have waited on for its wait row to say anything.
const MinRuntimeWaitRequests = 20

// RuntimeWaitTruth is what a runtime fixture measured about its own wait phase:
// the event-loop thread (TID, the process's main thread), the monotonic window
// of the phase (CLOCK_MONOTONIC nanoseconds, the clock of the scheduler events),
// how many loopback HTTP requests it waited on, the server-side hold each one had
// (the loop is idle at least that long per request) and the sum of the round
// trips the runtime itself observed (the loop is idle at most that long).
type RuntimeWaitTruth struct {
	TID            uint32
	StartNs, EndNs uint64
	Requests       int
	ServerDelayNs  uint64
	WaitTotalNs    uint64
}

// RuntimeWaitComparison is the outcome of CompareRuntimeWait.
type RuntimeWaitComparison struct {
	Verdict string
	Reason  string
	// NativeNs is the loop thread's native blocked time inside the window;
	// LowerNs and UpperNs the bounds the runtime's own measurements put on it;
	// RunnableNs, UnknownNs and CensoredNs the rest of the loop thread's evidence.
	NativeNs, LowerNs, UpperNs        uint64
	RunnableNs, UnknownNs, CensoredNs uint64
	Intervals                         int
}

// CompareRuntimeWait judges the wait row of a runtime column: the native blocked
// time of the runtime's event-loop thread, inside the window in which the runtime
// waited on its loopback requests, has to lie between what the runtime's own
// measurements force it to be at least (every request was held server-side for
// ServerDelayNs while the same loop was idle) and at most (the round trips it
// observed), widened by the approved tolerance. It is judged on the loop thread
// only: the runtime's helper threads sleep through the same window.
//
// Missing evidence is unknown, never a pass: too few requests, no recorded hold
// or window, no interval of the loop thread at all, an unknown-split or censored
// interval inside the window, or a coverage correction (the loop thread's own or a
// domain-wide one) that revoked the scheduler evidence of part of it. A loop thread
// with known evidence but no blocked time (a collector that reports every wait as
// run-queue delay) fails.
func CompareRuntimeWait(truth RuntimeWaitTruth, native []nativeperf.Interval) RuntimeWaitComparison {
	c := RuntimeWaitComparison{Intervals: truth.Requests}
	switch {
	case truth.Requests < MinRuntimeWaitRequests:
		c.Verdict, c.Reason = VerdictUnknown, fmt.Sprintf("only %d requests waited on, need %d", truth.Requests, MinRuntimeWaitRequests)
		return c
	case truth.ServerDelayNs == 0 || truth.WaitTotalNs == 0 || truth.EndNs <= truth.StartNs || truth.TID == 0:
		c.Verdict, c.Reason = VerdictUnknown, "the runtime recorded no wait window, server hold or round trips"
		return c
	}
	c.LowerNs = uint64(float64(uint64(truth.Requests)*truth.ServerDelayNs) * (1 - BlockedTolerance))
	c.UpperNs = uint64(float64(truth.WaitTotalNs) * (1 + BlockedTolerance))
	seen := false
	for _, iv := range native {
		if iv.Correction {
			// a nonadditive coverage replacement: the scheduler evidence of that span was revoked, so it cannot be
			// summed and it cannot be taken as absent either
			if iv.Task == (nativeperf.TaskKey{}) || iv.Task.TID == truth.TID {
				c.UnknownNs += overlap(truth.StartNs, truth.EndNs, uint64(iv.Start), uint64(iv.End))
			}
			continue
		}
		if iv.Task.TID != truth.TID {
			continue
		}
		seen = true
		o := overlap(truth.StartNs, truth.EndNs, uint64(iv.Start), uint64(iv.End))
		switch iv.Kind {
		case nativeperf.IntervalBlocked:
			c.NativeNs += o
		case nativeperf.IntervalRunnable:
			c.RunnableNs += o
		case nativeperf.IntervalUnknown:
			c.UnknownNs += o
		case nativeperf.IntervalCensored:
			c.CensoredNs += o
		}
	}
	switch {
	case !seen:
		c.Verdict, c.Reason = VerdictUnknown, "no scheduler interval of the event-loop thread"
	case c.UnknownNs > 0 || c.CensoredNs > 0:
		c.Verdict, c.Reason = VerdictUnknown, fmt.Sprintf("the window holds %d ns of unknown-split, corrected or censored time of the event-loop thread (%d ns censored)", c.UnknownNs, c.CensoredNs)
	case c.NativeNs < c.LowerNs:
		c.Verdict, c.Reason = VerdictFail, fmt.Sprintf("native blocked time %d ns is below the %d ns the loop was idle on %d requests held %d ns each (-%.0f%%)", c.NativeNs, c.LowerNs, truth.Requests, truth.ServerDelayNs, BlockedTolerance*100)
	case c.NativeNs > c.UpperNs:
		c.Verdict, c.Reason = VerdictFail, fmt.Sprintf("native blocked time %d ns exceeds the %d ns of round trips the runtime observed (+%.0f%%)", c.NativeNs, c.UpperNs, BlockedTolerance*100)
	default:
		c.Verdict = VerdictPass
	}
	return c
}
