//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func contendScenario(coordinatorSamples int, coordinatorBlockedNs uint64, runnableNs uint64) *scenResult {
	sc := &scenResult{Name: "sched_contend", Mode: "contend", TargetTID: 10, Extra: map[string]any{"runnable_delay_truth_ns": uint64(1_000_000)},
		Cap: qual.CaptureResult{Ready: true}, Corr: &qual.Correlation{}}
	for _, tid := range []uint32{11, 12} {
		for range 50 {
			sc.Cap.Events = append(sc.Cap.Events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Task: nativeperf.TaskKey{TGID: 10, TID: tid}, CPUEvent: &nativeperf.CPUSample{}})
		}
		sc.Corr.Intervals = append(sc.Corr.Intervals,
			nativeperf.Interval{Task: nativeperf.TaskKey{TGID: 10, TID: tid}, Kind: nativeperf.IntervalRunnable, Start: 0, End: model.MonoNano(runnableNs / 2)},
			nativeperf.Interval{Task: nativeperf.TaskKey{TGID: 10, TID: tid}, Kind: nativeperf.IntervalBlocked, Start: 0, End: 1_000})
	}
	for range coordinatorSamples {
		sc.Cap.Events = append(sc.Cap.Events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Task: nativeperf.TaskKey{TGID: 10, TID: 13}, CPUEvent: &nativeperf.CPUSample{}})
	}
	sc.Corr.Intervals = append(sc.Corr.Intervals, nativeperf.Interval{Task: nativeperf.TaskKey{TGID: 10, TID: 13}, Kind: nativeperf.IntervalBlocked, Start: 0, End: model.MonoNano(coordinatorBlockedNs)})
	return sc
}

// The contention truth is the workload's pinned workers. Its coordinator thread
// sleeps in 1 ms polls for the whole run (seconds of blocked time by design) and
// gets one or two CPU samples when it happens to run: it is not a contended thread,
// and its blocked time must neither fail nor decide the runnable-delay row.
func TestRunqueueRowJudgesTheCPUBoundThreadsNotTheSleepingCoordinator(t *testing.T) {
	a := newAccept()
	a.results["sched_contend"] = contendScenario(2, 1_000_000, 900_000)
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateSupported {
		t.Fatalf("%+v", a.res.RunqueueSplit)
	}
}

func TestRunqueueRowStillFailsWhenTheContendedThreadsAreMostlyBlockedOrOffTruth(t *testing.T) {
	a := newAccept()
	a.results["sched_contend"] = contendScenario(0, 0, 300_000) // 30% of the truth
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("a runnable delay at 30%% of the truth passed: %+v", a.res.RunqueueSplit)
	}
	a = newAccept()
	sc := contendScenario(0, 0, 900_000)
	sc.Corr.Intervals[1].End = 900_000 // the contended thread blocked as long as it was runnable
	sc.Corr.Intervals[3].End = 900_000
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("blocked time as large as the runnable delay passed: %+v", a.res.RunqueueSplit)
	}
}

func TestSchedulerRowsFailWhenTheCorrelationOverflowedItsBuffer(t *testing.T) {
	a := newAccept()
	sc := contendScenario(0, 0, 900_000)
	sc.Corr.ConsumeErrors, sc.Corr.FirstError = 2, "native resource budget exceeded"
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("an overflowed correlation passed: %+v", a.res.RunqueueSplit)
	}
}
