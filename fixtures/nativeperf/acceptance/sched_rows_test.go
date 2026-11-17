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
	sc := &scenResult{Name: "sched_contend", Mode: "contend", TargetTID: 10, Extra: map[string]any{"runnable_delay_truth_ns": uint64(1_000_000), "sleeper_runnable_bound_ns": uint64(100_000)},
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
	return giveMemory(sc)
}

// giveMemory sets the capture's memory facts: one target on 8 CPUs, a helper that
// was 10,000 KiB resident and this process 12,000 KiB when the capture was
// admitted, and high-water marks of 24,000 KiB and 27,000 KiB afterwards (about
// what the real runs measure).
func giveMemory(sc *scenResult) *scenResult {
	sc.TargetCount, sc.ClientRSSBeforeKiB, sc.ClientHWMKiB = 1, 12_000, 27_000
	sc.Admission = qual.AdmissionMemory{Targets: 1, Threads: 3, HelperRSS: 10_000 << 10, ClientRSS: 12_000 << 10}
	sc.HelperBefore.RSSKiB, sc.HelperPeak.HWMKiB = 10_000, 24_000
	sc.Corr.CPUs = 8
	if sc.Corr.ReservationBytes == 0 {
		// D40: the share the harness is handed once the leases and the allowance are out of the budget
		share, err := qual.CorrelationReservation(nativeperf.DefaultConfig(1), sc.Admission, 8)
		if err != nil {
			panic(err)
		}
		sc.Corr.ReservationBytes = share
	}
	return sc
}

// The correlation reservation is carved out of the same 64 MiB as every other
// working set of the capture: when they do not fit together (what the helper's own
// admission charged, nominally, plus the reservation) or the measured resident
// memory goes over, the row fails instead of reporting a split that was bought
// with memory outside the budget.
func TestSchedulerRowsFailWhenTheCorrelationReservationDoesNotFitTheBudget(t *testing.T) {
	for name, mutate := range map[string]func(*scenResult){
		"admission charge plus reservation": func(sc *scenResult) { sc.Admission.ClientRSS = 20_000 << 10 },
		"measured resident memory":          func(sc *scenResult) { sc.ClientHWMKiB, sc.HelperPeak.HWMKiB = 30_000, 30_000 },
	} {
		a := newAccept()
		sc := contendScenario(2, 1_000_000, 1_000_000)
		mutate(sc)
		a.results["sched_contend"] = sc
		a.deriveSchedulerFromCaptures(a.res, map[string]any{})
		if a.res.RunqueueSplit.State != qual.StateFailed {
			t.Errorf("%s: %+v", name, a.res.RunqueueSplit)
		}
	}
	a := newAccept()
	a.results["sched_contend"] = contendScenario(2, 1_000_000, 1_000_000)
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateSupported {
		t.Fatalf("the measured numbers fit and the row did not pass: %+v", a.res.RunqueueSplit)
	}
}

// The harness's own working sets are part of the budget too: the events it retained and the intervals the
// correlator returned must fit their allowance, and the product's ProfileSource leases (map-read scratch, assembly,
// export: 24 MiB for one target) must be admitted behind the same admission charge. A capture that fits the nominal
// sum but not one of these fails its row.
func TestSchedulerRowsFailWhenTheHarnessOrTheProductLeasesDoNotFit(t *testing.T) {
	for name, mutate := range map[string]func(*scenResult){
		"retained events over their allowance":      func(sc *scenResult) { sc.RetainedBytes = qual.ConsumerAllowanceBytes + 1 },
		"returned intervals over their allowance":   func(sc *scenResult) { sc.Corr.IntervalBytes = qual.ConsumerAllowanceBytes + 1 },
		"retained plus returned over the allowance": func(sc *scenResult) { sc.RetainedBytes, sc.Corr.IntervalBytes = 3<<20, 2<<20 },
		"product leases refused behind the charge": func(sc *scenResult) {
			// a 30 MiB harness: the capture's own charge and a 12 MiB share fit the 64 MiB, the 24 MiB of leases do not
			sc.Admission.ClientRSS = 30 << 20
			sc.Corr.ReservationBytes = 12 << 20
		},
	} {
		a := newAccept()
		sc := contendScenario(2, 1_000_000, 1_000_000)
		mutate(sc)
		a.results["sched_contend"] = sc
		a.deriveSchedulerFromCaptures(a.res, map[string]any{})
		if a.res.RunqueueSplit.State != qual.StateFailed {
			t.Errorf("%s: %+v", name, a.res.RunqueueSplit)
		}
	}
	// the same capture inside every allowance passes, and its ledger names the leases
	a := newAccept()
	sc := contendScenario(2, 1_000_000, 1_000_000)
	sc.RetainedBytes, sc.Corr.IntervalBytes, sc.Corr.ReservationBytes = 1<<20, 1<<20, 4<<20
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateSupported {
		t.Fatalf("%+v", a.res.RunqueueSplit)
	}
	ledger, _ := a.res.RunqueueSplit.Detail["memory_ledger"].(map[string]any)
	if ledger["profile_source_leases_bytes"] != uint64(24<<20) || ledger["product_admits_leases"] != true || ledger["retained_events_bytes"] != uint64(1<<20) || ledger["returned_intervals_bytes"] != uint64(1<<20) {
		t.Fatalf("%+v", ledger)
	}
}

// A harness that was 9 MiB resident when the capture was admitted leaves less than the 32 MiB cap once the
// ProfileSource leases and the allowance are out of the budget (D40): the correlator is handed what is
// left, the ledger adds up to the budget, and the row is judged on its split.
func TestSchedulerRowsPassWhenTheCorrelatorWasHandedWhatTheChargeLeaves(t *testing.T) {
	sc := contendScenario(2, 1_000_000, 1_000_000)
	sc.Admission.ClientRSS, sc.Admission.HelperRSS = 9_000<<10, 8_000<<10
	share, err := qual.CorrelationReservation(nativeperf.DefaultConfig(1), sc.Admission, 8)
	if err != nil || share >= qual.CorrelationReservationBytes {
		t.Fatalf("%d %v", share, err)
	}
	sc.Corr.ReservationBytes = share
	a := newAccept()
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateSupported {
		t.Fatalf("%+v", a.res.RunqueueSplit)
	}
	sc.Corr.ReservationBytes = qual.CorrelationReservationBytes // the fixed 32 MiB share would not have fit
	a = newAccept()
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("%+v", a.res.RunqueueSplit)
	}
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

func coordinatorRunnable(sc *scenResult, ns uint64) {
	sc.Corr.Intervals = append(sc.Corr.Intervals, nativeperf.Interval{Task: nativeperf.TaskKey{TGID: 10, TID: 13}, Kind: nativeperf.IntervalRunnable, Start: 0, End: model.MonoNano(ns)})
}

// A collector that reports a sleeping thread's blocked time as run-queue delay
// leaves the CPU-bound threads' numbers intact (they hardly sleep), so the
// contended-thread comparison alone cannot see it. The sleeper's own measured
// bound does: its run-queue delay cannot exceed what its sleeps overshot.
func TestRunqueueRowFailsWhenTheSleepersBlockedTimeIsReportedAsRunnable(t *testing.T) {
	a := newAccept()
	sc := contendScenario(2, 1_000_000, 1_000_000)
	coordinatorRunnable(sc, 1_000_000) // the 1 ms the coordinator slept, reported as run-queue delay
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("blocked time reported as runnable delay passed: %+v", a.res.RunqueueSplit)
	}
}

func TestRunqueueRowSleeperBoundIsTheApprovedToleranceNotLooser(t *testing.T) {
	for name, tc := range map[string]struct {
		ns   uint64
		want qual.State
	}{"at the bound": {100_000, qual.StateSupported}, "upper edge": {125_000, qual.StateSupported}, "above": {125_001, qual.StateFailed}} {
		a := newAccept()
		sc := contendScenario(2, 1_000_000, 1_000_000)
		coordinatorRunnable(sc, tc.ns)
		a.results["sched_contend"] = sc
		a.deriveSchedulerFromCaptures(a.res, map[string]any{})
		if got := a.res.RunqueueSplit.State; got != tc.want {
			t.Errorf("%s: %s, want %s: %+v", name, got, tc.want, a.res.RunqueueSplit)
		}
	}
}

// Without the workload's sleeper measurement (or with a sleeper the capture never
// saw) the row cannot show that blocked time stays out of the run-queue delay: it
// is unqualified, never supported.
func TestRunqueueRowIsNotSupportedWithoutSleeperEvidence(t *testing.T) {
	a := newAccept()
	sc := contendScenario(2, 1_000_000, 1_000_000)
	delete(sc.Extra, "sleeper_runnable_bound_ns")
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State == qual.StateSupported {
		t.Fatalf("supported without a sleeper ground truth: %+v", a.res.RunqueueSplit)
	}
	a = newAccept()
	sc = contendScenario(0, 0, 1_000_000) // no coordinator interval at all
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State == qual.StateSupported {
		t.Fatalf("supported although no sleeper was observed: %+v", a.res.RunqueueSplit)
	}
}

// A collector that never reports run-queue delay: the contended threads' waits
// all show up as blocked time. The workload measured them as waiting for the CPU.
func TestRunqueueRowFailsWhenNoRunnableDelayIsEverReported(t *testing.T) {
	a := newAccept()
	sc := contendScenario(2, 1_000_000, 1_000_000)
	for i := range sc.Corr.Intervals {
		if sc.Corr.Intervals[i].Kind == nativeperf.IntervalRunnable {
			sc.Corr.Intervals[i].Kind = nativeperf.IntervalBlocked
		}
	}
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateFailed {
		t.Fatalf("zero runnable delay with complete blocked evidence did not fail: %+v", a.res.RunqueueSplit)
	}
}
