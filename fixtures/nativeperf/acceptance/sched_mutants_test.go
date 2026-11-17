//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// These tests run the REAL correlator (through qual.Correlate, with progress
// proofs, exactly as the acceptance run does) over a hand-built, ground-truth-known
// stream and judge it with the committed row logic: two CPU-bound threads pinned
// to CPU 0 taking 4 ms turns (each waits 4 ms behind the other) and a coordinator
// on CPU 1 that sleeps in 1.05 ms polls and runs 10 us after each wake. They are
// NOT scheduler evidence: the real-kernel proof is the acceptance run on the 6.1
// and 6.6 qualification hosts with the same mutations applied to the collector.

const (
	mutSlice     = 4_000_000
	mutSlices    = 40
	mutPolls     = 150
	mutPollSleep = 1_050_000
	mutPollRun   = 10_000
)

var mutDomain = nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}

func mutKey(tid uint32) nativeperf.TaskKey {
	return nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 10, TID: tid, ProcessStart: 1, Generation: 1}
}

// mutScenario returns the contention scenario as the acceptance run builds it:
// CPU samples (to find the contended threads), the real correlation of the stream,
// and the workload's two ground truths (hog wall-minus-CPU, sleeper overshoot).
func mutScenario() *scenResult {
	coord, h1, h2 := mutKey(10), mutKey(11), mutKey(12)
	hogs := []nativeperf.TaskKey{h1, h2}
	var evs []nativeperf.SanitizedEvent
	add := func(at uint64, cpu uint32, e nativeperf.SanitizedEvent) {
		e.Time, e.CPU, e.Domain = model.MonoNano(at), cpu, mutDomain
		evs = append(evs, e)
	}
	for k := 1; k <= mutSlices; k++ {
		prev, next := hogs[(k-1)%2], hogs[k%2]
		add(uint64(k*mutSlice), 0, nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Switch: &nativeperf.SchedulerSwitch{Previous: &prev, Next: &next, PreviousState: 0, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}})
	}
	for i := 0; i < mutPolls; i++ {
		out := uint64(1_000_000 + i*(mutPollSleep+mutPollRun+50_000))
		add(out, 1, nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Switch: &nativeperf.SchedulerSwitch{Previous: &coord, PreviousState: 1, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}})
		add(out+mutPollSleep, 1, nativeperf.SanitizedEvent{Kind: nativeperf.EventWakeup, Task: coord, Wakeup: &nativeperf.SchedulerWakeup{Target: coord, TargetCPU: 1}})
		add(out+mutPollSleep+mutPollRun, 1, nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Switch: &nativeperf.SchedulerSwitch{Next: &coord}})
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time < evs[j].Time })
	res := qual.CaptureResult{Ready: true, Proofs: []nativeperf.AcquisitionProof{{Domain: mutDomain, CPUs: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, Through: 0}}, ProofAt: []int{0}}
	for i := range evs {
		evs[i].Sequence = model.Uint64(i + 1)
		res.Events = append(res.Events, evs[i])
		if (i+1)%10 == 0 {
			res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: mutDomain, CPUs: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, Through: evs[i].Time, Progress: true})
			res.ProofAt = append(res.ProofAt, len(res.Events))
		}
	}
	end := evs[len(evs)-1].Time + 1
	res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: mutDomain, CPUs: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, Through: end, Final: true})
	res.ProofAt = append(res.ProofAt, len(res.Events))
	// the known stream is 490 events in 0.3 s: it needs the share a 4 MiB helper and a 4 MiB harness leave (D40: the
	// ProfileSource leases and the consumer allowance come off the 64 MiB first), about 700 buffered events
	adm := qual.AdmissionMemory{Targets: 1, Threads: 3, HelperRSS: 4_000 << 10, ClientRSS: 4_000 << 10}
	corr := qual.CorrelateWithin(res, nativeperf.DefaultConfig(1), adm)
	// CPU samples (kept out of the correlated stream): each hog holds about half of
	// them, the coordinator a stray one or two
	for _, k := range []nativeperf.TaskKey{h1, h2, coord} {
		n := 40
		if k == coord {
			n = 2
		}
		for range n {
			res.Events = append(res.Events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Task: k, CPUEvent: &nativeperf.CPUSample{}})
		}
	}
	sc := giveMemory(&scenResult{Name: "sched_contend", Mode: "contend", TargetTID: 10, Cap: res, Corr: &corr, Extra: map[string]any{
		// each hog runs 80 ms of the 160 ms and waits for the other the rest
		"runnable_delay_truth_ns": uint64(mutSlices * mutSlice),
		// what the workload measures: each poll overshot its requested 1 ms by 60 us
		"sleeper_runnable_bound_ns": uint64(mutPolls * (mutPollSleep + mutPollRun - 1_000_000)),
	}})
	sc.Admission, sc.ClientRSSBeforeKiB, sc.HelperBefore.RSSKiB = adm, 4_000, 4_000
	return sc
}

func rowOf(sc *scenResult) qual.Row {
	a := newAccept()
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	return a.res.RunqueueSplit
}

// relabel is the mutated collector: it reports what the correlator measured with
// the given kinds swapped.
func relabel(sc *scenResult, from, to nativeperf.IntervalKind) *scenResult {
	m := *sc
	c := *sc.Corr
	c.Intervals = append([]nativeperf.Interval(nil), sc.Corr.Intervals...)
	for i := range c.Intervals {
		if !c.Intervals[i].Correction && c.Intervals[i].Kind == from {
			c.Intervals[i].Kind = to
		}
	}
	m.Corr = &c
	return &m
}

func TestRealCorrelatorOnTheKnownStreamPassesTheRunqueueRow(t *testing.T) {
	sc := mutScenario()
	if sc.Corr.Err != "" || sc.Corr.ConsumeErrors != 0 {
		t.Fatalf("%+v", sc.Corr)
	}
	if r := rowOf(sc); r.State != qual.StateSupported {
		t.Fatalf("%+v", r)
	}
}

// The mutant that reports a sleeping thread's blocked time as runnable delay
// (the correlator's blocked/runnable split conflated): the coordinator's 1.05 ms
// sleeps become run-queue delay. The contended threads hardly sleep, so only the
// sleeper's measured bound can reject it.
func TestMutantReportingBlockedTimeAsRunnableDelayFailsTheRow(t *testing.T) {
	r := rowOf(relabel(mutScenario(), nativeperf.IntervalBlocked, nativeperf.IntervalRunnable))
	if r.State != qual.StateFailed {
		t.Fatalf("a collector that reports sleeping time as run-queue delay passed: %+v", r)
	}
}

// The mutant that never reports run-queue delay at all.
func TestMutantReportingNoRunnableDelayFailsTheRow(t *testing.T) {
	r := rowOf(relabel(mutScenario(), nativeperf.IntervalRunnable, nativeperf.IntervalBlocked))
	if r.State != qual.StateFailed {
		t.Fatalf("a collector that never reports run-queue delay passed: %+v", r)
	}
}
