//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// runSchedulerScenarios runs the blocking and pinned-contention workloads under
// the real scheduler path (cpu_offcpu mode, sched_switch/sched_wakeup tracepoints
// through the signed-grant helper) and correlates the captured events with the
// committed per-session Correlator. It is only called when the capability probe
// says the scheduler tracepoints can be opened.
func (a *accept) runSchedulerScenarios(base nativeperf.Config) {
	cfg := base
	// The product's default ring (256 KiB per stream): a pinned contended CPU emits
	// several thousand scheduler records a second, and a 64 KiB ring overflows
	// (explicit kernel loss, which revokes coverage) between two reads of one stream.
	cfg.RingBytes = 256 << 10
	for _, item := range []struct {
		name string
		secs float64
	}{{"blocking", 6}, {"contend", 4}} {
		fmt.Fprintf(os.Stderr, "acceptance: scheduler scenario %s\n", item.name)
		r := a.runScenario("sched_"+item.name, item.name, item.secs, cfg, 0, nil, nativeperf.ModeCPUOffCPU)
		sp := *findSpec(item.name)
		a.assert(sp, r)
		a.results["sched_"+item.name] = r
	}
}

func (a *accept) corrSummary(r *scenResult) map[string]any {
	m := r.summary()
	if r.Corr == nil {
		return m
	}
	c := r.Corr
	kinds := map[string]int{}
	var blocked, runnable, censored, unknown uint64
	for _, iv := range c.Intervals {
		kinds[string(iv.Kind)]++
		d := uint64(iv.End - iv.Start)
		switch iv.Kind {
		case nativeperf.IntervalBlocked:
			blocked += d
		case nativeperf.IntervalRunnable:
			runnable += d
		case nativeperf.IntervalCensored:
			censored += d
		case nativeperf.IntervalUnknown:
			unknown += d
		}
	}
	m["correlation"] = map[string]any{
		"error": c.Err, "consume_errors": c.ConsumeErrors, "first_consume_error": c.FirstError, "scheduler_switch_events": c.SwitchEvents, "scheduler_wakeup_events": c.WakeupEvents,
		"cpu_samples_in_same_capture": c.CPUSamples, "loss_events": c.LossEvents, "cpus": c.CPUs, "interval_kinds": kinds, "progress_proofs_applied": c.ProgressProofs, "peak_buffered_events": c.PeakHeapEvents,
		"blocked_ns_all_authorized_tasks": blocked, "runnable_ns_all_authorized_tasks": runnable, "censored_ns": censored, "unknown_ns": unknown,
	}
	return m
}

func (a *accept) deriveSchedulerFromCaptures(res *qual.QualificationResult, detail map[string]any) {
	sb, sc := a.results["sched_blocking"], a.results["sched_contend"]
	off, rq := map[string]any{}, map[string]any{}
	for k, v := range detail {
		off[k], rq[k] = v, v
	}
	state := func(r *scenResult, row *qual.Row, d map[string]any, what string) bool {
		switch {
		case r == nil:
			*row = qual.Row{State: qual.StateNotRun, Reason: "scheduler scenario not run", Detail: d}
		case r.Err != "":
			*row = qual.Row{State: qual.StateError, Reason: r.Err, Exercised: true, Detail: d}
		case !r.Cap.Ready && r.Cap.ErrorCode == "permission_denied":
			*row = qual.Row{State: qual.StateDenied, Reason: "helper refused the scheduler capture: permission_denied", Detail: d}
		case !r.Cap.Ready:
			*row = qual.Row{State: qual.StateError, Reason: "helper refused the scheduler capture: " + r.Cap.ErrorCode + r.Cap.ReadError, Exercised: true, Detail: d}
		case r.Corr == nil || r.Corr.Err != "":
			why := "no correlation"
			if r.Corr != nil {
				why = r.Corr.Err
			}
			*row = qual.Row{State: qual.StateFailed, Reason: what + ": scheduler capture could not be correlated: " + why + " (stream end: " + r.Cap.ErrorCode + r.Cap.ReadError + ")", Exercised: true, Detail: d}
		case r.Corr.ConsumeErrors > 0:
			*row = qual.Row{State: qual.StateFailed, Reason: fmt.Sprintf("%s: the scheduler correlation overflowed its bounded buffer %d time(s) (first: %s), so its coverage was revoked", what, r.Corr.ConsumeErrors, r.Corr.FirstError), Exercised: true, Detail: d}
		default:
			return true
		}
		return false
	}
	if sb != nil {
		off["scenario"] = a.corrSummary(sb)
	}
	if sc != nil {
		rq["scenario"] = a.corrSummary(sc)
	}
	if state(sb, &res.OffCPU, off, "off_cpu") {
		var native []nativeperf.Interval
		for _, iv := range sb.Corr.Intervals {
			if uint32(iv.Task.TGID) == uint32(sb.TargetTID) {
				native = append(native, iv)
			}
		}
		cmp := qual.CompareBlocked(sb.Blocked, native)
		off["comparison"] = map[string]any{"verdict": cmp.Verdict, "reason": cmp.Reason, "ground_truth_intervals": cmp.Intervals, "matched": cmp.Matched, "truth_ns": cmp.TruthNs, "native_blocked_ns": cmp.NativeNs, "summed_deviation": cmp.Deviation, "worst_single_interval_deviation": cmp.MaxInterval, "tolerance": qual.BlockedTolerance}
		switch {
		case len(sb.Failures) > 0:
			res.OffCPU = qual.Failed("blocking scenario assertions: "+fmt.Sprint(sb.Failures), off)
		case cmp.Verdict == qual.VerdictPass:
			res.OffCPU = qual.Supported([]string{fmt.Sprintf("native blocked time %d ns vs the workload's monotonic ground truth %d ns over %d intervals: deviation %.1f%% (limit %.0f%%)", cmp.NativeNs, cmp.TruthNs, cmp.Intervals, cmp.Deviation*100, qual.BlockedTolerance*100)}, off)
		case cmp.Verdict == qual.VerdictFail:
			res.OffCPU = qual.Failed(cmp.Reason, off)
		default:
			res.OffCPU = qual.Unqualified("scheduler_evidence_unknown: "+cmp.Reason, off)
		}
	}
	if state(sc, &res.RunqueueSplit, rq, "runqueue_split") {
		// The contended threads are the CPU-bound ones: each holds at least a tenth
		// of the capture's CPU samples (the pinned workers hold about half each). The
		// workload's coordinator, which sleeps in 1 ms polls for the whole run and is
		// sampled only when it happens to be running, is blocked by design and is not
		// part of the contention truth.
		perThread, total := map[uint32]int{}, 0
		for _, e := range sc.Cap.Events {
			if e.CPUEvent != nil {
				perThread[e.Task.TID]++
				total++
			}
		}
		contended := map[uint32]bool{}
		for tid, n := range perThread {
			if n*10 >= total {
				contended[tid] = true
			}
		}
		var native []nativeperf.Interval
		var processBlocked, unknownContended, censoredContended uint64
		corrections := map[string]int{}
		for _, iv := range sc.Corr.Intervals {
			if iv.Correction {
				corrections[string(iv.Reason)]++
			}
			if uint32(iv.Task.TGID) != uint32(sc.TargetTID) {
				continue
			}
			if iv.Kind == nativeperf.IntervalBlocked && !iv.Correction {
				processBlocked += uint64(iv.End - iv.Start)
			}
			if contended[iv.Task.TID] {
				native = append(native, iv)
				switch {
				case iv.Kind == nativeperf.IntervalUnknown && !iv.Correction:
					unknownContended += uint64(iv.End - iv.Start)
				case iv.Kind == nativeperf.IntervalCensored:
					censoredContended += uint64(iv.End - iv.Start)
				}
			}
		}
		truth, _ := sc.Extra["runnable_delay_truth_ns"].(uint64)
		verdict, runnable := qual.CompareRunnable(truth, native)
		var blocked uint64
		for _, iv := range native {
			if iv.Kind == nativeperf.IntervalBlocked && !iv.Correction {
				blocked += uint64(iv.End - iv.Start)
			}
		}
		ratio := 0.0
		if truth > 0 {
			ratio = float64(runnable) / float64(truth)
		}
		rq["comparison"] = map[string]any{"verdict": verdict, "runnable_truth_ns": truth, "native_runnable_ns": runnable, "native_blocked_ns_contended_threads": blocked, "native_unknown_split_ns_contended_threads": unknownContended, "native_censored_ns_contended_threads": censoredContended, "native_blocked_ns_whole_process": processBlocked, "coverage_corrections_by_reason": corrections, "contended_threads": len(contended), "native_over_truth": ratio, "tolerance": qual.BlockedTolerance}
		switch {
		case len(sc.Failures) > 0:
			res.RunqueueSplit = qual.Failed("contention scenario assertions: "+fmt.Sprint(sc.Failures), rq)
		case verdict == qual.VerdictPass:
			res.RunqueueSplit = qual.Supported([]string{fmt.Sprintf("native runnable delay %d ns of the %d contended threads vs the workload's wall-minus-CPU ground truth %d ns (%.1f%%, limit +-%.0f%%), distinct from the %d ns those threads were blocked", runnable, len(contended), truth, ratio*100, qual.BlockedTolerance*100, blocked)}, rq)
		case verdict == qual.VerdictFail:
			res.RunqueueSplit = qual.Failed(fmt.Sprintf("runnable delay not distinct from blocked time or not the measured contention: native runnable %d ns vs ground truth %d ns (%.1f%%, limit +-%.0f%%), blocked %d ns of the same threads", runnable, truth, ratio*100, qual.BlockedTolerance*100, blocked), rq)
		default:
			res.RunqueueSplit = qual.Unqualified("scheduler_evidence_unknown: no runnable evidence for the contended threads", rq)
		}
	}
}
