//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"soundpost/fixtures/nativeperf/qual"
	"soundpost/internal/nativeperf"
)

// runSchedulerScenarios runs the blocking and pinned-contention workloads under
// the real scheduler path (cpu_offcpu mode, sched_switch/sched_wakeup tracepoints
// through the signed-grant helper) and correlates the captured events with the
// committed per-session Correlator. It is only called when the capability probe
// says the scheduler tracepoints can be opened.
func (a *accept) runSchedulerScenarios(base nativeperf.Config) {
	cfg := base
	cfg.RingBytes = 64 << 10
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
		"cpu_samples_in_same_capture": c.CPUSamples, "loss_events": c.LossEvents, "cpus": c.CPUs, "interval_kinds": kinds,
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
		var native []nativeperf.Interval
		for _, iv := range sc.Corr.Intervals {
			if uint32(iv.Task.TGID) == uint32(sc.TargetTID) {
				native = append(native, iv)
			}
		}
		truth, _ := sc.Extra["runnable_delay_truth_ns"].(uint64)
		verdict, runnable := qual.CompareRunnable(truth, native)
		var blocked uint64
		for _, iv := range native {
			if iv.Kind == nativeperf.IntervalBlocked {
				blocked += uint64(iv.End - iv.Start)
			}
		}
		ratio := 0.0
		if truth > 0 {
			ratio = float64(runnable) / float64(truth)
		}
		rq["comparison"] = map[string]any{"verdict": verdict, "runnable_truth_ns": truth, "native_runnable_ns": runnable, "native_blocked_ns_same_task": blocked, "native_over_truth": ratio}
		switch {
		case len(sc.Failures) > 0:
			res.RunqueueSplit = qual.Failed("contention scenario assertions: "+fmt.Sprint(sc.Failures), rq)
		case verdict == qual.VerdictPass:
			res.RunqueueSplit = qual.Supported([]string{fmt.Sprintf("native runnable delay %d ns (ground truth wall-minus-CPU %d ns) distinct from native blocked time %d ns", runnable, truth, blocked)}, rq)
		case verdict == qual.VerdictFail:
			res.RunqueueSplit = qual.Failed("runnable delay not distinct from blocked time", rq)
		default:
			res.RunqueueSplit = qual.Unqualified("scheduler_evidence_unknown: no runnable evidence for the contended threads", rq)
		}
	}
}
