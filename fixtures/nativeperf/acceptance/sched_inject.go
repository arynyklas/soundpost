//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The scheduler injection rows (plan 04 task 09, criteria 04.04-C13 and 04.09-C7): real scheduler captures through the
// signed-grant helper whose evidence is deliberately damaged, judged by qual.JudgeSchedulerLoss, qual.JudgeMissingWake
// and qual.JudgeFinalCensor. Every record is a real kernel record; what is injected is the damage:
//
//   - loss: 4 KiB scheduler rings and a reader stalled for several seconds, so the kernel overflows the rings and the
//     helper delivers explicit loss records (nothing is fabricated);
//   - missing wake: every wakeup record of the target is dropped on the consumer side before the correlator sees it
//     (the switch-out and switch-in records stay), so a wake is genuinely missing from the evidence;
//   - final censor: the capture is stopped while the target sleeps in one long nanosleep (workloads.c blockhold), so
//     the last interval is still open when the final acquisition proof is made.

const (
	injectionHold      = 5 // seconds the blockhold workload sleeps
	injectionHoldStop  = 1500 * time.Millisecond
	injectionLossRing  = 4096
	injectionStallFor  = 3 * time.Second
	injectionStallWhen = 40 // scheduler events consumed before the reader stalls
)

// injectionRun is one injection capture and the verdict of its judge.
type injectionRun struct {
	Run     *scenResult
	Verdict qual.InjectionVerdict
	Dropped int // wakeup records dropped on the consumer side (missing wake)
	Stalled bool
}

// wrapSink forwards to the correlation sink the harness gave it. Revoke is forwarded so a stream that ends on an
// identity error still ends the correlation (qual.Capture looks for it on the sink it was given).
type wrapSink struct {
	inner qual.EventSink
	event func(e nativeperf.SanitizedEvent) (forward bool)
}

func (w *wrapSink) Event(e nativeperf.SanitizedEvent) bool {
	if w.event != nil && !w.event(e) {
		return false
	}
	return w.inner.Event(e)
}

func (w *wrapSink) Proof(p nativeperf.AcquisitionProof) { w.inner.Proof(p) }

func (w *wrapSink) Revoke(through uint64) {
	if r, ok := w.inner.(interface{ Revoke(uint64) }); ok {
		r.Revoke(through)
	}
}

// dropWakeups returns the hook that drops every wakeup record, counting them.
func dropWakeups(dropped *int) func(qual.EventSink) qual.EventSink {
	return func(inner qual.EventSink) qual.EventSink {
		return &wrapSink{inner: inner, event: func(e nativeperf.SanitizedEvent) bool {
			if e.Wakeup != nil {
				*dropped++
				return false
			}
			return true
		}}
	}
}

// stallReader returns the hook that makes the reader sleep for d once after it has consumed n events.
func stallReader(n int, d time.Duration, stalled *bool) func(qual.EventSink) qual.EventSink {
	return func(inner qual.EventSink) qual.EventSink {
		var once sync.Once
		seen := 0
		return &wrapSink{inner: inner, event: func(nativeperf.SanitizedEvent) bool {
			seen++
			if seen >= n {
				once.Do(func() {
					*stalled = true
					time.Sleep(d)
				})
			}
			return true
		}}
	}
}

// stopAfterHold ends the capture once the workload's output (everything after its ready line) says it sleeps and d has
// passed since.
func stopAfterHold(d time.Duration, output func() string) func() bool {
	var since time.Time
	return func() bool {
		if since.IsZero() {
			if strings.Contains(output(), "holding\n") {
				since = time.Now()
			}
			return false
		}
		return time.Since(since) >= d
	}
}

// holdStopHook is stopAfterHold as the scenario's stop condition.
func holdStopHook(d time.Duration) func(w *qual.Workload) bool {
	var stop func() bool
	return func(w *qual.Workload) bool {
		if stop == nil {
			stop = stopAfterHold(d, w.Output)
		}
		return stop()
	}
}

// runSchedulerInjections runs the three injection captures. It is only called when the probe says the scheduler
// tracepoints open.
func (a *accept) runSchedulerInjections(base nativeperf.Config) {
	a.schedInject = map[string]*injectionRun{}
	cfg := base
	cfg.RingBytes = schedulerRingBytes

	fmt.Fprintln(os.Stderr, "acceptance: scheduler injection missing_wake")
	mw := &injectionRun{}
	mw.Run = a.runScenarioWith("sched_inject_missing_wake", "blocking", 6, cfg, 0, nil, nativeperf.ModeCPUOffCPU, scenHooks{wrapSink: dropWakeups(&mw.Dropped)})
	a.assertBlocking(mw.Run)
	mw.Verdict = a.judgeMissingWake(mw)
	a.schedInject["missing_wake"] = mw

	fmt.Fprintln(os.Stderr, "acceptance: scheduler injection final_censor")
	fc := &injectionRun{}
	fc.Run = a.runScenarioWith("sched_inject_final_censor", "blockhold", injectionHold, cfg, 0, nil, nativeperf.ModeCPUOffCPU, scenHooks{stopWhen: holdStopHook(injectionHoldStop)})
	fc.Verdict = a.judgeFinalCensor(fc)
	a.schedInject["final_censor"] = fc

	fmt.Fprintln(os.Stderr, "acceptance: scheduler injection loss")
	lossCfg := cfg
	lossCfg.RingBytes = injectionLossRing
	lo := &injectionRun{}
	lo.Run = a.runScenarioWith("sched_inject_loss", "blocking", 6, lossCfg, 0, nil, nativeperf.ModeCPUOffCPU, scenHooks{wrapSink: stallReader(injectionStallWhen, injectionStallFor, &lo.Stalled)})
	lo.Verdict = a.judgeSchedulerLoss(lo)
	a.schedInject["loss"] = lo
}

// injectionUsable says why an injection capture cannot be judged at all ("" when it can).
func injectionUsable(r *scenResult) string {
	switch {
	case r == nil:
		return "injection capture not run"
	case r.Err != "":
		return "fixture error: " + r.Err
	case !r.Cap.Ready:
		return "helper refused the scheduler capture: " + r.Cap.ErrorCode + r.Cap.ReadError
	case r.WorkloadExit != 0 || !r.SelfVerified:
		return fmt.Sprintf("workload did not verify its own ground truth (exit %d, self_verified=%v)", r.WorkloadExit, r.SelfVerified)
	case r.Corr == nil:
		return "no correlation"
	case r.Corr.Err != "":
		return "scheduler capture could not be correlated: " + r.Corr.Err + " (stream end: " + r.Cap.ErrorCode + r.Cap.ReadError + ")"
	}
	return ""
}

func unusable(why string) qual.InjectionVerdict {
	return qual.InjectionVerdict{Verdict: "error", Reason: why}
}

func (a *accept) judgeMissingWake(run *injectionRun) qual.InjectionVerdict {
	r := run.Run
	if why := injectionUsable(r); why != "" {
		return unusable(why)
	}
	if len(r.Failures) > 0 {
		return unusable("blocking workload assertions: " + fmt.Sprint(r.Failures))
	}
	if run.Dropped == 0 {
		return unusable("no wakeup record reached the consumer, so none was dropped: the injection did not happen")
	}
	var native []nativeperf.Interval
	for _, iv := range r.Corr.Intervals {
		if uint32(iv.Task.TGID) == r.TargetTID {
			native = append(native, iv)
		}
	}
	return qual.JudgeMissingWake(r.Blocked, native)
}

func (a *accept) judgeFinalCensor(run *injectionRun) qual.InjectionVerdict {
	r := run.Run
	if why := injectionUsable(r); why != "" {
		return unusable(why)
	}
	var hold *qual.BlockedTruth
	for _, l := range r.GT {
		if l.Kind == "block_hold" {
			hold = &qual.BlockedTruth{TID: uint32(l.TID), Start: l.StartNs, End: l.EndNs}
		}
	}
	if hold == nil {
		return unusable("the workload recorded no block_hold interval")
	}
	r.Extra["block_hold_start_ns"], r.Extra["block_hold_end_ns"], r.Extra["final_proof_through_ns"] = hold.Start, hold.End, r.Corr.FinalThrough
	return qual.JudgeFinalCensor(*hold, r.Corr.FinalThrough, r.Corr.Intervals)
}

func (a *accept) judgeSchedulerLoss(run *injectionRun) qual.InjectionVerdict {
	r := run.Run
	switch {
	case r == nil:
		return unusable("injection capture not run")
	case r.Err != "":
		return unusable("fixture error: " + r.Err)
	case !r.Cap.Ready:
		return unusable("helper refused the scheduler capture: " + r.Cap.ErrorCode + r.Cap.ReadError)
	case !run.Stalled:
		return unusable("the reader never stalled: the injection did not happen")
	case r.Corr == nil:
		return unusable("no correlation")
	}
	var lossAt []uint64
	for _, e := range r.Cap.Events {
		if e.Loss != nil {
			lossAt = append(lossAt, uint64(e.Time))
		}
	}
	if r.Corr.Err != "" && len(lossAt) == 0 && r.Cap.ErrorCode == "loss" {
		// the stream ended on the explicit closed code loss and nothing was reported as measured after it
		return qual.InjectionVerdict{Verdict: qual.VerdictPass, Reason: "the stream ended with the explicit closed code loss and carried no final proof"}
	}
	if r.Corr.Err != "" {
		return unusable("scheduler capture could not be correlated: " + r.Corr.Err + " (stream end: " + r.Cap.ErrorCode + r.Cap.ReadError + ")")
	}
	return qual.JudgeSchedulerLoss(lossAt, r.Corr.Intervals)
}

// injectionDetail is the report detail of one injection capture.
func injectionDetail(run *injectionRun) map[string]any {
	d := map[string]any{"verdict": run.Verdict.Verdict, "reason": run.Verdict.Reason, "intervals": run.Verdict.Intervals, "covered": run.Verdict.Covered, "truth_ns": run.Verdict.TruthNs, "native_ns": run.Verdict.NativeNs, "deviation": run.Verdict.Deviation}
	if run.Run != nil {
		d["scenario"] = run.Run.summary()
		if run.Run.Corr != nil {
			c := run.Run.Corr
			d["correlation"] = map[string]any{"switch_events": c.SwitchEvents, "wakeup_events_seen": c.WakeupEvents, "loss_events": c.LossEvents, "consume_errors": c.ConsumeErrors, "first_error": c.FirstError, "interval_counts": c.IntervalCounts, "final_through": c.FinalThrough}
		}
	}
	if run.Dropped > 0 {
		d["wakeup_records_dropped"] = run.Dropped
	}
	if run.Stalled {
		d["reader_stalled_for"] = injectionStallFor.String()
	}
	return d
}

// applyInjectionToRow folds the verdict of an injection into a row that is otherwise supported: a failed judge fails
// the row, an unknown or erroring one stops it being supported, a pass adds its evidence.
func applyInjectionToRow(row *qual.Row, name string, run *injectionRun) {
	if row.Detail == nil {
		row.Detail = map[string]any{}
	}
	var inj map[string]any
	if cur, ok := row.Detail["injections"].(map[string]any); ok {
		inj = cur
	} else {
		inj = map[string]any{}
		row.Detail["injections"] = inj
	}
	if run == nil {
		inj[name] = map[string]any{"verdict": "not_run"}
		if row.State == qual.StateSupported {
			*row = qual.Row{State: qual.StateNotRun, Reason: name + " injection not run", Detail: row.Detail}
		}
		return
	}
	inj[name] = injectionDetail(run)
	if row.State != qual.StateSupported {
		return
	}
	switch run.Verdict.Verdict {
	case qual.VerdictPass:
		row.Evidence = append(row.Evidence, name+" injection: "+run.Verdict.Reason)
	case qual.VerdictFail:
		*row = qual.Failed(name+" injection: "+run.Verdict.Reason, row.Detail)
	case qual.VerdictUnknown:
		*row = qual.Unqualified("scheduler_evidence_unknown: "+name+" injection: "+run.Verdict.Reason, row.Detail)
	default:
		*row = qual.Row{State: qual.StateError, Reason: name + " injection: " + run.Verdict.Reason, Exercised: true, Detail: row.Detail}
	}
}

// applySchedulerOffCPUInjections applies the missing-wake and final-censor verdicts to the off-CPU row; the loss
// verdict goes to the loss row (applySchedulerLossInjection), next to the CPU-ring injection (deriveInjectionRows).
func (a *accept) applySchedulerOffCPUInjections(res *qual.QualificationResult) {
	applyInjectionToRow(&res.OffCPU, "missing_wake", a.schedInject["missing_wake"])
	applyInjectionToRow(&res.OffCPU, "final_censor", a.schedInject["final_censor"])
}

func (a *accept) applySchedulerLossInjection(res *qual.QualificationResult) {
	applyInjectionToRow(&res.Loss, "scheduler_loss", a.schedInject["loss"])
}
