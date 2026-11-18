//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const injTarget = 4242

func injTask(tid uint32) nativeperf.TaskKey {
	return nativeperf.TaskKey{BootID: "b", PIDNamespace: 1, TGID: injTarget, TID: tid, ProcessStart: 1, Generation: 1}
}

func injInterval(kind nativeperf.IntervalKind, start, end uint64) nativeperf.Interval {
	return nativeperf.Interval{Kind: kind, Task: injTask(injTarget), Start: model.MonoNano(start), End: model.MonoNano(end)}
}

func injCapturedScenario() *scenResult {
	return &scenResult{Name: "inject", Cap: qual.CaptureResult{Ready: true}, WorkloadExit: 0, SelfVerified: true, TargetTID: injTarget, Extra: map[string]any{}, Corr: &qual.Correlation{}}
}

func injBlockingTruth(r *scenResult, n int) {
	for i := range n {
		start := 1_000_000_000 + uint64(i)*300_000_000
		r.Blocked = append(r.Blocked, qual.BlockedTruth{TID: injTarget, Start: start, End: start + 200_000_000})
	}
}

func injUnknown(r *scenResult) {
	for _, g := range r.Blocked {
		r.Corr.Intervals = append(r.Corr.Intervals, injInterval(nativeperf.IntervalUnknown, g.Start+100_000, g.End+900_000))
	}
}

func TestMissingWakeRowFailsWhenTheCorrelatorInfersTheWake(t *testing.T) {
	a := newAccept()
	honest := &injectionRun{Run: injCapturedScenario(), Dropped: 120}
	injBlockingTruth(honest.Run, 24)
	injUnknown(honest.Run)
	if v := a.judgeMissingWake(honest); v.Verdict != qual.VerdictPass {
		t.Fatalf("honest capture: %s", v)
	}

	contaminated := &injectionRun{Run: injCapturedScenario(), Dropped: 120}
	injBlockingTruth(contaminated.Run, 24)
	for _, g := range contaminated.Run.Blocked {
		contaminated.Run.Corr.Intervals = append(contaminated.Run.Corr.Intervals, injInterval(nativeperf.IntervalBlocked, g.Start, g.End))
	}
	if v := a.judgeMissingWake(contaminated); v.Verdict != qual.VerdictFail {
		t.Fatalf("blocked time with every wake dropped passed: %s", v)
	}

	// no wake record was dropped: the injection did not happen, so nothing was proven
	idle := &injectionRun{Run: injCapturedScenario()}
	injBlockingTruth(idle.Run, 24)
	injUnknown(idle.Run)
	if v := a.judgeMissingWake(idle); v.Verdict != "error" || !strings.Contains(v.Reason, "did not happen") {
		t.Fatalf("an injection that dropped nothing was judged: %s", v)
	}

	// intervals of other processes are not the target's evidence
	foreign := &injectionRun{Run: injCapturedScenario(), Dropped: 1}
	injBlockingTruth(foreign.Run, 24)
	injUnknown(foreign.Run)
	for i := range foreign.Run.Corr.Intervals {
		foreign.Run.Corr.Intervals[i].Task.TGID++
	}
	if v := a.judgeMissingWake(foreign); v.Verdict == qual.VerdictPass {
		t.Fatalf("another process's intervals passed: %s", v)
	}

	failing := &injectionRun{Run: injCapturedScenario(), Dropped: 1}
	injBlockingTruth(failing.Run, 24)
	injUnknown(failing.Run)
	failing.Run.Failures = []string{"workload"}
	if v := a.judgeMissingWake(failing); v.Verdict != "error" {
		t.Fatalf("workload assertion failure ignored: %s", v)
	}
}

func TestInjectionCapturesThatCannotBeJudgedAreErrorsNotPasses(t *testing.T) {
	a := newAccept()
	for _, c := range []struct {
		name   string
		mutate func(r *scenResult)
	}{
		{"fixture error", func(r *scenResult) { r.Err = "launch: boom" }},
		{"helper refused", func(r *scenResult) { r.Cap.Ready = false; r.Cap.ErrorCode = "permission_denied" }},
		{"workload exit", func(r *scenResult) { r.WorkloadExit = 3 }},
		{"workload unverified", func(r *scenResult) { r.SelfVerified = false }},
		{"no correlation", func(r *scenResult) { r.Corr = nil }},
		{"correlation error", func(r *scenResult) { r.Corr.Err = "capture has no initial and final acquisition proof" }},
	} {
		name, mutate := c.name, c.mutate
		r := injCapturedScenario()
		injBlockingTruth(r, 24)
		injUnknown(r)
		mutate(r)
		if v := a.judgeMissingWake(&injectionRun{Run: r, Dropped: 1}); v.Verdict != "error" {
			t.Errorf("missing wake, %s: %s", name, v)
		}
		fc := &injectionRun{Run: r}
		r.GT = []qual.GroundTruthLine{{Kind: "block_hold", TID: injTarget, StartNs: 1_000_000_000, EndNs: 6_000_000_000}}
		if v := a.judgeFinalCensor(fc); v.Verdict != "error" {
			t.Errorf("final censor, %s: %s", name, v)
		}
	}
	if v := a.judgeFinalCensor(&injectionRun{Run: injCapturedScenario()}); v.Verdict != "error" || !strings.Contains(v.Reason, "no block_hold") {
		t.Errorf("a final censor capture without the workload's own record was judged: %s", v)
	}
	if v := a.judgeMissingWake(&injectionRun{}); v.Verdict != "error" {
		t.Errorf("a missing capture was judged: %s", v)
	}
}

func TestFinalCensorRowReadsTheWorkloadsOwnRecordAndTheFinalProof(t *testing.T) {
	a := newAccept()
	r := injCapturedScenario()
	r.GT = []qual.GroundTruthLine{{Kind: "block_hold", TID: injTarget, StartNs: 1_000_000_000, EndNs: 6_000_000_000}}
	r.Corr.FinalThrough = 2_500_000_000
	r.Corr.Intervals = []nativeperf.Interval{injInterval(nativeperf.IntervalCensored, 1_000_150_000, 2_500_000_000)}
	if v := a.judgeFinalCensor(&injectionRun{Run: r}); v.Verdict != qual.VerdictPass {
		t.Fatalf("honest censored interval: %s", v)
	}
	if r.Extra["final_proof_through_ns"] != uint64(2_500_000_000) {
		t.Errorf("the final proof instant is not in the report detail: %v", r.Extra)
	}
	r.Corr.Intervals = []nativeperf.Interval{injInterval(nativeperf.IntervalBlocked, 1_000_150_000, 2_500_000_000)}
	if v := a.judgeFinalCensor(&injectionRun{Run: r}); v.Verdict != qual.VerdictFail {
		t.Fatalf("an open interval reported as completed blocked time passed: %s", v)
	}
}

func TestSchedulerLossRowIgnoredLossFails(t *testing.T) {
	a := newAccept()
	loss := func(at uint64) nativeperf.SanitizedEvent {
		return nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Time: model.MonoNano(at), Loss: &nativeperf.LossEvent{Count: 9, Reason: nativeperf.ReasonLoss}}
	}
	run := func(corrections bool, straddle bool) *injectionRun {
		r := injCapturedScenario()
		r.Cap.Events = []nativeperf.SanitizedEvent{loss(3_000_000_000)}
		r.Corr.Intervals = []nativeperf.Interval{injInterval(nativeperf.IntervalBlocked, 2_700_000_000, 2_800_000_000)}
		if corrections {
			r.Corr.Intervals = append(r.Corr.Intervals, nativeperf.Interval{Kind: nativeperf.IntervalUnknown, End: 3_000_001_000, Reason: nativeperf.ReasonLoss, Correction: true})
		}
		if straddle {
			r.Corr.Intervals = append(r.Corr.Intervals, injInterval(nativeperf.IntervalBlocked, 2_900_000_000, 3_100_000_000))
		}
		return &injectionRun{Run: r, Stalled: true}
	}
	if v := a.judgeSchedulerLoss(run(true, false)); v.Verdict != qual.VerdictPass {
		t.Fatalf("a loss answered by a correction: %s", v)
	}
	if v := a.judgeSchedulerLoss(run(false, false)); v.Verdict != qual.VerdictFail {
		t.Fatalf("an ignored loss passed: %s", v)
	}
	if v := a.judgeSchedulerLoss(run(true, true)); v.Verdict != qual.VerdictFail {
		t.Fatalf("an interval straddling the loss passed: %s", v)
	}
	notStalled := run(true, false)
	notStalled.Stalled = false
	if v := a.judgeSchedulerLoss(notStalled); v.Verdict != "error" {
		t.Fatalf("a run whose reader never stalled was judged: %s", v)
	}
	none := run(true, false)
	none.Run.Cap.Events = nil
	if v := a.judgeSchedulerLoss(none); v.Verdict != qual.VerdictUnknown {
		t.Fatalf("no loss provoked is not a pass: %s", v)
	}
	// the stream may end on the explicit closed code loss instead of delivering a final proof
	ended := run(true, false)
	ended.Run.Cap.Events = nil
	ended.Run.Corr.Err, ended.Run.Cap.ErrorCode = "capture has no initial and final acquisition proof", "loss"
	if v := a.judgeSchedulerLoss(ended); v.Verdict != qual.VerdictPass {
		t.Fatalf("a stream that ended on the closed code loss: %s", v)
	}
	broken := run(true, false)
	broken.Run.Corr.Err, broken.Run.Cap.ErrorCode = "capture has no initial and final acquisition proof", "acquisition_failed"
	if v := a.judgeSchedulerLoss(broken); v.Verdict != "error" {
		t.Fatalf("an uncorrelated capture without the loss code was judged: %s", v)
	}
	// a stream that ended on the closed code loss AFTER delivering loss events was not cut by loss alone: judged as an error
	cutAfterLoss := run(true, false)
	cutAfterLoss.Run.Corr.Err, cutAfterLoss.Run.Cap.ErrorCode = "capture has no initial and final acquisition proof", "loss"
	if v := a.judgeSchedulerLoss(cutAfterLoss); v.Verdict != "error" {
		t.Fatalf("a capture cut with loss events delivered was judged: %s", v)
	}
	// no loss event and no closed loss code: nothing explains the missing final proof
	unexplained := run(true, false)
	unexplained.Run.Cap.Events = nil
	unexplained.Run.Corr.Err, unexplained.Run.Cap.ErrorCode = "capture has no initial and final acquisition proof", "acquisition_failed"
	if v := a.judgeSchedulerLoss(unexplained); v.Verdict != "error" {
		t.Fatalf("a capture without final proof, loss events or the loss code was judged: %s", v)
	}
}

func TestInjectionVerdictsFoldIntoTheRowsTheyBelongTo(t *testing.T) {
	supported := func() qual.Row { return qual.Supported([]string{"base evidence"}, map[string]any{}) }
	run := func(verdict string) *injectionRun {
		return &injectionRun{Run: injCapturedScenario(), Verdict: qual.InjectionVerdict{Verdict: verdict, Reason: "why"}}
	}
	row := supported()
	applyInjectionToRow(&row, "missing_wake", run(qual.VerdictPass))
	if row.State != qual.StateSupported || len(row.Evidence) != 2 || !strings.Contains(row.Evidence[1], "missing_wake injection: why") {
		t.Errorf("pass: %+v", row)
	}
	row = supported()
	applyInjectionToRow(&row, "missing_wake", run(qual.VerdictFail))
	if row.State != qual.StateFailed || !strings.Contains(row.Reason, "missing_wake injection: why") || !row.Exercised {
		t.Errorf("fail: %+v", row)
	}
	row = supported()
	applyInjectionToRow(&row, "missing_wake", run(qual.VerdictUnknown))
	if row.State != qual.StateUnqualified || !strings.HasPrefix(row.Reason, "scheduler_evidence_unknown:") {
		t.Errorf("unknown: %+v", row)
	}
	row = supported()
	applyInjectionToRow(&row, "missing_wake", run("error"))
	if row.State != qual.StateError || !row.Exercised {
		t.Errorf("error: %+v", row)
	}
	row = supported()
	applyInjectionToRow(&row, "final_censor", nil)
	if row.State != qual.StateNotRun {
		t.Errorf("not run: %+v", row)
	}
	// a row that is not supported keeps its own state and reason: the injection only adds detail
	failed := qual.Failed("own failure", map[string]any{})
	applyInjectionToRow(&failed, "missing_wake", run(qual.VerdictPass))
	if failed.State != qual.StateFailed || failed.Reason != "own failure" || len(failed.Evidence) != 0 {
		t.Errorf("a failed row was changed: %+v", failed)
	}
	// both injections of one row are reported
	row = supported()
	applyInjectionToRow(&row, "missing_wake", run(qual.VerdictPass))
	applyInjectionToRow(&row, "final_censor", run(qual.VerdictPass))
	inj, _ := row.Detail["injections"].(map[string]any)
	if len(inj) != 2 || len(row.Evidence) != 3 {
		t.Errorf("injections in the detail: %v, evidence %v", inj, row.Evidence)
	}
	if err := row.Validate("off_cpu"); err != nil {
		t.Error(err)
	}
}

type injRecorder struct {
	events  []nativeperf.SanitizedEvent
	proofs  int
	revoked []uint64
}

func (r *injRecorder) Event(e nativeperf.SanitizedEvent) bool {
	r.events = append(r.events, e)
	return true
}
func (r *injRecorder) Proof(nativeperf.AcquisitionProof) { r.proofs++ }
func (r *injRecorder) Revoke(through uint64)             { r.revoked = append(r.revoked, through) }

func TestWakeupDropSinkDropsOnlyWakeupsAndForwardsTheRest(t *testing.T) {
	var dropped int
	inner := &injRecorder{}
	sink := dropWakeups(&dropped)(inner)
	wake := nativeperf.SanitizedEvent{Kind: nativeperf.EventWakeup, Wakeup: &nativeperf.SchedulerWakeup{Target: injTask(1)}}
	sw := nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Switch: &nativeperf.SchedulerSwitch{}}
	loss := nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Loss: &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}}
	for _, e := range []nativeperf.SanitizedEvent{wake, sw, wake, loss} {
		sink.Event(e)
	}
	if dropped != 2 || len(inner.events) != 2 || inner.events[0].Switch == nil || inner.events[1].Loss == nil {
		t.Errorf("dropped %d, forwarded %+v", dropped, inner.events)
	}
	sink.Proof(nativeperf.AcquisitionProof{})
	sink.(interface{ Revoke(uint64) }).Revoke(77)
	if inner.proofs != 1 || len(inner.revoked) != 1 || inner.revoked[0] != 77 {
		t.Errorf("proofs %d, revoked %v", inner.proofs, inner.revoked)
	}
}

func TestStalledReaderSinkSleepsOnceAfterTheThresholdAndForwardsEverything(t *testing.T) {
	var stalled bool
	inner := &injRecorder{}
	sink := stallReader(3, 120*time.Millisecond, &stalled)(inner)
	ev := nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Loss: &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}}
	start := time.Now()
	sink.Event(ev)
	sink.Event(ev)
	if time.Since(start) > 100*time.Millisecond || stalled {
		t.Fatalf("stalled before the threshold: %v %v", time.Since(start), stalled)
	}
	sink.Event(ev)
	if !stalled || time.Since(start) < 120*time.Millisecond {
		t.Fatalf("no stall at the threshold: %v %v", time.Since(start), stalled)
	}
	again := time.Now()
	sink.Event(ev)
	sink.Event(ev)
	if time.Since(again) > 100*time.Millisecond || len(inner.events) != 5 {
		t.Fatalf("stalled twice or dropped events: %v, %d forwarded", time.Since(again), len(inner.events))
	}
}

func TestHoldStopWaitsForTheWorkloadsHoldingLineAndThenForTheDelay(t *testing.T) {
	out := ""
	stop := stopAfterHold(80*time.Millisecond, func() string { return out })
	if stop() {
		t.Fatal("stopped before the workload said it was holding")
	}
	out = "something else\n"
	if stop() {
		t.Fatal("stopped on output that is not the holding line")
	}
	time.Sleep(100 * time.Millisecond)
	if stop() {
		t.Fatal("the delay was counted from output that is not the holding line")
	}
	out = "holding\n"
	if stop() {
		t.Fatal("stopped the moment the holding line appeared")
	}
	if stop() {
		t.Fatal("stopped before the delay since the holding line had passed")
	}
	time.Sleep(100 * time.Millisecond)
	out = "" // once seen, the line is remembered
	if !stop() {
		t.Fatal("did not stop once the delay had passed")
	}
}

// supportedBlockingScenario is a scheduler blocking capture whose native blocked time matches its ground truth.
func supportedBlockingScenario() *scenResult {
	sb := &scenResult{Name: "sched_blocking", Mode: "blocking", TargetTID: 10, Extra: map[string]any{}, Cap: qual.CaptureResult{Ready: true}, Corr: &qual.Correlation{}}
	for i := range 24 {
		start := 1_000_000_000 + uint64(i)*300_000_000
		sb.Blocked = append(sb.Blocked, qual.BlockedTruth{TID: 11, Start: start, End: start + 200_000_000})
		sb.Corr.Intervals = append(sb.Corr.Intervals, nativeperf.Interval{Task: nativeperf.TaskKey{TGID: 10, TID: 11}, Kind: nativeperf.IntervalBlocked, Start: model.MonoNano(start), End: model.MonoNano(start + 200_000_000)})
	}
	return giveMemory(sb)
}

func injectionWithVerdict(verdict string) *injectionRun {
	return &injectionRun{Run: injCapturedScenario(), Verdict: qual.InjectionVerdict{Verdict: verdict, Reason: "because"}}
}

func TestOffCPURowIsOnlySupportedWithTheMissingWakeAndFinalCensorInjections(t *testing.T) {
	derive := func(inject map[string]*injectionRun) qual.Row {
		a := newAccept()
		a.caps.OffCPU = nativeperf.Supported
		a.results["sched_blocking"] = supportedBlockingScenario()
		a.schedInject = inject
		a.deriveRows()
		return a.res.OffCPU
	}
	if row := derive(map[string]*injectionRun{"missing_wake": injectionWithVerdict(qual.VerdictPass), "final_censor": injectionWithVerdict(qual.VerdictPass)}); row.State != qual.StateSupported || len(row.Evidence) != 3 {
		t.Fatalf("both injections passed: %+v", row)
	}
	if row := derive(nil); row.State != qual.StateNotRun || !strings.Contains(row.Reason, "injection not run") {
		t.Errorf("no injection ran: %+v", row)
	}
	if row := derive(map[string]*injectionRun{"missing_wake": injectionWithVerdict(qual.VerdictPass)}); row.State != qual.StateNotRun || !strings.Contains(row.Reason, "final_censor") {
		t.Errorf("the final censor injection did not run: %+v", row)
	}
	if row := derive(map[string]*injectionRun{"missing_wake": injectionWithVerdict(qual.VerdictFail), "final_censor": injectionWithVerdict(qual.VerdictPass)}); row.State != qual.StateFailed || !strings.Contains(row.Reason, "missing_wake") {
		t.Errorf("a failed missing wake injection: %+v", row)
	}
	if row := derive(map[string]*injectionRun{"missing_wake": injectionWithVerdict(qual.VerdictPass), "final_censor": injectionWithVerdict(qual.VerdictFail)}); row.State != qual.StateFailed || !strings.Contains(row.Reason, "final_censor") {
		t.Errorf("a failed final censor injection: %+v", row)
	}
	inj, _ := derive(map[string]*injectionRun{"missing_wake": injectionWithVerdict(qual.VerdictPass), "final_censor": injectionWithVerdict(qual.VerdictPass)}).Detail["injections"].(map[string]any)
	if len(inj) != 2 {
		t.Errorf("injections in the off_cpu detail: %v", inj)
	}
}

func TestLossRowIsOnlySupportedWithTheSchedulerRingInjectionWhenTheSchedulerPathRuns(t *testing.T) {
	derive := func(offCPU nativeperf.Status, inject map[string]*injectionRun) qual.Row {
		a := newAccept()
		a.caps.OffCPU = offCPU
		a.injections["loss_ring_4096_reader_stall"] = &scenResult{Name: "loss", Cap: qual.CaptureResult{Ready: true, ErrorCode: "loss"}, Extra: map[string]any{}}
		a.schedInject = inject
		a.deriveRows()
		return a.res.Loss
	}
	if row := derive(nativeperf.Supported, map[string]*injectionRun{"loss": injectionWithVerdict(qual.VerdictPass)}); row.State != qual.StateSupported || len(row.Evidence) != 2 {
		t.Fatalf("scheduler loss injection passed: %+v", row)
	}
	if row := derive(nativeperf.Supported, nil); row.State != qual.StateNotRun || !strings.Contains(row.Reason, "scheduler_loss") {
		t.Errorf("scheduler loss injection did not run: %+v", row)
	}
	if row := derive(nativeperf.Supported, map[string]*injectionRun{"loss": injectionWithVerdict(qual.VerdictFail)}); row.State != qual.StateFailed || !strings.Contains(row.Reason, "scheduler_loss injection: because") {
		t.Errorf("an ignored scheduler loss: %+v", row)
	}
	// without a scheduler path there is no scheduler ring to lose records from: the CPU-ring injection decides alone
	if row := derive(nativeperf.Unsupported, nil); row.State != qual.StateSupported || len(row.Evidence) != 1 {
		t.Errorf("no scheduler path: %+v", row)
	}
}
