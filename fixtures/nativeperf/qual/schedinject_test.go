// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const injTID = 4242

var injTask = nativeperf.TaskKey{BootID: "b", PIDNamespace: 1, TGID: injTID, TID: injTID, ProcessStart: 1, Generation: 1}

func injIV(kind nativeperf.IntervalKind, start, end uint64) nativeperf.Interval {
	return nativeperf.Interval{Kind: kind, Task: injTask, Start: model.MonoNano(start), End: model.MonoNano(end)}
}

func injCorrection(end uint64, reason nativeperf.Reason) nativeperf.Interval {
	return nativeperf.Interval{Kind: nativeperf.IntervalUnknown, End: model.MonoNano(end), Reason: reason, Correction: true}
}

func injTruth(n int) []BlockedTruth {
	var out []BlockedTruth
	for i := range n {
		start := 1_000_000_000 + uint64(i)*300_000_000
		out = append(out, BlockedTruth{TID: injTID, Start: start, End: start + 200_000_000})
	}
	return out
}

func injUnknownFor(truth []BlockedTruth, shrink uint64) []nativeperf.Interval {
	var out []nativeperf.Interval
	for _, g := range truth {
		out = append(out, injIV(nativeperf.IntervalUnknown, g.Start+shrink, g.End))
	}
	return out
}

func wantVerdict(t *testing.T, name string, got InjectionVerdict, want string, reason string) {
	t.Helper()
	if got.Verdict != want || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: %s (want %s mentioning %q)", name, got, want, reason)
	}
}

func TestMissingWakeMustBeReportedAsUnknownSplitNeverBlocked(t *testing.T) {
	truth := injTruth(24)
	wantVerdict(t, "honest unknown split", JudgeMissingWake(truth, injUnknownFor(truth, 100_000)), VerdictPass, "every one of 24 intervals")

	// the blocked time of a wake nobody recorded is an inferred wake, however well it matches the truth
	var inferred []nativeperf.Interval
	for _, g := range truth {
		inferred = append(inferred, injIV(nativeperf.IntervalBlocked, g.Start, g.End))
	}
	wantVerdict(t, "blocked without wake", JudgeMissingWake(truth, inferred), VerdictFail, "a wake was inferred")

	// one blocked sliver among otherwise honest unknown intervals still fails
	mixed := injUnknownFor(truth, 100_000)
	mixed = append(mixed, injIV(nativeperf.IntervalBlocked, truth[11].Start+10, truth[11].Start+11))
	wantVerdict(t, "single blocked ns", JudgeMissingWake(truth, mixed), VerdictFail, "a wake was inferred")

	// nothing at all, or evidence for some intervals only, is unknown, never a pass
	wantVerdict(t, "no intervals", JudgeMissingWake(truth, nil), VerdictUnknown, "24 of 24")
	wantVerdict(t, "one interval missing", JudgeMissingWake(truth, injUnknownFor(truth[1:], 0)), VerdictUnknown, "1 of 24")
	wantVerdict(t, "too few intervals", JudgeMissingWake(truth[:19], injUnknownFor(truth[:19], 0)), VerdictUnknown, "only 19")
	wantVerdict(t, "exactly the minimum", JudgeMissingWake(truth[:20], injUnknownFor(truth[:20], 0)), VerdictPass, "")

	// unknown time of another thread, or corrections, is no evidence for this thread
	other := injUnknownFor(truth, 0)
	for i := range other {
		other[i].Task.TID++
	}
	wantVerdict(t, "other thread", JudgeMissingWake(truth, other), VerdictUnknown, "24 of 24")
	corrections := injUnknownFor(truth, 0)
	for i := range corrections {
		corrections[i].Correction = true
	}
	wantVerdict(t, "corrections only", JudgeMissingWake(truth, corrections), VerdictUnknown, "24 of 24")

	// the unknown time has to account for the blocking truth: 24% short passes, 30% short fails
	wantVerdict(t, "24% short", JudgeMissingWake(truth, injUnknownFor(truth, 48_000_000)), VerdictPass, "")
	wantVerdict(t, "30% short", JudgeMissingWake(truth, injUnknownFor(truth, 60_000_000)), VerdictFail, "does not account")
}

func TestMissingWakeCountsCensoredTimeAsUnknown(t *testing.T) {
	truth := injTruth(20)
	var native []nativeperf.Interval
	for _, g := range truth {
		native = append(native, injIV(nativeperf.IntervalCensored, g.Start, g.End))
	}
	wantVerdict(t, "censored", JudgeMissingWake(truth, native), VerdictPass, "")
}

func TestFinalCensorOpenIntervalIsCensoredNotCompleted(t *testing.T) {
	hold := BlockedTruth{TID: injTID, Start: 1_000_000_000, End: 6_000_000_000}
	const through = 2_500_000_000
	good := []nativeperf.Interval{injIV(nativeperf.IntervalCensored, 1_000_150_000, through)}
	wantVerdict(t, "censored", JudgeFinalCensor(hold, through, good), VerdictPass, "one censored interval")

	for _, kind := range []nativeperf.IntervalKind{nativeperf.IntervalBlocked, nativeperf.IntervalRunnable, nativeperf.IntervalUnknown} {
		wantVerdict(t, "open interval reported as "+string(kind), JudgeFinalCensor(hold, through, []nativeperf.Interval{injIV(kind, 1_000_150_000, through)}), VerdictFail, "was completed")
	}
	// a completed interval beside the censored one is just as wrong
	both := append([]nativeperf.Interval{injIV(nativeperf.IntervalBlocked, 1_500_000_000, 2_000_000_000)}, good...)
	wantVerdict(t, "blocked beside censored", JudgeFinalCensor(hold, through, both), VerdictFail, "was completed")
	// completed time before the sleep started is not part of it
	before := append([]nativeperf.Interval{injIV(nativeperf.IntervalBlocked, 900_000_000, 1_000_000_000+FinalCensorSlackNs)}, good...)
	wantVerdict(t, "blocked before the sleep", JudgeFinalCensor(hold, through, before), VerdictPass, "")

	wantVerdict(t, "wrong end", JudgeFinalCensor(hold, through, []nativeperf.Interval{injIV(nativeperf.IntervalCensored, 1_000_150_000, through-1)}), VerdictFail, "not at the final proof")
	wantVerdict(t, "wrong start", JudgeFinalCensor(hold, through, []nativeperf.Interval{injIV(nativeperf.IntervalCensored, 1_000_000_000+FinalCensorSlackNs+1, through)}), VerdictFail, "workload's own record")
	wantVerdict(t, "start at the slack", JudgeFinalCensor(hold, through, []nativeperf.Interval{injIV(nativeperf.IntervalCensored, 1_000_000_000+FinalCensorSlackNs, through)}), VerdictPass, "")
	wantVerdict(t, "start before the sleep", JudgeFinalCensor(hold, through, []nativeperf.Interval{injIV(nativeperf.IntervalCensored, 1_000_000_000-FinalCensorSlackNs-1, through)}), VerdictFail, "workload's own record")
	wantVerdict(t, "two censored", JudgeFinalCensor(hold, through, append(append([]nativeperf.Interval(nil), good...), good...)), VerdictFail, "2 censored")
	wantVerdict(t, "no interval", JudgeFinalCensor(hold, through, nil), VerdictUnknown, "no interval of the sleeping thread")

	other := injIV(nativeperf.IntervalCensored, 1_000_150_000, through)
	other.Task.TID++
	wantVerdict(t, "another thread's censored interval", JudgeFinalCensor(hold, through, []nativeperf.Interval{other}), VerdictUnknown, "no interval")
	corr := injIV(nativeperf.IntervalCensored, 1_000_150_000, through)
	corr.Correction = true
	wantVerdict(t, "a correction", JudgeFinalCensor(hold, through, []nativeperf.Interval{corr}), VerdictUnknown, "no interval")

	// a capture that ended before or after the sleep proves nothing about an open interval
	wantVerdict(t, "ended after the sleep", JudgeFinalCensor(hold, hold.End, good), VerdictUnknown, "did not end inside")
	wantVerdict(t, "ended at the sleep start", JudgeFinalCensor(hold, hold.Start+FinalCensorSlackNs, good), VerdictUnknown, "did not end inside")
}

func TestSchedulerLossMustBeAnsweredByAWideCorrection(t *testing.T) {
	const lossAt = 3_000_000_000
	before := injIV(nativeperf.IntervalBlocked, 2_700_000_000, 2_800_000_000)
	correction := injCorrection(lossAt+1000, nativeperf.ReasonLoss)
	wantVerdict(t, "answered", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{before, correction}), VerdictPass, "1 loss events")
	wantVerdict(t, "correction ends at the loss", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{injCorrection(lossAt, nativeperf.ReasonLoss)}), VerdictPass, "")

	wantVerdict(t, "ignored", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{before}), VerdictFail, "was ignored")
	wantVerdict(t, "correction ends before the loss", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{injCorrection(lossAt-1, nativeperf.ReasonLoss)}), VerdictFail, "was ignored")
	wantVerdict(t, "correction without a reason", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{injCorrection(lossAt+1000, "")}), VerdictFail, "was ignored")
	scoped := injCorrection(lossAt+1000, nativeperf.ReasonLoss)
	scoped.Task = injTask
	wantVerdict(t, "task-scoped correction", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{scoped}), VerdictFail, "was ignored")
	notUnknown := injCorrection(lossAt+1000, nativeperf.ReasonLoss)
	notUnknown.Kind = nativeperf.IntervalBlocked
	wantVerdict(t, "a correction that claims to be blocked", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{notUnknown}), VerdictFail, "was ignored")
	notCorrection := injIV(nativeperf.IntervalUnknown, 0, lossAt+1000)
	notCorrection.Task = nativeperf.TaskKey{}
	notCorrection.Reason = nativeperf.ReasonLoss
	wantVerdict(t, "an unknown interval that is no correction", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{notCorrection}), VerdictFail, "was ignored")

	// measured time must not straddle the loss, whatever its kind
	for _, kind := range []nativeperf.IntervalKind{nativeperf.IntervalBlocked, nativeperf.IntervalRunnable, nativeperf.IntervalUnknown, nativeperf.IntervalCensored} {
		wantVerdict(t, "straddling "+string(kind), JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{correction, injIV(kind, 2_900_000_000, 3_100_000_000)}), VerdictFail, "straddles")
	}
	wantVerdict(t, "ends at the loss", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{correction, injIV(nativeperf.IntervalBlocked, 2_900_000_000, lossAt)}), VerdictPass, "")
	wantVerdict(t, "starts at the loss", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{correction, injIV(nativeperf.IntervalBlocked, lossAt, 3_100_000_000)}), VerdictPass, "")
	cpu := injIV(nativeperf.IntervalCPU, 2_900_000_000, 3_100_000_000)
	wantVerdict(t, "an on-CPU observation is no scheduler interval", JudgeSchedulerLoss([]uint64{lossAt}, []nativeperf.Interval{correction, cpu}), VerdictPass, "")

	// every loss needs its own answer, and the straddle check runs against every one of them
	wantVerdict(t, "second loss unanswered", JudgeSchedulerLoss([]uint64{lossAt, lossAt + 5_000_000}, []nativeperf.Interval{correction}), VerdictFail, "was ignored")
	wantVerdict(t, "second loss straddled", JudgeSchedulerLoss([]uint64{lossAt, lossAt + 500_000_000}, []nativeperf.Interval{injCorrection(lossAt+600_000_000, nativeperf.ReasonLoss), injIV(nativeperf.IntervalBlocked, lossAt+400_000_000, lossAt+700_000_000)}), VerdictFail, "straddles")

	wantVerdict(t, "no loss provoked", JudgeSchedulerLoss(nil, []nativeperf.Interval{before}), VerdictUnknown, "no loss event")
}

func TestSchedulerInjectionControlsBehaveAndAreRequiredByTheGate(t *testing.T) {
	got := runSchedulerInjectionControls()
	if len(got) != len(SchedulerInjectionControls) {
		t.Fatalf("%d controls for %d required names", len(got), len(SchedulerInjectionControls))
	}
	for i, nc := range got {
		if nc.Name != SchedulerInjectionControls[i] || !nc.Behaved {
			t.Errorf("control %d %q behaved=%v: %s", i, nc.Name, nc.Behaved, nc.Reason)
		}
	}
	required := map[string]bool{}
	for _, name := range RequiredNegativeControls {
		required[name] = true
	}
	all := map[string]NegativeControl{}
	for _, nc := range RunNegativeControls() {
		all[nc.Name] = nc
	}
	for _, name := range SchedulerInjectionControls {
		if !required[name] {
			t.Errorf("control %s is not required by the release gate", name)
		}
		if nc, ok := all[name]; !ok || !nc.Behaved {
			t.Errorf("RunNegativeControls does not carry a behaving %s (%+v)", name, nc)
		}
	}
}

func constantJudges(verdict string) injectionJudges {
	v := InjectionVerdict{Verdict: verdict, Reason: "constant"}
	return injectionJudges{
		loss:   func([]uint64, []nativeperf.Interval) InjectionVerdict { return v },
		wake:   func([]BlockedTruth, []nativeperf.Interval) InjectionVerdict { return v },
		censor: func(BlockedTruth, uint64, []nativeperf.Interval) InjectionVerdict { return v },
	}
}

// The controls are what keeps a judge that waves everything through (or rejects everything) from being believed.
func TestSchedulerInjectionControlsObjectToBrokenJudges(t *testing.T) {
	wants := map[string]string{
		"scheduler_loss_ignored":                                 VerdictFail,
		"scheduler_loss_interval_straddles_loss":                 VerdictFail,
		"scheduler_loss_not_provoked_is_not_a_pass":              VerdictUnknown,
		"scheduler_missing_wake_reported_as_blocked":             VerdictFail,
		"scheduler_missing_wake_without_evidence_is_not_a_pass":  VerdictUnknown,
		"scheduler_open_interval_completed_as_blocked":           VerdictFail,
		"scheduler_open_interval_without_evidence_is_not_a_pass": VerdictUnknown,
		"scheduler_injection_positive_controls_accepted":         VerdictPass,
	}
	for _, verdict := range []string{VerdictPass, VerdictFail, VerdictUnknown} {
		for _, nc := range schedulerInjectionControlsWith(constantJudges(verdict)) {
			want, ok := wants[nc.Name]
			if !ok {
				t.Fatalf("unexpected control %s", nc.Name)
			}
			if nc.Behaved != (want == verdict) {
				t.Errorf("a judge that always says %s: control %s behaved=%v (%s)", verdict, nc.Name, nc.Behaved, nc.Reason)
			}
		}
	}
}
