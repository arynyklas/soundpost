// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// Judges of the scheduler injection rows (plan 04 task 09: "missing wake/loss, final blocked censor"). Each one reads
// intervals the committed Correlator returned for a REAL scheduler capture whose evidence was deliberately damaged
// (loss: a 4 KiB scheduler ring and a stalled reader; missing wake: every wakeup record of the target dropped on the
// consumer side; final censor: the capture stopped while the target slept). A judge passes only the behavior the
// criterion states, fails a contaminated one, and answers "unknown" when the run did not provoke the situation.

// FinalCensorSlackNs bounds how far the start of the censored interval may sit from the workload's own clock.
const FinalCensorSlackNs = 30_000_000

// InjectionVerdict is the outcome of one injection judge.
type InjectionVerdict struct {
	Verdict string // VerdictPass, VerdictFail or VerdictUnknown
	Reason  string
	// Measured numbers for the report.
	Intervals int    // ground-truth intervals (missing wake) or loss events (loss)
	Covered   int    // intervals with unknown-split / censor / correction evidence
	TruthNs   uint64 // ground-truth blocked time
	NativeNs  uint64 // native time the judge compared against it
	Deviation float64
}

func (v InjectionVerdict) String() string { return v.Verdict + ": " + v.Reason }

// JudgeMissingWake judges a capture whose wakeup records were all dropped. Without a wake the correlator must report
// the whole off-CPU time of every ground-truth interval as unknown split (switch-out to switch-in), never as blocked
// time (which needs the wake) and never as nothing; the unknown time must account for the blocking truth within
// BlockedTolerance. Any blocked interval that overlaps the truth is an inferred wake and fails.
func JudgeMissingWake(truth []BlockedTruth, native []nativeperf.Interval) InjectionVerdict {
	v := InjectionVerdict{Intervals: len(truth)}
	if len(truth) < MinBlockedIntervals {
		v.Verdict, v.Reason = VerdictUnknown, fmt.Sprintf("only %d ground-truth intervals, need %d", len(truth), MinBlockedIntervals)
		return v
	}
	uncovered := 0
	for _, g := range truth {
		var blocked, unknown uint64
		for _, iv := range native {
			if iv.Correction || uint32(iv.Task.TID) != g.TID {
				continue
			}
			o := overlap(g.Start, g.End, uint64(iv.Start), uint64(iv.End))
			switch iv.Kind {
			case nativeperf.IntervalBlocked:
				blocked += o
			case nativeperf.IntervalUnknown, nativeperf.IntervalCensored:
				unknown += o
			}
		}
		v.TruthNs += g.End - g.Start
		if blocked > 0 {
			v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("a wake was inferred: %d ns of the %d ns interval of thread %d was reported as completed blocked time although no wakeup record existed", blocked, g.End-g.Start, g.TID)
			return v
		}
		if unknown == 0 {
			uncovered++
			continue
		}
		v.Covered++
		v.NativeNs += unknown
	}
	if uncovered > 0 {
		v.Verdict, v.Reason = VerdictUnknown, fmt.Sprintf("%d of %d intervals have no unknown-split evidence at all", uncovered, len(truth))
		return v
	}
	v.Deviation = float64(diff(v.NativeNs, v.TruthNs)) / float64(v.TruthNs)
	if v.Deviation > BlockedTolerance {
		v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("unknown-split off-CPU time %d ns does not account for the %d ns the workload was blocked (deviation %.1f%%, limit %.0f%%)", v.NativeNs, v.TruthNs, v.Deviation*100, BlockedTolerance*100)
		return v
	}
	v.Verdict, v.Reason = VerdictPass, fmt.Sprintf("every one of %d intervals was reported as unknown split (%d ns of %d ns blocked, deviation %.1f%%), none as blocked", len(truth), v.NativeNs, v.TruthNs, v.Deviation*100)
	return v
}

// JudgeFinalCensor judges a capture that ended while the target slept. hold is the workload's own record of that sleep
// (its start; its end lies after finalThrough, the instant of the final acquisition proof). The open interval has to be
// returned censored, from the switch-out (within FinalCensorSlackNs of the workload's clock) to exactly the final
// proof, and no completed blocked or runnable interval may cover any of the open time.
func JudgeFinalCensor(hold BlockedTruth, finalThrough uint64, native []nativeperf.Interval) InjectionVerdict {
	v := InjectionVerdict{Intervals: 1, TruthNs: finalThrough - minU64(finalThrough, hold.Start)}
	if finalThrough <= hold.Start+FinalCensorSlackNs || finalThrough >= hold.End {
		v.Verdict, v.Reason = VerdictUnknown, fmt.Sprintf("the capture did not end inside the sleep (sleep %d..%d, final proof %d)", hold.Start, hold.End, finalThrough)
		return v
	}
	var censored []nativeperf.Interval
	var completed uint64
	for _, iv := range native {
		if iv.Correction || uint32(iv.Task.TID) != hold.TID {
			continue
		}
		switch iv.Kind {
		case nativeperf.IntervalCensored:
			censored = append(censored, iv)
		case nativeperf.IntervalBlocked, nativeperf.IntervalRunnable, nativeperf.IntervalUnknown:
			completed += overlap(hold.Start+FinalCensorSlackNs, finalThrough, uint64(iv.Start), uint64(iv.End))
		}
	}
	if completed > 0 {
		v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("the interval still open at the end of the capture was completed: %d ns of it reported as a finished blocked, runnable or unknown interval", completed)
		return v
	}
	if len(censored) != 1 {
		if len(censored) == 0 {
			v.Verdict, v.Reason = VerdictUnknown, "no interval of the sleeping thread was returned for the open time"
		} else {
			v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("%d censored intervals for one open sleep", len(censored))
		}
		return v
	}
	c := censored[0]
	switch {
	case uint64(c.End) != finalThrough:
		v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("censored interval ends at %d, not at the final proof %d", uint64(c.End), finalThrough)
	case diff(uint64(c.Start), hold.Start) > FinalCensorSlackNs:
		v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("censored interval starts at %d, %d ns from the workload's own record of the sleep start %d", uint64(c.Start), diff(uint64(c.Start), hold.Start), hold.Start)
	default:
		v.Covered, v.NativeNs = 1, uint64(c.End-c.Start)
		v.Verdict, v.Reason = VerdictPass, fmt.Sprintf("the open sleep was returned as one censored interval of %d ns ending at the final proof, not as completed blocked time", v.NativeNs)
	}
	return v
}

// JudgeSchedulerLoss judges a scheduler capture with explicit kernel loss. lossTimes are the event times of the
// loss events the stream carried. The correlator must answer every one with a domain-wide correction (coverage
// replaced, with a reason) reaching at least that instant, and no measured blocked, runnable or unknown interval may
// straddle a loss instant: that would hand loss-contaminated time to a consumer as measured duration.
func JudgeSchedulerLoss(lossTimes []uint64, native []nativeperf.Interval) InjectionVerdict {
	v := InjectionVerdict{Intervals: len(lossTimes)}
	if len(lossTimes) == 0 {
		v.Verdict, v.Reason = VerdictUnknown, "the stalled reader provoked no loss event"
		return v
	}
	for _, at := range lossTimes {
		answered := false
		for _, iv := range native {
			if iv.Correction && iv.Task == (nativeperf.TaskKey{}) && iv.Kind == nativeperf.IntervalUnknown && iv.Reason != "" && uint64(iv.End) >= at {
				answered = true
				break
			}
		}
		if !answered {
			v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("loss at %d was ignored: no domain-wide coverage correction reaches it", at)
			return v
		}
		v.Covered++
		for _, iv := range native {
			if iv.Correction {
				continue
			}
			switch iv.Kind {
			case nativeperf.IntervalBlocked, nativeperf.IntervalRunnable, nativeperf.IntervalUnknown, nativeperf.IntervalCensored:
				if uint64(iv.Start) < at && uint64(iv.End) > at {
					v.Verdict, v.Reason = VerdictFail, fmt.Sprintf("a %s interval %d..%d of thread %d straddles the loss at %d", iv.Kind, uint64(iv.Start), uint64(iv.End), iv.Task.TID, at)
					return v
				}
			}
		}
	}
	v.Verdict, v.Reason = VerdictPass, fmt.Sprintf("%d loss events each answered by a domain-wide coverage correction, no measured interval straddles one", len(lossTimes))
	return v
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// SchedulerInjectionControls are the negative and positive controls of the three injection judges. They run before
// the real path of the acceptance runner (RunNegativeControls includes them): a judge that accepts a contaminated
// capture (a loss that nobody answered, a wake that was never recorded but whose blocked time was reported, a
// still-open interval reported as finished) or rejects an honest one cannot be mistaken for evidence.
var SchedulerInjectionControls = []string{
	"scheduler_loss_ignored",
	"scheduler_loss_interval_straddles_loss",
	"scheduler_loss_not_provoked_is_not_a_pass",
	"scheduler_missing_wake_reported_as_blocked",
	"scheduler_missing_wake_without_evidence_is_not_a_pass",
	"scheduler_open_interval_completed_as_blocked",
	"scheduler_open_interval_without_evidence_is_not_a_pass",
	"scheduler_injection_positive_controls_accepted",
}

// injectionJudges are the three judges a control run exercises; the controls take them as a value so a test can hand
// them broken ones and see the controls object.
type injectionJudges struct {
	loss   func(lossTimes []uint64, native []nativeperf.Interval) InjectionVerdict
	wake   func(truth []BlockedTruth, native []nativeperf.Interval) InjectionVerdict
	censor func(hold BlockedTruth, finalThrough uint64, native []nativeperf.Interval) InjectionVerdict
}

func runSchedulerInjectionControls() []NegativeControl {
	return schedulerInjectionControlsWith(injectionJudges{JudgeSchedulerLoss, JudgeMissingWake, JudgeFinalCensor})
}

func schedulerInjectionControlsWith(j injectionJudges) []NegativeControl {
	const tid = 4242
	task := nativeperf.TaskKey{BootID: "neg-boot", PIDNamespace: 1, TGID: tid, TID: tid, ProcessStart: 1, Generation: 1}
	iv := func(kind nativeperf.IntervalKind, start, end uint64, correction bool, reason nativeperf.Reason, t nativeperf.TaskKey) nativeperf.Interval {
		return nativeperf.Interval{Kind: kind, Task: t, Start: model.MonoNano(start), End: model.MonoNano(end), Reason: reason, Correction: correction}
	}
	var truth []BlockedTruth
	var unknown, blocked []nativeperf.Interval
	for i := range 24 {
		start := 1_000_000_000 + uint64(i)*300_000_000
		end := start + 200_000_000
		truth = append(truth, BlockedTruth{TID: tid, Start: start, End: end})
		unknown = append(unknown, iv(nativeperf.IntervalUnknown, start+100_000, end+900_000, false, nativeperf.ReasonUnmeasured, task))
		blocked = append(blocked, iv(nativeperf.IntervalBlocked, start+100_000, end, false, "", task))
	}
	hold := BlockedTruth{TID: tid, Start: 1_000_000_000, End: 6_000_000_000}
	const through = 2_500_000_000
	censored := []nativeperf.Interval{iv(nativeperf.IntervalCensored, 1_000_150_000, through, false, nativeperf.ReasonUnmeasured, task)}
	finished := []nativeperf.Interval{iv(nativeperf.IntervalBlocked, 1_000_150_000, through, false, "", task)}
	const lossAt = 3_000_000_000
	correction := iv(nativeperf.IntervalUnknown, 0, lossAt+1000, true, nativeperf.ReasonLoss, nativeperf.TaskKey{})
	before := iv(nativeperf.IntervalBlocked, 2_700_000_000, 2_800_000_000, false, "", task)
	straddle := iv(nativeperf.IntervalBlocked, 2_900_000_000, 3_100_000_000, false, "", task)

	var out []NegativeControl
	record := func(name string, got InjectionVerdict, want string) {
		out = append(out, NegativeControl{Name: name, Rejected: got.Verdict != VerdictPass, Behaved: got.Verdict == want, Reason: got.String()})
	}
	record("scheduler_loss_ignored", j.loss([]uint64{lossAt}, []nativeperf.Interval{before}), VerdictFail)
	record("scheduler_loss_interval_straddles_loss", j.loss([]uint64{lossAt}, []nativeperf.Interval{correction, straddle}), VerdictFail)
	record("scheduler_loss_not_provoked_is_not_a_pass", j.loss(nil, []nativeperf.Interval{before}), VerdictUnknown)
	record("scheduler_missing_wake_reported_as_blocked", j.wake(truth, blocked), VerdictFail)
	record("scheduler_missing_wake_without_evidence_is_not_a_pass", j.wake(truth, nil), VerdictUnknown)
	record("scheduler_open_interval_completed_as_blocked", j.censor(hold, through, finished), VerdictFail)
	record("scheduler_open_interval_without_evidence_is_not_a_pass", j.censor(hold, through, nil), VerdictUnknown)
	good := []InjectionVerdict{
		j.loss([]uint64{lossAt}, []nativeperf.Interval{before, correction}),
		j.wake(truth, unknown),
		j.censor(hold, through, censored),
	}
	nc := NegativeControl{Name: "scheduler_injection_positive_controls_accepted", Behaved: true}
	for _, g := range good {
		if g.Verdict != VerdictPass {
			nc.Rejected, nc.Behaved, nc.Reason = true, false, g.String()
			break
		}
	}
	return append(out, nc)
}
