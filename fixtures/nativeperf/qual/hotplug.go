// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The judge of the cpu_hotplug scenario (plan 04 task 09: "CPU hotplug ... prove explicit degraded/error behavior"; task 6:
// "on exec/namespace change/exit/hotplug emit target-generation/loss and reset correlation before new events"). It reads
// what a REAL scheduler capture did when a CPU left the online set under it: the stream has to end with the closed code
// topology_changed, the correlation has to be revoked from the last instant the topology was proven (one domain-wide
// coverage correction, no final proof, no completed interval beyond it), and the CPU samples before the change, which are
// task-scoped and unaffected, have to be there.

// MinHotplugSamples is how many CPU samples before the change the capture must have delivered for the "pre-change
// samples stay valid" half to be judged at all.
const MinHotplugSamples = 5

// HotplugEvidence is what one scheduler capture observed around a real CPU change.
type HotplugEvidence struct {
	// Provoked is true when the CPU really left the online set during the capture (the offline write returned).
	Provoked bool
	// StartNs is the capture start (the initial proof's Through); OfflineDoneNs the event-clock instant the offline write
	// returned.
	StartNs, OfflineDoneNs uint64
	// ErrorCode is the closed code the stream ended on ("" when it did not end on one); Complete says the helper sent its
	// complete frame; FinalProof says a final acquisition proof reached the consumer.
	ErrorCode  string
	Complete   bool
	FinalProof bool
	// Revoked/RevokedFrom: the correlation was revoked from this instant (the error's ProvenThrough).
	Revoked     bool
	RevokedFrom uint64
	// Intervals are the intervals the correlator returned; CPUSamplesBefore is how many CPU samples the stream delivered
	// with an event time at or before RevokedFrom.
	Intervals        []nativeperf.Interval
	CPUSamplesBefore int
}

// JudgeTopologyChange judges one scheduler capture that lost a CPU. It answers "unknown" when the CPU change did not
// happen during the capture (nothing was provoked) and fails every silent outcome: a completed capture, a stream that ends
// without the closed code, an error that did not revoke the scheduler coverage, a proof instant outside the capture, a
// correction that does not reach back to it, a measured interval beyond the correction, or no pre-change samples.
func JudgeTopologyChange(e HotplugEvidence) InjectionVerdict {
	v := InjectionVerdict{Intervals: 1}
	fail := func(format string, args ...any) InjectionVerdict {
		v.Verdict, v.Reason = VerdictFail, fmt.Sprintf(format, args...)
		return v
	}
	if !e.Provoked {
		v.Verdict, v.Reason = VerdictUnknown, "the CPU did not leave the online set during the capture: nothing was provoked"
		return v
	}
	switch {
	case e.Complete || e.FinalProof:
		return fail("the capture completed (complete frame %v, final proof %v) after a CPU left the online set: a silent claim of complete coverage", e.Complete, e.FinalProof)
	case e.ErrorCode == "":
		return fail("the capture neither ended nor reported anything after a CPU left the online set")
	case e.ErrorCode != "topology_changed":
		return fail("the capture ended with the closed code %q, want topology_changed", e.ErrorCode)
	case !e.Revoked:
		return fail("the stream ended on topology_changed but the scheduler correlation was not revoked")
	case e.RevokedFrom < e.StartNs || e.RevokedFrom > e.OfflineDoneNs:
		return fail("the correlation was revoked from %d, outside [capture start %d, offline completed %d]: it either revokes nothing it should or vouches for evidence of a CPU that was gone", e.RevokedFrom, e.StartNs, e.OfflineDoneNs)
	}
	var correction *nativeperf.Interval
	for i, iv := range e.Intervals {
		if iv.Correction && iv.Task == (nativeperf.TaskKey{}) && iv.Kind == nativeperf.IntervalUnknown && iv.Reason != "" && uint64(iv.Start) <= e.RevokedFrom && uint64(iv.End) >= e.RevokedFrom {
			correction = &e.Intervals[i]
			break
		}
	}
	if correction == nil {
		return fail("no domain-wide coverage correction with a reason reaches back to the proven instant %d", e.RevokedFrom)
	}
	covered := 0
	for _, iv := range e.Intervals {
		if iv.Correction {
			continue
		}
		switch iv.Kind {
		case nativeperf.IntervalBlocked, nativeperf.IntervalRunnable, nativeperf.IntervalUnknown, nativeperf.IntervalCensored:
			if iv.End > correction.End {
				return fail("a %s interval %d..%d of thread %d lies beyond the revoked window ending %d: measured time the correction does not cover", iv.Kind, uint64(iv.Start), uint64(iv.End), iv.Task.TID, uint64(correction.End))
			}
			if uint64(iv.End) > e.RevokedFrom {
				covered++
			}
		}
	}
	if e.CPUSamplesBefore < MinHotplugSamples {
		v.Verdict, v.Reason = VerdictUnknown, fmt.Sprintf("only %d CPU samples before the change, need %d to judge that they stay valid", e.CPUSamplesBefore, MinHotplugSamples)
		return v
	}
	v.Covered, v.NativeNs = covered, uint64(correction.End-correction.Start)
	v.Verdict, v.Reason = VerdictPass, fmt.Sprintf("the stream ended on topology_changed, the correlation was revoked from %d (capture start %d, offline completed %d) by a domain-wide correction %d..%d, %d intervals ended after the proven instant and all lie under it, %d CPU samples before the change retained, no final proof", e.RevokedFrom, e.StartNs, e.OfflineDoneNs, uint64(correction.Start), uint64(correction.End), covered, e.CPUSamplesBefore)
	return v
}

// HotplugControls are the negative and positive controls of the hotplug judge; they run with the other negative controls
// before the real path of the acceptance runner: a judge that accepts a silent-complete capture (or one whose error did
// not revoke anything) cannot be mistaken for evidence.
var HotplugControls = []string{
	"cpu_hotplug_silent_complete",
	"cpu_hotplug_final_proof_after_the_change",
	"cpu_hotplug_stream_ends_without_a_code",
	"cpu_hotplug_wrong_closed_code",
	"cpu_hotplug_error_without_revocation",
	"cpu_hotplug_revoked_from_unproven_instant",
	"cpu_hotplug_interval_beyond_the_correction",
	"cpu_hotplug_not_provoked_is_not_a_pass",
	"cpu_hotplug_positive_control_accepted",
}

func runHotplugControls() []NegativeControl {
	return hotplugControlsWith(JudgeTopologyChange)
}

func hotplugControlsWith(judge func(HotplugEvidence) InjectionVerdict) []NegativeControl {
	const (
		start   = 1_000_000_000
		offDone = 4_000_000_000
		proven  = 3_800_000_000
		end     = 4_200_000_000
	)
	task := nativeperf.TaskKey{BootID: "neg-boot", PIDNamespace: 1, TGID: 4242, TID: 4242, ProcessStart: 1, Generation: 1}
	iv := func(kind nativeperf.IntervalKind, s, e uint64, correction bool, t nativeperf.TaskKey) nativeperf.Interval {
		reason := nativeperf.Reason("")
		if correction {
			reason = nativeperf.ReasonGeneration
		}
		return nativeperf.Interval{Kind: kind, Task: t, Start: model.MonoNano(s), End: model.MonoNano(e), Reason: reason, Correction: correction}
	}
	honest := HotplugEvidence{
		Provoked: true, StartNs: start, OfflineDoneNs: offDone, ErrorCode: "topology_changed", Revoked: true, RevokedFrom: proven,
		Intervals:        []nativeperf.Interval{iv(nativeperf.IntervalBlocked, 2_000_000_000, 2_100_000_000, false, task), iv(nativeperf.IntervalUnknown, proven, end, true, nativeperf.TaskKey{})},
		CPUSamplesBefore: 40,
	}
	mutate := func(f func(e *HotplugEvidence)) HotplugEvidence {
		e := honest
		e.Intervals = append([]nativeperf.Interval(nil), honest.Intervals...)
		f(&e)
		return e
	}
	var out []NegativeControl
	record := func(name string, e HotplugEvidence, want string) {
		got := judge(e)
		out = append(out, NegativeControl{Name: name, Rejected: got.Verdict != VerdictPass, Behaved: got.Verdict == want, Reason: got.String()})
	}
	record("cpu_hotplug_silent_complete", mutate(func(e *HotplugEvidence) {
		e.ErrorCode, e.Revoked, e.Complete, e.FinalProof, e.Intervals = "", false, true, true, nil
	}), VerdictFail)
	record("cpu_hotplug_final_proof_after_the_change", mutate(func(e *HotplugEvidence) { e.FinalProof = true }), VerdictFail)
	record("cpu_hotplug_stream_ends_without_a_code", mutate(func(e *HotplugEvidence) { e.ErrorCode, e.Revoked = "", false }), VerdictFail)
	record("cpu_hotplug_wrong_closed_code", mutate(func(e *HotplugEvidence) { e.ErrorCode = "acquisition_failed" }), VerdictFail)
	record("cpu_hotplug_error_without_revocation", mutate(func(e *HotplugEvidence) { e.Revoked, e.RevokedFrom, e.Intervals = false, 0, e.Intervals[:1] }), VerdictFail)
	record("cpu_hotplug_revoked_from_unproven_instant", mutate(func(e *HotplugEvidence) { e.RevokedFrom = offDone + 500_000_000 }), VerdictFail)
	record("cpu_hotplug_interval_beyond_the_correction", mutate(func(e *HotplugEvidence) {
		e.Intervals = append(e.Intervals, iv(nativeperf.IntervalBlocked, proven, end+300_000_000, false, task))
	}), VerdictFail)
	record("cpu_hotplug_not_provoked_is_not_a_pass", mutate(func(e *HotplugEvidence) { e.Provoked = false }), VerdictUnknown)
	positive := judge(honest)
	out = append(out, NegativeControl{Name: "cpu_hotplug_positive_control_accepted", Rejected: positive.Verdict != VerdictPass, Behaved: positive.Verdict == VerdictPass, Reason: positive.String()})
	return out
}
