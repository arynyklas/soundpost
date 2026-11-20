// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	hpStart   = 1_000_000_000
	hpOffDone = 4_000_000_000
	hpProven  = 3_800_000_000
	hpEnd     = 4_200_000_000
)

func hpCorrection(from, to uint64) nativeperf.Interval {
	return nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Start: model.MonoNano(from), End: model.MonoNano(to), Reason: nativeperf.ReasonGeneration, Correction: true}
}

func hpHonest() HotplugEvidence {
	return HotplugEvidence{
		Provoked: true, StartNs: hpStart, OfflineDoneNs: hpOffDone, ErrorCode: "topology_changed", Revoked: true, RevokedFrom: hpProven,
		Intervals:        []nativeperf.Interval{injIV(nativeperf.IntervalBlocked, 2_000_000_000, 2_100_000_000), injIV(nativeperf.IntervalRunnable, 3_700_000_000, 3_900_000_000), hpCorrection(hpProven, hpEnd)},
		CPUSamplesBefore: 40,
	}
}

func TestJudgeTopologyChange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(e *HotplugEvidence)
		verdict string
		reason  string
	}{
		{"honest capture", func(e *HotplugEvidence) {}, VerdictPass, "ended on topology_changed"},
		{"not provoked", func(e *HotplugEvidence) { e.Provoked = false }, VerdictUnknown, "nothing was provoked"},
		{"silent complete", func(e *HotplugEvidence) { e.ErrorCode, e.Revoked, e.Complete, e.FinalProof = "", false, true, true }, VerdictFail, "silent claim of complete coverage"},
		{"final proof only", func(e *HotplugEvidence) { e.FinalProof = true }, VerdictFail, "completed"},
		{"complete frame only", func(e *HotplugEvidence) { e.Complete = true }, VerdictFail, "completed"},
		{"no code", func(e *HotplugEvidence) { e.ErrorCode = "" }, VerdictFail, "neither ended nor reported"},
		{"another code", func(e *HotplugEvidence) { e.ErrorCode = "loss" }, VerdictFail, `"loss"`},
		{"not revoked", func(e *HotplugEvidence) { e.Revoked = false }, VerdictFail, "not revoked"},
		{"revoked from before the capture", func(e *HotplugEvidence) { e.RevokedFrom = hpStart - 1 }, VerdictFail, "outside"},
		{"revoked from zero", func(e *HotplugEvidence) { e.RevokedFrom = 0 }, VerdictFail, "outside"},
		{"revoked from after the CPU was gone", func(e *HotplugEvidence) { e.RevokedFrom = hpOffDone + 1 }, VerdictFail, "outside"},
		{"no correction", func(e *HotplugEvidence) { e.Intervals = e.Intervals[:2] }, VerdictFail, "no domain-wide coverage correction"},
		{"correction for one task only", func(e *HotplugEvidence) {
			c := hpCorrection(hpProven, hpEnd)
			c.Task = injTask
			e.Intervals[2] = c
		}, VerdictFail, "no domain-wide coverage correction"},
		{"correction without a reason", func(e *HotplugEvidence) { e.Intervals[2].Reason = "" }, VerdictFail, "no domain-wide coverage correction"},
		{"correction starts after the proven instant", func(e *HotplugEvidence) { e.Intervals[2] = hpCorrection(hpProven+1, hpEnd) }, VerdictFail, "no domain-wide coverage correction"},
		{"correction ends before the proven instant", func(e *HotplugEvidence) { e.Intervals[2] = hpCorrection(0, hpProven-1) }, VerdictFail, "no domain-wide coverage correction"},
		{"measured interval beyond the correction", func(e *HotplugEvidence) {
			e.Intervals = append(e.Intervals, injIV(nativeperf.IntervalBlocked, hpProven, hpEnd+1))
		}, VerdictFail, "beyond the revoked window"},
		{"measured censored interval beyond the correction", func(e *HotplugEvidence) {
			e.Intervals = append(e.Intervals, injIV(nativeperf.IntervalCensored, hpProven, hpEnd+1))
		}, VerdictFail, "beyond the revoked window"},
		{"interval ending exactly at the correction end", func(e *HotplugEvidence) {
			e.Intervals = append(e.Intervals, injIV(nativeperf.IntervalBlocked, hpProven, hpEnd))
		}, VerdictPass, "ended on topology_changed"},
		{"too few samples before the change", func(e *HotplugEvidence) { e.CPUSamplesBefore = MinHotplugSamples - 1 }, VerdictUnknown, "CPU samples before the change"},
		{"exactly the minimum of samples", func(e *HotplugEvidence) { e.CPUSamplesBefore = MinHotplugSamples }, VerdictPass, "ended on topology_changed"},
	} {
		e := hpHonest()
		e.Intervals = append([]nativeperf.Interval(nil), e.Intervals...)
		tc.mutate(&e)
		got := JudgeTopologyChange(e)
		if got.Verdict != tc.verdict || !strings.Contains(got.Reason, tc.reason) {
			t.Errorf("%s: %s, want %s containing %q", tc.name, got, tc.verdict, tc.reason)
		}
	}
}

func TestHotplugControlsBehaveAndRunWithTheOtherNegativeControls(t *testing.T) {
	got := runHotplugControls()
	if len(got) != len(HotplugControls) {
		t.Fatalf("%d controls for %d names", len(got), len(HotplugControls))
	}
	for i, nc := range got {
		if nc.Name != HotplugControls[i] || !nc.Behaved {
			t.Errorf("control %d %q behaved=%v: %s", i, nc.Name, nc.Behaved, nc.Reason)
		}
	}
	all := map[string]NegativeControl{}
	for _, nc := range RunNegativeControls() {
		all[nc.Name] = nc
	}
	for _, name := range HotplugControls {
		if nc, ok := all[name]; !ok || !nc.Behaved {
			t.Errorf("RunNegativeControls does not carry a behaving %s (%+v)", name, nc)
		}
	}
}

// A judge that accepts the silent-complete capture (the defect this scenario exists to catch) is not believed: the
// controls object, whatever else it gets right.
func TestHotplugControlsObjectToBrokenJudges(t *testing.T) {
	wants := map[string]string{
		"cpu_hotplug_silent_complete":                VerdictFail,
		"cpu_hotplug_final_proof_after_the_change":   VerdictFail,
		"cpu_hotplug_stream_ends_without_a_code":     VerdictFail,
		"cpu_hotplug_wrong_closed_code":              VerdictFail,
		"cpu_hotplug_error_without_revocation":       VerdictFail,
		"cpu_hotplug_revoked_from_unproven_instant":  VerdictFail,
		"cpu_hotplug_interval_beyond_the_correction": VerdictFail,
		"cpu_hotplug_not_provoked_is_not_a_pass":     VerdictUnknown,
		"cpu_hotplug_positive_control_accepted":      VerdictPass,
	}
	for _, verdict := range []string{VerdictPass, VerdictFail, VerdictUnknown} {
		constant := func(HotplugEvidence) InjectionVerdict { return InjectionVerdict{Verdict: verdict, Reason: "constant"} }
		for _, nc := range hotplugControlsWith(constant) {
			want, ok := wants[nc.Name]
			if !ok {
				t.Fatalf("unexpected control %s", nc.Name)
			}
			if nc.Behaved != (want == verdict) {
				t.Errorf("a judge that always says %s: control %s behaved=%v (%s)", verdict, nc.Name, nc.Behaved, nc.Reason)
			}
		}
	}
	// the specific mutant: the real judge with the completion check removed accepts a silent-complete capture
	noCompletionCheck := func(e HotplugEvidence) InjectionVerdict {
		e.Complete, e.FinalProof = false, false
		if e.ErrorCode == "" {
			e.ErrorCode, e.Revoked, e.RevokedFrom = "topology_changed", true, hpProven
			e.Intervals = []nativeperf.Interval{hpCorrection(hpProven, hpEnd)}
		}
		return JudgeTopologyChange(e)
	}
	objected := false
	for _, nc := range hotplugControlsWith(noCompletionCheck) {
		if !nc.Behaved {
			objected = true
		}
	}
	if !objected {
		t.Fatal("a judge that waves a silent-complete capture through was not caught by the controls")
	}
}
