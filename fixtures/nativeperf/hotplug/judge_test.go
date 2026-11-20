//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const online = "0-7"

var allCPUs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}

func completeView() captureView {
	return captureView{Ready: true, Complete: true, InitialCPUs: allCPUs, FinalProof: true, FinalCPUs: allCPUs, Events: 100,
		SchedOnCPUPre: 20, OnCPUBefore: 20}
}

func refusedView() captureView {
	return captureView{Ready: true, ErrorCode: "topology_changed", InitialCPUs: allCPUs, Events: 100, StartedNs: 1_000, EndedNs: 5_200,
		SchedOnCPUPre: 20, OnCPUBefore: 20, Revoked: true, ProvenThrough: 4_900, Corrections: 1, CorrectionFrom: 4_900, CorrectionTo: 5_100, CorrectionWhy: "generation_changed",
		Intervals: 30, Overlapped: 3}
}

func base(kind scenarioKind) scenarioResult {
	return scenarioResult{Name: string(kind), Kind: kind, CPU: 7, OnlineBefore: online, OnlineAfter: online,
		Offline: window{Start: 5_000, End: 5_100}, Online: window{Start: 5_900, End: 6_000}, Repinned: 6_100, RanAfterRepin: true,
		HelperAlive: true, HelperFDsReleased: true, TargetAlive: true}
}

func passing(kind scenarioKind) scenarioResult {
	r := base(kind)
	switch kind {
	case kindControl:
		r.Offline, r.Online, r.Repinned = window{}, window{}, 0
		r.Capture = completeView()
	case kindHold, kindFlap, kindFlapSparse:
		r.Capture = refusedView()
		rc := completeView()
		r.Recapture = &rc
	case kindCPUOnly:
		r.Capture = captureView{Ready: true, Events: 80, OnCPUBefore: 10, OnCPUAfterPin: 10, AfterOnline: 40}
	}
	return r
}

func failures(r scenarioResult) string {
	judge(&r)
	if r.Pass != (len(r.Failures) == 0) {
		panic("pass and failures disagree")
	}
	return strings.Join(r.Failures, " | ")
}

func TestJudgeAcceptsTheRequiredBehaviourOfEveryScenario(t *testing.T) {
	for _, kind := range []scenarioKind{kindControl, kindHold, kindFlap, kindFlapSparse, kindCPUOnly} {
		r := passing(kind)
		judge(&r)
		if !r.Pass {
			t.Errorf("%s: %s", kind, strings.Join(r.Failures, " | "))
		}
	}
	// a flap the capture did not announce passes only when the CPU's own stream still delivers
	r := passing(kindFlap)
	r.Capture = completeView()
	r.Capture.SchedOnCPUPin = 5
	judge(&r)
	if !r.Pass {
		t.Errorf("a flap that left the CPU's stream alive: %v", r.Failures)
	}
}

func TestJudgeRefusesToPassWhatDidNotHappen(t *testing.T) {
	r := passing(kindHold)
	r.NotExercised = "the kernel refused the CPU hotplug: EBUSY"
	judge(&r)
	if r.Pass || len(r.Failures) != 0 {
		t.Errorf("a hotplug the kernel refused is not a pass and not a failure of the product: pass=%t %v", r.Pass, r.Failures)
	}
	r = passing(kindHold)
	r.Offline, r.Online = window{}, window{}
	if got := failures(r); !strings.Contains(got, "hotplug did not happen") {
		t.Errorf("a capture that never saw a hotplug cannot pass the hold scenario: %q", got)
	}
	r = passing(kindCPUOnly)
	r.Offline = window{}
	if got := failures(r); !strings.Contains(got, "hotplug did not happen") {
		t.Errorf("the per-thread scenario needs its hotplug too: %q", got)
	}
	r = passing(kindHold)
	r.SetupError = "pin the workload: EPERM"
	if got := failures(r); !strings.Contains(got, "harness setup") {
		t.Errorf("a setup error is a failure: %q", got)
	}
	r = passing(kindHold)
	r.Capture = captureView{ErrorCode: "permission_denied"}
	if got := failures(r); !strings.Contains(got, "not admitted") {
		t.Errorf("a refused admission proves nothing about hotplug: %q", got)
	}
}

func TestJudgeRejectsASilentlyCompleteCaptureOverAChangedTopology(t *testing.T) {
	r := passing(kindHold)
	r.Capture = completeView()
	if got := failures(r); !strings.Contains(got, "claimed a complete capture over a changed topology") {
		t.Errorf("hold: %q", got)
	}
	// a flap that completes while the CPU's stream is dead under a final proof that claims the CPU
	r = passing(kindFlap)
	r.Capture = completeView()
	if got := failures(r); !strings.Contains(got, "silent coverage loss") {
		t.Errorf("flap: %q", got)
	}
	// without ground truth that the target ran there the liveness claim cannot be judged
	r.RanAfterRepin = false
	if got := failures(r); !strings.Contains(got, "no ground truth") {
		t.Errorf("flap without ground truth: %q", got)
	}
	// a stream that ended without any closed code, or without the topology code, is not the required refusal
	r = passing(kindHold)
	r.Capture.ErrorCode, r.Capture.ReadError = "", "stream closed by helper"
	if got := failures(r); !strings.Contains(got, `want "topology_changed"`) {
		t.Errorf("an unexplained close: %q", got)
	}
	r = passing(kindHold)
	r.Capture.ErrorCode = "acquisition_failed"
	if got := failures(r); !strings.Contains(got, `want "topology_changed"`) {
		t.Errorf("another closed code: %q", got)
	}
}

func TestJudgeHoldsARefusalToItsConsequences(t *testing.T) {
	for name, mutate := range map[string]func(*scenarioResult){
		"a final proof after the refusal": func(r *scenarioResult) { r.Capture.FinalProof, r.Capture.Complete = true, true },
		"no revoke":                       func(r *scenarioResult) { r.Capture.Revoked = false },
		"no generation correction":        func(r *scenarioResult) { r.Capture.CorrectionWhy = "" },
		"a correction before the change":  func(r *scenarioResult) { r.Capture.CorrectionFrom, r.Capture.CorrectionTo = 100, 4_000 },
		"a correction after the change":   func(r *scenarioResult) { r.Capture.CorrectionFrom, r.Capture.CorrectionTo = 5_500, 6_000 },
		"evidence from beyond the end":    func(r *scenarioResult) { r.Capture.NewerThanCorrection = 3 },
		"revoked from the first instant":  func(r *scenarioResult) { r.Capture.ProvenThrough, r.Capture.CorrectionFrom = 0, 0 },
		"a proof from after the change":   func(r *scenarioResult) { r.Capture.ProvenThrough = r.Offline.End + 1 },
		"a hole before the correction":    func(r *scenarioResult) { r.Capture.CorrectionFrom = r.Capture.ProvenThrough + 1 },
		"a stale proof": func(r *scenarioResult) {
			r.Offline, r.Online = window{Start: 3_000_000_000, End: 3_000_000_100}, window{Start: 3_000_000_900, End: 3_000_001_000}
			r.Capture.EndedNs, r.Capture.CorrectionFrom, r.Capture.CorrectionTo, r.Capture.ProvenThrough = 3_000_000_200, 1_000, 3_000_000_150, 1_000
		},
		"a negative interval":             func(r *scenarioResult) { r.Capture.Negative = 1 },
		"an invalid interval":             func(r *scenarioResult) { r.Capture.Invalid = 1 },
		"a late report":                   func(r *scenarioResult) { r.Capture.EndedNs = 5_000 + uint64(detectionBudgetNs) + 1 },
		"events from the offline CPU":     func(r *scenarioResult) { r.Capture.SchedWhileOff = 2 },
		"a target that never ran there":   func(r *scenarioResult) { r.Capture.SchedOnCPUPre = 0 },
		"a capture over another topology": func(r *scenarioResult) { r.Capture.InitialCPUs = []uint32{0, 1, 2} },
		"no capture on the restored set":  func(r *scenarioResult) { r.Recapture = nil },
		"a restored capture revoked": func(r *scenarioResult) {
			v := completeView()
			v.Revoked = true
			r.Recapture = &v
		},
		"a restored capture without final proof": func(r *scenarioResult) {
			v := completeView()
			v.FinalProof, v.Complete = false, false
			r.Recapture = &v
		},
		"a restored capture of fewer CPUs": func(r *scenarioResult) {
			v := completeView()
			v.InitialCPUs, v.FinalCPUs = []uint32{0, 1, 2, 3, 4, 5, 6}, []uint32{0, 1, 2, 3, 4, 5, 6}
			r.Recapture = &v
		},
		"a CPU left offline":   func(r *scenarioResult) { r.OnlineAfter = "0-6" },
		"a dead helper":        func(r *scenarioResult) { r.HelperAlive = false },
		"leaked descriptors":   func(r *scenarioResult) { r.HelperFDsReleased = false },
		"a dead target":        func(r *scenarioResult) { r.TargetAlive = false },
		"a failed correlation": func(r *scenarioResult) { r.Capture.CorrelationErr = "advance: invalid" },
	} {
		r := passing(kindHold)
		mutate(&r)
		judge(&r)
		if r.Pass {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestJudgeCPUOnlyCaptureMustSurviveTheHotplug(t *testing.T) {
	for name, mutate := range map[string]func(*scenarioResult){
		"ended by the hotplug":            func(r *scenarioResult) { r.Capture.ErrorCode = "topology_changed" },
		"closed by the helper":            func(r *scenarioResult) { r.Capture.ReadError = "stream closed by helper" },
		"samples from the offline CPU":    func(r *scenarioResult) { r.Capture.OnCPUWhileOff = 1 },
		"no sample after the CPU is back": func(r *scenarioResult) { r.Capture.AfterOnline = 0 },
		"no sample from the CPU again":    func(r *scenarioResult) { r.Capture.OnCPUAfterPin = 0 },
		"the target never ran there":      func(r *scenarioResult) { r.RanAfterRepin = false },
		"no sample before":                func(r *scenarioResult) { r.Capture.OnCPUBefore = 0 },
	} {
		r := passing(kindCPUOnly)
		mutate(&r)
		judge(&r)
		if r.Pass {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestJudgeControlCaptureMustComplete(t *testing.T) {
	for name, mutate := range map[string]func(*scenarioResult){
		"an error code":   func(r *scenarioResult) { r.Capture.ErrorCode = "topology_changed" },
		"no final proof":  func(r *scenarioResult) { r.Capture.FinalProof, r.Capture.Complete = false, false },
		"a revoke":        func(r *scenarioResult) { r.Capture.Revoked = true },
		"another set":     func(r *scenarioResult) { r.Capture.FinalCPUs = []uint32{0, 1} },
		"no event at all": func(r *scenarioResult) { r.Capture.SchedOnCPUPre, r.Capture.OnCPUBefore = 0, 0 },
	} {
		r := passing(kindControl)
		mutate(&r)
		judge(&r)
		if r.Pass {
			t.Errorf("%s was accepted", name)
		}
	}
	// a coverage correction of one task's unmeasured start is normal in a complete capture
	r := passing(kindControl)
	r.Capture.Corrections = 2
	judge(&r)
	if !r.Pass {
		t.Errorf("a complete capture with task corrections: %v", r.Failures)
	}
}

func TestScanIntervalsReadsTheGenerationCorrection(t *testing.T) {
	d := nativeperf.ClockDomain{HostID: "h", BootID: "b"}
	task := nativeperf.TaskKey{BootID: "b", TGID: 1, TID: 1, ProcessStart: 1, Generation: 1, PIDNamespace: 1}
	measure := func(n uint64) nativeperf.Measure {
		return nativeperf.Measure{Unit: nativeperf.UnitNanoseconds, Value: model.Uint64(n)}
	}
	iv := func(kind nativeperf.IntervalKind, start, end uint64) nativeperf.Interval {
		return nativeperf.Interval{Kind: kind, Task: task, Domain: d, Start: model.MonoNano(start), End: model.MonoNano(end), Measure: measure(end - start)}
	}
	generation := nativeperf.Interval{Domain: d, Kind: nativeperf.IntervalUnknown, Start: 100, End: 300, Measure: measure(200), Reason: nativeperf.ReasonGeneration, Correction: true}
	unmeasured := nativeperf.Interval{Domain: d, Task: task, Kind: nativeperf.IntervalUnknown, Start: 0, End: 50, Measure: measure(50), Reason: nativeperf.ReasonUnmeasured, Correction: true}
	var v captureView
	scanIntervals(&v, []nativeperf.Interval{unmeasured, iv(nativeperf.IntervalBlocked, 10, 90), iv(nativeperf.IntervalBlocked, 90, 150), iv(nativeperf.IntervalRunnable, 120, 250), generation})
	want := captureView{Intervals: 5, Corrections: 2, CorrectionFrom: 100, CorrectionTo: 300, CorrectionWhy: "generation_changed", Overlapped: 2, Straddling: 1}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("got %+v want %+v", v, want)
	}
	v = captureView{}
	scanIntervals(&v, []nativeperf.Interval{generation, iv(nativeperf.IntervalBlocked, 200, 400)})
	if v.NewerThanCorrection != 1 {
		t.Errorf("an interval that ends after the correction does is evidence from beyond the stream: %+v", v)
	}
	v = captureView{}
	bad := iv(nativeperf.IntervalBlocked, 10, 20)
	bad.End = 5
	scanIntervals(&v, []nativeperf.Interval{bad})
	if v.Negative != 1 || v.Invalid != 1 {
		t.Errorf("a negative interval is counted twice, as negative and as invalid: %+v", v)
	}
	// without a domain-wide generation correction nothing is related to a boundary
	v = captureView{}
	scanIntervals(&v, []nativeperf.Interval{unmeasured, iv(nativeperf.IntervalBlocked, 10, 90)})
	if v.CorrectionWhy != "" || v.Overlapped != 0 || v.Corrections != 1 {
		t.Errorf("task corrections are not the boundary: %+v", v)
	}
}

func TestParseAndFormatCPULists(t *testing.T) {
	for text, want := range map[string][]uint32{"0-7": allCPUs, "0": {0}, "0-2,4": {0, 1, 2, 4}, "0,2,4-5\n": {0, 2, 4, 5}} {
		got, err := parseCPUList(text)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v %v", text, got, err)
		}
	}
	for _, bad := range []string{"", "a", "3-1", "0-", "2,1", "0-2,1", "0-2000", "-3"} {
		if got, err := parseCPUList(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
	if got := formatCPUList([]uint32{0, 1, 2, 4, 6, 7}); got != "0-2,4,6-7" {
		t.Errorf("format: %q", got)
	}
}

func TestPickCPUNeverChoosesCPU0OrTheLastCPU(t *testing.T) {
	all := func(uint32) bool { return true }
	if cpu, err := pickCPU(allCPUs, -1, all); err != nil || cpu != 7 {
		t.Errorf("default: %d %v", cpu, err)
	}
	if cpu, err := pickCPU([]uint32{0, 1, 2, 5}, -1, func(c uint32) bool { return c != 5 }); err != nil || cpu != 2 {
		t.Errorf("the highest CPU with an online switch: %d %v", cpu, err)
	}
	if cpu, err := pickCPU(allCPUs, 3, all); err != nil || cpu != 3 {
		t.Errorf("explicit: %d %v", cpu, err)
	}
	for name, call := range map[string]func() (uint32, error){
		"cpu0":             func() (uint32, error) { return pickCPU(allCPUs, 0, all) },
		"offline":          func() (uint32, error) { return pickCPU([]uint32{0, 1}, 5, all) },
		"one CPU":          func() (uint32, error) { return pickCPU([]uint32{0}, -1, all) },
		"nothing to flip":  func() (uint32, error) { return pickCPU(allCPUs, -1, func(uint32) bool { return false }) },
		"explicit no file": func() (uint32, error) { return pickCPU(allCPUs, 3, func(uint32) bool { return false }) },
	} {
		if cpu, err := call(); err == nil {
			t.Errorf("%s: chose cpu%d", name, cpu)
		}
	}
}

func TestParseStatCountsFieldsAfterTheCommand(t *testing.T) {
	// fields 4..38 are 1..35, field 39 (the processor) is 5
	line := "1234 (my (odd) name) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 5 40 41"
	state, cpu, ok := parseStat(line)
	if !ok || state != 'R' || cpu != 5 {
		t.Errorf("state %c cpu %d ok %t", state, cpu, ok)
	}
	if _, _, ok := parseStat("1 (x) R 1 2"); ok {
		t.Errorf("a short line must not parse")
	}
}
