//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"soundpost/fixtures/nativeperf/qual"
	"soundpost/internal/nativeperf"
)

func newAccept() *accept {
	return &accept{res: &qual.QualificationResult{RuntimeBuild: map[string]qual.RuntimeBuild{}}, results: map[string]*scenResult{}, injections: map[string]*scenResult{}, nonce: "0123456789abcdef"}
}

func goodCPU() *scenResult {
	r := &scenResult{Name: "cpu", Mode: "cpu", Cap: qual.CaptureResult{Ready: true, Frames: 400}, SelfVerified: true, CPUSeconds: 10, Extra: map[string]any{}, Threads: 1}
	r.Stats = qual.StackStats{CPUSamples: 900, ChainsWithHot: 900, HotSamples: 900, Samples3Frames: 900, InWindow: 900,
		FunctionSamples: map[string]int{"spqual_serve": 900}, NonLeaf: map[string]int{},
		ExpectedPresent: map[string]int{"spqual_hot": 900, "spqual_hash_block": 900, "spqual_serve": 900, "spqual_worker_loop": 900}}
	return r
}

func goodNoFP() *scenResult {
	r := goodCPU()
	r.Name, r.Mode = "nofp", "nofp"
	r.Stats.ExpectedPresent = map[string]int{"spqual_nofp_hot": 900, "spqual_worker_loop": 900}
	r.Stats.NonLeaf = map[string]int{"spqual_worker_loop": 900}
	return r
}

func TestAssertCPUHotFunctionRuleIsExactlyEightyPercent(t *testing.T) {
	a := newAccept()
	sp := *findSpec("cpu")
	for _, tc := range []struct {
		chains int
		fails  bool
	}{{720, false}, {719, true}, {0, true}} {
		r := goodCPU()
		r.Stats.ChainsWithHot = tc.chains
		a.assert(sp, r)
		got := strings.Contains(strings.Join(r.Failures, ";"), "hot function")
		if got != tc.fails {
			t.Errorf("hot in %d/900 chains: failures %v, want fail=%v", tc.chains, r.Failures, tc.fails)
		}
	}
	// a count of non-empty callchains is not the hot function
	r := goodCPU()
	r.Stats.ChainsWithHot, r.Stats.Samples3Frames = 0, 900
	a.assert(sp, r)
	if len(r.Failures) == 0 {
		t.Error("deep non-empty stacks without the hot function passed")
	}
}

func TestAssertRejectsRejectedCaptureAndUnverifiedWorkload(t *testing.T) {
	a := newAccept()
	sp := *findSpec("cpu")
	r := goodCPU()
	r.CheckErr = qual.ErrSyntheticSamples
	a.assert(sp, r)
	if len(r.Failures) == 0 {
		t.Error("a rejected capture passed")
	}
	r = goodCPU()
	r.SelfVerified = false
	a.assert(sp, r)
	if len(r.Failures) == 0 {
		t.Error("a workload that did not verify its ground truth passed")
	}
	r = goodCPU()
	r.Cap.NeedleHits = 1
	a.assert(sp, r)
	if !strings.Contains(strings.Join(r.Failures, ";"), "privacy canary") {
		t.Errorf("a canary on the socket passed: %v", r.Failures)
	}
}

func TestFrameCoverageRuleReportsPartialNeverInvented(t *testing.T) {
	cases := []struct {
		name   string
		fp, nf func() *scenResult
		want   qual.State
	}{
		{"partial without frame pointers", goodCPU, goodNoFP, qual.StateSupported},
		{"no-fp coverage equals fp coverage", goodCPU, func() *scenResult {
			r := goodCPU()
			r.Name, r.Mode = "nofp", "nofp"
			r.Stats.ExpectedPresent = map[string]int{"spqual_nofp_hot": 900, "spqual_nofp_mid": 900, "spqual_nofp_serve": 900, "spqual_nofp_entry": 900, "spqual_worker_loop": 900}
			return r
		}, qual.StateFailed},
		{"fp build resolves too little", func() *scenResult {
			r := goodCPU()
			r.Stats.ExpectedPresent = map[string]int{"spqual_hot": 900}
			return r
		}, goodNoFP, qual.StateFailed},
		{"invented frame in the no-fp chain", goodCPU, func() *scenResult {
			r := goodNoFP()
			r.Failures = []string{"frame spqual_nofp_mid appears as a caller: invented frame"}
			return r
		}, qual.StateFailed},
	}
	for _, tc := range cases {
		a := newAccept()
		a.results["cpu"], a.results["nofp"] = tc.fp(), tc.nf()
		a.caps.OffCPU = nativeperf.Unsupported
		a.deriveRows()
		if a.res.FrameCoverage.State != tc.want {
			t.Errorf("%s: frame_coverage %s (%s), want %s", tc.name, a.res.FrameCoverage.State, a.res.FrameCoverage.Reason, tc.want)
		}
	}
}

func TestDerivedRowsNeverSupportedWithoutRealCapture(t *testing.T) {
	a := newAccept()
	a.caps.OffCPU = nativeperf.Unsupported
	a.deriveRows()
	for name, row := range a.res.Rows() {
		if row.State == qual.StateSupported {
			t.Errorf("row %s supported with no scenario having run", name)
		}
	}
	if a.res.Overhead.State != qual.StateNotRun {
		t.Errorf("overhead %s: the acceptance runner does not measure overhead", a.res.Overhead.State)
	}
	if a.res.ExitCode() == qual.ExitOK {
		t.Error("an empty run passed the release gate")
	}
	a = newAccept()
	cpu := goodCPU()
	cpu.Cap.Ready = false
	cpu.Failures = []string{"helper refused"}
	a.results["cpu"] = cpu
	a.deriveRows()
	if a.res.CPU.State != qual.StateFailed {
		t.Errorf("cpu row %s after a failed scenario", a.res.CPU.State)
	}
}

func TestSchedulerRowsAreUnqualifiedWithTheExactReason(t *testing.T) {
	for _, tc := range []struct {
		name, access, pidns, want string
		reasons                   []nativeperf.Reason
	}{
		{"tracefs denied", "readdir /sys/kernel/tracing: EACCES; open events/sched/sched_switch/format: EACCES", "inode 4026531836, initial namespace: true", "tracefs_denied", nil},
		{"tracefs permission", "readdir /sys/kernel/tracing: EPERM", "", "tracefs_denied", nil},
		{"tracefs absent", "readdir /sys/kernel/tracing: ENOENT", "inode 4026531836, initial namespace: true", "tracefs_unavailable", []nativeperf.Reason{nativeperf.ReasonTraceFS}},
		{"not the initial pid namespace", "readdir /sys/kernel/tracing: ok", "inode 4026532367, initial namespace: false", "scheduler_pid_namespace_not_initial", []nativeperf.Reason{nativeperf.ReasonEvent}},
	} {
		a := newAccept()
		a.caps = nativeperf.Capabilities{OffCPU: nativeperf.Unsupported, Reasons: tc.reasons}
		a.res.Permissions.TracefsAccess, a.res.Permissions.PIDNamespace = tc.access, tc.pidns
		a.deriveSchedulerRows(a.res)
		for name, row := range map[string]qual.Row{"off_cpu": a.res.OffCPU, "runqueue_split": a.res.RunqueueSplit} {
			if row.State != qual.StateUnqualified || row.Reason != tc.want || row.Exercised || row.Validate(name) != nil {
				t.Errorf("%s: %s = %+v, want unqualified/%s", tc.name, name, row, tc.want)
			}
		}
	}
}

func TestSupportedSchedulerProbeWithoutCaptureStaysUnexercised(t *testing.T) {
	a := newAccept()
	a.caps = nativeperf.Capabilities{OffCPU: nativeperf.Supported}
	a.deriveSchedulerRows(a.res)
	if a.res.OffCPU.State == qual.StateSupported || a.res.RunqueueSplit.State == qual.StateSupported {
		t.Fatal("a capability probe alone produced a supported off-CPU row")
	}
}

func TestInjectedLimitsMustBeExplicit(t *testing.T) {
	within := func(*scenResult) (bool, string) { return true, "" }
	over := func(*scenResult) (bool, string) { return false, "over the limit" }
	refused := &scenResult{Cap: qual.CaptureResult{ErrorCode: "resource_limit"}}
	if ok, outcome := explicitInjection(refused, within); !ok || outcome != "refused:resource_limit" {
		t.Errorf("closed refusal: %v %s", ok, outcome)
	}
	silent := &scenResult{}
	if ok, _ := explicitInjection(silent, within); ok {
		t.Error("a refusal without any closed code was accepted")
	}
	made := &scenResult{Cap: qual.CaptureResult{ErrorCode: "mystery"}}
	if ok, _ := explicitInjection(made, within); ok {
		t.Error("an invented error code was accepted")
	}
	leak := &scenResult{Cap: qual.CaptureResult{ErrorCode: "resource_limit"}, HelperPerfAfter: 2}
	if ok, _ := explicitInjection(leak, within); ok {
		t.Error("a refusal that leaked perf FDs was accepted")
	}
	events := &scenResult{Cap: qual.CaptureResult{ErrorCode: "resource_limit", Events: make([]nativeperf.SanitizedEvent, 1)}}
	if ok, _ := explicitInjection(events, within); ok {
		t.Error("a refusal that still delivered events was accepted")
	}
	admitted := &scenResult{Cap: qual.CaptureResult{Ready: true}}
	if ok, _ := explicitInjection(admitted, within); !ok {
		t.Error("an admitted session within its limit was rejected")
	}
	if ok, _ := explicitInjection(admitted, over); ok {
		t.Error("an admitted session over its limit was accepted")
	}
	released := &scenResult{Cap: qual.CaptureResult{Ready: true}, HelperFDsAfter: 3}
	if ok, _ := explicitInjection(released, within); ok {
		t.Error("a session that did not return to its baseline FD count was accepted")
	}
}

func TestPrivacyRowNeedsFramesAndAPresentCanary(t *testing.T) {
	mk := func(frames, hits int, comm, argv bool) *accept {
		a := newAccept()
		a.results["cpu"] = &scenResult{Cap: qual.CaptureResult{Frames: frames, Bytes: frames * 100, NeedleHits: hits}}
		a.canaryInComm, a.canaryInArgv = comm, argv
		a.derivePrivacy(a.res)
		return a
	}
	if mk(100, 0, true, true).res.Privacy.State != qual.StateSupported {
		t.Error("clean audit with the canary present should be supported")
	}
	for name, a := range map[string]*accept{"hit": mk(100, 1, true, true), "no frames": mk(0, 0, true, true), "canary absent in comm": mk(100, 0, false, true), "canary absent in argv": mk(100, 0, true, false)} {
		if a.res.Privacy.State == qual.StateSupported {
			t.Errorf("%s: privacy row supported", name)
		}
	}
}

func TestPermissionCasesRequireADistinctGenuineDenial(t *testing.T) {
	foreign := qual.PermissionCase{Name: "unprivileged_helper_foreign_uid_target", Outcome: "refused", ErrorCode: "permission_denied", FDsReleased: true}
	same := qual.PermissionCase{Name: "unprivileged_helper_same_uid_target", Outcome: "captured_genuine_samples", Samples: 100, FDsReleased: true}
	if f := permissionFailures([]qual.PermissionCase{foreign, same}); len(f) != 0 {
		t.Fatalf("valid cases failed: %v", f)
	}
	bad := map[string][]qual.PermissionCase{
		"foreign capture succeeded":       {{Name: foreign.Name, Outcome: "captured_genuine_samples", FDsReleased: true}, same},
		"foreign refusal with other code": {{Name: foreign.Name, Outcome: "refused", ErrorCode: "acquisition_failed", FDsReleased: true}, same},
		"foreign refusal leaked":          {{Name: foreign.Name, Outcome: "refused", ErrorCode: "permission_denied"}, same},
		"foreign empty session":           {{Name: foreign.Name, Outcome: "session_without_genuine_samples", FDsReleased: true}, same},
		"same-uid silent empty success":   {foreign, {Name: same.Name, Outcome: "session_without_genuine_samples", FDsReleased: true}},
		"same-uid invented code":          {foreign, {Name: same.Name, Outcome: "refused", ErrorCode: "mystery", FDsReleased: true}},
		"case missing":                    {foreign},
		"none":                            nil,
	}
	for name, cases := range bad {
		if len(permissionFailures(cases)) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
