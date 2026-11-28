// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"strings"
	"testing"
)

func TestQualificationIdentityRowStates(t *testing.T) {
	rc := overheadCtx(t)
	build := &Build{Family: "wsl2-linux-kernel", Version: "6.6.87", OS: "linux", Arch: "amd64", ID: "k"}
	pass := rc.identityRow(build, "exit", false, execResult{Stdout: "{\"samples\": 12}\n"})
	if pass.State != StateExercised || pass.Outcome != OutcomePassed || len(pass.Series) != 1 {
		t.Fatalf("a scenario that exits 0 passes with its numbers: %+v", pass)
	}
	fail := rc.identityRow(build, "exec", false, execResult{Exit: 1, Stderr: "exec: generation_changed"})
	if fail.State != StateExercised || fail.Outcome != OutcomeFailed || !strings.Contains(fail.Failures[0], "generation_changed") {
		t.Fatalf("a failing scenario is a measured failure: %+v", fail)
	}
	// PID reuse that never happened is not a pass and not a failure of the product.
	skipped := rc.identityRow(build, "pid-reuse", false, execResult{Exit: 1, Stderr: "pid-reuse: " + pidReuseNotObserved})
	if skipped.State != StateNotExercised || !strings.Contains(skipped.Reason, "precondition never occurred") || skipped.Build != nil {
		t.Fatalf("unobserved PID reuse must be not_exercised: %+v", skipped)
	}
	// The same closed code under another scenario, or any other pid-reuse failure, stays a failure.
	if r := rc.identityRow(build, "exit", false, execResult{Exit: 1, Stderr: pidReuseNotObserved}); r.State != StateExercised || r.Outcome != OutcomeFailed {
		t.Errorf("only the pid-reuse scenario may be excused by that code: %+v", r)
	}
	if r := rc.identityRow(build, "pid-reuse", false, execResult{Exit: 1, Stderr: "pid-reuse: target_identity_unavailable"}); r.Outcome != OutcomeFailed {
		t.Errorf("a pid-reuse run that failed for another reason is a failure: %+v", r)
	}
	if r := rc.identityRow(build, "pid-reuse", false, execResult{Exit: -1, Err: errTimeout}); r.Outcome != OutcomeFailed {
		t.Errorf("a timed-out scenario is a failure: %+v", r)
	}
}

var errTimeout = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string { return "deadline exceeded" }

// CPU hotplug is no longer a gap nobody tried: it has a harness (native_hotplug.go), and container modes have theirs (native_container.go,
// 07.06#12; D79 for which of its scenarios a kernel must show). The container_modes half of what the old loop over both gaps held is
// TestContainerModesPrerequisitesAreNotExercisedWithTheExactReason (another architecture, another kernel series, WSL2: not exercised and
// never extrapolated) and TestContainerGapRemovedFromNativeGaps, both in native_container_test.go. What stays true is that a row is never
// exercised without the real thing. (a) A genuine runner that lacks the opt-in or root reports not_exercised with the reason and starts
// nothing; (b) a WSL2 host, another kernel series or another architecture never exercises the row, opt-in or not; (c) a hotplug that did
// not occur is never a pass; and no capability is left in nativeGaps.
func TestQualificationNativeGapsAreNeverExercised(t *testing.T) {
	spec := func(arch, capability string) RowSpec {
		return RowSpec{ID: "g", Subject: &Subject{Family: "linux-kernel", Version: "6.6", OS: "linux", Arch: arch}, Params: map[string]string{"capability": capability}}
	}
	old := hostMutation
	defer func() { hostMutation = old }()
	// (b) with the opt-in granted: the gate speaks first and nothing is started (the contexts have no ctx: a process would panic)
	hostMutation = func() (bool, string) { return true, "" }
	wsl := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}}
	if r := runNativeHotplug(wsl, spec("arm64", "cpu_hotplug")); r.State != StateNotExercised || !strings.Contains(r.Reason, "never extrapolated") {
		t.Errorf("another architecture: %+v", r)
	}
	if r := runNativeHotplug(wsl, spec("amd64", "cpu_hotplug")); r.State != StateNotExercised || !strings.Contains(r.Reason, "WSL2") {
		t.Errorf("a WSL2 host does not qualify a Linux row: %+v", r)
	}
	other := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.1.115", Class: "linux"}}
	if r := runNativeHotplug(other, spec("amd64", "cpu_hotplug")); r.State != StateNotExercised || !strings.Contains(r.Reason, "no Linux 6.6 runner") {
		t.Errorf("another kernel series: %+v", r)
	}
	// (a) a genuine runner without the opt-in
	hostMutation = func() (bool, string) { return false, hostMutationEnv + "=1 is not set" }
	genuine := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.40", Class: "linux"}}
	r := runNativeHotplug(genuine, spec("amd64", "cpu_hotplug"))
	if r.State != StateNotExercised || !strings.Contains(r.Reason, hostMutationEnv+"=1 is not set") || !strings.Contains(r.Reason, "nothing was changed") || strings.Contains(r.Reason, "additionally") {
		t.Errorf("a genuine runner without the opt-in must say why it changed nothing: %+v", r)
	}
	// (c) a harness report whose hotplug never happened, or that never ran one, is not a pass
	rc := overheadCtx(t)
	noWrite := hotplugStdout(t, func(rep map[string]any) {
		hotplugScenarios(rep)[1].(map[string]any)["online_write"] = map[string]any{"start_ns": 0, "end_ns": 0}
	})
	if r := rc.hotplugRow(hotplugBuild(), execResult{Stdout: noWrite}, "0-7", "0-7", nil, nil); r.State == StateExercised && r.Outcome == OutcomePassed {
		t.Errorf("a hotplug scenario without its online write passed: %+v", r)
	}
	stub := `{"harness":"cpu_hotplug","not_exercised":"no CPU can be taken offline"}` + "\n"
	if r := rc.hotplugRow(hotplugBuild(), execResult{Exit: hotplugExitNotExercised, Stdout: stub}, "0", "0", nil, nil); r.State != StateNotExercised {
		t.Errorf("a harness that could not hotplug: %+v", r)
	}
	if len(nativeGaps) != 0 {
		t.Errorf("no native capability is left without a harness: %v", nativeGaps)
	}
	if r := runNativeGap(genuine, spec("amd64", "cpu_hotplug")); r.State != StateNotExercised || !strings.Contains(r.Reason, "unknown") {
		t.Errorf("cpu_hotplug is not a gap any more: %+v", r)
	}
}

func TestQualificationSeparationFromRawSeries(t *testing.T) {
	apart := separation(modePair{statBlock{[]float64{1, 1.2}}, statBlock{[]float64{2, 2.1}}}, modePair{statBlock{[]float64{10}}, statBlock{[]float64{30}}})
	if !strings.Contains(apart, "p95: every capture run (min 2) is above every baseline run (max 1.2)") || !strings.Contains(apart, "cpu/request: every capture run") {
		t.Errorf("separated series: %s", apart)
	}
	overlap := separation(modePair{statBlock{[]float64{1, 3}}, statBlock{[]float64{2, 4}}}, modePair{statBlock{[]float64{10}}, statBlock{[]float64{30}}})
	if !strings.Contains(overlap, "NOT separated from run-to-run noise") {
		t.Errorf("overlapping series must say so: %s", overlap)
	}
}

func TestQualificationKernelSeries(t *testing.T) {
	for in, want := range map[string]string{"6.6.87.2-microsoft-standard-WSL2": "6.6", "6.1.115": "6.1", "6.12": "6.12", "6": "", "": ""} {
		if got := kernelSeries(in); got != want {
			t.Errorf("kernelSeries(%q) = %q, want %q", in, got, want)
		}
	}
}
