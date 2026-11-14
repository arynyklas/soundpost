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
	pass := rc.identityRow(build, "exit", execResult{Stdout: "{\"samples\": 12}\n"})
	if pass.State != StateExercised || pass.Outcome != OutcomePassed || len(pass.Series) != 1 {
		t.Fatalf("a scenario that exits 0 passes with its numbers: %+v", pass)
	}
	fail := rc.identityRow(build, "exec", execResult{Exit: 1, Stderr: "exec: generation_changed"})
	if fail.State != StateExercised || fail.Outcome != OutcomeFailed || !strings.Contains(fail.Failures[0], "generation_changed") {
		t.Fatalf("a failing scenario is a measured failure: %+v", fail)
	}
	// PID reuse that never happened is not a pass and not a failure of the product.
	skipped := rc.identityRow(build, "pid-reuse", execResult{Exit: 1, Stderr: "pid-reuse: " + pidReuseNotObserved})
	if skipped.State != StateNotExercised || !strings.Contains(skipped.Reason, "precondition never occurred") || skipped.Build != nil {
		t.Fatalf("unobserved PID reuse must be not_exercised: %+v", skipped)
	}
	// The same closed code under another scenario, or any other pid-reuse failure, stays a failure.
	if r := rc.identityRow(build, "exit", execResult{Exit: 1, Stderr: pidReuseNotObserved}); r.State != StateExercised || r.Outcome != OutcomeFailed {
		t.Errorf("only the pid-reuse scenario may be excused by that code: %+v", r)
	}
	if r := rc.identityRow(build, "pid-reuse", execResult{Exit: 1, Stderr: "pid-reuse: target_identity_unavailable"}); r.Outcome != OutcomeFailed {
		t.Errorf("a pid-reuse run that failed for another reason is a failure: %+v", r)
	}
	if r := rc.identityRow(build, "pid-reuse", execResult{Exit: -1, Err: errTimeout}); r.Outcome != OutcomeFailed {
		t.Errorf("a timed-out scenario is a failure: %+v", r)
	}
}

var errTimeout = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string { return "deadline exceeded" }

func TestQualificationNativeGapsAreNeverExercised(t *testing.T) {
	rc := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}}
	spec := func(arch, capability string) RowSpec {
		return RowSpec{ID: "g", Subject: &Subject{Family: "linux-kernel", Version: "6.6", OS: "linux", Arch: arch}, Params: map[string]string{"capability": capability}}
	}
	for _, c := range []string{"cpu_hotplug", "container_modes"} {
		r := runNativeGap(rc, spec("arm64", c))
		if r.State != StateNotExercised || !strings.Contains(r.Reason, "additionally") || !strings.Contains(r.Reason, "never extrapolated") {
			t.Errorf("%s: gap reason + gate reason expected: %+v", c, r)
		}
	}
	genuine := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.40", Class: "linux"}}
	r := runNativeGap(genuine, spec("amd64", "cpu_hotplug"))
	if r.State != StateNotExercised || !strings.Contains(r.Reason, "/sys/devices/system/cpu") || strings.Contains(r.Reason, "additionally") {
		t.Errorf("even a genuine runner does not exercise hot-unplug here: %+v", r)
	}
	if r := runNativeGap(genuine, spec("amd64", "nonsense")); r.State != StateNotExercised || !strings.Contains(r.Reason, "unknown") {
		t.Errorf("unknown gap: %+v", r)
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
