// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestNativeRowsOnTheRealKernel runs the PID-reuse and CPU hotplug rows of the real runner on this host. It is the
// evidence run of those rows and does nothing unless SOUNDPOST_QUALIFY_REAL_NATIVE=1 (it builds the committed fixtures and,
// with root and SOUNDPOST_QUALIFY_HOST_MUTATION=1, steers ns_last_pid in a disposable PID namespace and takes a CPU
// offline). SOUNDPOST_QUALIFY_REAL_NATIVE_OUT names the file that receives both rows as JSON. Without the opt-in the
// PID-reuse row must come out not_exercised; with it, exercised/passed.
func TestNativeRowsOnTheRealKernel(t *testing.T) {
	if os.Getenv("SOUNDPOST_QUALIFY_REAL_NATIVE") != "1" {
		t.Skip("set SOUNDPOST_QUALIFY_REAL_NATIVE=1 on a Linux runner to run the native rows for real")
	}
	host := hostInfo()
	rc := &runCtx{ctx: context.Background(), root: repoRoot(t), work: t.TempDir(), reportDir: t.TempDir(), host: host, probes: map[string]*probeResult{}, cache: map[string]any{}}
	if err := os.MkdirAll(filepath.Join(rc.reportDir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := func(capability, runner string) RowSpec {
		return RowSpec{ID: "real." + capability, Subject: &Subject{Family: "linux-kernel", Version: kernelSeries(host.Kernel), OS: "linux", Arch: host.Arch}, Params: map[string]string{"capability": capability}}
	}
	mutate, why := hostMutation()
	rows := map[string]Row{
		"pid_reuse":   runNativeIdentity(rc, spec("pid_reuse", "native_identity")),
		"cpu_hotplug": runNativeHotplug(rc, spec("cpu_hotplug", "native_hotplug")),
	}
	raw, _ := json.MarshalIndent(map[string]any{"host": host, "host_mutation_allowed": mutate, "host_mutation_why_not": why, "rows": rows}, "", "  ")
	if out := os.Getenv("SOUNDPOST_QUALIFY_REAL_NATIVE_OUT"); out != "" {
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s", raw)
	for name, row := range rows {
		switch {
		case mutate && (row.State != StateExercised || row.Outcome != OutcomePassed):
			t.Errorf("%s with the opt-in: %s %s %s %v", name, row.State, row.Outcome, row.Reason, row.Failures)
		case !mutate && row.State != StateNotExercised:
			t.Errorf("%s without the opt-in must be not_exercised: %s %s", name, row.State, row.Outcome)
		}
	}
}

func TestIdentityInvocationForcesPIDReuseOnlyWithTheOptIn(t *testing.T) {
	args := []string{"--scenario", "pid-reuse", "--workload", "/w/reuse"}
	have := func(string) (string, error) { return "/usr/bin/unshare", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	// the default run starts the smoke itself and writes nothing to the kernel
	name, argv, steered, why := identityInvocation("pid-reuse", "/w/smoke", args, false, have)
	if name != "/w/smoke" || !reflect.DeepEqual(argv, args) || steered || why != "" {
		t.Fatalf("no opt-in: %q %v %t %q", name, argv, steered, why)
	}
	// with the opt-in the smoke is started as PID 1 of a disposable PID namespace and asked to steer ns_last_pid there
	name, argv, steered, why = identityInvocation("pid-reuse", "/w/smoke", args, true, have)
	want := []string{"--pid", "--fork", "--mount-proc", "/w/smoke", "--steer-ns-last-pid", "--scenario", "pid-reuse", "--workload", "/w/reuse"}
	if name != "/usr/bin/unshare" || !reflect.DeepEqual(argv, want) || !steered || why != "" {
		t.Fatalf("opt-in: %q %v %t %q", name, argv, steered, why)
	}
	// nothing but a PID namespace and a private /proc is unshared: no pid_max, no user, network or mount-propagation change
	for _, arg := range argv[:4] {
		if arg != "--pid" && arg != "--fork" && arg != "--mount-proc" && arg != "/w/smoke" {
			t.Errorf("unexpected unshare argument %q", arg)
		}
	}
	// the opt-in without the tool the forcing needs is not_exercised, never a silent fall back to the unforced run
	name, argv, steered, why = identityInvocation("pid-reuse", "/w/smoke", args, true, missing)
	if name != "" || argv != nil || steered || !strings.Contains(why, "unshare") || !strings.Contains(why, hostMutationEnv) {
		t.Fatalf("no unshare: %q %v %t %q", name, argv, steered, why)
	}
	// no other scenario is ever forced, opt-in or not
	for _, scenario := range []string{"exit", "exec", "namespaces", "no-frame-pointers"} {
		other := []string{"--scenario", scenario}
		name, argv, steered, why = identityInvocation(scenario, "/w/smoke", other, true, have)
		if name != "/w/smoke" || !reflect.DeepEqual(argv, other) || steered || why != "" {
			t.Errorf("%s: %q %v %t %q", scenario, name, argv, steered, why)
		}
	}
}

func TestSteeredPIDReuseRow(t *testing.T) {
	rc := overheadCtx(t)
	build := &Build{Family: "linux-kernel", Version: "6.1.0-54-amd64", OS: "linux", Arch: "amd64", ID: "k"}
	report := `{"scenario":"pid-reuse","actual_numeric_pid_reuse":true,"ns_last_pid_steered":true,"reused_pid":4242,"attempt":2,"same_process_start":false,"same_generation":false}` + "\n"
	pass := rc.identityRow(build, "pid-reuse", true, execResult{Stdout: report})
	if pass.State != StateExercised || pass.Outcome != OutcomePassed || pass.Command == nil || !strings.Contains(pass.Command.Command, "--steer-ns-last-pid") {
		t.Fatalf("a steered run that saw the recycled number resolve to another process start passes: %+v", pass)
	}
	// the row says it forced the cursor, how, and what it did not touch
	if len(pass.Evidence) < 2 || !strings.Contains(pass.Evidence[0], "ns_last_pid steered") || !strings.Contains(pass.Evidence[0], hostMutationEnv) {
		t.Errorf("evidence: %v", pass.Evidence)
	}
	if len(pass.Limits) != 1 || !strings.Contains(pass.Limits[0], "forced") || !strings.Contains(pass.Limits[0], "pid_max is untouched") || !strings.Contains(pass.Limits[0], "disposable PID namespace") {
		t.Errorf("limits: %v", pass.Limits)
	}
	// the unforced row keeps its own description
	plain := rc.identityRow(build, "pid-reuse", false, execResult{Stdout: report})
	if plain.Command == nil || strings.Contains(plain.Command.Command, "steer") || len(plain.Limits) != 1 || !strings.Contains(plain.Limits[0], "not a forced collision") {
		t.Errorf("an unforced run is not described as forced: %+v", plain)
	}
	// the other scenarios say nothing about PID reuse
	if exit := rc.identityRow(build, "exit", false, execResult{Stdout: `{"samples": 3}` + "\n"}); len(exit.Limits) != 0 {
		t.Errorf("an exit row carries a PID-reuse limit: %v", exit.Limits)
	}
	for name, stdout := range map[string]string{
		"no report":                      "",
		"not steered":                    strings.Replace(report, `"ns_last_pid_steered":true`, `"ns_last_pid_steered":false`, 1),
		"no reuse observed":              strings.Replace(report, `"actual_numeric_pid_reuse":true`, `"actual_numeric_pid_reuse":false`, 1),
		"the process start was the same": strings.Replace(report, `"same_process_start":false`, `"same_process_start":true`, 1),
		"the field missing":              strings.Replace(report, `"same_process_start":false,`, ``, 1),
	} {
		r := rc.identityRow(build, "pid-reuse", true, execResult{Stdout: stdout})
		if r.State != StateExercised || r.Outcome != OutcomeFailed || !strings.Contains(strings.Join(r.Failures, " | "), "without proving a forced, observed reuse") {
			t.Errorf("%s: a steered exit 0 that does not prove the reuse passed: %+v", name, r)
		}
	}
	// a steered run whose smoke failed is a failure; one that never saw a recycled number is not_exercised, never a pass
	if r := rc.identityRow(build, "pid-reuse", true, execResult{Exit: 1, Stderr: "pid-reuse: real_pid_reuse_joined"}); r.Outcome != OutcomeFailed || !strings.Contains(r.Failures[0], "real_pid_reuse_joined") {
		t.Errorf("the smoke caught the product joining two generations: %+v", r)
	}
	unseen := rc.identityRow(build, "pid-reuse", true, execResult{Exit: 1, Stderr: "pid-reuse: " + pidReuseNotObserved})
	if unseen.State != StateNotExercised || !strings.Contains(unseen.Reason, "forced") || !strings.Contains(unseen.Reason, "precondition never occurred") {
		t.Errorf("steering that produced no reuse: %+v", unseen)
	}
	// without the opt-in the reason says how to force it
	unforced := rc.identityRow(build, "pid-reuse", false, execResult{Exit: 1, Stderr: "pid-reuse: " + pidReuseNotObserved})
	if unforced.State != StateNotExercised || !strings.Contains(unforced.Reason, hostMutationEnv+"=1") || !strings.Contains(unforced.Reason, "disposable PID namespace") {
		t.Errorf("unforced: %+v", unforced)
	}
}
