// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func hotplugScenarioJSON(name, kind string, hotplug bool) map[string]any {
	s := map[string]any{"scenario": name, "kind": kind, "cpu": 7, "pass": true,
		"offline_write": map[string]any{"start_ns": 0, "end_ns": 0}, "online_write": map[string]any{"start_ns": 0, "end_ns": 0},
		"capture": map[string]any{"events": 100, "loss_events": 0, "ended_ns": 5200, "proven_through_ns": 4900, "scheduler_events_on_cpu_after_repin": 0}}
	if hotplug {
		s["offline_write"] = map[string]any{"start_ns": 5000, "end_ns": 5100}
		s["online_write"] = map[string]any{"start_ns": 5900, "end_ns": 6000}
	}
	return s
}

// hotplugStdout is what the harness prints after a clean run, one JSON object, changed by mutate.
func hotplugStdout(t *testing.T, mutate func(rep map[string]any)) string {
	t.Helper()
	var scenarios []any
	for _, need := range hotplugRequired {
		scenarios = append(scenarios, hotplugScenarioJSON(need.kind, need.kind, need.hotplug))
	}
	scenarios = append(scenarios, hotplugScenarioJSON("flap_sparse#2", "flap_sparse", true))
	rep := map[string]any{"harness": "cpu_hotplug", "kernel": "6.1.0-54-amd64", "cpu": 7, "online_before": "0-7", "online_after": "0-7",
		"cpu_restored": true, "scenarios": scenarios, "scenarios_failed": 0, "scenarios_not_exercised": 0, "pass": true}
	if mutate != nil {
		mutate(rep)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw) + "\n"
}

func hotplugScenarios(rep map[string]any) []any { return rep["scenarios"].([]any) }

func hotplugBuild() *Build {
	return &Build{Family: "linux-kernel", Version: "6.1.0-54-amd64", OS: "linux", Arch: "amd64", ID: "kernel-release:6.1.0-54-amd64"}
}

func TestHotplugRowPassesOnlyAReportThatProvesTheHotplug(t *testing.T) {
	rc := overheadCtx(t)
	pass := rc.hotplugRow(hotplugBuild(), execResult{Stdout: hotplugStdout(t, nil)}, "0-7", "0-7", nil, nil)
	if pass.State != StateExercised || pass.Outcome != OutcomePassed || pass.Build == nil || len(pass.Evidence) < 2 || pass.Command == nil || len(pass.Limits) == 0 {
		t.Fatalf("a clean run of every scenario passes: %+v", pass)
	}
	names := map[string]bool{}
	for _, s := range pass.Series {
		names[s.Name] = true
	}
	for _, want := range []string{"hotplug.hold.events", "hotplug.hold.reported_after_offline_write_ms", "hotplug.flap_sparse.runs", "hotplug.flap_sparse.scheduler_events_on_cpu_after_it_came_back"} {
		if !names[want] {
			t.Errorf("series %s missing: %v", want, names)
		}
	}
	if err := ValidateRow(Row{ID: "r", Subject: Subject{Family: "linux-kernel", Version: "6.1", OS: "linux", Arch: "amd64"}, State: pass.State, Outcome: pass.Outcome, Build: pass.Build, Command: pass.Command, Evidence: pass.Evidence, Series: pass.Series, Limits: pass.Limits, Loss: pass.Loss}); err != nil {
		t.Errorf("the row is not valid: %v", err)
	}
	for name, tc := range map[string]struct {
		res           execResult
		before, after string
		restored      []int
		restoreErr    error
		mutate        func(map[string]any)
		want          string
	}{
		"a non-zero exit": {res: execResult{Exit: 1, Stdout: hotplugStdout(t, nil), Stderr: "boom"}, want: "exited 1"},
		"a timeout":       {res: execResult{Exit: -1, Err: errTimeout, Stdout: hotplugStdout(t, nil)}, want: "did not finish"},
		"no report":       {res: execResult{Stdout: "no json here\n"}, want: "printed no cpu_hotplug report"},
		"another harness": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) { r["harness"] = "other" })}, want: "printed no cpu_hotplug report"},
		"a CPU left offline": {res: execResult{Stdout: hotplugStdout(t, nil)}, before: "0-7", after: "0-6", restored: []int{7},
			want: "left the online set"},
		"a CPU that could not be put back": {res: execResult{Stdout: hotplugStdout(t, nil)}, before: "0-7", after: "0-7", restoreErr: errors.New("cpu7: EBUSY"),
			want: "left the online set"},
		"the harness says it did not restore": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) { r["cpu_restored"] = false })}, want: "not restored"},
		"a failed scenario": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) {
			s := hotplugScenarios(r)[2].(map[string]any)
			s["pass"], s["failures"] = false, []string{"silent coverage loss"}
		})}, want: "silent coverage loss"},
		"a failed scenario without a reason": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) { hotplugScenarios(r)[1].(map[string]any)["pass"] = false })}, want: "no reason reported"},
		"a scenario that did not happen": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) {
			hotplugScenarios(r)[1].(map[string]any)["not_exercised"] = "EBUSY"
		})}, want: "did not happen"},
		"a hotplug scenario that wrote nothing": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) {
			hotplugScenarios(r)[1].(map[string]any)["offline_write"] = map[string]any{"start_ns": 0, "end_ns": 0}
		})}, want: "no offline/online write"},
		"a hotplug scenario that never came back": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) {
			hotplugScenarios(r)[3].(map[string]any)["online_write"] = map[string]any{"start_ns": 0, "end_ns": 0}
		})}, want: "no offline/online write"},
		"no flap scenario": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) {
			r["scenarios"] = append(hotplugScenarios(r)[:2:2], hotplugScenarios(r)[3:]...)
		})}, want: "no flap scenario"},
		"no sparse flap": {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) { r["scenarios"] = hotplugScenarios(r)[:3] })}, want: "no flap_sparse scenario"},
		"no scenarios":   {res: execResult{Stdout: hotplugStdout(t, func(r map[string]any) { r["scenarios"] = []any{} })}, want: "no control scenario"},
	} {
		before, after := tc.before, tc.after
		if before == "" {
			before, after = "0-7", "0-7"
		}
		r := rc.hotplugRow(hotplugBuild(), tc.res, before, after, tc.restored, tc.restoreErr)
		if r.State != StateExercised || r.Outcome != OutcomeFailed || !strings.Contains(strings.Join(r.Failures, " | "), tc.want) {
			t.Errorf("%s: %+v (want a failure naming %q)", name, r, tc.want)
		}
	}
}

func TestHotplugRowNotExercisedStaysNotExercised(t *testing.T) {
	rc := overheadCtx(t)
	stub := `{"harness":"cpu_hotplug","not_exercised":"no CPU can be taken offline: fewer than two CPUs are online"}` + "\n"
	r := rc.hotplugRow(hotplugBuild(), execResult{Exit: hotplugExitNotExercised, Stdout: stub}, "0", "0", nil, nil)
	if r.State != StateNotExercised || !strings.Contains(r.Reason, "fewer than two CPUs") || r.Build != nil || r.Outcome != "" {
		t.Fatalf("a harness that could not hotplug is not_exercised with its reason: %+v", r)
	}
	// a full report in which a scenario did not happen (the kernel refused the write) is not_exercised too, never a pass
	refused := hotplugStdout(t, func(rep map[string]any) {
		s := hotplugScenarios(rep)[1].(map[string]any)
		s["not_exercised"], s["pass"] = "the kernel refused the CPU hotplug: EBUSY", false
		rep["scenarios_not_exercised"], rep["pass"] = 1, false
	})
	r = rc.hotplugRow(hotplugBuild(), execResult{Exit: hotplugExitNotExercised, Stdout: refused}, "0-7", "0-7", nil, nil)
	if r.State != StateNotExercised || !strings.Contains(r.Reason, "EBUSY") {
		t.Fatalf("a refused hotplug: %+v", r)
	}
	// ... unless the harness also left the host changed: that is a failure whatever the harness thought of it
	r = rc.hotplugRow(hotplugBuild(), execResult{Exit: hotplugExitNotExercised, Stdout: refused}, "0-7", "0-6", []int{7}, nil)
	if r.State != StateExercised || r.Outcome != OutcomeFailed {
		t.Fatalf("a refused hotplug that left a CPU offline: %+v", r)
	}
	// exit 3 without any reason is not a free pass to "not exercised"
	r = rc.hotplugRow(hotplugBuild(), execResult{Exit: hotplugExitNotExercised, Stdout: hotplugStdout(t, nil)}, "0-7", "0-7", nil, nil)
	if r.State != StateExercised || r.Outcome != OutcomeFailed {
		t.Fatalf("exit 3 with a clean report contradicts itself: %+v", r)
	}
}

func TestRunNativeHotplugIsNeverExercisedWithoutAGenuineRunnerAndTheOptIn(t *testing.T) {
	spec := func(arch string) RowSpec {
		return RowSpec{ID: "h", Subject: &Subject{Family: "linux-kernel", Version: "6.1", OS: "linux", Arch: arch}, Params: map[string]string{"capability": "cpu_hotplug"}}
	}
	// With the opt-in granted the gate still speaks first: none of these hosts is a genuine 6.1 amd64 runner, and nothing is
	// started (the context has no ctx: a process would panic the runner)
	grant := func(ok bool, why string) func() {
		old := hostMutation
		hostMutation = func() (bool, string) { return ok, why }
		return func() { hostMutation = old }
	}
	defer grant(true, "")()
	for name, tc := range map[string]struct {
		host HostInfo
		arch string
		want string
	}{
		"WSL2":                {HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.1.87.2-microsoft-standard-WSL2", Class: "wsl2"}, "amd64", "WSL2"},
		"another kernel":      {HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.40", Class: "linux"}, "amd64", "no Linux 6.1 runner"},
		"another arch":        {HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.1.115", Class: "linux"}, "arm64", "never extrapolated"},
		"not Linux":           {HostInfo{OS: "windows", Arch: "amd64", Class: "windows"}, "amd64", "native Linux capture cannot run here"},
		"another arch of 6.6": {HostInfo{OS: "linux", Arch: "arm64", Kernel: "6.1.115", Class: "linux"}, "amd64", "never extrapolated"},
	} {
		r := runNativeHotplug(&runCtx{host: tc.host}, spec(tc.arch))
		if r.State != StateNotExercised || !strings.Contains(r.Reason, tc.want) || r.Build != nil {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// a genuine runner without the opt-in (or without root) changes nothing and says why
	genuine := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.1.115", Class: "linux"}}
	for name, why := range map[string]string{"no opt-in": hostMutationEnv + "=1 is not set", "not root": "the run is not root (euid 1000)"} {
		restore := grant(false, why)
		r := runNativeHotplug(genuine, spec("amd64"))
		restore()
		if r.State != StateNotExercised || !strings.Contains(r.Reason, why) || !strings.Contains(r.Reason, "nothing was changed") || !strings.Contains(r.Reason, "/sys/devices/system/cpu/cpuN/online") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestHostMutationNeedsTheOptInAndRoot(t *testing.T) {
	t.Setenv(hostMutationEnv, "")
	if ok, why := hostMutation(); ok || !strings.Contains(why, hostMutationEnv) {
		t.Errorf("no opt-in: %t %q", ok, why)
	}
	t.Setenv(hostMutationEnv, "true")
	if ok, _ := hostMutation(); ok {
		t.Error("only the value 1 opts in")
	}
	t.Setenv(hostMutationEnv, "1")
	ok, why := hostMutation()
	if os.Geteuid() == 0 {
		if !ok || why != "" {
			t.Errorf("root with the opt-in: %t %q", ok, why)
		}
	} else if ok || !strings.Contains(why, "not root") {
		t.Errorf("the opt-in without root: %t %q", ok, why)
	}
}

func TestParseCPUSet(t *testing.T) {
	for text, want := range map[string][]int{"0-3": {0, 1, 2, 3}, "0": {0}, "0-1,4,6-7\n": {0, 1, 4, 6, 7}, "": nil} {
		set, err := parseCPUSet(text)
		var got []int
		for c := range 16 {
			if set[c] {
				got = append(got, c)
			}
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v %v", text, got, err)
		}
	}
	for _, bad := range []string{"a", "3-1", "0-", "-1", "0-99999"} {
		if _, err := parseCPUSet(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestRestoreCPUsPutsBackWhatTheHarnessLeftOffline(t *testing.T) {
	old := cpuSysfs
	defer func() { cpuSysfs = old }()
	cpuSysfs = t.TempDir()
	write := func(cpu, value string) string {
		dir := filepath.Join(cpuSysfs, "cpu"+cpu)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "online")
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cpu6, cpu7 := write("6", "1\n"), write("7", "0\n")
	if err := os.WriteFile(filepath.Join(cpuSysfs, "online"), []byte("0-6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if text, err := readOnlineCPUs(); err != nil || text != "0-6" {
		t.Fatalf("online set %q %v", text, err)
	}
	restored, err := restoreCPUs("0-7", "0-6")
	raw, _ := os.ReadFile(cpu7)
	if err != nil || !reflect.DeepEqual(restored, []int{7}) || string(raw) != "1\n" {
		t.Fatalf("restored %v %v, cpu7 switch %q", restored, err, raw)
	}
	if raw, _ := os.ReadFile(cpu6); string(raw) != "1\n" {
		t.Fatal("a CPU that was never away was written")
	}
	// nothing to put back: nothing is written
	if restored, err := restoreCPUs("0-7", "0-7"); err != nil || len(restored) != 0 {
		t.Fatalf("an unchanged online set: %v %v", restored, err)
	}
	// a CPU whose switch cannot be written is reported, the others are still put back
	write("5", "0\n")
	if err := os.Remove(cpu7); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(cpu7)); err != nil {
		t.Fatal(err)
	}
	restored, err = restoreCPUs("0-7", "0-4,6")
	if err == nil || !strings.Contains(err.Error(), "cpu7") || !reflect.DeepEqual(restored, []int{5}) {
		t.Fatalf("restored %v, error %v", restored, err)
	}
	if _, err := restoreCPUs("garbage", "0"); err == nil {
		t.Fatal("an unreadable online set")
	}
}
