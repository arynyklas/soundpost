// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func containerSpec(arch, series string) RowSpec {
	return RowSpec{ID: "runtime.native.linux-" + series + "." + arch + ".container_modes", Required: true,
		Subject: &Subject{Family: "linux-kernel", Version: series, OS: "linux", Arch: arch}, Params: map[string]string{"capability": "container_modes"}}
}

func genuineHost(kernel string) *runCtx {
	return &runCtx{root: "/work/repo", host: HostInfo{OS: "linux", Arch: "amd64", Kernel: kernel, Class: "linux"}, reportDir: filepath.Join(os.TempDir(), "qualify-container-test")}
}

func runcFound() (string, error)  { return "/usr/bin/runc", nil }
func runcAbsent() (string, error) { return "", errors.New("not found") }

func TestContainerModesPrerequisitesAreNotExercisedWithTheExactReason(t *testing.T) {
	rc := genuineHost("6.1.0-54-amd64")
	cases := []struct {
		name  string
		rc    *runCtx
		spec  RowSpec
		euid  int
		runc  func() (string, error)
		wants string
	}{
		{"not root", rc, containerSpec("amd64", "6.1"), 1000, runcFound, "must run as root"},
		{"no runc", rc, containerSpec("amd64", "6.1"), 0, runcAbsent, "runc is not installed"},
		{"other kernel series", rc, containerSpec("amd64", "6.6"), 0, runcFound, "there is no Linux 6.6 runner here"},
		{"other architecture", rc, containerSpec("arm64", "6.1"), 0, runcFound, "never extrapolated"},
		{"wsl2 host", &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}}, containerSpec("amd64", "6.6"), 0, runcFound, "WSL2"},
		{"windows host", &runCtx{host: HostInfo{OS: "windows", Arch: "amd64", Kernel: "10.0"}}, containerSpec("amd64", "6.1"), 0, runcFound, "windows"},
	}
	for _, c := range cases {
		build, why := c.rc.containerPrerequisite(c.spec, c.euid, c.runc)
		if build != nil || !strings.Contains(why, c.wants) {
			t.Errorf("%s: want a refusal containing %q, got build=%v why=%q", c.name, c.wants, build, why)
		}
	}
	build, why := rc.containerPrerequisite(containerSpec("amd64", "6.1"), 0, runcFound)
	if why != "" || build == nil || build.Version != "6.1.0-54-amd64" || build.OS != "linux" || build.Arch != "amd64" {
		t.Errorf("a root pinned-series host with runc may run the row: build=%+v why=%q", build, why)
	}
}

func harnessReport(mutate func(*containerReport)) execResult {
	r := containerReport{Schema: containerReportSchema, Status: "pass", Kernel: "6.1.0-54-amd64", Runc: "runc version 1.1.5", Limits: []string{"one host"}}
	for _, name := range containerRequiredScenarios {
		r.Scenarios = append(r.Scenarios, containerScenario{Name: name, Status: "pass", Expected: "x", Observed: "x"})
	}
	if mutate != nil {
		mutate(&r)
	}
	raw, _ := json.MarshalIndent(r, "", " ")
	return execResult{Stdout: string(raw), Exit: 0, Duration: 90 * time.Second}
}

func TestContainerRowPassesOnlyWhenEveryRequiredScenarioPassed(t *testing.T) {
	rc := genuineHost("6.1.0-54-amd64")
	_ = os.MkdirAll(filepath.Join(rc.reportDir, "evidence"), 0o755)
	build := &Build{Family: "linux-kernel", Version: "6.1.0-54-amd64", OS: "linux", Arch: "amd64"}
	row := rc.containerRow(build, harnessReport(nil))
	if row.State != StateExercised || row.Outcome != OutcomePassed || len(row.Failures) != 0 || row.Command == nil || row.Command.ExitCode != 0 {
		t.Fatalf("a complete passing report is exercised/passed: %+v", row)
	}
	if len(row.Evidence) == 0 || !strings.Contains(strings.Join(row.Evidence, " "), "native-container-modes.json") {
		t.Errorf("the harness report is kept as evidence: %v", row.Evidence)
	}
	if len(row.Limits) == 0 {
		t.Error("the harness' own limits travel with the row")
	}
}

func TestContainerRowFailures(t *testing.T) {
	rc := genuineHost("6.1.0-54-amd64")
	_ = os.MkdirAll(filepath.Join(rc.reportDir, "evidence"), 0o755)
	build := &Build{Family: "linux-kernel", Version: "6.1.0-54-amd64", OS: "linux", Arch: "amd64"}
	cases := map[string]struct {
		res   execResult
		wants string
	}{
		"a scenario failed": {func() execResult {
			res := harnessReport(func(r *containerReport) {
				r.Status = "fail"
				r.Scenarios[2].Status, r.Scenarios[2].Why = "fail", "want the typed denied result, got samples"
			})
			res.Exit = 1
			return res
		}(), "typed denied result"},
		"a required scenario is missing":                               {harnessReport(func(r *containerReport) { r.Scenarios = r.Scenarios[1:] }), "missing"},
		"a required scenario did not pass though the report says pass": {harnessReport(func(r *containerReport) { r.Scenarios[0].Status = "not_exercised" }), containerRequiredScenarios[0]},
		"exit 0 with a failing status": {func() execResult {
			res := harnessReport(func(r *containerReport) {
				r.Status = "fail"
				r.Scenarios[0].Status, r.Scenarios[0].Why = "fail", "boom"
			})
			res.Exit = 0
			return res
		}(), "exit code 0"},
		"exit 1 with a passing report": {func() execResult { res := harnessReport(nil); res.Exit = 1; return res }(), "exit code 1"},
		"unknown schema":               {harnessReport(func(r *containerReport) { r.Schema = "other/9" }), "schema"},
		"harness crashed":              {execResult{Exit: 2, Stderr: "container: open /x: permission denied"}, "permission denied"},
		"unparseable report":           {execResult{Exit: 0, Stdout: "ok"}, "no readable report"},
		"timeout":                      {execResult{Exit: -1, Err: errors.New("context deadline exceeded")}, "deadline"},
	}
	for name, c := range cases {
		row := rc.containerRow(build, c.res)
		if row.State != StateExercised || row.Outcome != OutcomeFailed || !strings.Contains(strings.Join(row.Failures, " | "), c.wants) {
			t.Errorf("%s: want exercised/failed mentioning %q, got %+v", name, c.wants, row)
		}
	}
}

func TestContainerRowNotExercisedKeepsTheHarnessReason(t *testing.T) {
	rc := genuineHost("6.1.0-54-amd64")
	build := &Build{Family: "linux-kernel", Version: "6.1.0-54-amd64", OS: "linux", Arch: "amd64"}
	res := harnessReport(func(r *containerReport) {
		r.Status, r.Reason, r.Scenarios = "not_exercised", "no OCI runtime: runc is not installed", nil
	})
	res.Exit = 10
	row := rc.containerRow(build, res)
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "no OCI runtime") || row.Outcome != "" {
		t.Errorf("the harness' reason is the row's reason: %+v", row)
	}
	res = harnessReport(func(r *containerReport) {
		r.Status = "not_exercised"
		r.Scenarios[3].Status, r.Scenarios[3].Why = "not_exercised", "--keep-paranoid: the host's perf_event_paranoid is 1 and this scenario needs 3"
	})
	res.Exit = 10
	row = rc.containerRow(build, res)
	if row.State != StateNotExercised || !strings.Contains(row.Reason, containerRequiredScenarios[3]) || !strings.Contains(row.Reason, "--keep-paranoid") {
		t.Errorf("one scenario that could not run makes the row not_exercised, naming it: %+v", row)
	}
	res = execResult{Exit: 10, Stderr: "something"}
	if row = rc.containerRow(build, res); row.State != StateNotExercised {
		t.Errorf("exit 10 without a report is not_exercised: %+v", row)
	}
}

func TestContainerGapRemovedFromNativeGaps(t *testing.T) {
	if _, ok := nativeGaps["container_modes"]; ok {
		t.Error("container_modes has a harness now: it is no longer an always-not-exercised gap")
	}
	if _, ok := runners["native_container"]; !ok {
		t.Error("the native_container runner must be registered")
	}
}

func TestLevel3ScenariosAreRequiredOnlyWhereTheKernelEnforcesLevel3(t *testing.T) {
	enforced := requiredContainerScenarios(nil)
	for name := range containerLevel3Scenarios {
		found := false
		for _, n := range enforced {
			found = found || n == name
		}
		if !found {
			t.Errorf("%s must be required when the probe says level 3 is enforced", name)
		}
	}
	na := func(r *containerReport) {
		for i := range r.Scenarios {
			if containerLevel3Scenarios[r.Scenarios[i].Name] {
				r.Scenarios[i].Status, r.Scenarios[i].Why = "not_exercised", containerLevel3Reason
			}
		}
		r.Status = "pass"
	}
	if got := requiredContainerScenarios(harnessReportScenarios(na)); len(got) != len(containerRequiredScenarios)-2 {
		t.Errorf("inapplicable level-3 scenarios must leave the requirement: %v", got)
	}
	rc := genuineHost("6.6.162")
	if row := rc.containerRow(&Build{}, harnessReport(na)); row.Outcome != OutcomePassed {
		t.Errorf("a vanilla kernel passes on the remaining scenarios, got %+v", row)
	}
	// the exemption is the probe's reason only: another not_exercised reason, or an absent scenario, never qualifies
	other := func(r *containerReport) {
		na(r)
		for i := range r.Scenarios {
			if containerLevel3Scenarios[r.Scenarios[i].Name] {
				r.Scenarios[i].Why = "--keep-paranoid"
			}
		}
	}
	if row := rc.containerRow(&Build{}, harnessReport(other)); row.Outcome == OutcomePassed {
		t.Error("a level-3 scenario not exercised for another reason must not pass")
	}
	missing := func(r *containerReport) {
		var keep []containerScenario
		for _, s := range r.Scenarios {
			if !containerLevel3Scenarios[s.Name] {
				keep = append(keep, s)
			}
		}
		r.Scenarios = keep
	}
	if row := rc.containerRow(&Build{}, harnessReport(missing)); row.Outcome == OutcomePassed {
		t.Error("absent level-3 scenarios must not pass")
	}
	// an inconclusive probe and a prefix-only reason never exempt: both scenarios stay required
	for _, why := range []string{"level3_probe_inconclusive: the control attempt at level 2 failed too", containerLevel3Reason + ": allowed at level 3", containerLevel3Reason + " "} {
		why := why
		unk := func(r *containerReport) {
			na(r)
			for i := range r.Scenarios {
				if containerLevel3Scenarios[r.Scenarios[i].Name] {
					r.Scenarios[i].Why = why
				}
			}
		}
		if got := requiredContainerScenarios(harnessReportScenarios(unk)); len(got) != len(containerRequiredScenarios) {
			t.Errorf("%q must keep both level-3 scenarios required: %v", why, got)
		}
		if row := rc.containerRow(&Build{}, harnessReport(unk)); row.Outcome == OutcomePassed {
			t.Errorf("%q must not qualify the row: %+v", why, row)
		}
	}
}

func harnessReportScenarios(mutate func(*containerReport)) []containerScenario {
	var r containerReport
	_ = json.Unmarshal([]byte(harnessReport(mutate).Stdout), &r)
	return r.Scenarios
}
