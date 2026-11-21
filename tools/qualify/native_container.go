// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// containerReportSchema is the schema of the report fixtures/nativeperf/container prints.
const containerReportSchema = "soundpost.container-modes/1"

// Exit codes of fixtures/nativeperf/container: every scenario passed, one failed, or the harness (or a scenario) could
// not run.
const (
	containerExitPass         = 0
	containerExitFail         = 1
	containerExitNotExercised = 10
)

// containerRequiredScenarios are the scenarios a `container_modes` pass needs, each one a real helper under runc:
// approved modes (the shipped Compose recipe, the hostPID recipe), denied-permission rows (seccomp, foreign uid, host
// perf_event_paranoid with and without CAP_PERFMON, no CAP_PERFMON on the host's own setting), identity after a
// container restart, cgroup limit rows and a PID-namespace change. The harness reports the same names; a report that lacks
// one is a failed row, never a pass.
var containerRequiredScenarios = []string{
	"approved_joined_pid_ns",
	"approved_host_pid_ns",
	"denied_seccomp_withholds_perf_event_open",
	"denied_foreign_uid_target",
	"denied_perf_event_paranoid_3_with_perfmon",
	"denied_perf_event_paranoid_3_without_perfmon",
	"no_perfmon_same_uid_host_paranoid",
	"stale_policy_restarted_target",
	"cgroup_memory_limit_hit_during_capture",
	"cgroup_pids_limit_hit_at_start",
	"pid_namespace_change_isolated_helper",
}

// containerLevel3Scenarios are the two scenarios that hold only on a kernel that enforces kernel.perf_event_paranoid=3
// (a Debian/Android patch, not upstream). The harness probes first and reports them not_exercised with this reason
// prefix where the kernel does not enforce it (D79 amendment): they are then not applicable, never a pass.
var containerLevel3Scenarios = map[string]bool{
	"denied_perf_event_paranoid_3_with_perfmon":    true,
	"denied_perf_event_paranoid_3_without_perfmon": true,
}

const containerLevel3Reason = "kernel_lacks_paranoid_level3"

func (s containerScenario) level3NotApplicable() bool {
	return containerLevel3Scenarios[s.Name] && s.Status == "not_exercised" && s.Why == containerLevel3Reason
}

// requiredContainerScenarios is containerRequiredScenarios minus the level-3 scenarios the harness reported as not
// applicable to this kernel. With an enforcing kernel (no such report) all of them are required.
func requiredContainerScenarios(reported []containerScenario) []string {
	skip := map[string]bool{}
	for _, s := range reported {
		if s.level3NotApplicable() {
			skip[s.Name] = true
		}
	}
	var out []string
	for _, n := range containerRequiredScenarios {
		if !skip[n] {
			out = append(out, n)
		}
	}
	return out
}

type containerScenario struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Why      string `json:"why,omitempty"`
	Capture  *struct {
		CPUSamples uint64 `json:"cpu_samples"`
	} `json:"capture,omitempty"`
	HelperExit int `json:"helper_exit_code"`
}

type containerReport struct {
	Schema    string              `json:"schema"`
	Status    string              `json:"status"`
	Reason    string              `json:"reason,omitempty"`
	Kernel    string              `json:"kernel"`
	Runc      string              `json:"runc"`
	Scenarios []containerScenario `json:"scenarios"`
	Limits    []string            `json:"limits"`
}

// containerPrerequisite decides whether this host may run the container-modes harness for the row, and returns the
// build the row would describe. A required row needs a genuine Linux runner of the row's kernel series and architecture
// (nativeGate); the harness itself needs root (namespaces, cgroups, mounts, and a root-owned operator policy) and a
// daemonless OCI runtime (runc). It never installs anything.
func (rc *runCtx) containerPrerequisite(spec RowSpec, euid int, lookRunc func() (string, error)) (*Build, string) {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return nil, why
	}
	if rc.subject(spec).Family == "wsl2-linux-kernel" {
		return nil, "container-mode evidence is produced on the pinned genuine Linux runners only; no OCI runtime or cgroup v2 container fixture is run on WSL2"
	}
	if euid != 0 {
		return nil, fmt.Sprintf("the container-modes harness must run as root (euid is %d): runc creates namespaces, cgroups and mounts, and the helper accepts only a root-owned operator policy; this qualification does not escalate privileges", euid)
	}
	if _, err := lookRunc(); err != nil {
		return nil, "no OCI runtime: runc is not installed (a daemonless runc is required; this qualification installs nothing)"
	}
	return build, ""
}

// containerBuild builds one committed command statically (CGO off) into the work directory.
func (rc *runCtx) containerBuild(name, pkg string, ldflags string) (string, string) {
	key := "container-build:" + name
	if v, ok := rc.cache[key]; ok {
		r := v.([2]string)
		return r[0], r[1]
	}
	out, why := filepath.Join(rc.work, name), ""
	if gobin, w := rc.goBin(); w != "" {
		why = w
	} else {
		args := []string{"build", "-trimpath"}
		if ldflags != "" {
			args = append(args, "-ldflags", ldflags)
		}
		args = append(args, "-o", out, pkg)
		if res := rc.exec(15*time.Minute, rc.root, []string{"CGO_ENABLED=0"}, gobin, args...); res.Exit != 0 {
			why, out = "building "+pkg+" failed: "+tail(rc.rel(res.Stderr), 300), ""
		}
	}
	rc.cache[key] = [2]string{out, why}
	return out, why
}

// runNativeContainer runs the committed container-modes harness: the real helper under runc with approved modes, denied
// permission rows, cgroup limit rows and a namespace change, each judged by the helper's own typed answer.
func runNativeContainer(rc *runCtx, spec RowSpec) Row {
	build, why := rc.containerPrerequisite(spec, os.Geteuid(), func() (string, error) { return exec.LookPath("runc") })
	if why != "" {
		return notExercised(why)
	}
	helper, why := rc.containerBuild("container-helper", "./cmd/soundpost-perf-acquire", "")
	if why != "" {
		return notExercised(why)
	}
	client, why := rc.containerBuild("container-client", "./tools/smoke/nativehelper/client", "")
	if why != "" {
		return notExercised(why)
	}
	burner, why := rc.containerBuild("container-burner", "./tools/smoke/nativehelper/burner", "-B gobuildid")
	if why != "" {
		return notExercised(why)
	}
	harness, why := rc.containerBuild("container-harness", "./fixtures/nativeperf/container", "")
	if why != "" {
		return notExercised(why)
	}
	seccomp := filepath.Join(rc.work, "soundpost-perf.seccomp.json")
	raw, err := os.ReadFile(filepath.Join(rc.root, "deploy", "seccomp", "soundpost-perf.json"))
	if err != nil {
		return notExercised("the shipped seccomp profile cannot be read: " + err.Error())
	}
	if err = os.WriteFile(seccomp, raw, 0o644); err != nil {
		return notExercised("the seccomp profile cannot be staged: " + err.Error())
	}
	args := []string{"--helper", helper, "--client", client, "--burner", burner, "--seccomp", seccomp, "--kernel-series", rc.subject(spec).Version, "--seconds", "5"}
	res := rc.exec(25*time.Minute, rc.root, nil, harness, args...)
	row := rc.containerRow(build, res)
	if row.Command != nil {
		row.Command.Command = "container-harness --helper <built soundpost-perf-acquire> --client <built> --burner <built> --seccomp <shipped profile> --kernel-series " + rc.subject(spec).Version + " --seconds 5"
	}
	return row
}

// containerRow turns one harness run into a row. Only a report whose status, exit code and every required scenario
// agree on a pass is a pass; a scenario that could not run makes the row not_exercised; anything else is a measured
// failure.
func (rc *runCtx) containerRow(build *Build, res execResult) Row {
	cmd := &CommandRun{Command: "container-harness", ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}
	failed := func(msgs ...string) Row {
		return Row{State: StateExercised, Outcome: OutcomeFailed, Build: build, Command: cmd, Failures: msgs, FailureClass: "harness",
			Evidence: []string{"fixtures/nativeperf/container run under runc"}}
	}
	if res.Err != nil {
		return failed("the container-modes harness did not complete: " + res.Err.Error())
	}
	obj, raw := lastJSONObjectMultiline(res.Stdout)
	var rep containerReport
	if obj == nil || json.Unmarshal(raw, &rep) != nil {
		if res.Exit == containerExitNotExercised {
			return notExercised("the container-modes harness could not run: " + tail(rc.rel(res.Stderr), 300))
		}
		return failed(fmt.Sprintf("the container-modes harness exited %d with no readable report: %s", res.Exit, tail(rc.rel(res.Stderr), 300)))
	}
	evidence := rc.writeEvidence("native-container-modes.json", raw)
	if rep.Schema != containerReportSchema {
		return failed(fmt.Sprintf("the harness report has schema %q, want %q", rep.Schema, containerReportSchema))
	}
	want := map[int]string{containerExitPass: "pass", containerExitFail: "fail", containerExitNotExercised: "not_exercised"}[res.Exit]
	if want == "" || want != rep.Status {
		return failed(fmt.Sprintf("the harness exit code %d does not match its report status %q", res.Exit, rep.Status))
	}
	if rep.Status == "not_exercised" {
		reasons := []string{}
		if rep.Reason != "" {
			reasons = append(reasons, rep.Reason)
		}
		for _, s := range rep.Scenarios {
			if s.Status == "not_exercised" {
				reasons = append(reasons, s.Name+": "+s.Why)
			}
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "the harness reported not_exercised without a reason")
		}
		return notExercised(strings.Join(reasons, "; "))
	}
	byName := map[string]containerScenario{}
	var failures []string
	for _, s := range rep.Scenarios {
		byName[s.Name] = s
		if s.Status != "pass" && !s.level3NotApplicable() {
			failures = append(failures, fmt.Sprintf("scenario %s: %s (expected %s, observed %s)", s.Name, strings.TrimSpace(s.Why), s.Expected, s.Observed))
		}
	}
	if rep.Status == "pass" {
		// a pass is every required scenario, present and passed, whatever else the report says
		for _, name := range requiredContainerScenarios(rep.Scenarios) {
			if s, ok := byName[name]; !ok {
				failures = append(failures, "required scenario "+name+" is missing from the report")
			} else if s.Status != "pass" && !strings.Contains(strings.Join(failures, " "), "scenario "+name+":") {
				failures = append(failures, "required scenario "+name+" did not pass: "+s.Status)
			}
		}
	}
	row := Row{State: StateExercised, Build: build, Command: cmd, Limits: rep.Limits}
	row.Evidence = []string{fmt.Sprintf("real helper under runc (%s) on kernel %s: %d scenarios", rep.Runc, rep.Kernel, len(rep.Scenarios)), evidence}
	for _, s := range rep.Scenarios {
		if s.Capture != nil && s.Capture.CPUSamples > 0 {
			row.Series = append(row.Series, Series{Name: "container." + s.Name + ".cpu_samples", Unit: "count", Values: []float64{float64(s.Capture.CPUSamples)}})
		}
	}
	if len(failures) > 0 {
		row.Outcome = OutcomeFailed
		row.Failures = failures
		row.FailureClass = "assertion"
		return row
	}
	row.Outcome = OutcomePassed
	return row
}
