// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// hostMutationEnv opts a qualify run into the native scenarios that write kernel state: steering the PID allocator
// cursor (identity: PID reuse) and taking a CPU offline (CPU hotplug). Both also need root. Neither runs by default.
const hostMutationEnv = "SOUNDPOST_QUALIFY_HOST_MUTATION"

// hostMutation says whether this process may run a scenario that changes kernel state: the explicit opt-in and root.
// When it may not, the reason names what is missing. Tests replace it.
var hostMutation = func() (bool, string) {
	switch {
	case os.Getenv(hostMutationEnv) != "1":
		return false, hostMutationEnv + "=1 is not set"
	case os.Geteuid() != 0:
		return false, "the run is not root (euid " + strconv.Itoa(os.Geteuid()) + ")"
	}
	return true, ""
}

// cpuSysfs is where the kernel lists its CPUs. Tests point it at a temporary tree.
var cpuSysfs = "/sys/devices/system/cpu"

// hotplugExitNotExercised is the harness' exit code for "the hotplug could not be done here": not a pass, not a failure.
const hotplugExitNotExercised = 3

// hotplugRequired are the scenarios the harness must report (see fixtures/nativeperf/hotplug), and whether each one
// does a real offline/online write. A report without one of them, or one that claims a pass for a hotplug scenario
// without the two writes, is not a pass.
var hotplugRequired = []struct {
	kind    string
	hotplug bool
}{{"control", false}, {"hold", true}, {"flap", true}, {"flap_sparse", true}, {"cpu_only", true}}

type hotplugCapture struct {
	Events        float64 `json:"events"`
	LossEvents    float64 `json:"loss_events"`
	EndedNs       uint64  `json:"ended_ns"`
	ProvenThrough uint64  `json:"proven_through_ns"`
	OnCPUAfterPin float64 `json:"events_on_cpu_after_repin"`
	SchedAfterPin float64 `json:"scheduler_events_on_cpu_after_repin"`
}

// hotplugWrite is one write of a CPU's online switch, in CLOCK_MONOTONIC nanoseconds; zero when it never happened.
type hotplugWrite struct {
	StartNs uint64 `json:"start_ns"`
	EndNs   uint64 `json:"end_ns"`
}

type hotplugScenario struct {
	Name         string         `json:"scenario"`
	Kind         string         `json:"kind"`
	Offline      hotplugWrite   `json:"offline_write"`
	Online       hotplugWrite   `json:"online_write"`
	Capture      hotplugCapture `json:"capture"`
	NotExercised string         `json:"not_exercised"`
	SetupError   string         `json:"setup_error"`
	Failures     []string       `json:"failures"`
	Pass         bool           `json:"pass"`
}

type hotplugReport struct {
	Harness      string            `json:"harness"`
	Kernel       string            `json:"kernel"`
	CPU          int               `json:"cpu"`
	OnlineBefore string            `json:"online_before"`
	OnlineAfter  string            `json:"online_after"`
	CPURestored  bool              `json:"cpu_restored"`
	Scenarios    []hotplugScenario `json:"scenarios"`
	Failed       int               `json:"scenarios_failed"`
	// NotExercised is the whole harness' reason when it did not start (no opt-in, no CPU to offline).
	NotExercised string `json:"not_exercised"`
	Pass         bool   `json:"pass"`
}

// parseCPUSet reads the kernel's CPU list syntax ("0-7", "0-2,4").
func parseCPUSet(text string) (map[int]bool, error) {
	set := map[int]bool{}
	text = strings.TrimSpace(text)
	if text == "" {
		return set, nil
	}
	for _, part := range strings.Split(text, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return nil, fmt.Errorf("cpu list %q", text)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 8191 {
				return nil, fmt.Errorf("cpu list %q", text)
			}
		}
		for c := a; c <= b; c++ {
			set[c] = true
		}
	}
	return set, nil
}

func readOnlineCPUs() (string, error) {
	raw, err := os.ReadFile(filepath.Join(cpuSysfs, "online"))
	return strings.TrimSpace(string(raw)), err
}

// restoreCPUs puts back every CPU that was online in before and is not in after: whatever the harness did, a run that
// exits (or is killed by its deadline) must not leave the host with fewer CPUs. It returns the CPUs it had to bring back.
func restoreCPUs(before, after string) ([]int, error) {
	was, err := parseCPUSet(before)
	if err != nil {
		return nil, err
	}
	now, err := parseCPUSet(after)
	if err != nil {
		return nil, err
	}
	var missing []int
	for c := range was {
		if !now[c] {
			missing = append(missing, c)
		}
	}
	sort.Ints(missing)
	var restored []int
	var firstErr error
	for _, c := range missing {
		if err := os.WriteFile(filepath.Join(cpuSysfs, "cpu"+strconv.Itoa(c), "online"), []byte("1\n"), 0); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("cpu%d: %w", c, err)
			}
			continue
		}
		restored = append(restored, c)
	}
	return restored, firstErr
}

// runNativeHotplug takes a real CPU offline and back under real captures (fixtures/nativeperf/hotplug) and checks the
// plan's behaviour: the capture is refused explicitly, never silently complete, and the helper, the target and the
// topology survive. It changes host state, so it only runs with root and the explicit opt-in; otherwise it is
// not_exercised with the reason, and nothing is changed. A hotplug that did not happen is never a pass.
func runNativeHotplug(rc *runCtx, spec RowSpec) Row {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return notExercised(why)
	}
	if ok, why := hostMutation(); !ok {
		return notExercised("CPU hotplug was not run: the harness takes a CPU offline by writing /sys/devices/system/cpu/cpuN/online, a change of host state that needs root and an explicit " + hostMutationEnv + "=1 (" + why + "); nothing was changed")
	}
	workloads, why := rc.ccBuild("workloads", "fixtures/nativeperf/acceptance/workloads.c")
	if why != "" {
		return notExercised(why)
	}
	harness, why := rc.goBuild("hotplug-harness", "./fixtures/nativeperf/hotplug")
	if why != "" {
		return notExercised(why)
	}
	before, err := readOnlineCPUs()
	if err != nil {
		return notExercised("the kernel's online CPU set is unreadable: " + err.Error())
	}
	res := rc.exec(10*time.Minute, rc.root, []string{hostMutationEnv + "=1"}, harness, "--workload", workloads)
	after, _ := readOnlineCPUs()
	restored, restoreErr := restoreCPUs(before, after)
	return rc.hotplugRow(build, res, before, after, restored, restoreErr)
}

// hotplugRow turns one run of the harness into a row. The harness' exit code and its JSON report must agree: a pass
// needs every required scenario present, each one passed, each hotplug scenario with a real offline and online write,
// and the online set unchanged when the run ended.
func (rc *runCtx) hotplugRow(build *Build, res execResult, before, after string, restored []int, restoreErr error) Row {
	_, raw := lastJSONObjectMultiline(res.Stdout)
	var rep hotplugReport
	parsed := raw != nil && json.Unmarshal(raw, &rep) == nil && rep.Harness == "cpu_hotplug"
	if parsed && res.Exit == hotplugExitNotExercised && res.Err == nil && after == before {
		reason := rep.NotExercised
		for _, s := range rep.Scenarios {
			if reason == "" && s.NotExercised != "" {
				reason = s.Name + ": " + s.NotExercised
			}
		}
		if reason != "" {
			return notExercised("the CPU hotplug harness could not take a CPU offline here: " + reason)
		}
	}
	row := Row{State: StateExercised, Build: build, Command: &CommandRun{Command: "fixtures/nativeperf/hotplug", ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}}
	row.Evidence = []string{fmt.Sprintf("real CPU hotplug harness fixtures/nativeperf/hotplug: exit %d, online set %q before and %q after", res.Exit, before, after)}
	if raw != nil {
		row.Evidence = append(row.Evidence, rc.writeEvidence("native-cpu_hotplug.json", raw))
	}
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	switch {
	case res.Err != nil:
		fail("the harness did not finish: %v", res.Err)
	case res.Exit != 0:
		fail("the harness exited %d: %s", res.Exit, tail(rc.rel(res.Stderr), 240))
	}
	if !parsed {
		fail("the harness printed no cpu_hotplug report")
	}
	if after != before || len(restored) > 0 || restoreErr != nil {
		fail("the harness left the online set at %q (it was %q); the runner put back cpus %v (%v)", after, before, restored, restoreErr)
	}
	if parsed {
		if !rep.CPURestored {
			fail("the harness reports the online set was not restored (%q after %q)", rep.OnlineAfter, rep.OnlineBefore)
		}
		seen := map[string]int{}
		for _, s := range rep.Scenarios {
			seen[s.Kind]++
			switch {
			case s.NotExercised != "":
				fail("scenario %s did not happen: %s", s.Name, s.NotExercised)
			case !s.Pass:
				why := append([]string(nil), s.Failures...)
				if s.SetupError != "" {
					why = append(why, "setup: "+s.SetupError)
				}
				if len(why) == 0 {
					why = append(why, "no reason reported")
				}
				fail("scenario %s failed: %s", s.Name, strings.Join(why, "; "))
			}
			for _, need := range hotplugRequired {
				if need.kind == s.Kind && need.hotplug && (s.Offline.EndNs == 0 || s.Online.EndNs == 0) {
					fail("scenario %s reports no offline/online write", s.Name)
				}
			}
		}
		for _, need := range hotplugRequired {
			if seen[need.kind] == 0 {
				fail("the report has no %s scenario", need.kind)
			}
		}
		rc.hotplugSeries(&row, rep)
		row.Limits = []string{
			fmt.Sprintf("a real CPU hotplug: cpu%d's online switch was written 0 then 1 under live captures as root with %s=1; cpu0 was never touched; the online set was %q before and %q after", rep.CPU, hostMutationEnv, before, after),
			"the scheduler capture (per-CPU rings) must end with the closed code topology_changed and no final proof, with the correction starting at the last proof; the per-thread CPU capture owns no per-CPU stream and keeps delivering",
			"one CPU of this host's kernel series and architecture; no other series or architecture is extrapolated",
		}
		row.Loss = "a scheduler capture over a changed topology is refused (topology_changed) and revoked from its last proof; it never completes with a final proof over CPUs it lost"
	}
	if len(failures) == 0 {
		row.Outcome = OutcomePassed
		return row
	}
	row.Outcome, row.Failures = OutcomeFailed, failures
	return row
}

// hotplugSeries records the measured numbers of the first run of each scenario kind: how late after the offline write
// the topology change was reported, how old the proof it names was, and the event counts.
func (rc *runCtx) hotplugSeries(row *Row, rep hotplugReport) {
	done := map[string]bool{}
	add := func(name, unit string, v float64) {
		row.Series = append(row.Series, Series{Name: name, Unit: unit, Values: []float64{v}})
	}
	for _, s := range rep.Scenarios {
		if done[s.Kind] || !s.Pass {
			continue
		}
		done[s.Kind] = true
		add("hotplug."+s.Kind+".events", "events", s.Capture.Events)
		add("hotplug."+s.Kind+".loss_events", "events", s.Capture.LossEvents)
		if s.Offline.StartNs != 0 && s.Capture.EndedNs >= s.Offline.StartNs && s.Capture.ProvenThrough != 0 {
			add("hotplug."+s.Kind+".reported_after_offline_write_ms", "ms", float64(s.Capture.EndedNs-s.Offline.StartNs)/1e6)
			if s.Offline.StartNs >= s.Capture.ProvenThrough {
				add("hotplug."+s.Kind+".last_proof_before_offline_write_ms", "ms", float64(s.Offline.StartNs-s.Capture.ProvenThrough)/1e6)
			}
		}
		if s.Kind == "flap" || s.Kind == "flap_sparse" {
			add("hotplug."+s.Kind+".scheduler_events_on_cpu_after_it_came_back", "events", s.Capture.SchedAfterPin)
		}
	}
	runs := map[string]float64{}
	for _, s := range rep.Scenarios {
		runs[s.Kind]++
	}
	add("hotplug.flap_sparse.runs", "captures", runs["flap_sparse"])
}
