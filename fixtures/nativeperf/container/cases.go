//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type harness struct {
	env          *runtimeEnv
	runID        string
	seconds      int
	profile      []byte
	paranoid     int // value before the run
	keepParanoid bool
	mu           sync.Mutex
	raised       bool
}

// caseCfg is one scenario: how the three containers (workload, helper, operator-side client) are set up and what the
// helper's answer has to be.
type caseCfg struct {
	Name string
	Want expectation
	// Note says what the scenario establishes (printed in the report).
	Note string
	// TargetUID is the workload's uid; the helper is always uid 0.
	TargetUID uint32
	// PID is the helper's PID namespace relative to the workload's: joined (the shipped Compose recipe), host (the
	// Kubernetes hostPID recipe) or own (a namespace of its own: the workload is in another PID namespace).
	PID pidMode
	// NoPerfmon removes CAP_PERFMON from the helper (the Compose service without cap_add).
	NoPerfmon bool
	// Seccomp is "shipped" (default) or "withhold_perf_event_open".
	Seccomp string
	// Paranoid is the kernel.perf_event_paranoid value to set for the scenario (0: leave the host's value).
	Paranoid int
	// OperatorCaps are the operator-side client's capabilities (it needs CAP_SYS_PTRACE to read a foreign uid's /proc).
	OperatorCaps []string
	HelperLimits *limits
	TargetLimits *limits
	// SqueezeMemoryBytes lowers the helper's memory.max to this value half way through the capture.
	SqueezeMemoryBytes int64
	// Restart replaces the workload container by a fresh one (new PID namespace, cgroup, process start) after the
	// policy was written for the first, and captures the new one.
	Restart bool
	// HelperMustExitZero requires the helper to end 0 on SIGTERM (every scenario in which it is not killed by a limit).
	HelperMustExitZero bool
	// RequireLimitsApplied reads back pids.max/memory.max/cpu.max of the helper and the workload and requires that no
	// limit event (pids.events max, memory.events max/oom/oom_kill) was recorded: an approved capture stays inside its limits.
	RequireLimitsApplied bool
	// RequireDifferentPIDNS requires the helper's and the workload's PID namespaces to differ.
	RequireDifferentPIDNS bool
	// LimitHit requires the kernel to have recorded that the helper's limit was hit (memory.events oom_kill, or the
	// helper exited non-zero before serving: pids.events max) as an observation next to the helper's answer.
	LimitHit string // "", "memory", "pids"
}

var perfmonOnly = []string{"CAP_PERFMON"}

func shippedLimits() *limits {
	return &limits{Pids: 16, MemoryBytes: 64 << 20, CPUQuotaUS: 100000, CPUPeriodUS: 100000}
}

func workloadLimits() *limits {
	// half a CPU: the workload is throttled by its own cgroup while it is sampled
	return &limits{Pids: 64, MemoryBytes: 64 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000}
}

func scenarios() []caseCfg {
	return []caseCfg{
		{Name: "approved_joined_pid_ns", Want: wantSamples, PID: pidJoined, HelperMustExitZero: true, RequireLimitsApplied: true,
			Note: "the shipped Compose recipe: helper in the PID namespace of the workload container, uid 0 with only CAP_PERFMON, shipped seccomp profile, cgroup limits"},
		{Name: "approved_host_pid_ns", Want: wantSamples, PID: pidHost, HelperMustExitZero: true, RequireLimitsApplied: true, RequireDifferentPIDNS: true,
			Note: "the Kubernetes hostPID recipe: helper in the host PID namespace, workload in its own PID namespace"},
		{Name: "denied_seccomp_withholds_perf_event_open", Want: wantDenied, PID: pidJoined, Seccomp: "withhold_perf_event_open", HelperMustExitZero: true,
			Note: "the shipped profile minus its perf_event_open rule: the default EPERM applies"},
		{Name: "denied_foreign_uid_target", Want: wantDenied, PID: pidJoined, TargetUID: 65532, OperatorCaps: []string{"CAP_SYS_PTRACE"}, HelperMustExitZero: true,
			Note: "a workload of another uid than the helper's: a PERFMON-only helper cannot read its /proc entry"},
		{Name: "denied_perf_event_paranoid_3_with_perfmon", Want: wantDenied, PID: pidJoined, Paranoid: 3, HelperMustExitZero: true,
			Note: "kernel.perf_event_paranoid=3 (Debian: perf_event_open needs CAP_SYS_ADMIN) with CAP_PERFMON"},
		{Name: "denied_perf_event_paranoid_3_without_perfmon", Want: wantDenied, PID: pidJoined, Paranoid: 3, NoPerfmon: true, HelperMustExitZero: true,
			Note: "kernel.perf_event_paranoid=3 without CAP_PERFMON"},
		{Name: "no_perfmon_same_uid_host_paranoid", Want: "", PID: pidJoined, NoPerfmon: true, HelperMustExitZero: true,
			Note: "the Compose service without cap_add on the host's own perf_event_paranoid: user-space-only events of a same-uid target need no capability at 2 or lower, and are denied at 3"},
		{Name: "stale_policy_restarted_target", Want: wantRefusedAuthorization, PID: pidHost, Restart: true, HelperMustExitZero: true,
			Note: "the policy names one container instance; the workload container is restarted (new PID namespace, cgroup and process start) and the helper must refuse the new instance"},
		{Name: "cgroup_memory_limit_hit_during_capture", Want: wantNoSuccess, PID: pidJoined, SqueezeMemoryBytes: 1 << 20, LimitHit: "memory",
			Note: "the helper's cgroup memory.max is lowered to 1 MiB half way through a capture: the kernel OOM-kills it and the stream must not end as a complete capture"},
		{Name: "cgroup_pids_limit_hit_at_start", Want: wantNoSuccess, PID: pidJoined, HelperLimits: &limits{Pids: 3, MemoryBytes: 64 << 20, CPUQuotaUS: 100000, CPUPeriodUS: 100000}, LimitHit: "pids",
			Note: "the helper's pids.max is 3: its runtime cannot start the threads it needs, and no capture may be reported as a success"},
		{Name: "pid_namespace_change_isolated_helper", Want: wantNoSuccess, PID: pidOwn,
			Note: "the helper in a PID namespace of its own and the workload in another one: the client is outside the helper's namespace and the capture must not succeed"},
	}
}

func (h *harness) setParanoid(v int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.keepParanoid && h.paranoid != v {
		return errors.New("--keep-paranoid: the host's perf_event_paranoid is " + strconv.Itoa(h.paranoid) + " and this scenario needs " + strconv.Itoa(v))
	}
	if err := os.WriteFile(paranoidFile, []byte(strconv.Itoa(v)), 0o644); err != nil {
		return err
	}
	if got, err := readParanoid(); err != nil || got != v {
		return fmt.Errorf("kernel.perf_event_paranoid=%d is not accepted by this kernel (reads back %d)", v, got)
	}
	h.raised = v != h.paranoid
	return nil
}

func (h *harness) restoreParanoid() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.raised {
		_ = os.WriteFile(paranoidFile, []byte(strconv.Itoa(h.paranoid)), 0o644)
		h.raised = false
	}
}

func jsonLine(out string) string {
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "{") {
			line = l
		}
	}
	return line
}

func nsInode(pid int) string {
	link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
	if err != nil {
		return ""
	}
	return link
}

// readStatus returns the /proc/<pid>/status fields the audit needs, and the root mount options of the process.
func readAudit(pid int) (audit, error) {
	var a audit
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return a, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "CapEff":
			a.CapEff = v
		case "CapPrm":
			a.CapPrm = v
		case "CapBnd":
			a.CapBnd = v
		case "CapAmb":
			a.CapAmb = v
		case "NoNewPrivs":
			a.NoNewPrivs = v
		case "Seccomp":
			a.Seccomp = v
		case "Uid":
			a.UID = strings.Fields(v)[0]
		}
	}
	mi, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/mountinfo")
	if err != nil {
		return a, err
	}
	for _, line := range strings.Split(string(mi), "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && f[4] == "/" {
			a.RootMountOptions = f[5]
			break
		}
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	theirs, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net")
	a.NetNSIsHost = self != "" && self == theirs
	a.PIDNS = nsInode(pid)
	return a, nil
}

// readCgroup returns the interesting files of one cgroup directory; unreadable files are absent.
func (e *runtimeEnv) readCgroup(rel string) map[string]string {
	out := map[string]string{}
	for _, f := range []string{"pids.max", "pids.current", "pids.events", "memory.max", "memory.swap.max", "memory.current", "memory.events", "cpu.max", "cpu.stat"} {
		if raw, err := os.ReadFile(filepath.Join(e.cgroupRoot, rel, f)); err == nil {
			out[f] = strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(raw)), "\n", ";")), " ")
		}
	}
	return out
}

// counter reads "key value" from one of the multi-line cgroup files held in a readCgroup map.
func counter(files map[string]string, file, key string) int64 {
	for _, part := range strings.Split(files[file], ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), " "); ok && k == key {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func limitProblems(role string, files map[string]string, l *limits) []string {
	var out []string
	if l == nil {
		return out
	}
	if l.Pids > 0 && files["pids.max"] != strconv.FormatInt(l.Pids, 10) {
		out = append(out, fmt.Sprintf("%s pids.max is %q, want %d", role, files["pids.max"], l.Pids))
	}
	if l.MemoryBytes > 0 && files["memory.max"] != strconv.FormatInt(l.MemoryBytes, 10) {
		out = append(out, fmt.Sprintf("%s memory.max is %q, want %d", role, files["memory.max"], l.MemoryBytes))
	}
	if l.CPUQuotaUS > 0 && files["cpu.max"] != fmt.Sprintf("%d %d", l.CPUQuotaUS, l.CPUPeriodUS) {
		out = append(out, fmt.Sprintf("%s cpu.max is %q, want %d %d", role, files["cpu.max"], l.CPUQuotaUS, l.CPUPeriodUS))
	}
	if n := counter(files, "pids.events", "max"); n != 0 {
		out = append(out, fmt.Sprintf("%s hit its pids limit %d time(s)", role, n))
	}
	// memory.events `max` counts reclaim at the limit, which is pressure and not a failure; oom and oom_kill are failures
	for _, k := range []string{"oom", "oom_kill"} {
		if n := counter(files, "memory.events", k); n != 0 {
			out = append(out, fmt.Sprintf("%s memory.events %s=%d", role, k, n))
		}
	}
	return out
}

func (h *harness) workload(name string, uid uint32, lim *limits) (*ctr, error) {
	c, err := h.env.startRunning(ctrSpec{Name: name, Args: []string{"/burner"}, UID: uid, GID: uid, PID: pidOwn, Limits: lim}, h.runID)
	if err != nil {
		return c, err
	}
	return c, c.waitLine("ready", 30*time.Second)
}

// operator runs the operator-side client in one short-lived container with the given PID namespace and returns its JSON line.
func (h *harness) operator(name string, mode pidMode, joinPath string, caps []string, binds []bind, timeout time.Duration, args ...string) (map[string]any, string, error) {
	spec := ctrSpec{Name: name, Args: append([]string{"/client"}, args...), PID: mode, PIDPath: joinPath, Caps: caps, Binds: binds}
	stdout, stderr, exit, err := h.env.run(spec, h.runID, timeout)
	if err != nil {
		return nil, stdout, err
	}
	line := jsonLine(stdout)
	var m map[string]any
	if exit != 0 || line == "" || json.Unmarshal([]byte(line), &m) != nil {
		return nil, stdout, fmt.Errorf("operator %s exited %d: %s", name, exit, clip(strings.TrimSpace(stderr+stdout), 400))
	}
	return m, line, nil
}

// runCase runs one scenario end to end and returns its result; it never panics and always removes what it started.
func (h *harness) runCase(c caseCfg) (res scenarioResult) {
	res = scenarioResult{Name: c.Name, Status: statusFail, Expected: string(c.Want), HelperExit: -1, Detail: map[string]any{"note": c.Note}}
	notExercised := func(why string) scenarioResult {
		res.Status, res.Why, res.Observed = statusNotExercised, why, "not_exercised"
		return res
	}
	fail := func(why string) scenarioResult {
		res.Status = statusFail
		if res.Observed == "" {
			res.Observed = "error"
		}
		res.Why = strings.TrimSpace(res.Why + "; " + why)
		res.Why = strings.TrimPrefix(res.Why, "; ")
		return res
	}
	if c.Paranoid != 0 {
		if h.keepParanoid && h.paranoid != c.Paranoid {
			return notExercised("--keep-paranoid: the host's perf_event_paranoid is " + strconv.Itoa(h.paranoid) + " and this scenario needs " + strconv.Itoa(c.Paranoid))
		}
		defer h.restoreParanoid()
		if c.Paranoid >= 3 {
			// level 3 is a Debian/Android patch: where the kernel does not enforce it, a "denied at level 3" scenario can never be a pass
			switch outcome, why := h.probeLevel3(); outcome {
			case level3NotEnforced:
				res.Detail["level3_probe"] = why
				return notExercised(reasonNoParanoidLevel3)
			case level3Unknown:
				res.Detail["level3_probe"] = why
				return notExercised(reasonLevel3Unknown + ": " + why)
			}
		}
	}
	dir := filepath.Join(h.env.work, c.Name)
	runDir, polDir := filepath.Join(dir, "run"), filepath.Join(dir, "pol")
	for _, d := range []string{dir, runDir, polDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fail(err.Error())
		}
	}
	if err := os.Chmod(runDir, 0o700); err != nil { // the helper refuses a socket directory that is not root's private one
		return fail(err.Error())
	}
	target, err := h.workload("w-"+c.Name, c.TargetUID, workloadLimits())
	if target != nil {
		defer target.kill()
	}
	if err != nil {
		return fail("workload container: " + err.Error())
	}
	targetNS := nsInode(target.hostPID)

	// The operator's PID view: inside the workload's namespace (joined), the host's, or the host's while the helper is
	// isolated. pidArg is the workload's PID in that view.
	opMode, opPath, pidArg := pidHost, "", strconv.Itoa(target.hostPID)
	if c.PID == pidJoined {
		opMode, opPath, pidArg = pidJoined, "/proc/"+strconv.Itoa(target.hostPID)+"/ns/pid", "1"
	}
	policyBinds := []bind{{Source: polDir, Dest: "/policy"}}
	if _, line, err := h.operator("pol-"+c.Name, opMode, opPath, c.OperatorCaps, policyBinds, 2*time.Minute, "policy", "--pid", pidArg, "--binary", "/burner", "--out", "/policy"); err != nil {
		return fail("writing the operator policy: " + err.Error())
	} else {
		res.Detail["policy_result"] = json.RawMessage(line)
	}

	helperLimits := c.HelperLimits
	if helperLimits == nil {
		helperLimits = shippedLimits()
	}
	spec := ctrSpec{Name: "h-" + c.Name, Args: []string{"/helper"}, PID: c.PID, Limits: helperLimits,
		Binds: []bind{{Source: runDir, Dest: "/run/soundpost-perf"}, {Source: filepath.Join(polDir, "perf-policy.json"), Dest: "/etc/soundpost/perf-policy.json", ReadOnly: true}, {Source: "/etc/machine-id", Dest: "/etc/machine-id", ReadOnly: true}}}
	if c.PID == pidJoined {
		spec.PIDPath = "/proc/" + strconv.Itoa(target.hostPID) + "/ns/pid"
	}
	if !c.NoPerfmon {
		spec.Caps = perfmonOnly
	}
	switch c.Seccomp {
	case "", "shipped":
		spec.Seccomp, err = ociSeccomp(h.profile)
	case "withhold_perf_event_open":
		spec.Seccomp, err = ociSeccomp(h.profile, "perf_event_open")
	default:
		err = errors.New("unknown seccomp mode " + c.Seccomp)
	}
	if err != nil {
		return fail(err.Error())
	}
	helperCG := filepath.Join(h.env.cgroupDir, spec.Name)
	hw := h.env.watch(helperCG)
	defer hw.close()
	helper, err := h.env.startRunning(spec, h.runID)
	if helper != nil {
		defer helper.kill()
	}
	helperStartFailed := ""
	if err != nil {
		helperStartFailed = err.Error()
	}
	res.Detail["helper_pid_namespace"] = ""
	if helperStartFailed == "" {
		// let the service settle: a helper that is going to refuse its policy or its seccomp filter does so at once
		time.Sleep(2 * time.Second)
		if !helper.alive() {
			helperStartFailed = fmt.Sprintf("the helper container exited %d two seconds after start: %s", helper.exit, clip(strings.TrimSpace(helper.stderr.String()), 400))
		}
	}
	if helperStartFailed != "" {
		if c.LimitHit == "" {
			return fail("helper container: " + helperStartFailed)
		}
		res.Detail["helper_start"] = helperStartFailed
	}
	if helperStartFailed == "" {
		a, err := readAudit(helper.hostPID)
		if err != nil {
			return fail("auditing the helper: " + err.Error())
		}
		res.Audit = &a
		res.Detail["helper_pid_namespace"] = a.PIDNS
		res.Detail["target_pid_namespace"] = targetNS
		if probs := auditProblems(a, !c.NoPerfmon, true); len(probs) > 0 {
			res.Why = "the applied helper configuration is wrong: " + strings.Join(probs, "; ")
			return fail("")
		}
		if c.RequireDifferentPIDNS && (a.PIDNS == "" || a.PIDNS == targetNS) {
			return fail(fmt.Sprintf("the helper's PID namespace %s is the workload's %s; the scenario needs two namespaces", a.PIDNS, targetNS))
		}
	}

	if c.Restart {
		target.kill()
		target, err = h.workload("w2-"+c.Name, c.TargetUID, workloadLimits())
		if target != nil {
			defer target.kill()
		}
		if err != nil {
			return fail("restarted workload container: " + err.Error())
		}
		pidArg = strconv.Itoa(target.hostPID)
		res.Detail["restarted_target_pid_namespace"] = nsInode(target.hostPID)
		res.Detail["first_target_pid_namespace"] = targetNS
		// the kernel may hand the new container the inode of the namespace that just ended: the inode alone is not an identity
		res.Detail["pid_namespace_inode_reused"] = nsInode(target.hostPID) == targetNS
	}

	// the capture
	captureArgs := []string{"capture", "--pid", pidArg, "--binary", "/burner", "--seconds", strconv.Itoa(h.seconds)}
	capSpec := ctrSpec{Name: "cap-" + c.Name, Args: append([]string{"/client"}, captureArgs...), PID: opMode, PIDPath: opPath, Caps: c.OperatorCaps,
		Binds: []bind{{Source: runDir, Dest: "/run/soundpost-perf"}}}
	var snaps = map[string]map[string]string{}
	snapshot := func() {
		if target != nil {
			if s := h.env.readCgroup(target.cgroup); len(s) > 0 {
				snaps["workload"] = s
			}
		}
	}
	if c.Paranoid != 0 {
		// raised only for the capture request itself (about a second): it is host-wide and other processes use perf_event_open
		if err := h.setParanoid(c.Paranoid); err != nil {
			return notExercised(err.Error())
		}
	}
	capCtr, err := h.env.start(capSpec, h.runID)
	if capCtr != nil {
		defer capCtr.kill()
	}
	if err != nil {
		return fail("operator capture container: " + err.Error())
	}
	var squeezed bool
	finished := time.After(time.Duration(h.seconds+90) * time.Second)
	squeezeAt := time.Now().Add(time.Duration(h.seconds) * time.Second / 2)
	for running := true; running; {
		select {
		case <-capCtr.done:
			h.restoreParanoid() // the window in which the host-wide sysctl is raised ends with the capture request
			running = false
		case <-finished:
			capCtr.kill()
			return fail("the capture client did not finish")
		case <-time.After(100 * time.Millisecond):
			snapshot()
			if c.SqueezeMemoryBytes > 0 && !squeezed && time.Now().After(squeezeAt) && helper != nil && helper.alive() {
				squeezed = true
				if err := os.WriteFile(filepath.Join(h.env.cgroupRoot, helper.cgroup, "memory.max"), []byte(strconv.FormatInt(c.SqueezeMemoryBytes, 10)), 0o644); err != nil {
					return fail("lowering the helper's memory.max: " + err.Error())
				}
				res.Detail["squeezed_memory_max"] = c.SqueezeMemoryBytes
			}
		}
	}
	var cp capture
	line := jsonLine(capCtr.stdout.String())
	if capCtr.exit != 0 || line == "" || json.Unmarshal([]byte(line), &cp) != nil {
		res.Detail["capture_client_output"] = clip(strings.TrimSpace(capCtr.stderr.String()+capCtr.stdout.String()), 600)
		if c.Want != wantNoSuccess {
			return fail(fmt.Sprintf("the capture client exited %d without a result", capCtr.exit))
		}
		// a client that could not even ask is not a capture that succeeded: the typed no-success is recorded as such
		cp = capture{Mode: "capture", Outcome: "client_error", Error: clip(strings.TrimSpace(capCtr.stderr.String()), 300)}
	}
	res.Capture = &cp
	if s := hw.last(); len(s) > 0 {
		snaps["helper"] = s
	}
	if len(snaps) > 0 {
		res.Cgroups = map[string]any{}
		for k, v := range snaps {
			res.Cgroups[k] = v
		}
	}

	// the helper's end
	if helper != nil && helperStartFailed == "" {
		if helper.alive() {
			exit, err := helper.stopTERM(15 * time.Second)
			res.HelperExit = exit
			if err != nil {
				res.Why = strings.TrimSpace(res.Why + "; " + err.Error())
			}
		} else {
			res.HelperExit = helper.exit
		}
	} else if helper != nil {
		res.HelperExit = helper.exit
	}
	if helper != nil {
		res.HelperLog = clip(strings.TrimSpace(helper.stderr.String()), 600)
	}

	var problems []string
	switch {
	case c.Want == "":
		// the host-dependent scenario: the answer the host's perf_event_paranoid requires
		want := wantSamples
		if h.paranoid >= 3 {
			want = wantDenied
		}
		res.Expected = string(want) + " (host kernel.perf_event_paranoid=" + strconv.Itoa(h.paranoid) + ")"
		obs, ok, why := judge(want, cp)
		res.Observed = obs
		if !ok {
			problems = append(problems, why)
		}
	default:
		obs, ok, why := judge(c.Want, cp)
		res.Observed = obs
		if !ok {
			problems = append(problems, why)
		}
	}
	if c.HelperMustExitZero && res.HelperExit != 0 {
		problems = append(problems, fmt.Sprintf("the helper did not exit 0 on SIGTERM (exit %d): %s", res.HelperExit, res.HelperLog))
	}
	if c.RequireLimitsApplied {
		problems = append(problems, limitProblems("helper", snaps["helper"], helperLimits)...)
		problems = append(problems, limitProblems("workload", snaps["workload"], workloadLimits())...)
		if s := snaps["workload"]; counter(s, "cpu.stat", "nr_throttled") > 0 {
			res.Detail["workload_throttled_periods"] = counter(s, "cpu.stat", "nr_throttled")
		}
	}
	switch c.LimitHit {
	case "memory":
		oom := counter(snaps["helper"], "memory.events", "oom_kill")
		logLines := kernelLog(helperCG, "oom-kill:constraint=CONSTRAINT_MEMCG")
		res.Detail["helper_memory_events_oom_kill"] = oom
		res.Detail["kernel_log_oom"] = logLines
		if oom == 0 && len(logLines) == 0 {
			problems = append(problems, "the kernel recorded no OOM kill of the helper (neither memory.events oom_kill nor a kernel log line): the memory limit was not what ended it")
		}
		if res.HelperExit == 0 {
			problems = append(problems, "the helper exited 0 although its memory limit was hit")
		}
	case "pids":
		events := counter(snaps["helper"], "pids.events", "max")
		logLines := kernelLog(helperCG, "fork rejected by pids controller")
		res.Detail["helper_pids_events_max"] = events
		res.Detail["kernel_log_pids"] = logLines
		if events == 0 && len(logLines) == 0 {
			problems = append(problems, "the kernel recorded no rejected fork in the helper's cgroup (neither pids.events max nor a kernel log line): the pids limit was not what stopped it")
		}
		if helperStartFailed == "" && res.HelperExit == 0 {
			problems = append(problems, "the helper ran and exited 0 under pids.max=3: the limit was not what the scenario needed")
		}
	}
	if len(problems) == 0 {
		res.Status = statusPass
	} else {
		res.Why = strings.Join(problems, "; ")
	}
	return res
}
