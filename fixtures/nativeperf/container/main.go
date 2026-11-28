//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// container is the container-modes harness of the native Linux qualification (design section 13, plan 04 native
// profiling, plan 07 task 6): it runs the real soundpost-perf-acquire helper under an OCI runtime (runc, no daemon, no
// image store, no network namespace), configured as the shipped recipe says (deploy/compose.distributed.yaml
// `soundpost-perf-helper`, deploy/Dockerfile.perf-helper, deploy/seccomp/soundpost-perf.json): uid 0 holding only
// CAP_PERFMON, no_new_privileges, the deny-by-default seccomp profile, read-only root, cgroup v2 pids/memory/cpu limits,
// the host cgroup namespace and the PID namespace of the workload. A real CPU-burning workload runs in its own
// container; a real client (tools/smoke/nativehelper/client, in the helper's PID namespace) speaks the helper's signed-grant
// protocol. Every verdict is the helper's own answer, never the harness' inference.
//
// It must run as root on a Linux host with cgroup v2 and runc. It changes the host only temporarily: one sub-cgroup
// and one temporary directory (both removed) and, for the two perf_event_paranoid scenarios, kernel.perf_event_paranoid
// (raised to 3, restored, unless --keep-paranoid). It prints one JSON report on stdout and exits 0 (every scenario
// passed), 1 (a scenario failed) or 10 (the harness could not run or could not run a scenario: not_exercised).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	exitPass         = 0
	exitFail         = 1
	exitNotExercised = 10

	statusPass         = "pass"
	statusFail         = "fail"
	statusNotExercised = "not_exercised"

	paranoidFile = "/proc/sys/kernel/perf_event_paranoid"
	// initialPIDNamespaceInode is the proc inode of the initial PID namespace.
	initialPIDNamespaceInode = 0xEFFFFFFC
)

// scenarioResult is one scenario of the report.
type scenarioResult struct {
	Name     string         `json:"name"`
	Status   string         `json:"status"`
	Expected string         `json:"expected"`
	Observed string         `json:"observed"`
	Why      string         `json:"why,omitempty"`
	Capture  *capture       `json:"capture,omitempty"`
	Audit    *audit         `json:"helper_audit,omitempty"`
	Cgroups  map[string]any `json:"cgroups,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	// HelperExit is the exit code of the helper container after SIGTERM (-1: it was not stopped this way).
	HelperExit int    `json:"helper_exit_code"`
	HelperLog  string `json:"helper_log,omitempty"`
}

type report struct {
	Schema         string           `json:"schema"`
	Status         string           `json:"status"`
	Reason         string           `json:"reason,omitempty"`
	Kernel         string           `json:"kernel"`
	Runc           string           `json:"runc"`
	RunID          string           `json:"run_id"`
	ParanoidBefore int              `json:"perf_event_paranoid_before"`
	ParanoidAfter  int              `json:"perf_event_paranoid_after"`
	Scenarios      []scenarioResult `json:"scenarios"`
	Cleanup        []string         `json:"cleanup_leftovers"`
	Limits         []string         `json:"limits"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "container:", err)
		os.Exit(2)
	}
}

// notApplicable is a scenario the kernel cannot hold (level 3 not enforced): reported not_exercised, never passed, and
// not a reason to call the whole run not exercised.
func notApplicable(s scenarioResult) bool {
	return s.Status == statusNotExercised && s.Why == reasonNoParanoidLevel3
}

func reportStatus(scenarios []scenarioResult) string {
	status := statusPass
	for _, s := range scenarios {
		switch {
		case s.Status == statusFail:
			status = statusFail
		case s.Status == statusNotExercised && !notApplicable(s):
			if status == statusPass {
				status = statusNotExercised
			}
		}
	}
	if len(scenarios) == 0 && status == statusPass {
		status = statusNotExercised
	}
	return status
}

func finish(r *report) {
	r.Status = reportStatus(r.Scenarios)
	raw, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(raw))
	switch r.Status {
	case statusPass:
		os.Exit(exitPass)
	case statusFail:
		os.Exit(exitFail)
	}
	os.Exit(exitNotExercised)
}

func run() error {
	helperBin := flag.String("helper", "", "static cmd/soundpost-perf-acquire binary")
	clientBin := flag.String("client", "", "static tools/smoke/nativehelper/client binary")
	burnerBin := flag.String("burner", "", "static tools/smoke/nativehelper/burner binary built with -ldflags \"-B gobuildid\"")
	seccompFile := flag.String("seccomp", "deploy/seccomp/soundpost-perf.json", "the shipped seccomp profile")
	runcBin := flag.String("runc", "runc", "OCI runtime binary")
	seconds := flag.Int("seconds", 5, "capture duration per scenario (1..60)")
	runID := flag.String("run-id", "", "unique run id (default: derived from the process id)")
	series := flag.String("kernel-series", "", "required kernel series (e.g. 6.1); any other kernel is not_exercised")
	only := flag.String("only", "", "comma-separated scenario names to run (default: all)")
	keepParanoid := flag.Bool("keep-paranoid", false, "never write kernel.perf_event_paranoid: the paranoid scenarios become not_exercised unless the host is already at 3")
	flag.Parse()
	if flag.NArg() != 0 || *helperBin == "" || *clientBin == "" || *burnerBin == "" || *seconds < 1 || *seconds > 60 {
		return errors.New("usage: container --helper H --client C --burner B [--seccomp F] [--runc R] [--seconds 1..60] [--run-id ID] [--kernel-series S] [--only a,b] [--keep-paranoid]")
	}
	id := *runID
	if id == "" {
		id = strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	rep := &report{Schema: "soundpost.container-modes/1", RunID: id, Scenarios: []scenarioResult{}, Cleanup: []string{}, Limits: harnessLimits()}
	rep.Kernel = strings.TrimSpace(readSmall("/proc/sys/kernel/osrelease"))
	if reason := prerequisite(*runcBin, *series, rep); reason != "" {
		rep.Reason = reason
		finish(rep)
	}
	paranoid, err := readParanoid()
	if err != nil {
		return err
	}
	rep.ParanoidBefore = paranoid

	profile, err := os.ReadFile(*seccompFile)
	if err != nil {
		return err
	}
	env, err := newEnv(*runcBin, id, *helperBin, *clientBin, *burnerBin)
	if err != nil {
		return err
	}
	h := &harness{env: env, runID: id, seconds: *seconds, profile: profile, paranoid: paranoid, keepParanoid: *keepParanoid}
	// Whatever ends the run (a signal included) puts the sysctl back and removes the containers and the cgroup.
	var stopped = make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stopped
		h.restoreParanoid()
		env.cleanup()
		os.Exit(130)
	}()
	selected := map[string]bool{}
	for _, n := range strings.Split(*only, ",") {
		if n = strings.TrimSpace(n); n != "" {
			selected[n] = true
		}
	}
	for _, c := range scenarios() {
		if len(selected) > 0 && !selected[c.Name] {
			continue
		}
		fmt.Fprintln(os.Stderr, "container: scenario", c.Name)
		rep.Scenarios = append(rep.Scenarios, h.runCase(c))
	}
	h.restoreParanoid()
	if after, err := readParanoid(); err == nil {
		rep.ParanoidAfter = after
		if after != paranoid {
			rep.Scenarios = append(rep.Scenarios, scenarioResult{Name: "host_unchanged", Status: statusFail, Expected: "perf_event_paranoid restored", Observed: strconv.Itoa(after), Why: "kernel.perf_event_paranoid was " + strconv.Itoa(paranoid) + " before the run"})
		}
	}
	rep.Cleanup = env.cleanup()
	if len(rep.Cleanup) > 0 {
		rep.Scenarios = append(rep.Scenarios, scenarioResult{Name: "host_unchanged", Status: statusFail, Expected: "nothing left behind", Observed: "leftovers", Why: strings.Join(rep.Cleanup, "; ")})
	}
	finish(rep)
	return nil
}

// harnessLimits is what this harness does not show; it is printed with the report so a reader cannot take the
// report for more than it is.
func harnessLimits() []string {
	return []string{
		"one host, one kernel: the pinned series is the one this report names; no other kernel or architecture is extrapolated",
		"the OCI runtime is runc driven directly, not Docker or Compose and not the container image the release ships: the bundle is built from the same binaries' sources with the shipped seccomp profile and the Compose service's settings (uid 0, only CAP_PERFMON, no_new_privileges, read-only root, host cgroup namespace, workload PID namespace, pids 16, memory 64 MiB)",
		"the helper's container uses the host network namespace (no network namespace is created, so the host's networking is untouched); the Compose service uses network_mode none, which only withdraws network access the helper never uses (it listens on a unix socket)",
		"Kubernetes (Pod securityContext, Localhost seccomp, hostPID) is not exercised",
		"off-CPU and runqueue modes are not exercised in a container (the scheduler tracepoints need the initial PID namespace)",
		"kernel.perf_event_paranoid is host-wide: the two paranoid scenarios raise it to 3 only for the duration of one capture request each (about a second) and restore it at once; other processes of the host that use perf_event_open without CAP_SYS_ADMIN are refused in that window",
	}
}

// prerequisite returns why the harness cannot run at all, "" when it can.
func prerequisite(runcBin, series string, rep *report) string {
	switch {
	case os.Geteuid() != 0:
		return "the container harness must run as root (runc needs to create namespaces, cgroups and mounts, and the helper accepts only a root-owned policy)"
	case series != "" && kernelSeries(rep.Kernel) != series:
		return fmt.Sprintf("this host runs kernel %s (series %s); the row is for series %s", rep.Kernel, kernelSeries(rep.Kernel), series)
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return "no unified cgroup v2 hierarchy at /sys/fs/cgroup: the cgroup limit rows need cgroup v2"
	}
	raw, _ := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	for _, need := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(" "+strings.TrimSpace(string(raw))+" ", " "+need+" ") {
			return "the cgroup v2 controller " + need + " is not available at the root"
		}
	}
	if link, err := os.Readlink("/proc/self/ns/pid"); err != nil || link != fmt.Sprintf("pid:[%d]", initialPIDNamespaceInode) {
		return "the harness itself is not in the initial PID namespace (" + link + "): it needs the host's namespaces to place and audit containers"
	}
	if release := strings.ToLower(readSmall("/proc/sys/kernel/osrelease")); strings.Contains(release, "microsoft") || strings.Contains(release, "wsl") {
		return "WSL2 host (kernel " + rep.Kernel + "): design section 13 says WSL2 does not qualify a Linux row"
	}
	path, err := exec.LookPath(runcBin)
	if err != nil {
		return "no OCI runtime: " + runcBin + " is not installed (a daemonless runc is required; this harness does not install it)"
	}
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return "the OCI runtime " + path + " does not run: " + clip(strings.TrimSpace(string(out)), 200)
	}
	rep.Runc = strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", "; ")), " ")
	return ""
}

func kernelSeries(release string) string {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func readSmall(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return clip(string(raw), 4096)
}

func readParanoid() (int, error) {
	return strconv.Atoi(strings.TrimSpace(readSmall(paranoidFile)))
}

// newEnv builds the shared read-only root file system: the three static executables and the mount points.
func newEnv(runcBin, id, helper, client, burner string) (*runtimeEnv, error) {
	runcPath, err := exec.LookPath(runcBin)
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "natcont-"+id+"-")
	if err != nil {
		return nil, err
	}
	env := &runtimeEnv{runc: runcPath, work: work, rootfs: filepath.Join(work, "rootfs"), state: filepath.Join(work, "runc-state"), cgroupRoot: "/sys/fs/cgroup", cgroupDir: "natcont-" + id}
	fail := func(err error) (*runtimeEnv, error) { env.cleanup(); return nil, err }
	if err = os.Chmod(work, 0o755); err != nil {
		return fail(err)
	}
	for _, d := range []string{"proc", "dev", "sys", "etc/soundpost", "run/soundpost-perf", "policy", "tmp"} {
		if err = os.MkdirAll(filepath.Join(env.rootfs, d), 0o755); err != nil {
			return fail(err)
		}
	}
	for _, f := range []string{"etc/machine-id", "etc/soundpost/perf-policy.json"} {
		if err = os.WriteFile(filepath.Join(env.rootfs, f), nil, 0o644); err != nil {
			return fail(err)
		}
	}
	for dest, src := range map[string]string{"helper": helper, "client": client, "burner": burner} {
		raw, err := os.ReadFile(src)
		if err != nil {
			return fail(err)
		}
		path := filepath.Join(env.rootfs, dest)
		if err = os.WriteFile(path, raw, 0o555); err != nil {
			return fail(err)
		}
	}
	if _, err = exposeBuildID(filepath.Join(env.rootfs, "burner")); err != nil {
		return fail(err)
	}
	if err = os.MkdirAll(env.state, 0o700); err != nil {
		return fail(err)
	}
	parent := filepath.Join(env.cgroupRoot, env.cgroupDir)
	if err = os.Mkdir(parent, 0o755); err != nil {
		return fail(err)
	}
	// delegate the controllers the containers' limits need; best effort (runc enables them on the path as well)
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644)
	return env, nil
}
