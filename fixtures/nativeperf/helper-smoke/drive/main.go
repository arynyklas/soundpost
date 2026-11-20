//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// drive provisions everything fixtures/nativeperf/helper-smoke needs and runs its scenarios (authorized, denied,
// expired, fd-cap, cancel, and a short real capture) against the real cmd/soundpost-perf-acquire binary. It must run
// as root: the helper accepts only a root-owned policy at /etc/soundpost/perf-policy.json and the policy UID is the
// helper's euid. It builds nothing itself (the helper, the smoke and the controlled workload are built beforehand).
//
// Phase 1 starts the helper with its normal limits and runs authorized, denied, expired, cancel and capture (and, when asked
// with --scenarios, offcpu: the same target signed for the CPU + system-wide scheduler mode, whose refusal by tracefs, a
// missing capability or another operator layer is reported as that scenario's closed status). Phase 2
// starts a second helper, in the same installation, under a finite RLIMIT_NOFILE that cannot fit the request and runs
// fd-cap, whose own checks bind the limit to the helper peer by SO_PEERCRED and /proc/<pid>/limits. The operator key is
// the documented public fixture key of helper-e2e (never a production key). Everything this run created is removed.
//
// Default mode: the helper is a child of this process running as root (policy UID 0). With --unit NAME the helper is
// the installed systemd unit instead (packaging/systemd/soundpost-perf-acquire.service, installed by the operator
// script together with the account and the binary at the unit's ExecStart path): the policy UID is the unit user's, the
// smoke and the workload run as that user, the unit's own limits are recorded from `systemctl show` and /proc, and the
// fd-cap phase uses a transient drop-in (LimitNOFILE) that is removed afterwards.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	policyDir       = "/etc/soundpost"
	policyPath      = policyDir + "/perf-policy.json"
	runDir          = "/run/soundpost-perf"
	fixtureSeedText = "soundpost helper-e2e fixture seed v1: public test seed, not a secret"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "helper-smoke drive:", e)
		os.Exit(1)
	}
}

type phaseResult struct {
	Phase      string            `json:"phase"`
	HelperPID  int               `json:"helper_pid"`
	FDLimit    string            `json:"helper_nofile_limit"`
	Unit       map[string]string `json:"unit_properties,omitempty"`
	HelperProc map[string]string `json:"helper_proc,omitempty"`
	Scenarios  []json.RawMessage `json:"scenarios"`
	ExitCode   int               `json:"smoke_exit_code"`
	Stderr     string            `json:"smoke_stderr,omitempty"`
}

type summary struct {
	Kernel      string        `json:"kernel"`
	Mode        string        `json:"mode"`
	Phases      []phaseResult `json:"phases"`
	HelperExits []int         `json:"helper_exit_codes"`
	Failures    []string      `json:"failures"`
	Pass        bool          `json:"pass"`
}

// helperRun is one started helper: a child process, or the installed unit.
type helperRun struct {
	pid   int
	props map[string]string
	// stop ends the helper with SIGTERM semantics and returns its exit code and any reason it was not clean.
	stop func() (int, string)
}

type launcher struct {
	helperBin string
	// container mode: the helper is this image's entrypoint (deploy/Dockerfile.perf-helper shape), started with the real
	// audited seccomp profile, ALL capabilities dropped but PERFMON, no network and the host PID/cgroup namespaces.
	image, seccomp, apparmor string
	machineID                bool
	unit                     string
	user                     *user.User
	uid, gid                 uint32
}

func run() error {
	helperBin := flag.String("helper", "", "built cmd/soundpost-perf-acquire binary (child mode)")
	image := flag.String("container-image", "", "container image whose entrypoint is the static helper (container mode)")
	seccomp := flag.String("container-seccomp", "deploy/seccomp/soundpost-perf.json", "seccomp profile of the helper container")
	apparmor := flag.String("container-apparmor", "", "optional AppArmor profile name of the helper container (default: the runtime's)")
	machineID := flag.Bool("container-machine-id", true, "bind-mount the host /etc/machine-id read-only into the helper container (the shipped recipes must; false reproduces a recipe that does not)")
	smokeBin := flag.String("smoke", "", "built fixtures/nativeperf/helper-smoke binary")
	workload := flag.String("workload", "", "built fixtures/nativeperf/cpu/loop.c (-fno-pie -no-pie -g)")
	template := flag.String("policy-template", "fixtures/nativeperf/helper-e2e/operator-policy.json", "operator policy template (empty allowlist)")
	nofile := flag.Int("fd-cap-nofile", 32, "RLIMIT_NOFILE of the FD-limited helper of phase 2")
	unit := flag.String("unit", "", "installed systemd unit that is the helper (e.g. soundpost-perf-acquire.service)")
	unitUser := flag.String("unit-user", "soundpost-perf", "the unit's User= account")
	normalScenarios := flag.String("scenarios", "authorized,denied,expired,cancel,capture", "scenarios of the first phase (fd-cap always runs in the second)")
	workloadWrap := flag.String("workload-wrap", "", "command prefix that execs the workload (e.g. 'setpriv --bounding-set=-all --inh-caps=-all' so a PERFMON-only helper may read a same-uid target's identity)")
	flag.Parse()
	modes := 0
	for _, set := range []bool{*unit != "", *helperBin != "", *image != ""} {
		if set {
			modes++
		}
	}
	if flag.NArg() != 0 || *smokeBin == "" || *workload == "" || *nofile < 8 || modes != 1 {
		return errors.New("usage: drive --smoke <binary> --workload <binary> (--helper <binary> | --unit <name> [--unit-user <account>]) [--policy-template <file>] [--fd-cap-nofile N]")
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root: the helper accepts only a root-owned policy")
	}
	l := launcher{helperBin: *helperBin, unit: *unit, image: *image, seccomp: *seccomp, apparmor: *apparmor, machineID: *machineID, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	mode := "child-process-as-root"
	if *image != "" {
		mode = "container:" + *image
	}
	if *unit != "" {
		u, e := user.Lookup(*unitUser)
		if e != nil {
			return fmt.Errorf("unit account %s: %w", *unitUser, e)
		}
		uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
		if e1 != nil || e2 != nil {
			return errors.New("unit account has no numeric ids")
		}
		l.user, l.uid, l.gid = u, uint32(uid), uint32(gid)
		mode = "systemd-unit:" + *unit
	}
	key := fixtureKey()
	raw, e := os.ReadFile(*template)
	if e != nil {
		return e
	}
	tmpl, e := loadTemplate(raw, key, uint32(os.Geteuid()))
	if e != nil {
		return fmt.Errorf("policy template %s: %w", *template, e)
	}
	tmpl.UID = l.uid

	childArgv := append(strings.Fields(*workloadWrap), *workload)
	child := exec.Command(childArgv[0], childArgv[1:]...)
	if l.user != nil {
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: l.uid, Gid: l.gid}}
	}
	stdout, e := child.StdoutPipe()
	if e != nil {
		return e
	}
	if e = child.Start(); e != nil {
		return e
	}
	defer func() { child.Process.Signal(syscall.SIGTERM); child.Wait() }()
	if line, e := bufio.NewReader(stdout).ReadString('\n'); e != nil || line != "ready\n" {
		return errors.New("workload did not become ready")
	}
	target, e := nativeperf.ResolveLocalTarget(child.Process.Pid)
	if e != nil {
		return e
	}
	id, e := nativeperf.ResolveCgroupID(child.Process.Pid)
	if e != nil {
		return e
	}
	target.CgroupID = model.Uint64(id)
	build, e := workloadBuildID(*workload)
	if e != nil {
		return e
	}
	target.AllowedBuildIDs = []string{build}
	policy, e := renderPolicy(tmpl, target)
	if e != nil {
		return e
	}

	inst := &install{unitMode: *unit != ""}
	defer inst.remove()
	if e = inst.create(policy); e != nil {
		return e
	}
	private, e := os.MkdirTemp("", "helper-smoke-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(private)
	if e = os.Chmod(private, 0700); e != nil {
		return e
	}
	if e = os.Chown(private, int(l.uid), int(l.gid)); e != nil {
		return e
	}
	now := time.Now()
	base := filepath.Join(private, "base.json")
	expired := filepath.Join(private, "expired.json")
	fdcap := filepath.Join(private, "fdcap.json")
	offcpu := filepath.Join(private, "offcpu.json")
	for path, expires := range map[string]int64{base: now.Add(10 * time.Minute).Unix(), expired: now.Add(-time.Minute).Unix(), fdcap: now.Add(10 * time.Minute).Unix()} {
		if e = writeRequest(path, key, tmpl, target, expires, l, nativeperf.ModeCPU); e != nil {
			return e
		}
	}
	// the same target and configuration asking for the CPU and system-wide scheduler (off-CPU) paths (scenario offcpu)
	if e = writeRequest(offcpu, key, tmpl, target, now.Add(10*time.Minute).Unix(), l, nativeperf.ModeCPUOffCPU); e != nil {
		return e
	}

	sum := summary{Kernel: strings.TrimSpace(readSmall("/proc/sys/kernel/osrelease")), Mode: mode, Failures: []string{}}
	smokeArgs := func(extra ...string) []string {
		return append([]string{"--target-pid", strconv.Itoa(child.Process.Pid), "--request", base, "--offcpu-request", offcpu}, extra...)
	}
	phases := []struct {
		name    string
		nofile  int
		args    func(helperPID int) []string
		wantRun int
	}{
		{"normal-limits", 0, func(int) []string {
			return smokeArgs("--scenario", *normalScenarios, "--expired-request", expired)
		}, strings.Count(*normalScenarios, ",") + 1},
		{"fd-limited-helper", *nofile, func(pid int) []string {
			return smokeArgs("--scenario", "fd-cap", "--fd-cap-request", fdcap, "--fd-cap-helper-pid", strconv.Itoa(pid))
		}, 1},
	}
	if *unit != "" {
		defer func() { removeDropin(*unit) }()
	}
	for _, ph := range phases {
		res, helperExit, why, e := runPhase(l, *smokeBin, ph.name, ph.nofile, ph.args)
		if e != nil {
			return e
		}
		sum.Phases = append(sum.Phases, res)
		sum.HelperExits = append(sum.HelperExits, helperExit)
		if res.ExitCode != 0 {
			sum.Failures = append(sum.Failures, fmt.Sprintf("phase %s: helper-smoke exit %d: %s", ph.name, res.ExitCode, res.Stderr))
		}
		if len(res.Scenarios) != ph.wantRun {
			sum.Failures = append(sum.Failures, fmt.Sprintf("phase %s: %d scenario lines, want %d", ph.name, len(res.Scenarios), ph.wantRun))
		}
		for _, line := range res.Scenarios {
			var one struct {
				Scenario string
				Passed   bool
			}
			if json.Unmarshal(line, &one) != nil || !one.Passed {
				sum.Failures = append(sum.Failures, fmt.Sprintf("phase %s: scenario %s did not pass: %s", ph.name, one.Scenario, line))
			}
		}
		if helperExit != 0 || why != "" {
			sum.Failures = append(sum.Failures, fmt.Sprintf("phase %s: the helper did not stop cleanly on SIGTERM (exit %d %s)", ph.name, helperExit, why))
		}
	}
	sum.Pass = len(sum.Failures) == 0
	if e = json.NewEncoder(os.Stdout).Encode(sum); e != nil {
		return e
	}
	if !sum.Pass {
		return errors.New("helper smoke failed: " + strings.Join(sum.Failures, "; "))
	}
	return nil
}

// startContainer runs the helper as the entrypoint of a container shaped like deploy/Dockerfile.perf-helper under
// the audited seccomp profile: every capability dropped but PERFMON, no new privileges, no network, a read-only root,
// the operator policy read-only, the private socket directory shared with this driver, and the host PID and cgroup
// namespaces (the helper must see the authorized target's numeric identity and cgroup path; "no hostPID escalation"
// means this view is granted by the operator explicitly, as here).
func (l launcher) startContainer(nofile int) (helperRun, error) {
	name := fmt.Sprintf("l4w31-nativea-helper-%d", os.Getpid())
	args := []string{"run", "-d", "--name", name, "--pid=host", "--cgroupns=host", "--network=none", "--cap-drop=ALL", "--cap-add=PERFMON",
		"--security-opt=no-new-privileges", "--security-opt", "seccomp=" + l.seccomp, "--read-only", "--user", "0:0",
		"-v", policyDir + ":" + policyDir + ":ro", "-v", runDir + ":" + runDir}
	if l.machineID {
		// The helper names the host in every domain it exports from /etc/machine-id; a scratch image has none.
		args = append(args, "-v", "/etc/machine-id:/etc/machine-id:ro")
	}
	if l.apparmor != "" {
		args = append(args, "--security-opt", "apparmor="+l.apparmor)
	}
	if nofile > 0 {
		args = append(args, "--ulimit", fmt.Sprintf("nofile=%d:%d", nofile, nofile))
	}
	args = append(args, l.image)
	if out, e := exec.Command("docker", args...).CombinedOutput(); e != nil {
		return helperRun{}, fmt.Errorf("docker run: %v: %s", e, strings.TrimSpace(string(out)))
	}
	remove := func() { exec.Command("docker", "rm", "-f", name).Run() }
	pidText, e := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", name).Output()
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidText)))
	if e != nil || pid <= 0 {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		remove()
		return helperRun{}, fmt.Errorf("the helper container has no host PID: %v (logs: %s)", e, strings.TrimSpace(string(logs)))
	}
	exited := make(chan error, 1)
	alive := true
	var logs syncBuffer
	go func() {
		for alive {
			if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); e != nil {
				exited <- errors.New("helper container process gone")
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if e := waitSocket(exited, &alive, &logs); e != nil {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		remove()
		return helperRun{}, fmt.Errorf("%v; container logs: %s", e, strings.TrimSpace(string(out)))
	}
	alive = false
	props := map[string]string{"container": name, "image": l.image, "seccomp_profile": l.seccomp}
	return helperRun{pid: pid, props: props, stop: func() (int, string) {
		defer remove()
		if out, e := exec.Command("docker", "stop", "-t", "10", name).CombinedOutput(); e != nil {
			return -1, "docker stop: " + strings.TrimSpace(string(out))
		}
		code, e := exec.Command("docker", "inspect", "-f", "{{.State.ExitCode}}", name).Output()
		n, perr := strconv.Atoi(strings.TrimSpace(string(code)))
		if e != nil || perr != nil {
			return -1, "docker inspect exit code"
		}
		return n, ""
	}}, nil
}

func (l launcher) start(nofile int) (helperRun, error) {
	if l.unit != "" {
		return l.startUnit(nofile)
	}
	if l.image != "" {
		return l.startContainer(nofile)
	}
	var helper *exec.Cmd
	if nofile > 0 {
		helper = exec.Command("/bin/sh", "-c", fmt.Sprintf(`ulimit -n %d && exec "$0"`, nofile), l.helperBin)
	} else {
		helper = exec.Command(l.helperBin)
	}
	var logs syncBuffer
	helper.Stdout, helper.Stderr = &logs, &logs
	if e := helper.Start(); e != nil {
		return helperRun{}, e
	}
	exited := make(chan error, 1)
	go func() { exited <- helper.Wait() }()
	alive := true
	kill := func() {
		if alive {
			helper.Process.Kill()
			<-exited
			alive = false
		}
	}
	if e := waitSocket(exited, &alive, &logs); e != nil {
		kill()
		return helperRun{}, e
	}
	return helperRun{pid: helper.Process.Pid, stop: func() (int, string) {
		helper.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
			alive = false
			if helper.ProcessState != nil {
				return helper.ProcessState.ExitCode(), ""
			}
			return -1, "no process state"
		case <-time.After(10 * time.Second):
			kill()
			return -1, "did not exit within 10 s of SIGTERM"
		}
	}}, nil
}

func systemctl(args ...string) (string, error) {
	out, e := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), e
}

func dropinPath(unit string) string {
	return "/etc/systemd/system/" + unit + ".d/10-helper-smoke-fd-cap.conf"
}

func removeDropin(unit string) {
	if _, e := os.Lstat(dropinPath(unit)); e == nil {
		os.Remove(dropinPath(unit))
		os.Remove(filepath.Dir(dropinPath(unit)))
		systemctl("daemon-reload")
	}
}

// startUnit starts the installed unit (with a LimitNOFILE drop-in for the fd-cap phase) and records the properties the
// unit's sandbox is declared by, as systemd and the kernel report them for the running service.
func (l launcher) startUnit(nofile int) (helperRun, error) {
	removeDropin(l.unit)
	if nofile > 0 {
		if e := os.MkdirAll(filepath.Dir(dropinPath(l.unit)), 0755); e != nil {
			return helperRun{}, e
		}
		if e := os.WriteFile(dropinPath(l.unit), []byte(fmt.Sprintf("[Service]\nLimitNOFILE=%d\n", nofile)), 0644); e != nil {
			return helperRun{}, e
		}
		if out, e := systemctl("daemon-reload"); e != nil {
			return helperRun{}, fmt.Errorf("daemon-reload: %v: %s", e, out)
		}
	}
	if out, e := systemctl("start", l.unit); e != nil {
		j, _ := exec.Command("journalctl", "-u", l.unit, "--no-pager", "-n", "20").CombinedOutput()
		return helperRun{}, fmt.Errorf("systemctl start %s: %v: %s; journal: %s", l.unit, e, out, string(j))
	}
	props := map[string]string{}
	show, _ := systemctl("show", l.unit, "-p", "MainPID", "-p", "ActiveState", "-p", "SubState", "-p", "User", "-p", "LimitCORE", "-p", "LimitNOFILE", "-p", "CapabilityBoundingSet", "-p", "AmbientCapabilities", "-p", "NoNewPrivileges", "-p", "SystemCallFilter", "-p", "SystemCallErrorNumber", "-p", "SystemCallArchitectures", "-p", "MemoryMax", "-p", "TasksMax", "-p", "RestrictAddressFamilies", "-p", "MemoryDenyWriteExecute", "-p", "ProtectSystem", "-p", "PrivateTmp", "-p", "RuntimeDirectory", "-p", "RuntimeDirectoryMode", "-p", "IPAddressDeny", "-p", "UMask", "-p", "Restart")
	for _, line := range strings.Split(show, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	pid, _ := strconv.Atoi(props["MainPID"])
	if pid <= 0 {
		return helperRun{}, fmt.Errorf("unit %s has no MainPID: %v", l.unit, props)
	}
	var logs syncBuffer
	exited := make(chan error, 1)
	alive := true
	go func() {
		for alive {
			if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); e != nil {
				exited <- errors.New("main process gone")
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if e := waitSocket(exited, &alive, &logs); e != nil {
		j, _ := exec.Command("journalctl", "-u", l.unit, "--no-pager", "-n", "20").CombinedOutput()
		systemctl("stop", l.unit)
		return helperRun{}, fmt.Errorf("%v; journal: %s", e, string(j))
	}
	alive = false
	return helperRun{pid: pid, props: props, stop: func() (int, string) {
		out, e := systemctl("stop", l.unit)
		after, _ := systemctl("show", l.unit, "-p", "Result", "-p", "ExecMainStatus", "-p", "ActiveState")
		kv := map[string]string{}
		for _, line := range strings.Split(after, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[k] = v
			}
		}
		code, _ := strconv.Atoi(kv["ExecMainStatus"])
		if e != nil {
			return -1, "systemctl stop: " + out
		}
		if kv["Result"] != "success" {
			return code, "unit Result=" + kv["Result"]
		}
		return code, ""
	}}, nil
}

// procFields reads the sandbox state of the running helper from /proc.
func procFields(pid int) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(readSmall("/proc/"+strconv.Itoa(pid)+"/status"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && (k == "Seccomp" || k == "NoNewPrivs" || k == "CapEff" || k == "CapBnd" || k == "CapAmb" || k == "CapPrm" || k == "Uid" || k == "VmHWM" || k == "THP_enabled") {
			out[k] = strings.TrimSpace(v)
		}
	}
	for _, line := range strings.Split(readSmall("/proc/"+strconv.Itoa(pid)+"/limits"), "\n") {
		if strings.HasPrefix(line, "Max core file size") || strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(line)
			out[strings.Join(f[:len(f)-3], " ")] = f[len(f)-3] + "/" + f[len(f)-2]
		}
	}
	if cg := readSmall("/proc/" + strconv.Itoa(pid) + "/cgroup"); strings.HasPrefix(cg, "0::") {
		path := filepath.Join("/sys/fs/cgroup", strings.TrimSpace(strings.TrimPrefix(strings.SplitN(cg, "\n", 2)[0], "0::")))
		out["cgroup_memory.max"] = strings.TrimSpace(readSmall(path + "/memory.max"))
		out["cgroup_pids.max"] = strings.TrimSpace(readSmall(path + "/pids.max"))
	}
	return out
}

// runPhase starts one helper, runs the smoke against it, then stops the helper and returns its exit code.
func runPhase(l launcher, smokeBin, name string, nofile int, args func(int) []string) (phaseResult, int, string, error) {
	res := phaseResult{Phase: name}
	h, e := l.start(nofile)
	if e != nil {
		return res, 0, "", e
	}
	stopped := false
	defer func() {
		if !stopped {
			h.stop()
		}
	}()
	res.HelperPID = h.pid
	res.Unit = h.props
	res.FDLimit = nofileLimit(res.HelperPID)

	smoke := exec.Command(smokeBin, args(res.HelperPID)...)
	if l.user != nil {
		smoke.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: l.uid, Gid: l.gid}}
	}
	var out, errOut bytes.Buffer
	smoke.Stdout, smoke.Stderr = &out, &errOut
	e = smoke.Run()
	if e != nil {
		res.ExitCode = -1
		var ee *exec.ExitError
		if errors.As(e, &ee) {
			res.ExitCode = ee.ExitCode()
		}
	}
	res.Stderr = strings.TrimSpace(errOut.String())
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line != "" {
			res.Scenarios = append(res.Scenarios, json.RawMessage(line))
		}
	}
	res.HelperProc = procFields(h.pid)
	stopped = true
	code, why := h.stop()
	return res, code, why, nil
}

func nofileLimit(pid int) string {
	for _, line := range strings.Split(readSmall("/proc/"+strconv.Itoa(pid)+"/limits"), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			return strings.Join(strings.Fields(line)[3:5], "/")
		}
	}
	return ""
}

func writeRequest(path string, key ed25519.PrivateKey, tmpl nativeperf.OperatorPolicy, target nativeperf.Target, expires int64, l launcher, mode nativeperf.CaptureMode) error {
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: tmpl.Installation, UID: tmpl.UID, Revision: tmpl.Revision,
		Expires: expires, Targets: targets, Config: cfg, Mode: mode}, key)
	if e != nil {
		return e
	}
	b, e := json.Marshal(nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: mode})
	if e != nil {
		return e
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		return e
	}
	return os.Chown(path, int(l.uid), int(l.gid))
}

func fixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(fixtureSeedText))
	return ed25519.NewKeyFromSeed(seed[:])
}

func loadTemplate(raw []byte, key ed25519.PrivateKey, euid uint32) (nativeperf.OperatorPolicy, error) {
	var p nativeperf.OperatorPolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return p, e
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("trailing data after the policy object")
	}
	if p.Installation == "" || p.Revision == 0 {
		return p, errors.New("installation and revision are required")
	}
	if !bytes.Equal(p.PublicKey, key.Public().(ed25519.PublicKey)) {
		return p, errors.New("public key does not match the documented fixture seed key")
	}
	if p.UID != euid {
		return p, fmt.Errorf("UID %d is not the helper's euid %d", p.UID, euid)
	}
	if len(p.Allowlist) != 0 {
		return p, errors.New("allowlist must be empty in the template; the driver adds the live target")
	}
	return p, nil
}

func renderPolicy(t nativeperf.OperatorPolicy, target nativeperf.Target) ([]byte, error) {
	if e := target.Validate(); e != nil {
		return nil, e
	}
	if target.CgroupID == 0 || len(target.AllowedBuildIDs) == 0 {
		return nil, errors.New("target needs a cgroup id and a build id")
	}
	t.Allowlist = []nativeperf.Target{target}
	b, e := json.MarshalIndent(t, "", "  ")
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}

func cgroupV2Path(content string) (string, error) {
	group := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return "", errors.New("cgroup v2 identity unavailable")
	}
	for _, part := range strings.Split(group, "/") {
		if part == ".." {
			return "", errors.New("cgroup namespace path not visible")
		}
	}
	return group, nil
}

func buildIDFromNote(notes []byte) (string, error) {
	if len(notes) < 16 {
		return "", errors.New("invalid build ID note")
	}
	nameSize := binary.LittleEndian.Uint32(notes)
	descSize := binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (uint64(nameSize)+3)&^3
	if descSize == 0 || start+uint64(descSize) > uint64(len(notes)) {
		return "", errors.New("invalid build ID note bounds")
	}
	return hex.EncodeToString(notes[start : start+uint64(descSize)]), nil
}

func workloadBuildID(path string) (string, error) {
	f, e := elf.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC {
		return "", errors.New("compile the workload with -fno-pie -no-pie")
	}
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		return "", errors.New("GNU build ID required")
	}
	b, e := note.Data()
	if e != nil {
		return "", e
	}
	return buildIDFromNote(b)
}

// install owns the files and directories this run creates; remove undoes exactly those. In unit mode the unit's
// RuntimeDirectory owns /run/soundpost-perf, so this run never creates it.
type install struct {
	unitMode                              bool
	policyFile, policyDirMade, runDirMade bool
}

func (i *install) create(policy []byte) error {
	if _, e := os.Lstat(policyPath); e == nil {
		return fmt.Errorf("refusing to overwrite the existing %s", policyPath)
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, e := os.Lstat(runDir + "/acquire.sock"); e == nil {
		return fmt.Errorf("refusing to start: %s/acquire.sock already exists (another helper?)", runDir)
	} else if !os.IsNotExist(e) {
		return e
	}
	if st, e := os.Lstat(policyDir); os.IsNotExist(e) {
		if e = os.Mkdir(policyDir, 0755); e != nil {
			return e
		}
		i.policyDirMade = true
	} else if e != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", policyDir)
	}
	if !i.unitMode {
		if st, e := os.Lstat(runDir); os.IsNotExist(e) {
			if e = os.Mkdir(runDir, 0700); e != nil {
				return e
			}
			i.runDirMade = true
			if e = os.Chmod(runDir, 0700); e != nil {
				return e
			}
		} else if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("%s exists but is not a 0700 directory owned by the helper euid", runDir)
		}
	}
	f, e := os.OpenFile(policyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if e != nil {
		return e
	}
	i.policyFile = true
	_, e = f.Write(policy)
	if e == nil {
		e = f.Chmod(0644)
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	return e
}

func (i *install) remove() {
	if !i.unitMode {
		os.Remove(runDir + "/acquire.sock")
		if i.runDirMade {
			os.Remove(runDir)
		}
	}
	if i.policyFile {
		os.Remove(policyPath)
	}
	if i.policyDirMade {
		os.Remove(policyDir)
	}
}

func waitSocket(exited <-chan error, alive *bool, logs *syncBuffer) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-exited:
			*alive = false
			return fmt.Errorf("the helper exited before listening: %v (helper output: %s)", e, logs.tail(300))
		default:
		}
		if st, e := os.Lstat(nativeperf.HelperSocket); e == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("the helper did not create its socket within 10 s")
}

func readSmall(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return string(b)
}

// syncBuffer collects the helper's output; the helper prints nothing on success.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) tail(n int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.b.Bytes()
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}
