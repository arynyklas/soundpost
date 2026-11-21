//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// helper-e2e starts the real cmd/soundpost-perf-acquire binary end to end: it installs a root-owned operator policy at
// the helper's fixed path, starts the helper as a child, opens a signed CPU capture against a controlled workload over
// the helper's fixed socket, counts real samples, and proves from /proc that the helper opted itself out of transparent
// huge pages (prctl PR_SET_THP_DISABLE) rather than inheriting that from this driver. It must run as root and builds
// nothing itself: the helper and the workload are built beforehand (see docs/profiling/native-linux.md).
package main

import (
	"bufio"
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	policyDir  = "/etc/soundpost"
	policyPath = policyDir + "/perf-policy.json"
	runDir     = "/run/soundpost-perf"
	thpSysfs   = "/sys/kernel/mm/transparent_hugepage/enabled"
	// fixtureSeedText documents the (public, non-secret) seed of the fixture operator key. The key signs nothing but this
	// fixture's own capture request; operator-policy.json carries only its public half.
	fixtureSeedText = "soundpost helper-e2e fixture seed v1: public test seed, not a secret"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "helper-e2e:", e)
		os.Exit(1)
	}
}

// result is the one JSON line the driver prints.
type result struct {
	Kernel           string   `json:"kernel"`
	THPSysfs         string   `json:"thp_sysfs_enabled"`
	DriverTHPEnabled string   `json:"driver_thp_enabled"`
	HelperTHPEnabled string   `json:"helper_thp_enabled"`
	HelperSeccomp    string   `json:"helper_seccomp"`
	HelperNoNewPrivs string   `json:"helper_no_new_privs"`
	HelperVmHWMkB    int64    `json:"helper_vmhwm_kb"`
	HelperPID        int      `json:"helper_pid"`
	HelperExit       int      `json:"helper_exit_code"`
	Seconds          float64  `json:"capture_seconds"`
	Samples          uint64   `json:"cpu_samples"`
	LossEvents       uint64   `json:"loss_events"`
	LostRecords      uint64   `json:"lost_records"`
	Threads          int      `json:"threads_observed"`
	Proofs           uint64   `json:"progress_proofs"`
	StreamEnd        string   `json:"stream_end"`
	Failures         []string `json:"failures"`
	Pass             bool     `json:"pass"`
}

func run() error {
	helperBin := flag.String("helper", "", "built cmd/soundpost-perf-acquire binary")
	workload := flag.String("workload", "", "built fixtures/nativeperf/cpu/loop.c (-fno-pie -no-pie -g)")
	template := flag.String("policy-template", "fixtures/nativeperf/helper-e2e/operator-policy.json", "operator policy template (empty allowlist)")
	seconds := flag.Int("seconds", 10, "capture duration")
	flag.Parse()
	if flag.NArg() != 0 || *helperBin == "" || *workload == "" || *seconds < 1 || *seconds > 60 {
		return errors.New("usage: helper-e2e --helper <binary> --workload <binary> [--policy-template <file>] [--seconds 1..60]")
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root: the helper accepts only a root-owned policy and the policy UID is the helper's euid")
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
	// Recorded so a reader can tell whether this driver itself runs with THP disabled: if it did, the helper's value
	// could be inherited and would prove nothing about the helper's own prctl. The driver never calls prctl.
	selfStatus, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	driverTHP := statusField(selfStatus, "THP_enabled")
	res := result{Kernel: unameRelease(), THPSysfs: strings.TrimSpace(readSmall(thpSysfs)), DriverTHPEnabled: driverTHP, Failures: []string{}}

	child := exec.Command(*workload)
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

	inst := &install{}
	defer inst.remove()
	if e = inst.create(policy); e != nil {
		return e
	}
	helper := exec.Command(*helperBin)
	var logs syncBuffer
	helper.Stdout, helper.Stderr = &logs, &logs
	if e = helper.Start(); e != nil {
		return e
	}
	res.HelperPID = helper.Process.Pid
	exited := make(chan error, 1)
	go func() { exited <- helper.Wait() }()
	helperAlive := true
	defer func() {
		if helperAlive {
			helper.Process.Kill()
			<-exited
		}
	}()
	if e = waitSocket(exited, &helperAlive, &logs); e != nil {
		return e
	}

	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: tmpl.Installation, UID: uint32(os.Geteuid()), Revision: tmpl.Revision,
		Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}, key)
	if e != nil {
		return e
	}
	ctx := context.Background()
	session, e := nativeperf.OpenAuthorized(ctx, nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU})
	if e != nil {
		return fmt.Errorf("the real helper refused or failed the signed capture: %w (helper output: %s)", e, logs.tail(300))
	}
	start := time.Now()
	// CPU mode has no drain protocol: the helper ends a capture when the client stops or closes (its CPU source has no
	// Stop of its own), so the client's own end of the capture surfaces as a closed/failed read that is not an error.
	var ending atomic.Bool
	stop := time.AfterFunc(time.Duration(*seconds)*time.Second, func() {
		ending.Store(true)
		session.Stop()
		session.Close()
	})
	threads := map[uint32]bool{}
	var readErr error
	for {
		// NextItem is Session.Next plus the explicit topology/progress proofs that Next reports as ErrProgressRequired.
		item, e := session.NextItem(ctx)
		if e != nil {
			if ending.Load() {
				res.StreamEnd = e.Error()
			} else if !errors.Is(e, nativeperf.ErrSourceComplete) {
				readErr = e
			}
			break
		}
		if item.Proof != nil {
			res.Proofs++
			continue
		}
		switch ev := item.Event; {
		case ev.CPUEvent != nil:
			res.Samples++
			threads[ev.Task.TID] = true
		case ev.Loss != nil:
			res.LossEvents++
			res.LostRecords += uint64(ev.Loss.Count)
		}
	}
	// If the stream ended by itself before the deadline (a failure, handled above) the timer must not fire later.
	stop.Stop()
	res.Seconds = time.Since(start).Seconds()
	session.Close()
	res.Threads = len(threads)
	if readErr != nil {
		res.Failures = append(res.Failures, "capture stream ended with an error: "+readErr.Error())
	}

	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", helper.Process.Pid))
	if e != nil {
		return fmt.Errorf("helper status unreadable: %w", e)
	}
	res.HelperTHPEnabled = statusField(status, "THP_enabled")
	res.HelperSeccomp = statusField(status, "Seccomp")
	res.HelperNoNewPrivs = statusField(status, "NoNewPrivs")
	res.HelperVmHWMkB = statusKB(status, "VmHWM")

	helper.Process.Signal(syscall.SIGTERM)
	select {
	case werr := <-exited:
		helperAlive = false
		res.HelperExit = exitCode(helper.ProcessState, werr)
	case <-time.After(10 * time.Second):
		helper.Process.Kill()
		<-exited
		helperAlive = false
		res.HelperExit = -1
	}
	res.Failures = append(res.Failures, evaluate(res)...)
	res.Pass = len(res.Failures) == 0
	if e = json.NewEncoder(os.Stdout).Encode(res); e != nil {
		return e
	}
	if !res.Pass {
		return fmt.Errorf("end-to-end check failed: %s (helper output: %s)", strings.Join(res.Failures, "; "), logs.tail(300))
	}
	return nil
}

// evaluate lists every reason the end-to-end check does not pass.
func evaluate(r result) []string {
	var out []string
	if r.DriverTHPEnabled != "1" {
		out = append(out, "the driver's own THP_enabled is "+quote(r.DriverTHPEnabled)+", not 1: the helper's value could be inherited, so the opt-out would prove nothing (run the driver under the host's default THP setting)")
	}
	if r.HelperTHPEnabled != "0" {
		out = append(out, "helper THP_enabled is "+quote(r.HelperTHPEnabled)+", want 0 (the helper must call prctl PR_SET_THP_DISABLE itself)")
	}
	if r.Samples == 0 {
		out = append(out, "no real CPU samples were received")
	}
	if r.HelperExit != 0 {
		out = append(out, "the helper did not exit 0 on SIGTERM (exit "+strconv.Itoa(r.HelperExit)+")")
	}
	return out
}

func quote(s string) string {
	if s == "" {
		return "absent"
	}
	return strconv.Quote(s)
}

func exitCode(st *os.ProcessState, werr error) int {
	if st == nil {
		return -1
	}
	return st.ExitCode()
}

// fixtureKey is the fixed, publicly documented fixture operator key (never a production key).
func fixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(fixtureSeedText))
	return ed25519.NewKeyFromSeed(seed[:])
}

// loadTemplate strictly decodes the policy template and refuses one that is not exactly the fixture's: the public key
// must be the fixture key's, the allowlist must be empty (the driver fills it) and the UID must be the helper's euid.
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

// renderPolicy returns the strict JSON the helper reads: the template plus exactly one allowlisted target.
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

// statusField returns the value of a "Name:\tvalue" line of /proc/<pid>/status, or "" when absent.
func statusField(status []byte, name string) string {
	for _, line := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// statusKB parses a "VmHWM:\t  1234 kB" line; -1 when absent or malformed.
func statusKB(status []byte, name string) int64 {
	f := strings.Fields(statusField(status, name))
	if len(f) != 2 || f[1] != "kB" {
		return -1
	}
	n, e := strconv.ParseInt(f[0], 10, 64)
	if e != nil {
		return -1
	}
	return n
}

// cgroupV2Path returns the unified-hierarchy path of a /proc/<pid>/cgroup file.
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

// buildIDFromNote decodes the descriptor of an ELF .note.gnu.build-id section.
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

// install owns the files and directories this run creates; remove undoes exactly those.
type install struct {
	policyFile, policyDirMade, runDirMade bool
}

// create refuses to touch an existing policy or helper socket, creates the missing directories (policy 0755, run 0700)
// and writes the policy root-owned 0644 (the helper rejects group/other-writable and non-root-owned policies).
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
	os.Remove(runDir + "/acquire.sock")
	if i.runDirMade {
		os.Remove(runDir)
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

func unameRelease() string {
	return strings.TrimSpace(readSmall("/proc/sys/kernel/osrelease"))
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
