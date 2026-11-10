//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
)

// ---- host facts ----

// KernelRelease is the running kernel release string.
func KernelRelease() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// ReadKernelConfig digests /proc/config.gz (when the kernel exports it) and
// reads the three options this engine depends on.
func ReadKernelConfig() KernelConfig {
	raw, err := os.ReadFile("/proc/config.gz")
	if err != nil {
		return KernelConfig{Source: "unavailable: " + errnoName(err)}
	}
	sum := sha256.Sum256(raw)
	out := KernelConfig{Source: "/proc/config.gz", SHA256: hex.EncodeToString(sum[:])}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "CONFIG_PERF_EVENTS="):
			out.PerfEvents = strings.TrimPrefix(line, "CONFIG_PERF_EVENTS=")
		case strings.HasPrefix(line, "CONFIG_FRAME_POINTER="):
			out.FramePointer = strings.TrimPrefix(line, "CONFIG_FRAME_POINTER=")
		case strings.HasPrefix(line, "CONFIG_FTRACE="):
			out.Ftrace = strings.TrimPrefix(line, "CONFIG_FTRACE=")
		}
	}
	return out
}

func errnoName(err error) string {
	switch {
	case errors.Is(err, syscall.EACCES):
		return "EACCES"
	case errors.Is(err, syscall.EPERM):
		return "EPERM"
	case errors.Is(err, syscall.ENOENT):
		return "ENOENT"
	case errors.Is(err, syscall.ENOSYS):
		return "ENOSYS"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return "errno " + strconv.Itoa(int(errno))
	}
	return "error"
}

func mountLine(fstype string) string {
	b, _ := os.ReadFile("/proc/mounts")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[2] == fstype {
			return f[1] + " " + f[2] + " " + f[3]
		}
	}
	return "not mounted"
}

func statusField(name string) string {
	b, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, name+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, name+":"))
		}
	}
	return ""
}

// SnapshotPermissions records the host permission state at run time, including
// the exact tracefs access errno that blocks the scheduler path.
func SnapshotPermissions(caps nativeperf.Capabilities) HostPermissions {
	p := HostPermissions{
		CapEff: statusField("CapEff"), UID: os.Getuid(), Seccomp: statusField("Seccomp"), NoNewPrivs: statusField("NoNewPrivs"),
		TracefsMount: mountLine("tracefs"), CgroupMount: mountLine("cgroup2"), ProcMount: mountLine("proc"),
		CPUProbe: string(caps.Permissions.CPUEventOpen), OffCPUProbe: string(caps.OffCPU),
	}
	if b, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		p.PerfEventParanoid = strings.TrimSpace(string(b))
	} else {
		p.PerfEventParanoid = "unreadable"
	}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		p.LSM = strings.TrimSpace(string(b))
	} else {
		p.LSM = "unavailable: " + errnoName(err)
	}
	var access []string
	if _, err := os.ReadDir("/sys/kernel/tracing"); err != nil {
		access = append(access, "readdir /sys/kernel/tracing: "+errnoName(err))
	} else {
		access = append(access, "readdir /sys/kernel/tracing: ok")
	}
	if f, err := os.Open("/sys/kernel/tracing/events/sched/sched_switch/format"); err != nil {
		access = append(access, "open events/sched/sched_switch/format: "+errnoName(err))
	} else {
		f.Close()
		access = append(access, "open events/sched/sched_switch/format: ok")
	}
	p.TracefsAccess = strings.Join(access, "; ")
	// PROC_PID_INIT_INO: scheduler tracepoint records carry init-namespace PIDs.
	if info, err := os.Stat("/proc/self/ns/pid"); err == nil {
		ino := info.Sys().(*syscall.Stat_t).Ino
		p.PIDNamespace = fmt.Sprintf("inode %d, initial namespace: %v", ino, ino == 0xEFFFFFFC)
	} else {
		p.PIDNamespace = "unreadable: " + errnoName(err)
	}
	return p
}

// FileSHA256 hashes a file.
func FileSHA256(path string) (string, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), len(b), nil
}

// BuildIDOf reads the GNU build ID of an ELF file.
func BuildIDOf(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		return "", errors.New("no GNU build ID note")
	}
	notes, err := note.Data()
	if err != nil || len(notes) < 16 {
		return "", errors.New("invalid build ID note")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(notes), binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	if descSize == 0 || uint64(start)+uint64(descSize) > uint64(len(notes)) {
		return "", errors.New("invalid build ID note bounds")
	}
	return hex.EncodeToString(notes[start : start+descSize]), nil
}

// MonotonicNow is CLOCK_MONOTONIC in nanoseconds.
func MonotonicNow() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// ---- per-process accounting ----

// ProcUsage is a snapshot of one process's resource use.
type ProcUsage struct {
	CPUTicks uint64 // utime+stime in clock ticks
	RSSKiB   uint64
	HWMKiB   uint64
	FDs      int
}

// ReadProc reads /proc/<pid>; pid 0 means this process.
func ReadProc(pid int) (ProcUsage, error) {
	base := "/proc/self"
	if pid != 0 {
		base = "/proc/" + strconv.Itoa(pid)
	}
	var u ProcUsage
	stat, err := os.ReadFile(base + "/stat")
	if err != nil {
		return u, err
	}
	s := string(stat)
	if i := strings.LastIndex(s, ")"); i >= 0 {
		f := strings.Fields(s[i+1:])
		if len(f) > 12 {
			ut, _ := strconv.ParseUint(f[11], 10, 64)
			st, _ := strconv.ParseUint(f[12], 10, 64)
			u.CPUTicks = ut + st
		}
	}
	status, _ := os.ReadFile(base + "/status")
	for _, line := range strings.Split(string(status), "\n") {
		kv := strings.Fields(line)
		if len(kv) >= 2 && (kv[0] == "VmRSS:" || kv[0] == "VmHWM:") {
			n, _ := strconv.ParseUint(kv[1], 10, 64)
			if kv[0] == "VmRSS:" {
				u.RSSKiB = n
			} else {
				u.HWMKiB = n
			}
		}
	}
	if ents, err := os.ReadDir(base + "/fd"); err == nil {
		u.FDs = len(ents)
	}
	return u, nil
}

// PerfFDs counts this process's perf event file descriptors.
func PerfFDs() int {
	ents, _ := os.ReadDir("/proc/self/fd")
	n := 0
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.Contains(l, "perf_event") {
			n++
		}
	}
	return n
}

// ClockTicksPerSecond is USER_HZ (100 on every Linux the harness targets).
const ClockTicksPerSecond = 100

// ---- ground truth ----

// GroundTruthLine is one record of the workload's own ground-truth file.
type GroundTruthLine struct {
	Mode       string `json:"mode"`
	Kind       string `json:"kind"`
	PID        int    `json:"pid"`
	TID        int    `json:"tid"`
	StartNs    uint64 `json:"start_ns"`
	EndNs      uint64 `json:"end_ns"`
	ExpectedNs uint64 `json:"expected_min_ns"`
	Extra      uint64 `json:"extra"`
	Verified   bool   `json:"self_verified"`
	Failures   int    `json:"failures"`
}

// ReadGroundTruth parses a ground-truth file.
func ReadGroundTruth(path string) ([]GroundTruthLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []GroundTruthLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l GroundTruthLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("ground truth line: %w", err)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// ---- workload ----

// Workload is a running acceptance workload process.
type Workload struct {
	Cmd     *exec.Cmd
	PID     int
	Exe     string
	GTPath  string
	Nonce   string
	Target  nativeperf.Target
	BuildID string

	stdin    io.WriteCloser
	out      *lockedBuffer
	mu       sync.Mutex
	tids     map[uint32]bool
	resolver *Resolver
	stopPoll chan struct{}
	pollDone chan struct{}
	waited   chan struct{}
	exit     int
}

// LaunchOptions configure one workload launch.
type LaunchOptions struct {
	Bin       string
	Mode      string
	Seconds   float64
	Dir       string // directory for the ground-truth file
	Nonce     string
	Extra     []string
	Argv      []string // when set: the exact arguments (runtime scripts); Mode/Seconds/Extra are ignored
	ProcExe   bool     // the target binary is whatever /proc/<pid>/exe says (interpreters)
	RunAs     uint32   // when DropToUID is set, run the workload as this uid/gid
	DropToUID bool
}

// NewNonce returns a random per-run privacy canary token (hex).
func NewNonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// LaunchWorkload starts a workload, waits for its ready line and resolves the
// C10 target identity (cgroup, PID namespace, start time, GNU build ID).
func LaunchWorkload(o LaunchOptions) (*Workload, error) {
	exe, err := filepath.Abs(o.Bin)
	if err != nil {
		return nil, err
	}
	if o.Nonce == "" {
		o.Nonce = NewNonce()
	}
	gt := filepath.Join(o.Dir, fmt.Sprintf("groundtruth-%s-%d.jsonl", o.Mode, time.Now().UnixNano()))
	args := append([]string{o.Mode, gt, strconv.FormatFloat(o.Seconds, 'f', 3, 64), o.Nonce}, o.Extra...)
	if len(o.Argv) > 0 {
		args = o.Argv
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "SPQUAL_ENV_CANARY="+o.Nonce)
	if o.DropToUID {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: o.RunAs, Gid: o.RunAs}}
		os.Chmod(o.Dir, 0o777) // the unprivileged workload writes its ground-truth file here
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out := &lockedBuffer{}
	cmd.Stdout = out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := &Workload{Cmd: cmd, PID: cmd.Process.Pid, Exe: exe, GTPath: gt, Nonce: o.Nonce, stdin: stdin, out: out, tids: map[uint32]bool{}, waited: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		w.exit = 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			w.exit = ee.ExitCode()
		} else if err != nil {
			w.exit = -1
		}
		close(w.waited)
	}()
	readyDeadline := time.Now().Add(30 * time.Second)
	for {
		line, ok := out.firstLine()
		if ok {
			if !strings.HasPrefix(strings.TrimSpace(line), "ready ") {
				w.Kill()
				return nil, errors.New("workload did not report ready")
			}
			break
		}
		select {
		case <-w.waited:
			return nil, errors.New("workload exited before it was ready")
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(readyDeadline) {
			w.Kill()
			return nil, errors.New("workload readiness timeout")
		}
	}
	if o.ProcExe {
		link, lerr := os.Readlink(fmt.Sprintf("/proc/%d/exe", w.PID))
		if lerr != nil {
			w.Kill()
			return nil, lerr
		}
		exe, w.Exe = link, link
	}
	if w.Target, err = resolveTarget(w.PID); err != nil {
		w.Kill()
		return nil, err
	}
	if w.BuildID, err = BuildIDOf(exe); err != nil {
		w.Kill()
		return nil, err
	}
	w.Target.AllowedBuildIDs = []string{w.BuildID}
	if w.resolver, err = NewResolver(exe); err != nil {
		w.Kill()
		return nil, err
	}
	w.snapshot()
	w.stopPoll, w.pollDone = make(chan struct{}), make(chan struct{})
	go w.poll()
	return w, nil
}

func resolveTarget(pid int) (nativeperf.Target, error) {
	t, err := nativeperf.ResolveLocalTarget(pid)
	if err != nil {
		return t, err
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return t, err
	}
	group := ""
	for _, line := range strings.Split(string(cg), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return t, errors.New("cgroup v2 identity unavailable")
	}
	st, err := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if err != nil {
		return t, errors.New("cgroup identity not visible")
	}
	t.CgroupID = model.Uint64(st.Sys().(*syscall.Stat_t).Ino)
	return t, nil
}

func (w *Workload) snapshot() {
	if ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.PID)); err == nil {
		w.mu.Lock()
		for _, e := range ents {
			if n, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
				w.tids[uint32(n)] = true
			}
		}
		w.mu.Unlock()
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", w.PID)); err == nil {
		w.resolver.AddMaps(string(b))
	}
}

func (w *Workload) poll() {
	defer close(w.pollDone)
	t := time.NewTicker(40 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-w.stopPoll:
			return
		case <-t.C:
			w.snapshot()
		}
	}
}

// DoneSeen reports whether the workload has finished its measured phase (it
// prints "done" and idles until Finish).
func (w *Workload) DoneSeen() bool {
	w.out.mu.Lock()
	defer w.out.mu.Unlock()
	return bytes.Contains(w.out.buf.Bytes(), []byte("done\n"))
}

// Finish lets an idle workload exit.
func (w *Workload) Finish() { io.WriteString(w.stdin, "exit\n") }

// Go releases the workload to start its measured phase.
func (w *Workload) Go() error {
	_, err := io.WriteString(w.stdin, "go\n")
	return err
}

// KnownThread reports whether tid has been seen as a thread of the workload.
func (w *Workload) KnownThread(tid uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tids[tid]
}

// Resolver is the verifier-side frame lookup over the workload's ELF symbols.
func (w *Workload) Resolver() *Resolver { return w.resolver }

// Wait waits for the workload to exit and returns its exit code.
func (w *Workload) Wait(timeout time.Duration) (int, error) {
	select {
	case <-w.waited:
		w.stopTracking()
		return w.exit, nil
	case <-time.After(timeout):
		return -1, errors.New("workload did not exit in time")
	}
}

func (w *Workload) stopTracking() {
	if w.stopPoll != nil {
		select {
		case <-w.stopPoll:
		default:
			close(w.stopPoll)
		}
		<-w.pollDone
	}
}

// Kill terminates the workload.
func (w *Workload) Kill() {
	if w.Cmd != nil && w.Cmd.Process != nil {
		w.Cmd.Process.Kill()
	}
	select {
	case <-w.waited:
	case <-time.After(5 * time.Second):
	}
	w.stopTracking()
}

// ---- frame resolution ----

type fnSym struct {
	name        string
	start, size uint64
}
type span struct{ start, end, offset uint64 }

// Resolver maps sampled addresses to workload functions using only the ELF
// symbol table and snapshots of /proc/<pid>/maps taken while the process ran
// (several snapshots, so an exec that moves the load base is still resolved by
// the mapping that was live for it). Addresses outside the workload executable
// resolve to the empty string: they are reported unresolved, never invented.
type Resolver struct {
	exeBase string
	fns     []fnSym
	loads   []*elf.Prog
	mu      sync.Mutex
	exe     map[span]bool
	anyExec map[span]string
}

// NewResolver reads the symbol table of exe.
func NewResolver(exe string) (*Resolver, error) {
	f, err := elf.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if errors.Is(err, elf.ErrNoSymbols) {
		syms, err = nil, nil // stripped binary: every frame in it is reported unresolved
	}
	if err != nil {
		return nil, err
	}
	r := &Resolver{exeBase: "/" + filepath.Base(exe), exe: map[span]bool{}, anyExec: map[span]string{}}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Size > 0 {
			r.fns = append(r.fns, fnSym{s.Name, s.Value, s.Size})
		}
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			r.loads = append(r.loads, p)
		}
	}
	return r, nil
}

// AddMaps records the executable mappings in one /proc/<pid>/maps snapshot.
func (r *Resolver) AddMaps(maps string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range strings.Split(maps, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.Contains(f[1], "x") {
			continue
		}
		b := strings.Split(f[0], "-")
		if len(b) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(b[0], 16, 64)
		end, _ := strconv.ParseUint(b[1], 16, 64)
		off, _ := strconv.ParseUint(f[2], 16, 64)
		s := span{start, end, off}
		class := "anonymous_executable"
		if len(f) >= 6 {
			class = "file:" + filepath.Base(f[5])
			if strings.HasPrefix(f[5], "[") {
				class = "special:" + f[5]
			}
		}
		if len(f) >= 6 && strings.HasSuffix(f[5], r.exeBase) {
			r.exe[s] = true
			class = "target_executable"
		}
		r.anyExec[s] = class
	}
}

// InAnyExecutable reports whether ip lies in any executable mapping seen.
func (r *Resolver) InAnyExecutable(ip uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s := range r.anyExec {
		if ip >= s.start && ip < s.end {
			return true
		}
	}
	return false
}

// Classify names the kind of executable mapping ip lies in: the target
// executable, a named file (basename only), an anonymous executable region (JIT
// code) or "unmapped".
func (r *Resolver) Classify(ip uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s, class := range r.anyExec {
		if ip >= s.start && ip < s.end {
			return class
		}
	}
	return "unmapped"
}

// Resolve returns the workload function containing ip, or "".
func (r *Resolver) Resolve(ip uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s := range r.exe {
		if ip < s.start || ip >= s.end {
			continue
		}
		fileOffset := ip - s.start + s.offset
		for _, p := range r.loads {
			if fileOffset >= p.Off && fileOffset < p.Off+p.Filesz {
				v := p.Vaddr + (fileOffset - p.Off)
				for _, c := range r.fns {
					if v >= c.start && v < c.start+c.size {
						return c.name
					}
				}
			}
		}
	}
	return ""
}

// ---- helper process ----

const helperRoleFlag = "--qual-helper-role"

type operatorFile struct {
	PublicKey string              `json:"public_key"`
	Targets   []nativeperf.Target `json:"targets"`
	PeerUID   uint32              `json:"peer_uid"` // the one client uid the helper authorizes
}

// HelperRole runs the real nativeperf.Helper in this process when the command
// line asks for it. Every fixture main calls it first. It returns whether the
// process was a helper (and so must exit with the returned code).
func HelperRole(args []string) (bool, int) {
	if len(args) != 4 || args[0] != helperRoleFlag {
		return false, 0
	}
	raw, err := os.ReadFile(args[2])
	if err != nil {
		return true, ExitUsage
	}
	var op operatorFile
	if json.Unmarshal(raw, &op) != nil {
		return true, ExitUsage
	}
	pub, err := hex.DecodeString(op.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return true, ExitUsage
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: args[1], Net: "unix"})
	if err != nil {
		return true, ExitFail
	}
	os.Chmod(args[1], 0o600)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	h := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "qualification-fixture", UID: op.PeerUID, Revision: 1, PublicKey: pub, Allowlist: op.Targets}, Budget: nativeperf.NewResourceBudget(), Acquire: nativeperf.NewNativeAcquisition}
	fmt.Println("listening")
	h.Serve(ctx, l)
	return true, ExitOK
}

// HelperProc is a real helper running as its own process.
type HelperProc struct {
	Cmd     *exec.Cmd
	PID     int
	Sock    string
	Dir     string
	Targets []nativeperf.Target
	NoFile  uint64
	priv    ed25519.PrivateKey
}

// StartHelper starts the real helper as a child process of this binary. noFile
// > 0 lowers RLIMIT_NOFILE in that child only (FD-exhaustion injection, no
// privilege needed).
func StartHelper(targets []nativeperf.Target, noFile uint64) (*HelperProc, error) {
	return StartHelperAs(targets, noFile, 0, false)
}

// StartHelperAs is StartHelper with an optional privilege drop: when drop is
// set the helper child runs as uid/gid (no capabilities) while its single
// authorized peer stays this process. This is the least-privilege and the
// genuine permission-denial case; nothing on the host is changed.
func StartHelperAs(targets []nativeperf.Target, noFile uint64, uid uint32, drop bool) (*HelperProc, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "soundpost-qual-")
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(operatorFile{PublicKey: hex.EncodeToString(pub), Targets: targets, PeerUID: uint32(os.Getuid())})
	opFile := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(opFile, raw, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	h := &HelperProc{Sock: filepath.Join(dir, "acquire.sock"), Dir: dir, Targets: targets, NoFile: noFile, priv: priv}
	switch {
	case drop:
		// the dropped helper needs to read its operator file, execute a copy of this
		// binary (go run keeps it in a private build directory) and create its socket
		copyPath := filepath.Join(dir, "helper-bin")
		bin, err := os.ReadFile(self)
		if err != nil || os.WriteFile(copyPath, bin, 0o755) != nil || os.Chmod(opFile, 0o644) != nil || os.Chmod(dir, 0o777) != nil {
			os.RemoveAll(dir)
			return nil, errors.New("could not stage the unprivileged helper")
		}
		h.Cmd = exec.Command(copyPath, helperRoleFlag, h.Sock, opFile, "x")
		h.Cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, NoSetGroups: false}}
	case noFile > 0:
		h.Cmd = exec.Command("sh", "-c", fmt.Sprintf(`ulimit -n %d && exec "$0" "$@"`, noFile), self, helperRoleFlag, h.Sock, opFile, "x")
	default:
		h.Cmd = exec.Command(self, helperRoleFlag, h.Sock, opFile, "x")
	}
	out, err := h.Cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := h.Cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	h.PID = h.Cmd.Process.Pid
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case s := <-line:
		if s != "listening" {
			h.Stop()
			return nil, errors.New("helper process did not start")
		}
	case <-time.After(20 * time.Second):
		h.Stop()
		return nil, errors.New("helper start timeout")
	}
	return h, nil
}

// Request signs a capture request for the helper's targets.
func (h *HelperProc) Request(cfg nativeperf.Config, ttl time.Duration, mode nativeperf.CaptureMode) (nativeperf.CaptureRequest, error) {
	a, err := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "qualification-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(ttl).Unix(), Targets: h.Targets, Config: cfg, Mode: mode}, h.priv)
	return nativeperf.CaptureRequest{Authorization: a, Targets: h.Targets, Config: cfg, Mode: mode}, err
}

// Stop terminates the helper child and removes its directory.
func (h *HelperProc) Stop() {
	if h.Cmd != nil && h.Cmd.Process != nil {
		h.Cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { h.Cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			h.Cmd.Process.Kill()
			<-done
		}
	}
	os.RemoveAll(h.Dir)
}

// ---- capture ----

// CaptureOptions configure one capture over the helper socket.
type CaptureOptions struct {
	Config      nativeperf.Config
	Duration    time.Duration
	Needles     [][]byte      // privacy canaries searched in every socket frame
	StallAfter  int           // stop reading after this many events (loss injection)
	StallFor    time.Duration // ... for this long
	OnReady     func()        // called once the helper reports ready (start the workload)
	MaxEvents   int
	ReadTimeout time.Duration
	Mode        nativeperf.CaptureMode // default ModeCPU; ModeCPUOffCPU adds the scheduler path
	StopWhen    func() bool            // polled every 100 ms: end the capture (scheduler mode sends the fixed stop message and drains)
}

// CaptureResult is everything one capture observed on the helper socket.
type CaptureResult struct {
	Ready       bool
	ErrorCode   string // closed helper code from a refusal or an aborted stream
	ReadError   string
	Events      []nativeperf.SanitizedEvent
	Frames      int
	Bytes       int
	NeedleHits  int
	LossEvents  int
	LostSamples uint64
	Complete    bool
	Proofs      []nativeperf.AcquisitionProof
	StartedNs   uint64
	EndedNs     uint64
}

type wireReply struct {
	Error    string                     `json:"error"`
	Ready    bool                       `json:"ready"`
	Event    *nativeperf.SanitizedEvent `json:"event"`
	Proof    *nativeperf.AcquisitionProof
	Complete bool `json:"complete"`
}

func writeFrame(c net.Conn, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, err = c.Write(length[:]); err != nil {
		return err
	}
	_, err = c.Write(payload)
	return err
}

func readFrame(c net.Conn) (reply wireReply, raw []byte, err error) {
	var length [4]byte
	if _, err = io.ReadFull(c, length[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 64<<10 {
		err = errors.New("invalid helper frame")
		return
	}
	raw = make([]byte, n)
	if _, err = io.ReadFull(c, raw); err != nil {
		return
	}
	if e := json.Unmarshal(raw, &reply); e != nil {
		err = errors.New("helper frame undecodable")
	}
	return
}

// Capture sends a signed request to the helper and reads its sanitized stream.
// The client decoder is this file's own, not the code under test.
func Capture(ctx context.Context, h *HelperProc, o CaptureOptions) CaptureResult {
	var res CaptureResult
	mode := o.Mode
	if mode == "" {
		mode = nativeperf.ModeCPU
		o.Mode = mode
	}
	req, err := h.Request(o.Config, 5*time.Minute, mode)
	if err != nil {
		res.ReadError = "sign request"
		return res
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.Sock, Net: "unix"})
	if err != nil {
		res.ReadError = "helper unreachable"
		return res
	}
	defer conn.Close()
	res.StartedNs = MonotonicNow()
	if err = writeFrame(conn, req); err != nil {
		res.ReadError = "write request"
		return res
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	scan := func(raw []byte) {
		res.Frames++
		res.Bytes += len(raw) + 4
		res.NeedleHits += CountNeedles(raw, o.Needles)
	}
	ready, raw, err := readFrame(conn)
	if raw != nil {
		scan(raw)
	}
	if err != nil || !ready.Ready || ready.Error != "" {
		res.ErrorCode = ready.Error
		if res.ErrorCode == "" {
			res.ReadError = "no ready frame"
		}
		res.EndedNs = MonotonicNow()
		return res
	}
	res.Ready = true
	if o.OnReady != nil {
		o.OnReady()
	}
	type frameMsg struct {
		reply wireReply
		raw   []byte
		err   error
	}
	frames := make(chan frameMsg, 16)
	quit := make(chan struct{})
	defer close(quit)
	conn.SetReadDeadline(time.Time{})
	go func() {
		for {
			reply, raw, err := readFrame(conn)
			select {
			case frames <- frameMsg{reply, raw, err}:
			case <-quit:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	limit := time.Now().Add(o.Duration)
	sched := o.Mode == nativeperf.ModeCPUOffCPU
	stopping, stalled := false, false
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
			if time.Now().After(limit) {
				break loop
			}
			if !stopping && o.StopWhen != nil && o.StopWhen() {
				if !sched {
					break loop
				}
				// the fixed stop message: the helper then drains and sends the final proof
				if err := writeFrame(conn, struct {
					Stop bool `json:"stop"`
				}{true}); err != nil {
					res.ReadError = "write stop: " + err.Error()
					break loop
				}
				stopping = true
				limit = time.Now().Add(20 * time.Second)
			}
		case m := <-frames:
			if m.raw != nil {
				scan(m.raw)
			}
			if m.err != nil {
				if !res.Complete {
					if errors.Is(m.err, io.EOF) {
						res.ReadError = "stream closed by helper"
					} else {
						res.ReadError = m.err.Error()
					}
				}
				break loop
			}
			reply := m.reply
			switch {
			case reply.Error != "":
				res.ErrorCode = reply.Error
				break loop
			case reply.Complete:
				res.Complete = true
			case reply.Proof != nil:
				p := *reply.Proof
				p.CPUs = append([]uint32(nil), p.CPUs...)
				res.Proofs = append(res.Proofs, p)
			case reply.Event != nil:
				ev := *reply.Event
				if ev.Loss != nil {
					res.LossEvents++
					res.LostSamples += uint64(ev.Loss.Count)
				}
				if o.MaxEvents == 0 || len(res.Events) < o.MaxEvents {
					res.Events = append(res.Events, ev)
				}
				if o.StallAfter > 0 && !stalled && len(res.Events) >= o.StallAfter {
					stalled = true
					time.Sleep(o.StallFor)
				}
			}
		}
	}
	res.EndedNs = MonotonicNow()
	return res
}

// CountNeedles returns how many of the privacy canaries occur in one raw frame.
func CountNeedles(raw []byte, needles [][]byte) int {
	n := 0
	for _, needle := range needles {
		if len(needle) > 0 && bytes.Contains(raw, needle) {
			n++
		}
	}
	return n
}

// ---- derived measurements ----

// StackStats summarizes frame resolution over the CPU samples of one capture.
type StackStats struct {
	CPUSamples        int
	HotSamples        int // sample IP resolves to the named hot function
	HotInChain        int // hot function anywhere in IP+callchain
	ChainsWithHot     int
	Samples3Frames    int
	ResolvedFrames    int            // frames that resolved to a workload function
	UnresolvedFrames  int            // frames outside the workload executable (libc, vdso, unknown)
	FunctionSamples   map[string]int // appearances of each workload function in any chain
	InWindow          int            // samples whose monotonic time lies inside a ground-truth CPU phase
	TruncatedSamples  int
	EmptyChainSamples int
	ExpectedPresent   map[string]int // per expected function: samples whose chain contains it
	NonLeaf           map[string]int // workload functions found at callchain positions after the leaf
}

// Analyze resolves every CPU sample against the workload's ELF symbols. hot is
// the function name that must appear; expected lists the true call chain
// (leaf first); windows are the ground-truth CPU-phase intervals (ns).
func Analyze(events []nativeperf.SanitizedEvent, r *Resolver, hot string, expected []string, windows [][2]uint64) StackStats {
	st := StackStats{FunctionSamples: map[string]int{}, ExpectedPresent: map[string]int{}, NonLeaf: map[string]int{}}
	const slack = 100_000_000
	for _, e := range events {
		s := e.CPUEvent
		if e.Kind != nativeperf.EventCPU || s == nil {
			continue
		}
		st.CPUSamples++
		if s.Truncated != "" {
			st.TruncatedSamples++
		}
		t := uint64(e.Time)
		for _, w := range windows {
			if t+slack >= w[0] && t <= w[1]+slack {
				st.InWindow++
				break
			}
		}
		names := map[string]bool{}
		seenNonLeaf := map[string]bool{}
		frames := 0
		consider := func(ip uint64) {
			frames++
			if n := r.Resolve(ip); n != "" {
				names[n] = true
				st.ResolvedFrames++
			} else {
				st.UnresolvedFrames++
			}
		}
		consider(uint64(s.IP))
		if r.Resolve(uint64(s.IP)) == hot {
			st.HotSamples++
		}
		for _, c := range s.Callchain {
			if c.Context != "" || c.IP == 0 || c.IP == s.IP && frames == 1 {
				continue
			}
			consider(uint64(c.IP))
			if n := r.Resolve(uint64(c.IP)); n != "" {
				seenNonLeaf[n] = true
			}
		}
		for n := range seenNonLeaf {
			st.NonLeaf[n]++
		}
		if len(s.Callchain) == 0 {
			st.EmptyChainSamples++
		}
		if frames >= 3 {
			st.Samples3Frames++
		}
		if names[hot] {
			st.ChainsWithHot++
		}
		for n := range names {
			st.FunctionSamples[n]++
		}
		for _, x := range expected {
			if names[x] {
				st.ExpectedPresent[x]++
			}
		}
	}
	return st
}

// Coverage is the fraction of the expected true frames that were resolved in
// the average sample chain: sum over expected functions of the share of
// samples containing them, divided by the number of expected functions.
func (s StackStats) Coverage(expected []string) float64 {
	if s.CPUSamples == 0 || len(expected) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range expected {
		sum += float64(s.ExpectedPresent[x]) / float64(s.CPUSamples)
	}
	return sum / float64(len(expected))
}

// Percentiles returns p50 and p99 of a gap list.
func Percentiles(v []uint64) (p50, p99 uint64) {
	if len(v) == 0 {
		return
	}
	s := append([]uint64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2], s[(len(s)*99)/100]
}

// SampleGaps returns per-thread inter-sample gaps in ns.
func SampleGaps(events []nativeperf.SanitizedEvent) []uint64 {
	last := map[uint32]uint64{}
	var gaps []uint64
	for _, e := range events {
		if e.CPUEvent == nil {
			continue
		}
		if p, ok := last[e.Task.TID]; ok && uint64(e.Time) >= p {
			gaps = append(gaps, uint64(e.Time)-p)
		}
		last[e.Task.TID] = uint64(e.Time)
	}
	return gaps
}

// GOARCHName is the architecture label used in reports.
func GOARCHName() string { return runtime.GOARCH }

// lockedBuffer collects a child process stdout; the exec package copies into it
// and waits for that copy, so everything is available once the child has exited.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) firstLine() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.buf.Bytes()
	if i := bytes.IndexByte(data, 10); i >= 0 {
		return string(data[:i]), true
	}
	return "", false
}

// Output returns everything the workload printed after its ready line (call
// after Wait).
func (w *Workload) Output() string {
	w.out.mu.Lock()
	defer w.out.mu.Unlock()
	data := w.out.buf.Bytes()
	if i := bytes.IndexByte(data, 10); i >= 0 {
		return string(data[i+1:])
	}
	return ""
}

// Correlation is the outcome of replaying one scheduler capture through the
// committed per-session Correlator.
type Correlation struct {
	Intervals     []nativeperf.Interval
	Err           string // empty on success
	ConsumeErrors int
	FirstError    string
	SwitchEvents  int
	WakeupEvents  int
	CPUSamples    int
	LossEvents    int
	CPUs          int
	FinalThrough  uint64
}

// Correlate configures a Correlator from the capture initial topology proof,
// consumes every event, reports the final proof for every CPU and finalizes.
// Nothing is inferred: a capture without both proofs yields an error, never
// intervals.
func Correlate(res CaptureResult, cfg nativeperf.Config) Correlation {
	var out Correlation
	var initial, final *nativeperf.AcquisitionProof
	for i := range res.Proofs {
		if res.Proofs[i].Final {
			final = &res.Proofs[i]
		} else if initial == nil {
			initial = &res.Proofs[i]
		}
	}
	if initial == nil || final == nil {
		out.Err = "capture has no initial and final acquisition proof"
		return out
	}
	out.CPUs = len(initial.CPUs)
	out.FinalThrough = uint64(final.Through)
	c := nativeperf.NewCorrelator(cfg)
	if err := c.Configure(initial.Domain, initial.CPUs, 16<<20); err != nil {
		out.Err = "configure: " + err.Error()
		return out
	}
	for _, e := range res.Events {
		switch {
		case e.Switch != nil:
			out.SwitchEvents++
		case e.Wakeup != nil:
			out.WakeupEvents++
		case e.CPUEvent != nil:
			out.CPUSamples++
		case e.Loss != nil:
			out.LossEvents++
		}
		got, err := c.Consume(e)
		out.Intervals = append(out.Intervals, got...)
		if err != nil {
			out.ConsumeErrors++
			if out.FirstError == "" {
				out.FirstError = err.Error()
			}
		}
	}
	for _, cpu := range final.CPUs {
		if err := c.ReportProgress(cpu, final.Through); err != nil {
			out.Err = "report progress: " + err.Error()
			return out
		}
	}
	got, err := c.Finalize(final.Through)
	out.Intervals = append(out.Intervals, got...)
	if err != nil {
		out.Err = "finalize: " + err.Error()
	}
	return out
}
