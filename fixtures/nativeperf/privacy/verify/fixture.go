//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
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
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"soundpost/fixtures/nativeperf/privacy/privnode"
	"soundpost/fixtures/nativeperf/privacy/scan"
	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
)

type stageStat struct {
	Buffers int `json:"buffers"`
	Bytes   int `json:"bytes"`
}
type cpuRow struct {
	Samples          int      `json:"samples"`
	HotFunction      int      `json:"samples_in_hot_function"`
	DeepStacks       int      `json:"stacks_with_3_or_more_frames"`
	ResolvedCallers  int      `json:"frames_resolved_to_workload_callers"`
	ThreadsObserved  int      `json:"threads_observed"`
	LossEvents       int      `json:"loss_events"`
	SymbolsResolved  []string `json:"policy_authorized_symbols_resolved"`
	GenuineNumericOK bool     `json:"period_rate_method_numeric_ok"`
}
type schedulerRow struct {
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Switches int    `json:"switch_events"`
	Wakeups  int    `json:"wakeup_events"`
}
type exportRow struct {
	Batches          int  `json:"batches_admitted_over_real_route"`
	QueueObserved    bool `json:"exporter_queue_observed"`
	CompressedBytes  int  `json:"-"`
	StoragePositive  bool `json:"storage_positive_control_observed"`
	StorageFiles     int  `json:"storage_files_scanned"`
	StorageBytes     int  `json:"storage_bytes_scanned"`
	ReadSamples      int  `json:"read_samples"`
	ReadPages        int  `json:"read_pages"`
	ReadCapabilities int  `json:"read_capabilities"`
	ArtifactLinks    int  `json:"artifact_links_unavailable_without_grant"`
}
type drillRow struct {
	Requested      bool   `json:"requested"`
	Result         string `json:"result,omitempty"`
	ReleasedWithin int64  `json:"released_within_ms,omitempty"`
	Detail         string `json:"detail,omitempty"`
}
type cleanupRow struct {
	PerfFDsBefore    int `json:"perf_fds_before"`
	PerfFDsAfter     int `json:"perf_fds_after"`
	FDsBefore        int `json:"open_fds_before"`
	FDsAfter         int `json:"open_fds_after"`
	PerfMappingsLeft int `json:"perf_mappings_after"`
	DumpFiles        int `json:"dump_files_found"`
}
type report struct {
	Policy       string                  `json:"policy"`
	Endpoint     string                  `json:"endpoint"`
	Kernel       string                  `json:"kernel"`
	Paranoid     string                  `json:"perf_event_paranoid"`
	Capabilities nativeperf.Capabilities `json:"capabilities"`
	CPU          cpuRow                  `json:"cpu"`
	Scheduler    schedulerRow            `json:"scheduler"`
	Export       exportRow               `json:"export"`
	Stages       map[string]stageStat    `json:"stages"`
	Violations   []string                `json:"canary_violations"`
	NegativeCtl  bool                    `json:"negative_control"`
	PeerDeath    drillRow                `json:"peer_death"`
	HelperCrash  drillRow                `json:"helper_crash"`
	Syscalls     *syscallReport          `json:"syscall_audit,omitempty"`
	Cleanup      cleanupRow              `json:"cleanup"`
	NotRun       []string                `json:"not_run"`
	RSSMiB       uint64                  `json:"verifier_rss_mib_at_helper_start"`
	Failures     []string                `json:"failures"`
}

// fixtureEnv holds the per-run nonce, detector and audit; only this verifier
// knows the sentinel values.
type fixtureEnv struct {
	policy scan.Policy
	nonce  string
	audit  *scan.PrivacyAudit
	mu     sync.Mutex
	diag   []string
}

func newFixtureEnv(path string) (*fixtureEnv, error) {
	p, e := scan.LoadPolicy(path)
	if e != nil {
		return nil, errors.New("privacy policy unreadable")
	}
	raw := make([]byte, p.NonceHexLen/2)
	if _, e = rand.Read(raw); e != nil {
		return nil, e
	}
	nonce := hex.EncodeToString(raw)
	d, e := scan.NewDetector(p, nonce)
	if e != nil {
		return nil, e
	}
	return &fixtureEnv{policy: p, nonce: nonce, audit: scan.NewPrivacyAudit(d)}, nil
}
func (e *fixtureEnv) sentinel(kind string) string {
	v, err := e.policy.Sentinel(kind, e.nonce)
	if err != nil {
		panic(err)
	}
	return v
}

// observe audits one sanitized buffer; violations are collected (content-free).
func (e *fixtureEnv) observe(stage scan.Stage, b []byte) { _ = e.audit.Observe(stage, b) }

// diagnostic records fixture/product diagnostic text and audits it.
func (e *fixtureEnv) diagnostic(s string) {
	e.mu.Lock()
	e.diag = append(e.diag, s)
	e.mu.Unlock()
	e.observe(scan.StageDiagnostics, []byte(s))
}

func countFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	return len(entries)
}
func perfFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	n := 0
	for _, entry := range entries {
		if link, err := os.Readlink("/proc/self/fd/" + entry.Name()); err == nil && strings.Contains(link, "perf_event") {
			n++
		}
	}
	return n
}
func perfMappings() int {
	b, _ := os.ReadFile("/proc/self/maps")
	return strings.Count(string(b), "perf_event")
}
func paranoid() string {
	b, e := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if e != nil {
		return "unreadable"
	}
	return strings.TrimSpace(string(b))
}

// workload is the running canary and everything the verifier derived from it.
type workload struct {
	cmd    *exec.Cmd
	pid    int
	exe    string
	root   string
	target nativeperf.Target
}

func (w *workload) stop() {
	if w != nil && w.cmd != nil && w.cmd.Process != nil {
		w.cmd.Process.Kill()
		w.cmd.Wait()
	}
	if w != nil && w.root != "" {
		os.RemoveAll(w.root)
	}
}

func launchWorkload(env *fixtureEnv, workloadPath string) (*workload, error) {
	src, e := os.ReadFile(workloadPath)
	if e != nil {
		return nil, errors.New("workload binary unreadable (compile canary.c first)")
	}
	root, e := os.MkdirTemp("", "soundpost-privacy-")
	if e != nil {
		return nil, e
	}
	dir := filepath.Join(root, env.sentinel("path"))
	if e = os.MkdirAll(dir, 0o700); e != nil {
		return nil, e
	}
	w := &workload{root: root, exe: filepath.Join(dir, "canary")}
	if e = os.WriteFile(w.exe, src, 0o700); e != nil {
		return w, e
	}
	cmd := exec.Command(w.exe, env.sentinel("argv"), "0")
	cmd.Env = append(os.Environ(), "SPCNRY_ENV="+env.sentinel("env"), "TMPDIR="+root)
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return w, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return w, e
	}
	if e = cmd.Start(); e != nil {
		return w, e
	}
	w.cmd, w.pid = cmd, cmd.Process.Pid
	io.WriteString(stdin, "INPUT GET /search?q="+env.sentinel("input")+"\n")
	io.WriteString(stdin, "DB SELECT secret FROM vault WHERE owner='"+env.sentinel("db")+"'\n")
	stdin.Close()
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ready ") {
			return w, errors.New("workload did not place its sentinels")
		}
		placed := strings.Split(strings.TrimPrefix(line, "ready "), ",")
		for _, k := range env.policy.Kinds {
			found := false
			for _, p := range placed {
				found = found || p == k.ID
			}
			if !found {
				return w, errors.New("workload did not place sentinel kind " + k.ID)
			}
		}
	case <-time.After(15 * time.Second):
		return w, errors.New("workload readiness timeout")
	}
	target, e := nativeperf.ResolveLocalTarget(w.pid)
	if e != nil {
		return w, e
	}
	cg, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", w.pid))
	if e != nil {
		return w, e
	}
	group := ""
	for _, line := range strings.Split(string(cg), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return w, errors.New("cgroup v2 identity unavailable")
	}
	st, e := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if e != nil {
		return w, errors.New("cgroup identity not visible")
	}
	target.CgroupID = model.Uint64(st.Sys().(*syscall.Stat_t).Ino)
	f, e := elf.Open(w.exe)
	if e != nil {
		return w, e
	}
	defer f.Close()
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		return w, errors.New("GNU build ID required")
	}
	notes, e := note.Data()
	if e != nil || len(notes) < 16 {
		return w, errors.New("invalid build ID note")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(notes), binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	if descSize == 0 || uint64(start)+uint64(descSize) > uint64(len(notes)) {
		return w, errors.New("invalid build ID note bounds")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+descSize])}
	w.target = target
	return w, nil
}

// symbolizer maps a sampled instruction address to a function of the workload
// using only its ELF symbol table and its executable mapping (verifier side).
func symbolizer(w *workload) (func(uint64) string, error) {
	f, e := elf.Open(w.exe)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	symbols, e := f.Symbols()
	if e != nil {
		return nil, e
	}
	type fn struct {
		name        string
		start, size uint64
	}
	var fns []fn
	for _, s := range symbols {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Size > 0 {
			fns = append(fns, fn{s.Name, s.Value, s.Size})
		}
	}
	var loads []*elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loads = append(loads, p)
		}
	}
	maps, e := os.ReadFile(fmt.Sprintf("/proc/%d/maps", w.pid))
	if e != nil {
		return nil, e
	}
	type span struct{ start, end, offset uint64 }
	var spans []span
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") || !strings.HasSuffix(fields[5], "/canary") {
			continue
		}
		bounds := strings.Split(fields[0], "-")
		start, _ := strconv.ParseUint(bounds[0], 16, 64)
		end, _ := strconv.ParseUint(bounds[1], 16, 64)
		offset, _ := strconv.ParseUint(fields[2], 16, 64)
		spans = append(spans, span{start, end, offset})
	}
	if len(spans) == 0 {
		return nil, errors.New("workload executable mapping not found")
	}
	return func(ip uint64) string {
		for _, s := range spans {
			if ip < s.start || ip >= s.end {
				continue
			}
			fileOffset := ip - s.start + s.offset
			for _, p := range loads {
				if fileOffset >= p.Off && fileOffset < p.Off+p.Filesz {
					vaddr := p.Vaddr + (fileOffset - p.Off)
					for _, candidate := range fns {
						if vaddr >= candidate.start && vaddr < candidate.start+candidate.size {
							return candidate.name
						}
					}
				}
			}
		}
		return ""
	}, nil
}

// ---- helper wiring ----

type helperHandle struct {
	sock     string
	dir      string
	cancel   context.CancelFunc
	done     chan struct{}
	listener *net.UnixListener
	signer   ed25519.PrivateKey
	public   ed25519.PublicKey
	target   nativeperf.Target
	cfg      nativeperf.Config
	mode     nativeperf.CaptureMode
	active   chan *nativeperf.ProfileSource
}

// auditedSource observes every sanitized event at the owned staging boundary,
// immediately before the helper puts it on the socket. With contaminate set it is
// the NEGATIVE CONTROL: a careless collector that copies the thread command name
// (read from /proc, as a naive profiler would) into the clock-domain host label.
type auditedSource struct {
	inner       *nativeperf.ProfileSource
	env         *fixtureEnv
	contaminate bool
}

func (s *auditedSource) Next(ctx context.Context) (nativeperf.SanitizedEvent, error) {
	item, e := s.NextItem(ctx)
	if e != nil {
		return nativeperf.SanitizedEvent{}, e
	}
	if item.Event == nil {
		return nativeperf.SanitizedEvent{}, nativeperf.ErrProgressRequired
	}
	return *item.Event, nil
}
func (s *auditedSource) NextItem(ctx context.Context) (nativeperf.AcquisitionItem, error) {
	item, e := s.inner.NextItem(ctx)
	if e == nil && item.Event != nil {
		if s.contaminate && item.Event.Task.TID != 0 {
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/comm", item.Event.Task.TGID, item.Event.Task.TID)); err == nil {
				label := []byte(strings.TrimSpace(string(b)))
				for i, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
						label[i] = '-'
					}
				}
				item.Event.Domain.HostID = string(label)
			}
		}
		raw, _ := json.Marshal(item.Event)
		s.env.observe(scan.StageStaging, raw)
	}
	return item, e
}
func (s *auditedSource) Stop() error  { return s.inner.Stop() }
func (s *auditedSource) Close() error { return s.inner.Close() }

type cpuOnlySource struct {
	inner nativeperf.EventSource
	env   *fixtureEnv
}

func (s *cpuOnlySource) Next(ctx context.Context) (nativeperf.SanitizedEvent, error) {
	event, e := s.inner.Next(ctx)
	if e == nil {
		raw, _ := json.Marshal(event)
		s.env.observe(scan.StageStaging, raw)
	}
	return event, e
}
func (s *cpuOnlySource) Close() error { return s.inner.Close() }

type helperKind int

const (
	helperProfile helperKind = iota // ProfileSource: mapping readers + export reservations (real export path)
	helperCPU                       // bare CPU acquisition (drills)
)

func newOperator(w *workload, mode nativeperf.CaptureMode) (*helperHandle, error) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	return &helperHandle{public: public, signer: private, target: w.target, cfg: nativeperf.DefaultConfig(1), mode: mode, active: make(chan *nativeperf.ProfileSource, 4)}, nil
}

func (h *helperHandle) request(ttl time.Duration) (nativeperf.CaptureRequest, error) {
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(ttl).Unix(), Targets: []nativeperf.Target{h.target}, Config: h.cfg, Mode: h.mode}, h.signer)
	return nativeperf.CaptureRequest{Authorization: grant, Targets: []nativeperf.Target{h.target}, Config: h.cfg, Mode: h.mode}, e
}

func (h *helperHandle) start(env *fixtureEnv, kind helperKind, contaminate bool) error {
	dir, e := os.MkdirTemp("", "soundpost-privacy-sock-")
	if e != nil {
		return e
	}
	h.dir = dir
	h.sock = filepath.Join(dir, "acquire.sock")
	h.listener, e = net.ListenUnix("unix", &net.UnixAddr{Name: h.sock, Net: "unix"})
	if e != nil {
		return e
	}
	if e = os.Chmod(h.sock, 0o600); e != nil {
		return e
	}
	acquire := func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, r *nativeperf.Reservation) (nativeperf.EventSource, error) {
		if kind == helperCPU {
			s, e := nativeperf.NewCPUAcquisition(ctx, a, c, r)
			if e != nil {
				return nil, e
			}
			return &cpuOnlySource{inner: s, env: env}, nil
		}
		p := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
		p.AllowMappedELF = true
		s, e := nativeperf.NewProfileAcquisition(ctx, a, c, r, p)
		if e != nil {
			return nil, e
		}
		select {
		case h.active <- s:
		default:
		}
		return &auditedSource{inner: s, env: env, contaminate: contaminate}, nil
	}
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: h.public, Allowlist: []nativeperf.Target{h.target}}, Budget: nativeperf.NewResourceBudget(), Acquire: acquire}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan struct{})
	go func() { helper.Serve(ctx, h.listener); close(h.done) }()
	return nil
}

func (h *helperHandle) stop() {
	if h.cancel != nil {
		h.cancel()
		<-h.done
	}
	if h.dir != "" {
		os.RemoveAll(h.dir)
	}
}

// ---- helper wire protocol, client side (own decoder: the fixture must not share
// the code under test) ----

type wireReply struct {
	Error    string                     `json:"error"`
	Ready    bool                       `json:"ready"`
	Event    *nativeperf.SanitizedEvent `json:"event"`
	Proof    *nativeperf.AcquisitionProof
	Complete bool `json:"complete"`
}

func writeFrame(c net.Conn, v any) error {
	payload, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, e = c.Write(length[:]); e != nil {
		return e
	}
	_, e = c.Write(payload)
	return e
}

// readFrame reads one frame, audits the exact bytes at the socket stage and decodes it.
func (e *fixtureEnv) readFrame(c net.Conn) (wireReply, error) {
	var length [4]byte
	var reply wireReply
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return reply, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 64<<10 {
		return reply, errors.New("invalid helper frame")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c, payload); err != nil {
		return reply, err
	}
	e.observe(scan.StageSocket, append(length[:], payload...))
	if err := json.Unmarshal(payload, &reply); err != nil {
		return reply, errors.New("helper frame undecodable")
	}
	return reply, nil
}

func monotonicNow() (model.MonoNano, error) {
	var ts syscall.Timespec
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0, errors.New("clock unavailable")
	}
	return model.MonoNano(uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)), nil
}
func fixedID(label, value string) model.ID {
	h := sha256.Sum256([]byte("soundpost-privacy-fixture-v1\x00" + label + "\x00" + value))
	var id model.ID
	copy(id[:], h[:])
	return id
}

// ---- the fixture ----

func runFixture(o options) (*report, int, error) {
	env, e := newFixtureEnv(o.policyPath)
	if e != nil {
		return nil, exitUsage, e
	}
	rep := &report{Policy: o.policyPath, Kernel: kernelRelease(), Paranoid: paranoid(), Stages: map[string]stageStat{}, NegativeCtl: o.negativeControl}
	rep.Cleanup.PerfFDsBefore, rep.Cleanup.FDsBefore = perfFDs(), countFDs()
	failed := func(format string, args ...any) { rep.Failures = append(rep.Failures, fmt.Sprintf(format, args...)) }
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	if preset := os.Getenv(o.endpointEnv); preset != "" {
		return rep, exitUsage, errors.New("an external endpoint cannot be used: this fixture needs the node's admin and read composition in process; unset " + o.endpointEnv + " to use the real in-process node")
	}
	if e = probeRealPerf(); e != nil {
		rep.NotRun = append(rep.NotRun, "real acquisition: "+e.Error())
		return rep, exitFail, errors.New("real perf_event_open denied: " + e.Error() + " (kernel.perf_event_paranoid=" + rep.Paranoid + ")")
	}
	w, e := launchWorkload(env, o.workload)
	defer w.stop()
	if e != nil {
		return rep, exitFail, e
	}
	symbol, e := symbolizer(w)
	if e != nil {
		return rep, exitFail, e
	}
	caps, probeErr := nativeperf.Probe(ctx, []nativeperf.Target{{PIDNamespace: w.target.PIDNamespace, TGID: w.target.TGID, ProcessStart: w.target.ProcessStart}})
	rep.Capabilities = caps
	if raw, err := json.Marshal(caps); err == nil {
		env.observe(scan.StageDiagnostics, raw)
	}
	if probeErr != nil {
		env.diagnostic(probeErr.Error())
	}
	mode := nativeperf.ModeCPU
	rep.Scheduler = schedulerRow{Status: string(caps.OffCPU)}
	if caps.OffCPU == nativeperf.Supported {
		mode = nativeperf.ModeCPUOffCPU
	} else {
		reason := "unsupported"
		if len(caps.Reasons) > 0 {
			reason = string(caps.Reasons[0])
		}
		rep.Scheduler.Reason = reason
		if _, err := os.Open("/sys/kernel/tracing/events/sched/sched_switch/format"); err != nil {
			rep.Scheduler.Reason += "; open sched_switch format: " + strings.TrimPrefix(err.Error(), "open /sys/kernel/tracing/events/sched/sched_switch/format: ")
		}
		rep.NotRun = append(rep.NotRun, "scheduler acquisition (sched_switch/wakeup tracepoints) and the real scheduler privacy rows: "+rep.Scheduler.Reason)
	}
	// ORDER MATTERS for the helper's own 64MiB accounting: it charges the resident
	// memory of itself and of its exporter peer. Acquisition and the process drills
	// therefore run first, while this process is small; the heavy node starts only
	// afterwards for export, storage and read.
	h, e := newOperator(w, mode)
	if e != nil {
		return rep, exitFail, e
	}
	defer h.stop()
	if e = h.start(env, helperProfile, o.negativeControl); e != nil {
		return rep, exitFail, e
	}
	rep.RSSMiB = rssMiB()
	captured, e := captureSession(ctx, env, h, o, symbol, rep)
	if e != nil {
		failed("real capture: %v", e)
	}
	h.stop()
	if _, ok := waitPerfFDs(rep.Cleanup.PerfFDsBefore, 5*time.Second); !ok {
		failed("perf FDs not released after the capture session")
	}
	if e == nil && o.injectPeerDeath {
		runPeerDeath(env, w, o, rep)
	}
	if e == nil && o.injectHelperEnd {
		runHelperCrash(env, w, o, rep)
	}
	if e == nil {
		debug.FreeOSMemory()
		n, nodeErr := privnode.Start(ctx, filepath.Join(w.root, "node"))
		if nodeErr != nil {
			failed("%v", nodeErr)
		} else {
			defer n.Close()
			rep.Endpoint = "in_process_real_node_tls_http (" + o.endpointEnv + " unset; real appcore + httpapi, batches over POST /ingest/v1/batches)"
			os.Setenv(o.endpointEnv, n.Server.URL)
			if err := exportAndRead(ctx, env, n, captured, rep, caps); err != nil {
				failed("export/read: %v", err)
			}
		}
	}
	return finishReport(env, rep, o, failed)
}

func kernelRelease() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// probeRealPerf opens (and closes) the fixed CPU software event on this thread.
func probeRealPerf() error {
	type attr struct {
		Type, Size               uint32
		Config, Freq, SampleType uint64
		ReadFormat, Flags        uint64
		Wakeup, BPType           uint32
		Config1                  uint64
	}
	a := attr{Type: 1, Size: 64, Freq: 99, SampleType: 1 | 2 | 4 | 32, Flags: 1 | 1<<5 | 1<<6 | 1<<10}
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&a)), 0, ^uintptr(0), ^uintptr(0), 8, 0)
	if errno != 0 {
		return errno
	}
	return syscall.Close(int(fd))
}

func finishReport(env *fixtureEnv, rep *report, o options, failed func(string, ...any)) (*report, int, error) {
	// Resource exactness: after every helper session and the node are gone.
	rep.Cleanup.PerfMappingsLeft = perfMappings()
	// Settle: the helper releases on its own goroutine after the peer closes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && perfFDs() != rep.Cleanup.PerfFDsBefore {
		time.Sleep(20 * time.Millisecond)
	}
	rep.Cleanup.PerfFDsAfter = perfFDs()
	rep.Cleanup.PerfMappingsLeft = perfMappings()
	if rep.Cleanup.PerfFDsAfter != rep.Cleanup.PerfFDsBefore || rep.Cleanup.PerfMappingsLeft != 0 {
		failed("perf resources leaked: fds %d->%d mappings %d", rep.Cleanup.PerfFDsBefore, rep.Cleanup.PerfFDsAfter, rep.Cleanup.PerfMappingsLeft)
	}
	rep.Cleanup.DumpFiles = len(dumpFiles(env))
	if rep.Cleanup.DumpFiles != 0 {
		failed("emergency dump artifacts found: %d", rep.Cleanup.DumpFiles)
	}
	// Final diagnostics: the report itself, before it is printed, is audited.
	raw, _ := json.Marshal(rep)
	env.observe(scan.StageDiagnostics, raw)
	for _, s := range scan.AllStages {
		b, n := env.audit.Observed(s)
		rep.Stages[string(s)] = stageStat{b, n}
	}
	for _, v := range env.audit.Violations() {
		rep.Violations = append(rep.Violations, v.String())
	}
	rep.Violations = dedupe(rep.Violations)
	rep.Cleanup.FDsAfter = countFDs()
	if len(rep.Violations) > 0 {
		return rep, exitCanary, errors.New("canary crossed an owned boundary (content is never printed)")
	}
	if !o.negativeControl {
		for _, s := range scan.AllStages {
			if rep.Stages[string(s)].Bytes == 0 {
				failed("stage %s was never observed", s)
			}
		}
	}
	if o.negativeControl {
		failed("negative control: the contaminated sanitizer was NOT detected")
	}
	if len(rep.Failures) > 0 {
		return rep, exitFail, errors.New(strings.Join(rep.Failures, "; "))
	}
	if rep.Scheduler.Status != string(nativeperf.Supported) {
		return rep, exitNoScheduler, errors.New("scheduler evidence unavailable on this kernel: CPU, privacy, export, read and cleanup rows passed; scheduler rows NOT run")
	}
	return rep, exitOK, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		// Collapse per-offset repeats: keep "stage: kind encoding" once.
		parts := strings.Split(s, " offset=")
		if !seen[parts[0]] {
			seen[parts[0]] = true
			out = append(out, parts[0])
		}
	}
	sort.Strings(out)
	return out
}

func dumpFiles(env *fixtureEnv) []string {
	var found []string
	for _, dir := range []string{os.TempDir()} {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() && path != dir && strings.HasPrefix(filepath.Base(path), ".") {
				return nil
			}
			base := filepath.Base(path)
			if !d.IsDir() && (base == "perf.data" || base == "perf.data.old" || base == "core" || strings.HasPrefix(base, "core.") || strings.HasSuffix(base, ".core")) {
				if info, e := d.Info(); e == nil && time.Since(info.ModTime()) < 10*time.Minute {
					found = append(found, path)
				}
			}
			return nil
		})
	}
	return found
}

// rssMiB is this process's resident set, the quantity the helper charges against
// its 64MiB budget for the exporter peer (and for itself when in process).
func rssMiB() uint64 {
	b, e := os.ReadFile("/proc/self/statm")
	if e != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, _ := strconv.ParseUint(f[1], 10, 64)
	return pages * uint64(os.Getpagesize()) >> 20
}
