//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

// Task 04.08 native capture/exfiltration privacy canaries and sandbox failure
// drills. PrivacyAudit is a test-only observer of owned, sanitized buffers: its
// stages are the owned staging buffers, the helper socket and diagnostics here
// (the exporter queue, wire, storage and read stages are exercised by
// internal/profiles/privacy_test.go and the verify fixture). It never receives
// the kernel mmap ring: the ring is not a sanitized artifact. The kernel ring's
// fixed ABI does transiently carry command names (and, for the scheduler
// tracepoint, prev/next comm bytes); this file proves they are skipped in
// place, not that they never existed.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"soundpost/fixtures/nativeperf/privacy/scan"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
)

type (
	// PrivacyAudit observes sanitized, owned buffers only; see scan.PrivacyAudit.
	PrivacyAudit = scan.PrivacyAudit
	// Stage names an observation boundary; there is deliberately no raw-ring stage.
	Stage = scan.Stage
)

const (
	StageStaging          = scan.StageStaging
	StageSocket           = scan.StageSocket
	StageExporterQueue    = scan.StageExporterQueue
	StageWireCompressed   = scan.StageWireCompressed
	StageWireDecompressed = scan.StageWireDecompressed
	StageStorage          = scan.StageStorage
	StageRead             = scan.StageRead
	StageExport           = scan.StageExport
	StageDiagnostics      = scan.StageDiagnostics
)

const (
	privacyPolicyFile   = "../../fixtures/nativeperf/privacy/policy.json"
	privacyCanarySource = "../../fixtures/nativeperf/privacy/canary.c"
)

type privacyEnv struct {
	policy scan.Policy
	nonce  string
	audit  *PrivacyAudit
}

func newPrivacyEnv(t *testing.T) *privacyEnv {
	t.Helper()
	p, e := scan.LoadPolicy(privacyPolicyFile)
	if e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, p.NonceHexLen/2)
	if _, e = rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	nonce := hex.EncodeToString(raw)
	d, e := scan.NewDetector(p, nonce)
	if e != nil {
		t.Fatal(e)
	}
	return &privacyEnv{policy: p, nonce: nonce, audit: scan.NewPrivacyAudit(d)}
}
func (e *privacyEnv) sentinel(kind string) string {
	v, err := e.policy.Sentinel(kind, e.nonce)
	if err != nil {
		panic(err)
	}
	return v
}

// requireClean fails if any sentinel crossed any observed boundary. Violations are
// content-free (kind, encoding, offset), so failing here never prints the value.
func (e *privacyEnv) requireClean(t *testing.T, stages ...Stage) {
	t.Helper()
	type key struct {
		stage Stage
		kind  string
	}
	counts := map[key]int{}
	var order []key
	for _, v := range e.audit.Violations() {
		k := key{v.Stage, v.Hit.Kind}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	for _, k := range order {
		t.Errorf("canary kind=%s crossed stage %s (%d detector hits; content is never printed)", k.kind, k.stage, counts[k])
	}
	if e := e.audit.RequireStages(stages...); e != nil {
		t.Error(e)
	}
}

// ---- kernel-record builders (fixed ABI, built in test memory; never audited) ----

func privacyRecordComm(tgid, tid uint32, comm string, exec bool, ts uint64) []byte {
	b := make([]byte, 56)
	binary.LittleEndian.PutUint32(b, perfRecordComm)
	if exec {
		binary.LittleEndian.PutUint16(b[4:], 1<<13)
	}
	binary.LittleEndian.PutUint16(b[6:], 56)
	binary.LittleEndian.PutUint32(b[8:], tgid)
	binary.LittleEndian.PutUint32(b[12:], tid)
	copy(b[16:32], comm)
	binary.LittleEndian.PutUint32(b[32:], tgid)
	binary.LittleEndian.PutUint32(b[36:], tid)
	binary.LittleEndian.PutUint64(b[40:], ts)
	binary.LittleEndian.PutUint32(b[48:], 1)
	return b
}
func privacyRecordSample(tgid, tid uint32, ip, ts uint64, cpu uint32, period uint64, chain ...uint64) []byte {
	b := make([]byte, 56+8*len(chain))
	binary.LittleEndian.PutUint32(b, perfRecordSample)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(b)))
	binary.LittleEndian.PutUint64(b[8:], ip)
	binary.LittleEndian.PutUint32(b[16:], tgid)
	binary.LittleEndian.PutUint32(b[20:], tid)
	binary.LittleEndian.PutUint64(b[24:], ts)
	binary.LittleEndian.PutUint32(b[32:], cpu)
	binary.LittleEndian.PutUint64(b[40:], period)
	binary.LittleEndian.PutUint64(b[48:], uint64(len(chain)))
	for i, v := range chain {
		binary.LittleEndian.PutUint64(b[56+8*i:], v)
	}
	return b
}
func privacyRecordLost(count, ts uint64, cpu uint32) []byte {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint32(b, perfRecordLost)
	binary.LittleEndian.PutUint16(b[6:], 48)
	binary.LittleEndian.PutUint64(b[16:], count)
	binary.LittleEndian.PutUint64(b[32:], ts)
	binary.LittleEndian.PutUint32(b[40:], cpu)
	return b
}

// privacyRing lays several records out in a private test ring (not an mmap).
func privacyRing(task TaskKey, records ...[]byte) *Ring {
	total := 0
	for _, r := range records {
		total += len(r)
	}
	size := 4096
	for size < total {
		size *= 2
	}
	data, meta := make([]byte, size), make([]byte, 4096)
	at := 0
	for _, r := range records {
		copy(data[at:], r)
		at += len(r)
	}
	binary.LittleEndian.PutUint64(meta[1024:], uint64(total))
	return &Ring{meta: meta, data: data, task: task, method: MethodSoftwareCPUClock, maxFrames: 128}
}

// ---- sanitizers: the production decoder and permanent contaminated variants ----

type privacySanitizer func(KernelRecordView, *Ring) (SanitizedEvent, bool, error)

// privacyLabel keeps only the characters ClockDomain identities admit; this is
// exactly the property that lets a careless collector smuggle a command name
// through a field the validator considers a harmless label.
func privacyLabel(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
func privacyCommBytes(v KernelRecordView) []byte {
	name := make([]byte, 0, 16)
	for i := 16; i < v.len() && i < 32 && v.byteAt(i) != 0; i++ {
		name = append(name, v.byteAt(i))
	}
	return name
}

// privacyContaminatedCommLabel is the NEGATIVE CONTROL: a real contaminated
// sanitizer variant that remembers the kernel's COMM record name and stamps it
// into the clock-domain host label of the next sample. The event still passes
// SanitizedEvent.Validate, so only the canary detector can catch it.
func privacyContaminatedCommLabel() privacySanitizer {
	var comm string
	return func(v KernelRecordView, r *Ring) (SanitizedEvent, bool, error) {
		if v.valid() && v.u32(0) == perfRecordComm && v.len() >= 41 {
			comm = privacyLabel(privacyCommBytes(v))
		}
		event, ok, e := decodeCPURecord(v, r)
		if ok && e == nil && event.Kind == EventCPU && comm != "" {
			event.Domain = ClockDomain{HostID: comm, BootID: r.task.BootID}
		}
		return event, ok, e
	}
}

// privacyContaminatedCommWord is the second NEGATIVE CONTROL: the nonce bytes of
// the kernel COMM name are packed into a callchain "address" (a raw-memory-word
// style leak that serializes as a decimal integer and passes every numeric check).
func privacyContaminatedCommWord() privacySanitizer {
	var comm []byte
	return func(v KernelRecordView, r *Ring) (SanitizedEvent, bool, error) {
		if v.valid() && v.u32(0) == perfRecordComm && v.len() >= 41 {
			comm = privacyCommBytes(v)
		}
		event, ok, e := decodeCPURecord(v, r)
		if ok && e == nil && event.CPUEvent != nil && len(comm) >= 15 {
			var word uint64
			for i, c := range comm[9:15] {
				word |= uint64(c) << (8 * i)
			}
			event.CPUEvent.Callchain = append(event.CPUEvent.Callchain, CallchainEntry{IP: model.Uint64(word)})
		}
		return event, ok, e
	}
}

// privacySanitizerUnderTest is the sanitizer the acquisition-boundary test
// exercises: the actual production decoder.
func privacySanitizerUnderTest() privacySanitizer { return decodeCPURecord }

func privacyPump(ring *Ring, sanitize privacySanitizer, domain ClockDomain, seq *uint64) ([]SanitizedEvent, error) {
	var out []SanitizedEvent
	for {
		consumed := false
		e := ring.consume(func(v KernelRecordView) error {
			consumed = true
			event, ok, e := sanitize(v, ring)
			if e != nil || !ok {
				return e
			}
			if event.Domain.HostID == "" {
				event.Domain = domain
			}
			*seq++
			event.Sequence = model.Uint64(*seq)
			if e = event.Validate(); e != nil {
				return e
			}
			out = append(out, event)
			return nil
		})
		if e != nil {
			return out, e
		}
		if !consumed {
			return out, nil
		}
	}
}

// ---- audited sources and the socket tap ----

// privacyAuditedSource observes each sanitized event at the owned staging
// boundary, immediately before the helper serializes it onto the socket.
type privacyAuditedSource struct {
	inner EventSource
	env   *privacyEnv
}

func (s *privacyAuditedSource) Next(ctx context.Context) (SanitizedEvent, error) {
	event, e := s.inner.Next(ctx)
	if e == nil {
		raw, _ := json.Marshal(event)
		_ = s.env.audit.Observe(StageStaging, raw) // violations are collected by the audit
	}
	return event, e
}
func (s *privacyAuditedSource) Close() error { return s.inner.Close() }

type privacyFailingSource struct {
	inner EventSource
	after int
	err   error
}

func (s *privacyFailingSource) Next(ctx context.Context) (SanitizedEvent, error) {
	if s.after <= 0 {
		return SanitizedEvent{}, s.err
	}
	s.after--
	return s.inner.Next(ctx)
}
func (s *privacyFailingSource) Close() error { return s.inner.Close() }

type privacySliceSource struct {
	events []SanitizedEvent
	next   int
}

func (s *privacySliceSource) Next(context.Context) (SanitizedEvent, error) {
	if s.next >= len(s.events) {
		return SanitizedEvent{}, ErrAcquisitionClosed
	}
	s.next++
	return s.events[s.next-1], nil
}
func (s *privacySliceSource) Close() error { return nil }

// privacyReadReply reads one real helper frame through the real decoder and
// tees the exact bytes it consumed into the acquisition-socket stage.
func privacyReadReply(env *privacyEnv, r io.Reader) (helperReply, error) {
	var tap bytes.Buffer
	var reply helperReply
	e := readMessage(io.TeeReader(r, &tap), &reply)
	if tap.Len() > 0 {
		_ = env.audit.Observe(StageSocket, tap.Bytes())
	}
	return reply, e
}

// privacyStreamEvents sends events through the real post-authorization helper
// stream over a real Unix socket and audits the owned staging copy and every
// frame the real decoder reads.
func privacyStreamEvents(t *testing.T, env *privacyEnv, events []SanitizedEvent) []helperReply {
	t.Helper()
	client, server := cpuSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, event := range events {
		raw, _ := json.Marshal(event)
		_ = env.audit.Observe(StageStaging, raw)
	}
	done := make(chan struct{})
	go func() { defer close(done); streamHelperEvents(ctx, server, &privacySliceSource{events: events}) }()
	var replies []helperReply
	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		reply, e := privacyReadReply(env, client)
		if e != nil {
			break
		}
		replies = append(replies, reply)
		if reply.Error != "" {
			break
		}
	}
	cancel()
	client.Close()
	<-done
	return replies
}

// privacyFakeRing models the kernel's per-thread ring: COMM records carry the
// command-name sentinel exactly where the fixed ABI puts it.
func privacyFakeRing(env *privacyEnv, task TaskKey) *Ring {
	comm := env.sentinel("comm")
	chain := []uint64{^uint64(511), 0x401100, 0x401180, 0x4011f0, 0x401260}
	return privacyRing(task,
		privacyRecordComm(task.TGID, task.TID, comm, false, 100),
		privacyRecordSample(task.TGID, task.TID, 0x401100, 110, 0, 10101010, chain...),
		privacyRecordComm(task.TGID, task.TID, comm, false, 120),
		privacyRecordSample(task.TGID, task.TID, 0x401108, 130, 0, 10101010, chain...),
		privacyRecordLost(3, 140, 0),
		privacyRecordSample(task.TGID, task.TID, 0x401110, 150, 0, 10101010, chain...),
	)
}

var (
	privacyDomain = ClockDomain{HostID: "privacy-host", BootID: "privacy-boot"}
	privacyTask   = TaskKey{BootID: "privacy-boot", PIDNamespace: 1, TGID: 70, TID: 71, ProcessStart: 1, Generation: 1}
)

// privacySchedulerEvents decodes synthetic scheduler tracepoint records whose
// prev/next comm fields hold the comm sentinel. Real tracefs is denied here, so
// this is a decoder-boundary fixture, not scheduler acquisition qualification.
func privacySchedulerEvents(t *testing.T, env *privacyEnv, domain ClockDomain, key TaskKey, base uint64) []SanitizedEvent {
	t.Helper()
	comm := env.sentinel("comm")
	switchLayout, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	wakeLayout, e := parseTraceFormat(SchedulerWakeupKind, schedulerFormat(SchedulerWakeupKind))
	if e != nil {
		t.Fatal(e)
	}
	// The kernel release is what the real layout loader stamps after matching 6.1/6.6.
	switchLayout.kernel, wakeLayout.kernel = "6.6", "6.6"
	authorized := AuthorizedTargets{schedulerTasks: []cpuThread{{task: key, start: 1}}}
	sw := func(at uint64, prev, next uint32, state uint64) []byte {
		b := make([]byte, 104)
		binary.LittleEndian.PutUint32(b, perfRecordSample)
		binary.LittleEndian.PutUint16(b[6:], 104)
		binary.LittleEndian.PutUint64(b[16:], at)
		binary.LittleEndian.PutUint32(b[40:], 60)
		copy(b[52:], comm)
		binary.LittleEndian.PutUint32(b[68:], prev)
		binary.LittleEndian.PutUint64(b[76:], state)
		copy(b[84:], comm)
		binary.LittleEndian.PutUint32(b[100:], next)
		return b
	}
	wake := func(at uint64, pid uint32) []byte {
		b := make([]byte, 80)
		binary.LittleEndian.PutUint32(b, perfRecordSample)
		binary.LittleEndian.PutUint16(b[6:], 80)
		binary.LittleEndian.PutUint64(b[16:], at)
		binary.LittleEndian.PutUint32(b[40:], 36)
		copy(b[52:], comm)
		binary.LittleEndian.PutUint32(b[68:], pid)
		return b
	}
	var out []SanitizedEvent
	add := func(layout NumericLayout, record []byte, seq uint64) {
		event, ok, e := decodeScheduler(KernelRecordView{first: record}, layout, authorized)
		if e != nil || !ok {
			t.Fatalf("scheduler decode failed: ok=%v %v", ok, e)
		}
		event.Domain = domain
		event.Sequence = model.Uint64(seq)
		if e = event.Validate(); e != nil {
			t.Fatal(e)
		}
		out = append(out, event)
	}
	// Task leaves the CPU sleeping at base, is woken at +40ms, runs again at +55ms.
	add(switchLayout, sw(base, key.TID, 999, 1), 1000)
	add(wakeLayout, wake(base+40_000_000, key.TID), 1001)
	add(switchLayout, sw(base+55_000_000, 999, key.TID, 0), 1002)
	return out
}

// privacySchedulerIntervals turns the decoded numeric scheduler events into
// correlated intervals (blocked 40ms, runnable 15ms).
func privacySchedulerIntervals(t *testing.T, events []SanitizedEvent, domain ClockDomain, base uint64) []Interval {
	t.Helper()
	c := NewCorrelator(DefaultConfig(1))
	if e := c.Configure(domain, []uint32{0}, 4<<20); e != nil {
		t.Fatal(e)
	}
	var out []Interval
	for _, event := range events {
		got, e := c.Consume(event)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, got...)
	}
	if e := c.ReportProgress(0, model.MonoNano(base+55_000_000+100_000_000)); e != nil {
		t.Fatal(e)
	}
	got, e := c.Advance(model.MonoNano(base + 55_000_000))
	if e != nil {
		t.Fatal(e)
	}
	return append(out, got...)
}

// ---- real workload, helper and client ----

func privacyParanoid() string {
	b, e := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if e != nil {
		return "unreadable"
	}
	return strings.TrimSpace(string(b))
}

// privacyRequireRealPerf skips (recording the exact errno and kernel setting)
// when the kernel denies the fixed CPU event. It never changes a sysctl.
func privacyRequireRealPerf(t *testing.T) {
	t.Helper()
	if e := probeOpen(1, 0, 0, -1); e != nil {
		t.Skipf("NOT run: real perf_event_open denied: %v (kernel.perf_event_paranoid=%s)", e, privacyParanoid())
	}
	if _, e := exec.LookPath("cc"); e != nil {
		t.Skip("NOT run: cc not available to build the canary workload")
	}
}

// privacyRequireInProcessHelper additionally requires that an in-process helper
// and exporter peer (both this process) fit the helper's own 64MiB aggregate
// accounting; the helper charges both RSS values, so a large test binary (the
// race detector's shadow memory) is refused by the helper itself.
func privacyRequireInProcessHelper(t *testing.T) {
	t.Helper()
	privacyRequireRealPerf(t)
	rss, e := processRSS(os.Getpid())
	if e != nil || 2*rss+(4<<20) > MaxMemoryBytes {
		t.Skipf("NOT run: test process RSS %d MiB (err=%v) exceeds the helper's 64MiB two-RSS accounting; the same rows run in the verify fixture process", rss>>20, e)
	}
}

type privacyCanary struct {
	cmd   *exec.Cmd
	pid   int
	exe   string
	root  string
	kinds []string
}

func privacyLaunchCanary(t *testing.T, env *privacyEnv, seconds int) *privacyCanary {
	t.Helper()
	cc, e := exec.LookPath("cc")
	if e != nil {
		t.Skip("NOT run: cc not available")
	}
	root := t.TempDir()
	dir := filepath.Join(root, env.sentinel("path"))
	if e = os.MkdirAll(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(dir, "canary")
	if out, e := exec.Command(cc, "-O2", "-pthread", "-fno-omit-frame-pointer", "-g", "-o", exe, privacyCanarySource).CombinedOutput(); e != nil {
		t.Fatalf("canary build failed: %v\n%s", e, out)
	}
	cmd := exec.Command(exe, env.sentinel("argv"), strconv.Itoa(seconds))
	cmd.Env = append(os.Environ(), "SPCNRY_ENV="+env.sentinel("env"), "TMPDIR="+root)
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	c := &privacyCanary{cmd: cmd, pid: cmd.Process.Pid, exe: exe, root: root}
	t.Cleanup(func() { c.cmd.Process.Kill(); c.cmd.Wait() })
	io.WriteString(stdin, "INPUT GET /search?q="+env.sentinel("input")+"\n")
	io.WriteString(stdin, "DB SELECT secret FROM vault WHERE owner='"+env.sentinel("db")+"'\n")
	stdin.Close()
	ready := make(chan string, 1)
	go func() {
		var line [256]byte
		n, _ := io.ReadAtLeast(stdout, line[:1], 1)
		for n < len(line) && (n == 0 || line[n-1] != '\n') {
			m, e := stdout.Read(line[n:])
			n += m
			if e != nil {
				break
			}
		}
		ready <- string(line[:n])
	}()
	select {
	case line := <-ready:
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ready ") {
			t.Fatalf("canary did not become ready (%q, stderr %q)", line, stderr.String())
		}
		c.kinds = strings.Split(strings.TrimPrefix(line, "ready "), ",")
	case <-time.After(10 * time.Second):
		t.Fatalf("canary readiness timeout (stderr %q)", stderr.String())
	}
	for _, k := range env.policy.Kinds {
		found := false
		for _, placed := range c.kinds {
			found = found || placed == k.ID
		}
		if !found {
			t.Fatalf("canary did not place sentinel kind %s", k.ID)
		}
	}
	return c
}

func privacyTargetFor(t *testing.T, c *privacyCanary) Target {
	t.Helper()
	target, e := ResolveLocalTarget(c.pid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", c.pid))
	if e != nil {
		t.Fatal(e)
	}
	group := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		t.Skip("NOT run: cgroup v2 identity unavailable")
	}
	st, e := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if e != nil {
		t.Skipf("NOT run: cgroup identity not visible: %v", e)
	}
	target.CgroupID = model.Uint64(st.Sys().(*syscall.Stat_t).Ino)
	f, e := os.Open(c.exe)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	build, e := executableBuildID(f)
	if e != nil {
		t.Fatal(e)
	}
	target.AllowedBuildIDs = []string{build}
	return target
}

// privacySymbols resolves sampled addresses to policy-authorized symbol names
// with the production bounded ELF reader (file offsets from the workload's own
// executable mapping); it is a verifier-side lookup, not helper behavior.
func privacySymbols(t *testing.T, c *privacyCanary) func(uint64) string {
	t.Helper()
	f, e := os.Open(c.exe)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	info, e := readELFSymbols(context.Background(), f, 32<<20, 65536)
	if e != nil {
		t.Fatal(e)
	}
	maps, e := os.ReadFile(fmt.Sprintf("/proc/%d/maps", c.pid))
	if e != nil {
		t.Fatal(e)
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
	return func(ip uint64) string {
		for _, s := range spans {
			if ip >= s.start && ip < s.end {
				name, _ := info.lookup(ip - s.start + s.offset)
				return name
			}
		}
		return ""
	}
}

// privacyRequireGenuineCPU proves an empty or fabricated export cannot satisfy
// privacy: real samples, real multi-frame frame-pointer stacks that resolve to
// the workload's own functions.
func privacyRequireGenuineCPU(t *testing.T, c *privacyCanary, events []SanitizedEvent) (samples int) {
	t.Helper()
	symbol := privacySymbols(t, c)
	hot, deep, chain := 0, 0, 0
	for _, event := range events {
		if event.CPUEvent == nil {
			continue
		}
		samples++
		if symbol(uint64(event.CPUEvent.IP)) == "spcnry_hot" {
			hot++
		}
		frames := 0
		for _, f := range event.CPUEvent.Callchain {
			if f.IP != 0 {
				frames++
				if n := symbol(uint64(f.IP)); n == "spcnry_handle_request" || n == "spcnry_hash_text" {
					chain++
				}
			}
		}
		if frames >= 3 {
			deep++
		}
		if event.CPUEvent.Period == 0 || event.CPUEvent.RequestedHz != 99 || event.CPUEvent.Method != MethodSoftwareCPUClock {
			t.Fatalf("sample lost its numeric period/rate/method: %+v", event.CPUEvent)
		}
	}
	if samples == 0 || hot == 0 || deep == 0 || chain == 0 {
		t.Fatalf("export is not genuine CPU evidence: samples=%d hot_function=%d deep_stacks=%d resolved_callers=%d", samples, hot, deep, chain)
	}
	return samples
}

type privacyOptions struct {
	seconds   int
	grantTTL  time.Duration
	wrap      func(EventSource) EventSource
	badKey    bool
	staleRev  bool
	noCanary  bool
	staleHelp bool
}
type privacySession struct {
	t         *testing.T
	env       *privacyEnv
	canary    *privacyCanary
	target    Target
	helper    *Helper
	cancel    context.CancelFunc
	servedErr error
	stopped   chan struct{}
	sock      string
	conn      *net.UnixConn
	request   CaptureRequest
	baseFDs   int
	baseAll   int // every open FD once the listener and workload exist, before any connection
}

func privacyPerfFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.Contains(link, "perf_event") {
			n++
		}
	}
	return n
}
func privacyOpenFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	return len(entries)
}
func (s *privacySession) budget() (memory, fds uint64) {
	s.helper.Budget.mu.Lock()
	defer s.helper.Budget.mu.Unlock()
	return s.helper.Budget.memory, s.helper.Budget.fds
}

// privacyStartSession starts a real in-process helper on a private socket with an
// operator-signed grant, optionally against a real canary target.
func privacyStartSession(t *testing.T, env *privacyEnv, opt privacyOptions) *privacySession {
	t.Helper()
	s := &privacySession{t: t, env: env, baseFDs: privacyPerfFDs()}
	var target Target
	if opt.noCanary {
		target = Target{CgroupID: 1, PIDNamespace: 1, TGID: 4242, ProcessStart: 1, AllowedBuildIDs: []string{"aabb"}}
	} else {
		s.canary = privacyLaunchCanary(t, env, opt.seconds)
		target = privacyTargetFor(t, s.canary)
	}
	s.target = target
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signer := private
	if opt.badKey {
		signer = other
	}
	ttl := opt.grantTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(ttl).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}, signer)
	if e != nil {
		t.Fatal(e)
	}
	s.request = CaptureRequest{Authorization: grant, Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	revision := uint64(1)
	if opt.staleRev {
		revision = 2
	}
	s.helper = &Helper{Policy: OperatorPolicy{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: revision, PublicKey: public, Allowlist: []Target{target}}, Budget: NewResourceBudget(), Acquire: func(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation) (EventSource, error) {
		source, e := NewCPUAcquisition(ctx, a, c, r)
		if e != nil {
			return nil, e
		}
		var out EventSource = &privacyAuditedSource{inner: source, env: env}
		if opt.wrap != nil {
			out = opt.wrap(out)
		}
		return out, nil
	}}
	s.sock = filepath.Join(t.TempDir(), "acquire.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: s.sock, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.baseAll = privacyOpenFDs()
	s.stopped = make(chan struct{})
	go func() { s.servedErr = s.helper.Serve(ctx, listener); close(s.stopped) }()
	t.Cleanup(func() {
		if s.conn != nil {
			s.conn.Close()
		}
		cancel()
		select {
		case <-s.stopped:
		case <-time.After(5 * time.Second):
			t.Error("helper Serve did not return after cancellation")
		}
	})
	return s
}
func (s *privacySession) dial() *net.UnixConn {
	s.t.Helper()
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.sock, Net: "unix"})
	if e != nil {
		s.t.Fatal(e)
	}
	s.conn = conn
	return conn
}

// connect sends the signed request and returns the first reply (Ready on success).
func (s *privacySession) connect() helperReply {
	s.t.Helper()
	conn := s.dial()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if e := writeMessage(conn, s.request); e != nil {
		s.t.Fatal(e)
	}
	reply, e := privacyReadReply(s.env, conn)
	if e != nil {
		s.t.Fatalf("no helper reply: %v", e)
	}
	conn.SetDeadline(time.Time{})
	return reply
}

// capture reads helper frames for d (or until the helper ends the stream).
func (s *privacySession) capture(d time.Duration) (events []SanitizedEvent, terminal helperReply, ended error) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.conn.SetReadDeadline(deadline)
		reply, e := privacyReadReply(s.env, s.conn)
		if e != nil {
			var timeout net.Error
			if errors.As(e, &timeout) && timeout.Timeout() {
				return events, terminal, nil
			}
			return events, terminal, e
		}
		if reply.Event != nil {
			events = append(events, *reply.Event)
		}
		if reply.Error != "" || reply.Complete {
			return events, reply, nil
		}
	}
	return events, terminal, nil
}

// waitReleased polls until the lease, ring FDs and mappings are gone.
func (s *privacySession) waitReleased(d time.Duration) error {
	deadline := time.Now().Add(d)
	if s.conn != nil {
		s.conn.Close()
	}
	for {
		memory, fds := s.budget()
		// Every FD, not just perf events: a leaked target pidfd/proc handle is a leak too.
		if memory == 0 && fds == 0 && privacyPerfFDs() == s.baseFDs && privacyOpenFDs() <= s.baseAll {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("resources not released: budget memory=%d fds=%d perf_fds=%d (baseline %d)", memory, fds, privacyPerfFDs(), s.baseFDs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// privacyDumpFiles lists forbidden dump/perf.data artifacts under dirs.
func privacyDumpFiles(t *testing.T, env *privacyEnv, dirs ...string) []string {
	t.Helper()
	var res []*regexp.Regexp
	for _, expr := range env.policy.Syscalls.ForbiddenOpenName {
		res = append(res, regexp.MustCompile(expr))
	}
	var found []string
	for _, dir := range dirs {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			for _, re := range res {
				if re.MatchString(path) {
					found = append(found, path)
				}
			}
			return nil
		})
	}
	return found
}

// =========================== tests ===========================

// The audit must never see the kernel ring: no raw-ring stage exists, the stage
// list matches the policy, and no Observe call in this file receives ring fields.
func TestPrivacyAuditNeverSeesRawRing(t *testing.T) {
	env := newPrivacyEnv(t)
	for _, stage := range []Stage{"raw_mmap_ring", "perf_data", "stack_dump", "registers"} {
		if e := env.audit.Observe(stage, []byte("x")); !errors.Is(e, scan.ErrUnknownStage) {
			t.Fatalf("stage %q accepted: %v", stage, e)
		}
	}
	policyStages := strings.Join(env.policy.Stages, ",")
	var have []string
	for _, s := range scan.AllStages {
		have = append(have, string(s))
	}
	if policyStages != strings.Join(have, ",") {
		t.Fatal("policy stage list drifted from the audit")
	}
	file, e := parser.ParseFile(token.NewFileSet(), "privacy_linux_test.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	ringFields := map[string]bool{"first": true, "second": true, "data": true, "meta": true, "mapping": true}
	calls := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Observe" {
			return true
		}
		calls++
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				if s, ok := m.(*ast.SelectorExpr); ok && ringFields[s.Sel.Name] {
					t.Errorf("Observe argument references raw ring field %q", s.Sel.Name)
				}
				return true
			})
		}
		return true
	})
	if calls < 5 {
		t.Fatalf("only %d Observe calls found; the ring-copy guard parsed the wrong file", calls)
	}
}

// TestNoContentAtAcquisitionBoundary: no canary and no raw ring/stack/register
// field crosses the owned staging buffers or the helper socket.
func TestNoContentAtAcquisitionBoundary(t *testing.T) {
	t.Run("kernel_ring_records", func(t *testing.T) {
		env := newPrivacyEnv(t)
		var seq uint64
		events, e := privacyPump(privacyFakeRing(env, privacyTask), privacySanitizerUnderTest(), privacyDomain, &seq)
		if e != nil {
			t.Fatal(e)
		}
		// Scheduler tracepoint records carry prev/next comm in their fixed raw payload.
		events = append(events, privacySchedulerEvents(t, env, privacyDomain, privacyTask, 1_000_000_000)...)
		samples, frames, switches, wakeups, losses := 0, 0, 0, 0, 0
		for _, event := range events {
			switch {
			case event.CPUEvent != nil:
				samples++
				frames += len(event.CPUEvent.Callchain)
			case event.Switch != nil:
				switches++
			case event.Wakeup != nil:
				wakeups++
			case event.Loss != nil:
				losses++
			}
		}
		if samples != 3 || frames < 3*4 || switches != 2 || wakeups != 1 || losses != 1 {
			t.Fatalf("an empty or truncated export cannot pass privacy: samples=%d frames=%d switches=%d wakeups=%d losses=%d", samples, frames, switches, wakeups, losses)
		}
		replies := privacyStreamEvents(t, env, events)
		if len(replies) < len(events)+1 || !replies[0].Ready {
			t.Fatalf("real helper stream delivered %d replies for %d events", len(replies), len(events))
		}
		env.requireClean(t, StageStaging, StageSocket)
	})
	t.Run("raw_stack_and_register_fields_fail_closed", func(t *testing.T) {
		env := newPrivacyEnv(t)
		// A mis-configured event (STACK_USER / REGS_USER) appends raw bytes after the
		// callchain. Fixed decoders must refuse the record, not export or forward it.
		chain := []uint64{^uint64(511), 0x401100, 0x401180}
		stack := make([]byte, 64)
		copy(stack, env.sentinel("stack"))
		copy(stack[32:], env.sentinel("heap"))
		for name, trailer := range map[string][]byte{"stack_user": stack, "regs_user": append([]byte{0x3, 0, 0, 0, 0, 0, 0, 0}, stack[:24]...)} {
			record := privacyRecordSample(70, 71, 0x401100, 110, 0, 5, chain...)
			record = append(record, trailer...)
			binary.LittleEndian.PutUint16(record[6:], uint16(len(record)))
			ring := privacyRing(privacyTask, record)
			var seq uint64
			events, e := privacyPump(ring, privacySanitizerUnderTest(), privacyDomain, &seq)
			if !errors.Is(e, ErrRingMalformed) || len(events) != 0 {
				t.Fatalf("%s: raw trailer accepted: %v (%d events)", name, e, len(events))
			}
			// The failure the helper would report contains only a closed code.
			code := helperErrorCode(e)
			_ = env.audit.Observe(StageDiagnostics, []byte(code+" "+e.Error()))
		}
		env.requireClean(t, StageDiagnostics)
	})
	t.Run("real_mapping_reader_paths", func(t *testing.T) {
		privacyRequireRealPerf(t)
		env := newPrivacyEnv(t)
		canary := privacyLaunchCanary(t, env, 0)
		target := privacyTargetFor(t, canary)
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		cfg := DefaultConfig(1)
		grant, e := SignStart(StartAuthorization{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}, private)
		if e != nil {
			t.Fatal(e)
		}
		authorized, e := authorizeLocal(PeerCredential{UID: uint32(os.Getuid())}, CaptureRequest{Authorization: grant, Targets: []Target{target}, Config: cfg, Mode: ModeCPU}, OperatorPolicy{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: []Target{target}})
		if e != nil {
			t.Fatal(e)
		}
		policy := DefaultSymbolPolicy(1)
		policy.AllowMappedELF = true
		reader, e := NewMappingReader(authorized, target, 1, policy)
		if e != nil {
			t.Fatal(e)
		}
		defer reader.Close()
		table, e := reader.Read(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(canary.exe, env.sentinel("path")) {
			t.Fatal("workload is not below the path sentinel directory")
		}
		for _, v := range []any{table.Mappings(), table.Modules(), table.Process()} {
			raw, _ := json.Marshal(v)
			_ = env.audit.Observe(StageStaging, raw)
		}
		if len(table.Mappings()) == 0 || len(table.Modules()) == 0 {
			t.Fatal("authorized module identities vanished; an empty table cannot prove privacy")
		}
		env.requireClean(t, StageStaging)
	})
	t.Run("real_helper_socket", func(t *testing.T) {
		privacyRequireInProcessHelper(t)
		env := newPrivacyEnv(t)
		s := privacyStartSession(t, env, privacyOptions{})
		if ready := s.connect(); !ready.Ready {
			t.Fatalf("helper refused: %+v", ready)
		}
		events, _, e := s.capture(2 * time.Second)
		if e != nil {
			t.Fatal(e)
		}
		samples := privacyRequireGenuineCPU(t, s.canary, events)
		t.Logf("real acquisition: %d genuine CPU samples crossed the socket with zero canaries", samples)
		env.requireClean(t, StageStaging, StageSocket)
	})
}

// The kernel ring really does carry the command sentinel in COMM records; the
// sanitizer skips them in place. This is the disclosed transient ABI field.
func TestPrivacyKernelRingTransientlyCarriesCommAndSanitizerSkipsIt(t *testing.T) {
	privacyRequireRealPerf(t)
	env := newPrivacyEnv(t)
	canary := privacyLaunchCanary(t, env, 0)
	target := privacyTargetFor(t, canary)
	entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", canary.pid))
	if e != nil || len(entries) < 3 {
		t.Fatal("canary threads missing", e)
	}
	var rings []*Ring
	for _, entry := range entries {
		tid, _ := strconv.ParseUint(entry.Name(), 10, 32)
		ring, e := openThreadCPU(TaskKey{BootID: privacyDomain.BootID, PIDNamespace: target.PIDNamespace, TGID: target.TGID, TID: uint32(tid), ProcessStart: target.ProcessStart, Generation: 1}, DefaultConfig(1), MethodSoftwareCPUClock)
		if e != nil {
			t.Skipf("NOT run: %v", e)
		}
		defer ring.Close()
		if e = enableCPU(ring); e != nil {
			t.Fatal(e)
		}
		rings = append(rings, ring)
	}
	needle := []byte(env.sentinel("comm"))
	deadline := time.Now().Add(5 * time.Second)
	ringComm, sanitizedComm := 0, 0
	for ringComm == 0 && time.Now().Before(deadline) {
		for _, ring := range rings {
			for {
				consumed := false
				e := ring.consume(func(v KernelRecordView) error {
					consumed = true
					// A boolean about the borrowed bytes; the bytes themselves are never audited.
					if v.u32(0) == perfRecordComm && (bytes.Contains(v.first, needle) || bytes.Contains(append(append([]byte(nil), v.first...), v.second...), needle)) {
						ringComm++
						event, ok, e := decodeCPURecord(v, ring)
						if e != nil || ok {
							t.Errorf("COMM record was not skipped: ok=%v err=%v", ok, e)
						}
						raw, _ := json.Marshal(event)
						_ = env.audit.Observe(StageStaging, raw)
						sanitizedComm++
						return nil
					}
					event, ok, e := decodeCPURecord(v, ring)
					if e == nil && ok {
						raw, _ := json.Marshal(event)
						_ = env.audit.Observe(StageStaging, raw)
					}
					return nil
				})
				if e != nil || !consumed {
					break
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ringComm == 0 {
		t.Fatal("the kernel ring never carried the comm sentinel; the workload premise is broken")
	}
	t.Logf("kernel ring carried %d COMM records holding the comm sentinel; all were skipped in place", sanitizedComm)
	env.requireClean(t, StageStaging)
}

// TestPrivacyNegativeControl*: permanent contaminated sanitizers. The detector
// must flag every one at BOTH the owned staging buffer and the socket.
func privacyContaminatedBoundary(t *testing.T, env *privacyEnv, sanitize privacySanitizer) {
	t.Helper()
	var seq uint64
	events, e := privacyPump(privacyFakeRing(env, privacyTask), sanitize, privacyDomain, &seq)
	if e != nil {
		t.Fatal(e)
	}
	privacyStreamEvents(t, env, events)
}
func TestPrivacyNegativeControlSanitizerCopiesComm(t *testing.T) {
	for name, sanitize := range map[string]privacySanitizer{"comm_in_domain_label": privacyContaminatedCommLabel(), "comm_bytes_in_address": privacyContaminatedCommWord()} {
		t.Run(name, func(t *testing.T) {
			env := newPrivacyEnv(t)
			privacyContaminatedBoundary(t, env, sanitize)
			staged, socket := false, false
			for _, v := range env.audit.Violations() {
				staged = staged || v.Stage == StageStaging
				socket = socket || v.Stage == StageSocket
			}
			if !staged || !socket {
				t.Fatalf("detector missed the contaminated sanitizer: staging=%v socket=%v violations=%v", staged, socket, env.audit.Violations())
			}
		})
	}
	t.Run("real_kernel_ring", func(t *testing.T) {
		privacyRequireRealPerf(t)
		env := newPrivacyEnv(t)
		canary := privacyLaunchCanary(t, env, 0)
		target := privacyTargetFor(t, canary)
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		cfg := DefaultConfig(1)
		grant, e := SignStart(StartAuthorization{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}, private)
		if e != nil {
			t.Fatal(e)
		}
		authorized, e := authorizeLocal(PeerCredential{UID: uint32(os.Getuid())}, CaptureRequest{Authorization: grant, Targets: []Target{target}, Config: cfg, Mode: ModeCPU}, OperatorPolicy{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: []Target{target}})
		if e != nil {
			t.Fatal(e)
		}
		budget := NewResourceBudget()
		var limit syscall.Rlimit
		syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
		cpus, _ := OnlineCPUs()
		lease, e := budget.Reserve(authorized, cfg, Topology{CPUs: uint64(len(cpus)), FDLimit: limit.Cur, OpenFDs: 64, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{HelperRSS: 8 << 20, ExportRSS: 8 << 20})
		if e != nil {
			t.Fatal(e)
		}
		defer lease.Close()
		source, e := NewCPUAcquisition(context.Background(), authorized, cfg, lease)
		if e != nil {
			t.Fatal(e)
		}
		defer source.Close()
		cpu := source.(*cpuSource)
		sanitize := privacyContaminatedCommLabel()
		var all []SanitizedEvent
		var seq uint64
		deadline := time.Now().Add(5 * time.Second)
		for len(env.audit.Violations()) == 0 && time.Now().Before(deadline) {
			for _, ring := range cpu.rings {
				events, e := privacyPump(ring, sanitize, cpu.domain, &seq)
				if e != nil {
					t.Fatal(e)
				}
				all = append(all, events...)
			}
			if len(all) > 0 {
				privacyStreamEvents(t, env, all)
				all = nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		if len(env.audit.Violations()) == 0 {
			t.Fatal("detector missed a contaminated sanitizer on the real kernel ring")
		}
	})
}

// TestPrivacyNegativeControlExplicit re-runs the contaminated sanitizer through
// the SAME boundary assertions TestNoContentAtAcquisitionBoundary uses. It is
// skipped by default; invoked explicitly it must FAIL, proving the guard is live:
//
//	SOUNDPOST_PRIVACY_NEGATIVE_CONTROL=1 go test ./internal/nativeperf -run TestPrivacyNegativeControlExplicit
func TestPrivacyNegativeControlExplicit(t *testing.T) {
	if os.Getenv("SOUNDPOST_PRIVACY_NEGATIVE_CONTROL") != "1" {
		t.Skip("explicit negative control: set SOUNDPOST_PRIVACY_NEGATIVE_CONTROL=1 (this test is expected to FAIL)")
	}
	env := newPrivacyEnv(t)
	privacyContaminatedBoundary(t, env, privacyContaminatedCommLabel())
	env.requireClean(t, StageStaging, StageSocket)
}

// ---- lifecycle: assembly, wire encodings and diagnostics ----

func privacyCapabilities(offCPU Status) Capabilities {
	return Capabilities{CPU: Supported, OffCPU: offCPU, RunqueueSplit: offCPU, Permissions: Permissions{CPUEventOpen: Supported, SchedulerEventOpen: offCPU}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}}
}

type privacyLifecycleResult struct {
	chunk model.ProfileChunk
	wire  []byte
}

func privacyLifecycle(t *testing.T, env *privacyEnv, events []SanitizedEvent, intervals []Interval, domain ClockDomain) privacyLifecycleResult {
	t.Helper()
	now := model.UnixNano(time.Now().UnixNano())
	limits := ProfileLimits{Profile: model.NewID(), Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: 1, Sequence: 1, Start: now, End: now + 2_000_000_000, Clock: model.TraceClock{Wall: now, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096}
	// The scheduler numeric channel here is a synthetic fixture: real scheduler
	// tracefs is unavailable on this kernel; only its privacy/numeric behavior is claimed.
	chunk, e := AssembleProfile(context.Background(), events, intervals, privacyCapabilities(Supported), limits)
	if e != nil {
		t.Fatal(e)
	}
	chunks, e := splitProfile(chunk)
	if e != nil {
		t.Fatal(e)
	}
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "privacy", Labels: model.Labels{}}
	var records []model.Record
	for i := range chunks {
		c := chunks[i]
		records = append(records, model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: now, Resource: resource, Payload: model.Payload{Profile: &c}})
	}
	batch := model.Batch{Version: 1, Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	wire, e := json.Marshal(batch)
	if e != nil {
		t.Fatal(e)
	}
	_ = env.audit.Observe(StageWireDecompressed, wire)
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(wire)
	w.Close()
	_ = env.audit.Observe(StageWireCompressed, z.Bytes())
	// The real ingest decoder accepts both encodings and reproduces the same batch.
	for _, encoding := range []string{"", "gzip"} {
		body := wire
		if encoding == "gzip" {
			body = z.Bytes()
		}
		decoded, e := ingest.Decode(bytes.NewReader(body), encoding)
		if e != nil {
			t.Fatalf("ingest decode (%q): %v", encoding, e)
		}
		again, _ := json.Marshal(decoded)
		if !bytes.Equal(again, wire) {
			t.Fatalf("wire round trip (%q) changed the batch", encoding)
		}
		_ = env.audit.Observe(StageWireDecompressed, again)
	}
	return privacyLifecycleResult{chunk: chunk, wire: wire}
}

// privacyRequireNumericEvidence: scheduler numeric values and genuine CPU
// stacks must be present so an empty export cannot pass privacy.
func privacyRequireNumericEvidence(t *testing.T, r privacyLifecycleResult, samples int) {
	t.Helper()
	if len(r.chunk.Samples) != samples || len(r.chunk.Stacks) == 0 || len(r.chunk.Frames) == 0 {
		t.Fatalf("assembled profile lost CPU evidence: %d samples (want %d) %d stacks %d frames", len(r.chunk.Samples), samples, len(r.chunk.Stacks), len(r.chunk.Frames))
	}
	for _, s := range r.chunk.Samples {
		if s.Native == nil || s.Native.Period == 0 || s.Native.RequestedHz != 99 || s.Count != 1 {
			t.Fatalf("native period/rate lost: %+v", s)
		}
		if len(r.chunk.Stacks[s.Stack].Frames) == 0 {
			t.Fatal("empty stack")
		}
	}
	var blocked, runnable uint64
	for _, i := range r.chunk.Intervals {
		d := uint64(i.End - i.Start)
		switch i.Kind {
		case "blocked":
			blocked += d
		case "runnable":
			runnable += d
		}
	}
	if blocked != 40_000_000 || runnable != 15_000_000 {
		t.Fatalf("scheduler numeric values changed: blocked=%d runnable=%d", blocked, runnable)
	}
	for _, want := range []string{"1040000000", "1055000000"} {
		if !bytes.Contains(r.wire, []byte(want)) {
			t.Fatalf("scheduler numeric value %s missing from the wire payload", want)
		}
	}
}

// TestNoContentAcrossProfileLifecycle: sanitized events -> assembled profile ->
// compressed/decompressed wire -> real ingest decoder, plus diagnostics. The
// backend storage/read/export and artifact-policy stages are in
// internal/profiles/privacy_test.go.
func TestNoContentAcrossProfileLifecycle(t *testing.T) {
	t.Run("kernel_ring_records", func(t *testing.T) {
		env := newPrivacyEnv(t)
		var seq uint64
		events, e := privacyPump(privacyFakeRing(env, privacyTask), privacySanitizerUnderTest(), privacyDomain, &seq)
		if e != nil {
			t.Fatal(e)
		}
		sched := privacySchedulerEvents(t, env, privacyDomain, privacyTask, 1_000_000_000)
		intervals := privacySchedulerIntervals(t, sched, privacyDomain, 1_000_000_000)
		r := privacyLifecycle(t, env, events, intervals, privacyDomain)
		privacyRequireNumericEvidence(t, r, 3)
		for _, i := range intervals {
			raw, _ := json.Marshal(i)
			_ = env.audit.Observe(StageDiagnostics, raw)
		}
		env.requireClean(t, StageWireCompressed, StageWireDecompressed, StageDiagnostics)
	})
	t.Run("real_helper_events", func(t *testing.T) {
		privacyRequireInProcessHelper(t)
		env := newPrivacyEnv(t)
		s := privacyStartSession(t, env, privacyOptions{})
		if ready := s.connect(); !ready.Ready {
			t.Fatalf("helper refused: %+v", ready)
		}
		events, _, e := s.capture(2 * time.Second)
		if e != nil {
			t.Fatal(e)
		}
		samples := privacyRequireGenuineCPU(t, s.canary, events)
		var cpuEvents []SanitizedEvent
		for _, event := range events {
			if event.CPUEvent != nil {
				cpuEvents = append(cpuEvents, event)
			}
		}
		task := cpuEvents[0].Task
		// Scheduler numerics are synthetic (tracefs denied); they join the real task.
		sched := privacySchedulerEvents(t, env, cpuEvents[0].Domain, task, 1_000_000_000)
		intervals := privacySchedulerIntervals(t, sched, cpuEvents[0].Domain, 1_000_000_000)
		r := privacyLifecycle(t, env, cpuEvents, intervals, cpuEvents[0].Domain)
		privacyRequireNumericEvidence(t, r, samples)
		caps, _ := Probe(context.Background(), []Target{{PIDNamespace: s.target.PIDNamespace, TGID: s.target.TGID, ProcessStart: s.target.ProcessStart}})
		diag, _ := json.Marshal(caps)
		_ = env.audit.Observe(StageDiagnostics, diag)
		env.requireClean(t, StageStaging, StageSocket, StageWireCompressed, StageWireDecompressed, StageDiagnostics)
	})
}

// =========================== fixed socket decoder ===========================

func privacyFrame(payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(b, uint32(len(payload)))
	copy(b[4:], payload)
	return b
}
func privacyJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func privacyValidEvent(seq uint64) SanitizedEvent {
	return SanitizedEvent{Kind: EventCPU, Time: 10, Sequence: model.Uint64(seq), Domain: privacyDomain, Task: privacyTask, CPUEvent: &CPUSample{IP: 0x401100, Callchain: []CallchainEntry{{IP: 0x401100}, {IP: 0x401180}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10101010}}
}

// readMessage is the single fixed decoder for both directions of the helper
// socket: it must reject every frame that is not exactly one bounded, known JSON value.
func TestPrivacySocketDecoderRejectsUnknownOversizedTruncatedFrames(t *testing.T) {
	env := newPrivacyEnv(t)
	canary := env.sentinel("input")
	event := privacyValidEvent(1)
	eventJSON := string(privacyJSON(helperReply{Event: &event}))
	maxFrame := make([]byte, maxHelperMessage)
	copy(maxFrame, `{"ready":true}`)
	for i := len(`{"ready":true}`); i < len(maxFrame); i++ {
		maxFrame[i] = ' '
	}
	header := func(n uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, n); return b }
	cases := []struct {
		name   string
		wire   []byte
		reject bool
		left   int // bytes that must remain unread (oversize must not allocate/read the body)
	}{
		{"exact_ready", privacyFrame([]byte(`{"ready":true}`)), false, 0},
		{"exactly_max_size", append(header(maxHelperMessage), maxFrame...), false, 0},
		{"one_over_max", append(header(maxHelperMessage+1), make([]byte, 16)...), true, 16},
		{"huge_length", append(header(1<<31), make([]byte, 16)...), true, 16},
		{"zero_length", append(header(0), make([]byte, 16)...), true, 16},
		{"truncated_header", []byte{0, 0}, true, 0},
		{"truncated_body", append(header(100), make([]byte, 10)...), true, 0},
		{"unknown_top_level_field", privacyFrame([]byte(`{"ready":true,"debug":"` + canary + `"}`)), true, 0},
		{"unknown_stack_dump_field", privacyFrame([]byte(`{"ready":true,"stack_dump":"` + canary + `"}`)), true, 0},
		{"unknown_event_field", privacyFrame([]byte(strings.Replace(eventJSON, `"kind":"cpu_sample"`, `"kind":"cpu_sample","comm":"`+canary+`"`, 1))), true, 0},
		{"unknown_cpu_sample_field", privacyFrame([]byte(strings.Replace(eventJSON, `"requested_hz":99`, `"requested_hz":99,"regs":"`+canary+`"`, 1))), true, 0},
		{"invalid_event_sequence", privacyFrame([]byte(strings.Replace(eventJSON, `"sequence":"1"`, `"sequence":"0"`, 1))), true, 0},
		{"trailing_second_value", privacyFrame([]byte(`{"ready":true}{"ready":true}`)), true, 0},
		{"trailing_garbage", privacyFrame([]byte(`{"ready":true} ` + canary)), true, 0},
		{"not_json", privacyFrame([]byte("not json " + canary)), true, 0},
		{"wrong_type", privacyFrame([]byte(`{"ready":"` + canary + `"}`)), true, 0},
		{"array", privacyFrame([]byte(`[]`)), true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.wire)
			var reply helperReply
			e := readMessage(reader, &reply)
			if tc.reject {
				if e == nil {
					t.Fatalf("%s accepted: %+v", tc.name, reply)
				}
				if reader.Len() != tc.left {
					t.Fatalf("decoder consumed the wrong amount: %d unread, want %d", reader.Len(), tc.left)
				}
				if strings.Contains(e.Error(), canary) {
					t.Fatal("decoder error echoes frame content")
				}
				_ = env.audit.Observe(StageDiagnostics, []byte(e.Error()))
			} else if e != nil || !reply.Ready {
				t.Fatalf("%s refused: %v", tc.name, e)
			}
		})
	}
	// The encoder refuses to emit what the decoder would refuse.
	if e := writeMessage(io.Discard, struct{ Pad string }{strings.Repeat("x", maxHelperMessage)}); !errors.Is(e, ErrInvalid) {
		t.Fatalf("oversized frame encoded: %v", e)
	}
	if e := env.audit.RequireStages(StageDiagnostics); e != nil {
		t.Fatal(e)
	}
	env.requireClean(t, StageDiagnostics)
}

// privacySequence feeds raw frames to the real client-side source and reports
// how many items were delivered, the terminal error and the sticky repeat error.
func privacySequence(t *testing.T, wire ...[]byte) (delivered int, terminal, again error) {
	t.Helper()
	client, server := cpuSocketPair(t)
	go func() {
		for _, frame := range wire {
			if _, e := server.Write(frame); e != nil {
				return
			}
		}
		server.Close()
	}()
	source := newSocketSource(context.Background(), client)
	defer source.Close()
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, e := source.NextItem(context.Background()); e != nil {
			terminal = e
			break
		}
		delivered++
	}
	_, again = source.NextItem(context.Background())
	return delivered, terminal, again
}
func TestPrivacySocketSourceRejectsMalformedEventSequences(t *testing.T) {
	env := newPrivacyEnv(t)
	canary := env.sentinel("input")
	event := func(n uint64) []byte {
		e := privacyValidEvent(n)
		return privacyFrame(privacyJSON(helperReply{Event: &e}))
	}
	proof := func(final bool) []byte {
		return privacyFrame(privacyJSON(helperReply{Proof: &AcquisitionProof{Domain: privacyDomain, CPUs: []uint32{0}, Through: 100, Final: final}}))
	}
	reply := func(r helperReply) []byte { return privacyFrame(privacyJSON(r)) }
	cases := []struct {
		name      string
		wire      [][]byte
		delivered int
		want      func(error) bool
	}{
		{"events_then_peer_exit_is_not_success", [][]byte{event(1), event(2)}, 2, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"ready_mid_stream", [][]byte{reply(helperReply{Ready: true})}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"event_and_error_together", [][]byte{reply(helperReply{Event: new(privacyValidEvent(1)), Error: "loss"})}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"complete_without_final_proof", [][]byte{reply(helperReply{Complete: true})}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"event_after_final_proof", [][]byte{proof(false), proof(true), event(1)}, 2, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"final_proof_before_topology", [][]byte{proof(true)}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"duplicate_topology_proof", [][]byte{proof(false), proof(false)}, 1, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"null_frame", [][]byte{privacyFrame([]byte("null"))}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"empty_object", [][]byte{privacyFrame([]byte("{}"))}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"unknown_field_carrying_canary", [][]byte{privacyFrame([]byte(`{"error":"loss","trace":"` + canary + `"}`))}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"permission_code_is_typed", [][]byte{reply(helperReply{Error: "permission_denied"})}, 0, func(e error) bool {
			var c *CapabilityError
			return errors.As(e, &c) && c.Status == Denied
		}},
		{"unknown_code_never_echoed", [][]byte{reply(helperReply{Error: "/proc/1/" + canary})}, 0, func(e error) bool { return errors.Is(e, ErrAcquisitionFailed) }},
		{"complete_only_after_final_proof", [][]byte{proof(false), proof(true), reply(helperReply{Complete: true})}, 2, func(e error) bool { return errors.Is(e, ErrSourceComplete) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			delivered, terminal, again := privacySequence(t, tc.wire...)
			if delivered != tc.delivered || terminal == nil || !tc.want(terminal) {
				t.Fatalf("delivered=%d terminal=%v", delivered, terminal)
			}
			if again == nil || again.Error() != terminal.Error() {
				t.Fatalf("terminal state not sticky: %v then %v", terminal, again)
			}
			if strings.Contains(terminal.Error(), canary) {
				t.Fatal("terminal error echoes frame content")
			}
			_ = env.audit.Observe(StageDiagnostics, []byte(terminal.Error()))
		})
	}
	env.requireClean(t, StageDiagnostics)
}

// A request that is not exactly one bounded, known, correctly signed JSON value is
// refused with the single closed code, before any reservation or perf event.
func TestPrivacyHelperRejectsMalformedAndRevokedRequestsWithoutOpeningAnything(t *testing.T) {
	env := newPrivacyEnv(t)
	canary := env.sentinel("input")
	s := privacyStartSession(t, env, privacyOptions{noCanary: true})
	good := privacyJSON(s.request)
	var asMap map[string]any
	if e := json.Unmarshal(good, &asMap); e != nil {
		t.Fatal(e)
	}
	withTop := func(k string, v any) []byte {
		m := map[string]any{}
		for key, value := range asMap {
			m[key] = value
		}
		m[k] = v
		return privacyFrame(privacyJSON(m))
	}
	header := func(n uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, n); return b }
	tampered := s.request
	tampered.Targets = []Target{s.target}
	tampered.Targets[0].TGID++
	cases := []struct {
		name      string
		wire      []byte
		closeSend bool
	}{
		{"unknown_request_field", withTop("Debug", canary), false},
		{"oversized_frame", header(maxHelperMessage + 1), false},
		{"zero_length_frame", header(0), false},
		{"truncated_header", []byte{0, 0}, true},
		{"truncated_body", append(header(200), good[:50]...), true},
		{"not_json", privacyFrame([]byte("not json " + canary)), false},
		{"trailing_value", privacyFrame(append(append([]byte(nil), good...), []byte(`{}`)...)), false},
		{"tampered_signed_target", privacyFrame(privacyJSON(tampered)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := s.dial()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write(tc.wire)
			if tc.closeSend {
				conn.CloseWrite()
			}
			reply, e := privacyReadReply(env, conn)
			if e != nil || reply.Error != "authorization_denied" || reply.Ready || reply.Event != nil {
				t.Fatalf("not refused with the closed code: %+v %v", reply, e)
			}
			conn.Close()
			if e = s.waitReleased(time.Second); e != nil {
				t.Fatal(e)
			}
		})
	}
	if e := env.audit.RequireStages(StageSocket); e != nil {
		t.Fatal(e)
	}
	env.requireClean(t, StageSocket)

	// Revocation, expiry, a foreign signer and a peer from another UID are refused
	// by authorizeLocal itself, again before anything is opened.
	for name, opt := range map[string]privacyOptions{"foreign_signing_key": {badKey: true, noCanary: true}, "policy_revision_advanced": {staleRev: true, noCanary: true}, "grant_already_expired": {grantTTL: -2 * time.Second, noCanary: true}} {
		t.Run(name, func(t *testing.T) {
			session := privacyStartSession(t, env, opt)
			reply := session.connect()
			if reply.Error != "authorization_denied" || reply.Ready {
				t.Fatalf("%s accepted: %+v", name, reply)
			}
			if e := session.waitReleased(time.Second); e != nil {
				t.Fatal(e)
			}
		})
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	cfg := DefaultConfig(1)
	grant, _ := SignStart(StartAuthorization{Installation: "privacy-fixture", UID: 12345, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{s.target}, Config: cfg, Mode: ModeCPU}, private)
	request := CaptureRequest{Authorization: grant, Targets: []Target{s.target}, Config: cfg, Mode: ModeCPU}
	policy := OperatorPolicy{Installation: "privacy-fixture", UID: 12345, Revision: 1, PublicKey: public, Allowlist: []Target{s.target}}
	if _, e := authorizeLocal(PeerCredential{UID: 54321}, request, policy); !errors.Is(e, ErrAuthorization) {
		t.Fatalf("peer from another UID accepted: %v", e)
	}
	if _, e := authorizeLocal(PeerCredential{UID: 12345}, request, policy); e != nil {
		t.Fatalf("control: matching peer refused: %v", e)
	}
}

// The closed reason vocabulary: every helper failure maps to a code from the
// policy vocabulary, and no error carrying a path/errno/command text can widen it.
func TestPrivacyHelperReasonVocabularyIsClosed(t *testing.T) {
	env := newPrivacyEnv(t)
	pathErr := &os.PathError{Op: "open", Path: "/proc/1/task/" + env.sentinel("path") + "/mem", Err: syscall.EACCES}
	cases := map[error]string{
		ErrAuthorization:                              "authorization_denied",
		ErrTopologyChanged:                            "topology_changed",
		context.Canceled:                              "source_canceled",
		ErrResources:                                  "resource_limit",
		ErrThreadCoverageChanged:                      "thread_coverage_changed",
		ErrTargetIdentity:                             "generation_changed",
		ErrRingOverwrite:                              "loss",
		ErrAcquisitionPending:                         "event_unavailable",
		&CapabilityError{Denied, ReasonPermission}:    "permission_denied",
		&CapabilityError{Unsupported, ReasonEvent}:    "event_unavailable",
		ErrAcquisitionFailed:                          "acquisition_failed",
		ErrRingMalformed:                              "acquisition_failed",
		pathErr:                                       "acquisition_failed",
		fmt.Errorf("wrapped %w", syscall.EPERM):       "acquisition_failed",
		fmt.Errorf("%s: %w", canaryText(env), io.EOF): "acquisition_failed",
	}
	seen := map[string]bool{}
	for err, want := range cases {
		got := helperErrorCode(err)
		if got != want {
			t.Errorf("%T -> %q, want %q", err, got, want)
		}
		seen[got] = true
		// The decoded error on the client side is also closed: never the wire text.
		if round := helperCodeError(got); strings.Contains(round.Error(), env.nonce) {
			t.Errorf("code %q decodes to a content-bearing error", got)
		}
	}
	var vocabulary []string
	for code := range seen {
		vocabulary = append(vocabulary, code)
	}
	want := append([]string(nil), env.policy.ReasonVocab...)
	sortStrings(vocabulary)
	sortStrings(want)
	if strings.Join(vocabulary, ",") != strings.Join(want, ",") {
		t.Fatalf("reason vocabulary drifted from policy: have %v want %v", vocabulary, want)
	}
	raw := []byte(strings.Join(vocabulary, " "))
	_ = env.audit.Observe(StageDiagnostics, raw)
	env.requireClean(t, StageDiagnostics)
}
func canaryText(env *privacyEnv) string { return "open " + env.sentinel("path") }
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// =========================== sandbox failure drills ===========================

// privacyNoNewDumps fails if a perf.data/core/stack dump file appears under the
// given directories while the drill runs.
func privacyNoNewDumps(t *testing.T, env *privacyEnv, dirs ...string) {
	t.Helper()
	before := map[string]bool{}
	for _, f := range privacyDumpFiles(t, env, dirs...) {
		before[f] = true
	}
	t.Cleanup(func() {
		for _, f := range privacyDumpFiles(t, env, dirs...) {
			if !before[f] {
				t.Errorf("emergency dump artifact created: %s", filepath.Base(f))
			}
		}
	})
}

// Expiry of the signed grant stops acquisition, closes the stream (never a
// success marker), and releases the lease, ring FDs and mappings.
func TestPrivacyDrillGrantExpiryStopsAcquisition(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	s := privacyStartSession(t, env, privacyOptions{grantTTL: 3 * time.Second})
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("refused: %+v", ready)
	}
	started := time.Now()
	events, terminal, ended := s.capture(10 * time.Second)
	elapsed := time.Since(started)
	if elapsed > 6*time.Second || len(events) == 0 {
		t.Fatalf("capture ran %v with %d events; the grant expires after at most 3s", elapsed, len(events))
	}
	if ended == nil || terminal.Complete || terminal.Error != "" {
		t.Fatalf("expiry was reported as a result instead of a closed stream: ended=%v terminal=%+v", ended, terminal)
	}
	if e := s.waitReleased(3 * time.Second); e != nil {
		t.Fatal(e)
	}
	env.requireClean(t, StageStaging, StageSocket)
}

// The consumer vanishing (SIGKILL-equivalent connection loss) stops acquisition,
// frees every resource and leaves the helper serving the next authorized peer.
func TestPrivacyDrillSocketPeerDeathReleasesAcquisition(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	s := privacyStartSession(t, env, privacyOptions{})
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("refused: %+v", ready)
	}
	if events, _, _ := s.capture(500 * time.Millisecond); len(events) == 0 {
		t.Fatal("no events before peer death")
	}
	if memory, fds := s.budget(); memory == 0 || fds == 0 || privacyPerfFDs() == s.baseFDs {
		t.Fatalf("premise: nothing was held during capture (%d %d %d)", memory, fds, privacyPerfFDs())
	}
	s.conn.Close()
	if e := s.waitReleased(3 * time.Second); e != nil {
		t.Fatal(e)
	}
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("helper did not survive peer death: %+v", ready)
	}
	if events, _, _ := s.capture(500 * time.Millisecond); len(events) == 0 {
		t.Fatal("released resources could not be reacquired")
	}
	env.requireClean(t, StageStaging, StageSocket)
}

// A consumer-side export failure stops acquisition through the real client
// session: the CPU source has no graceful Stop (documented), so Close is the stop.
func TestPrivacyDrillExportFailureStopsAcquisition(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	s := privacyStartSession(t, env, privacyOptions{})
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("refused: %+v", ready)
	}
	session := &Session{source: newSocketSource(context.Background(), s.conn)}
	if _, e := session.NextItem(context.Background()); e != nil {
		t.Fatal(e)
	}
	// The exporter failed: the consumer asks the helper to stop (the client
	// source's fixed {"stop":true} message), then closes. The CPU source behind
	// the helper has no graceful drain, so the helper cancels capture at once.
	if e := session.Stop(); e != nil {
		t.Fatalf("stop request not delivered: %v", e)
	}
	if e := session.Close(); e != nil {
		t.Logf("close: %v", e)
	}
	if e := s.waitReleased(3 * time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e := session.NextItem(context.Background()); e == nil {
		t.Fatal("closed session kept delivering")
	}
}

// Service shutdown/revocation of the helper's own context stops the capture.
func TestPrivacyDrillHelperShutdownStopsAcquisition(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	s := privacyStartSession(t, env, privacyOptions{})
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("refused: %+v", ready)
	}
	if events, _, _ := s.capture(400 * time.Millisecond); len(events) == 0 {
		t.Fatal("no events before shutdown")
	}
	s.cancel()
	_, terminal, _ := s.capture(3 * time.Second)
	if terminal.Complete {
		t.Fatal("shutdown reported completion")
	}
	select {
	case <-s.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
	if !errors.Is(s.servedErr, context.Canceled) {
		t.Fatalf("Serve returned %v", s.servedErr)
	}
	if e := s.waitReleased(3 * time.Second); e != nil {
		t.Fatal(e)
	}
}

// Every failure class stops acquisition with exactly its closed reason code,
// never with text, and releases the lease, rings and mappings each time.
func TestPrivacyDrillAcquisitionFailuresUseClosedReasonCounters(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	failures := []struct {
		name string
		err  error
		code string
	}{
		{"permission_change", &CapabilityError{Denied, ReasonPermission}, "permission_denied"},
		{"event_unavailable", &CapabilityError{Unsupported, ReasonEvent}, "event_unavailable"},
		{"generation_change", ErrTargetIdentity, "generation_changed"},
		{"thread_coverage_change", ErrThreadCoverageChanged, "thread_coverage_changed"},
		{"ring_overwrite", ErrRingOverwrite, "loss"},
		{"topology_change", ErrTopologyChanged, "topology_changed"},
		{"resource_limit", ErrResourceBudget, "resource_limit"},
		{"path_and_errno_bearing_error", &os.PathError{Op: "open", Path: "/proc/1/" + env.sentinel("path") + "/mem", Err: syscall.EACCES}, "acquisition_failed"},
	}
	next := 0
	s := privacyStartSession(t, env, privacyOptions{wrap: func(inner EventSource) EventSource {
		f := failures[next]
		next++
		return &privacyFailingSource{inner: inner, after: 3, err: f.err}
	}})
	counters := map[string]int{}
	for _, f := range failures {
		if ready := s.connect(); !ready.Ready {
			t.Fatalf("%s: refused: %+v", f.name, ready)
		}
		events, terminal, ended := s.capture(5 * time.Second)
		if ended != nil || terminal.Error != f.code || len(events) != 3 {
			t.Fatalf("%s: code=%q events=%d ended=%v want %q after 3 events", f.name, terminal.Error, len(events), ended, f.code)
		}
		counters[terminal.Error]++
		s.conn.Close()
		if e := s.waitReleased(3 * time.Second); e != nil {
			t.Fatalf("%s: %v", f.name, e)
		}
	}
	total := 0
	for code, n := range counters {
		known := false
		for _, v := range env.policy.ReasonVocab {
			known = known || v == code
		}
		if !known {
			t.Errorf("reason counter %q is outside the closed vocabulary", code)
		}
		total += n
	}
	if total != len(failures) || counters["acquisition_failed"] != 1 {
		t.Fatalf("counters %v", counters)
	}
	_ = env.audit.Observe(StageDiagnostics, privacyJSON(counters))
	env.requireClean(t, StageStaging, StageSocket, StageDiagnostics)
}

// The profiled process dying mid-capture (a crash of the target) is a generation
// or coverage failure with a closed code, never an empty successful profile.
func TestPrivacyDrillTargetCrashStopsAcquisition(t *testing.T) {
	privacyRequireInProcessHelper(t)
	env := newPrivacyEnv(t)
	privacyNoNewDumps(t, env, os.TempDir(), ".")
	s := privacyStartSession(t, env, privacyOptions{})
	if ready := s.connect(); !ready.Ready {
		t.Fatalf("refused: %+v", ready)
	}
	if events, _, _ := s.capture(500 * time.Millisecond); len(events) == 0 {
		t.Fatal("no events before the crash")
	}
	s.canary.cmd.Process.Kill()
	_, terminal, ended := s.capture(5 * time.Second)
	switch terminal.Error {
	case "generation_changed", "thread_coverage_changed", "acquisition_failed":
	default:
		t.Fatalf("target crash ended with %+v (stream error %v)", terminal, ended)
	}
	if terminal.Complete {
		t.Fatal("target crash reported as complete")
	}
	if e := s.waitReleased(3 * time.Second); e != nil {
		t.Fatal(e)
	}
	env.requireClean(t, StageStaging, StageSocket)
}

// =========================== syscall / configuration audit ===========================

// privacyAuditSource and helperMainPrintOK are the shared static source audit
// (scan.AuditGoSource), also used by the verify fixture.
func privacyAuditSource(p scan.Policy, filename, src string, printOK func(*ast.CallExpr) bool) []string {
	return scan.AuditGoSource(p, filename, src, printOK)
}
func helperMainPrintOK(call *ast.CallExpr) bool { return scan.HelperMainPrintOK(call) }

func privacyProductionSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	matches, e := filepath.Glob("*.go")
	if e != nil {
		t.Fatal(e)
	}
	matches = append(matches, "../../cmd/soundpost-perf-acquire/main.go")
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		files[path] = string(b)
	}
	return files
}

// The actual acquisition path's Go sources contain no forbidden proc-mem/ptrace/
// eBPF/register/stack-dump syscalls, constants, strings or imports; the raw
// syscall surface is exactly the reviewed one. (Static source/config audit; the
// dynamic strace audit of the real fixture run is TestPrivacySyscallAuditOfRealFixtureRun.)
func TestPrivacyAcquisitionPathStaticAudit(t *testing.T) {
	env := newPrivacyEnv(t)
	sources := privacyProductionSources(t)
	if len(sources) < 30 {
		t.Fatalf("audited only %d production files", len(sources))
	}
	rawCalls := 0
	for path, src := range sources {
		ok := (func(*ast.CallExpr) bool)(nil)
		if strings.HasSuffix(path, "soundpost-perf-acquire/main.go") {
			ok = helperMainPrintOK
		}
		for _, f := range privacyAuditSource(env.policy, path, src, ok) {
			t.Error(f)
		}
		rawCalls += strings.Count(src, "syscall.Syscall")
	}
	if rawCalls < 10 {
		t.Fatalf("only %d raw syscall sites seen; the audit is not looking at the acquisition sources", rawCalls)
	}
}

// Negative controls for the static audit itself: each mutation below is an
// actual forbidden change the audit must flag; the control source must be clean.
func TestPrivacyStaticAuditFlagsForbiddenSources(t *testing.T) {
	env := newPrivacyEnv(t)
	const prelude = "package x\nimport \"syscall\"\nvar _ = syscall.EPERM\nfunc f(fd uintptr) {\n"
	control := prelude + "\tsyscall.Syscall(syscall.SYS_IOCTL, fd, 0x2400, 0)\n\tsyscall.Syscall(434, 1, 0, 0)\n}\n"
	if got := privacyAuditSource(env.policy, "x.go", control, nil); len(got) != 0 {
		t.Fatalf("clean control flagged: %v", got)
	}
	mutants := map[string]string{
		"ptrace_constant":   prelude + "\tsyscall.Syscall(syscall.SYS_PTRACE, 16, 1, 0)\n}\n",
		"ptrace_number":     prelude + "\tsyscall.Syscall(101, 16, 1, 0)\n}\n",
		"process_vm_readv":  prelude + "\tsyscall.Syscall6(310, 1, 0, 0, 0, 0, 0)\n}\n",
		"bpf_constant":      prelude + "\tsyscall.Syscall(syscall.SYS_BPF, 5, 0, 0)\n}\n",
		"unlisted_ioctl":    prelude + "\tsyscall.Syscall(syscall.SYS_IOCTL, fd, 0x40042408, 0)\n}\n",
		"computed_ioctl":    prelude + "\tr := uintptr(0x2400)\n\tsyscall.Syscall(syscall.SYS_IOCTL, fd, r, 0)\n}\n",
		"computed_number":   prelude + "\tn := uintptr(101)\n\tsyscall.Syscall(n, 16, 1, 0)\n}\n",
		"raw_syscall":       prelude + "\tsyscall.RawSyscall(syscall.SYS_PERF_EVENT_OPEN, 0, 0, 0)\n}\n",
		"ptrace_helper":     prelude + "\tsyscall.PtraceAttach(1)\n}\n",
		"unlisted_package":  prelude + "\tsyscall.Kill(1, 9)\n}\n",
		"proc_mem_string":   prelude + "\t_ = \"/proc/\" + \"self/mem\"\n\t_ = \"/proc/1234/mem\"\n}\n",
		"stack_user_flag":   prelude + "\t_ = 1 << 13\n\tvar PERF_SAMPLE_STACK_USER = 1 << 13\n\t_ = PERF_SAMPLE_STACK_USER\n}\n",
		"exec_import":       "package x\nimport _ \"os/exec\"\n",
		"log_import":        "package x\nimport _ \"log\"\n",
		"fixture_import":    "package x\nimport _ \"soundpost/fixtures/nativeperf/privacy/scan\"\n",
		"prints_a_value":    "package x\nimport \"fmt\"\nfunc f(v any) { fmt.Println(v) }\n",
		"prints_to_stderr":  "package x\nimport (\"fmt\"\n\"os\")\nfunc f(v any) { fmt.Fprintf(os.Stderr, \"%v\", v) }\n",
		"perf_data_literal": "package x\nvar _ = \"/var/lib/perf.data\"\n",
	}
	for name, src := range mutants {
		if got := privacyAuditSource(env.policy, "x.go", src, nil); len(got) == 0 {
			t.Errorf("%s: forbidden source not flagged", name)
		}
	}
	// The helper main's one reviewed print stays admitted; any other form is not.
	allowed := "package x\nimport (\"fmt\"\n\"os\")\nfunc f(e error) { fmt.Fprintln(os.Stderr, \"native helper:\", e) }\n"
	if got := privacyAuditSource(env.policy, "x.go", allowed, helperMainPrintOK); len(got) != 0 {
		t.Fatalf("reviewed helper print refused: %v", got)
	}
	changed := "package x\nimport (\"fmt\"\n\"os\")\nfunc f(e error, v any) { fmt.Fprintln(os.Stderr, \"native helper:\", v) }\n"
	if got := privacyAuditSource(env.policy, "x.go", changed, helperMainPrintOK); len(got) == 0 {
		t.Fatal("printing a different value through the admitted line shape was allowed")
	}
}

// privacyRenderAttr renders an attribute the way `strace -v` prints it so the
// same policy audit that checks the real run also checks the in-code attributes.
func privacyRenderAttr(a cpuPerfAttr) string {
	types := map[uint32]string{0: "PERF_TYPE_HARDWARE", 1: "PERF_TYPE_SOFTWARE", 2: "PERF_TYPE_TRACEPOINT", 3: "PERF_TYPE_HW_CACHE", 4: "PERF_TYPE_RAW", 5: "PERF_TYPE_BREAKPOINT"}
	sample := []string{"IP", "TID", "TIME", "ADDR", "READ", "CALLCHAIN", "ID", "CPU", "PERIOD", "STREAM_ID", "RAW", "BRANCH_STACK", "REGS_USER", "STACK_USER", "WEIGHT", "DATA_SRC", "IDENTIFIER", "TRANSACTION", "REGS_INTR", "PHYS_ADDR", "AUX", "CGROUP", "DATA_PAGE_SIZE", "CODE_PAGE_SIZE", "WEIGHT_STRUCT"}
	var bits []string
	for i, name := range sample {
		if a.SampleType&(1<<uint(i)) != 0 {
			bits = append(bits, "PERF_SAMPLE_"+name)
		}
	}
	flags := []string{"disabled", "inherit", "pinned", "exclusive", "exclude_user", "exclude_kernel", "exclude_hv", "exclude_idle", "mmap", "comm", "freq", "inherit_stat", "enable_on_exec", "task", "watermark", "", "", "mmap_data", "sample_id_all", "exclude_host", "exclude_guest", "exclude_callchain_kernel", "exclude_callchain_user", "mmap2", "comm_exec", "use_clockid", "context_switch", "write_backward", "namespaces", "ksymbol", "bpf_event", "aux_output", "cgroup", "text_poke", "build_id"}
	var b strings.Builder
	fmt.Fprintf(&b, "1 perf_event_open({type=%s, sample_type=%s", types[a.Type], strings.Join(bits, "|"))
	for i, name := range flags {
		if name != "" {
			v := 0
			if a.Flags&(1<<uint(i)) != 0 {
				v = 1
			}
			fmt.Fprintf(&b, ", %s=%d", name, v)
		}
	}
	fmt.Fprintf(&b, ", config1=%d, config2=%d, sample_regs_user=%#x, sample_stack_user=%d, sample_regs_intr=%#x, branch_sample_type=%d}, 1, -1, -1, 8) = 3", a.Config1, a.Config2, a.SampleRegsUser, a.SampleStackUser, a.SampleRegsIntr, a.BranchSampleType)
	return b.String()
}

// The fixed in-code event attributes satisfy the exact perf_event_open policy,
// and mutated attributes (the fields a stack/register/branch dump would need)
// are flagged by the same audit.
func TestPrivacyEventAttributesMatchPolicy(t *testing.T) {
	env := newPrivacyEnv(t)
	audit := func(line string) []scan.Finding {
		f, _, e := scan.AuditStrace(env.policy, strings.NewReader(line+"\n"))
		if e != nil {
			t.Fatal(e)
		}
		return f
	}
	cpuSoft, _ := cpuAttr(MethodSoftwareCPUClock, 128)
	cpuHard, _ := cpuAttr(MethodHardwareCycles, 128)
	layout, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	sched := schedulerPerfAttr(layout, DefaultConfig(1))
	for name, attr := range map[string]cpuPerfAttr{"cpu_software": cpuSoft, "cpu_hardware": cpuHard, "scheduler": sched} {
		if f := audit(privacyRenderAttr(attr)); len(f) != 0 {
			t.Errorf("%s attribute violates the policy: %v", name, f)
		}
	}
	mutate := map[string]func(*cpuPerfAttr){
		"stack_user_sample_type": func(a *cpuPerfAttr) { a.SampleType |= 1 << 13; a.SampleStackUser = 8192 },
		"regs_user":              func(a *cpuPerfAttr) { a.SampleType |= 1 << 12; a.SampleRegsUser = ^uint64(0) },
		"regs_intr":              func(a *cpuPerfAttr) { a.SampleType |= 1 << 18; a.SampleRegsIntr = 1 },
		"branch_stack":           func(a *cpuPerfAttr) { a.SampleType |= 1 << 11; a.BranchSampleType = 1 },
		"raw_payload_on_cpu":     func(a *cpuPerfAttr) { a.SampleType |= 1 << 10 },
		"data_address":           func(a *cpuPerfAttr) { a.SampleType |= 1 << 3 },
		"mmap_records":           func(a *cpuPerfAttr) { a.Flags |= 1 << 8 },
		"inherit":                func(a *cpuPerfAttr) { a.Flags |= 1 << 1 },
		"kernel_callchain":       func(a *cpuPerfAttr) { a.Flags &^= 1 << 21 },
		"sampling_kernel":        func(a *cpuPerfAttr) { a.Flags &^= 1 << 5 },
		"not_disabled":           func(a *cpuPerfAttr) { a.Flags &^= 1 },
	}
	for name, mutation := range mutate {
		attr := cpuSoft
		mutation(&attr)
		if f := audit(privacyRenderAttr(attr)); len(f) == 0 {
			t.Errorf("%s: mutated attribute not flagged", name)
		}
	}
	rawSched := sched
	rawSched.SampleType |= 1 << 13
	if f := audit(privacyRenderAttr(rawSched)); len(f) == 0 {
		t.Error("scheduler stack dump not flagged")
	}
}

// Production code never imports the fixture packages that hold the sentinels and
// the audit; PrivacyAudit therefore cannot become a production content logger.
func TestPrivacyProductionCannotImportAuditFixtures(t *testing.T) {
	roots := []string{".", "../profiles", "../../cmd/soundpost-perf-acquire"}
	checked := 0
	for _, root := range roots {
		entries, e := os.ReadDir(root)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, e := parser.ParseFile(token.NewFileSet(), filepath.Join(root, entry.Name()), nil, parser.ImportsOnly)
			if e != nil {
				t.Fatal(e)
			}
			checked++
			for _, imp := range file.Imports {
				if strings.Contains(imp.Path.Value, "fixtures/") {
					t.Errorf("%s imports %s", entry.Name(), imp.Path.Value)
				}
			}
		}
	}
	if checked < 30 {
		t.Fatalf("only %d files checked", checked)
	}
}

// privacyEffectiveSyscalls evaluates a unit's SystemCallFilter lines in order the
// way systemd merges them: allow-list entries add, "~" entries remove. Group
// names are expanded recursively through systemd-analyze when it is installed;
// without it only literal entries are known (reported via the returned flag).
func privacyEffectiveSyscalls(lines []string) (allowed map[string]bool, expanded bool) {
	analyze, lookErr := exec.LookPath("systemd-analyze")
	cache := map[string][]string{}
	var expand func(string, int) []string
	expand = func(entry string, depth int) []string {
		if !strings.HasPrefix(entry, "@") || lookErr != nil || depth > 4 {
			return []string{entry}
		}
		if v, ok := cache[entry]; ok {
			return v
		}
		out, e := exec.Command(analyze, "syscall-filter", entry).Output()
		if e != nil {
			return []string{entry}
		}
		var names []string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || line == entry {
				continue
			}
			if strings.HasPrefix(line, "@") {
				names = append(names, expand(line, depth+1)...)
			} else {
				names = append(names, line)
			}
		}
		cache[entry] = names
		return names
	}
	allowed = map[string]bool{}
	for _, line := range lines {
		entries := strings.Fields(line)
		deny := len(entries) > 0 && strings.HasPrefix(entries[0], "~")
		for i, entry := range entries {
			if i == 0 {
				entry = strings.TrimPrefix(entry, "~")
			}
			entry, _, _ = strings.Cut(entry, ":")
			for _, name := range expand(entry, 0) {
				if deny {
					delete(allowed, name)
				} else {
					allowed[name] = true
				}
			}
		}
	}
	return allowed, lookErr == nil
}

// Packaging disables helper core dumps and never admits memory-reading,
// tracing or eBPF syscalls to the helper's seccomp filter, by the unit's
// effective SystemCallFilter (allow groups minus deny lists).
func TestPrivacyHelperPackagingDisablesDumpsAndMemoryReadSyscalls(t *testing.T) {
	env := newPrivacyEnv(t)
	raw, e := os.ReadFile("../../" + env.policy.Dump.SystemdUnit)
	if e != nil {
		t.Fatal(e)
	}
	directives := map[string]string{}
	var filters []string
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			directives[k] = v
			if k == "SystemCallFilter" {
				filters = append(filters, v)
			}
		}
	}
	for k, want := range env.policy.Dump.RequiredDirective {
		if directives[k] != want {
			t.Errorf("helper unit must set %s=%s (got %q): without it a crashed helper may write a core file", k, want, directives[k])
		}
	}
	allowed, expanded := privacyEffectiveSyscalls(filters)
	if !allowed["perf_event_open"] || !allowed["pidfd_open"] || !allowed["pidfd_send_signal"] {
		t.Fatalf("the unit no longer admits the helper's own syscalls: %v", filters)
	}
	if !expanded {
		t.Log("systemd-analyze unavailable: only literal SystemCallFilter entries were evaluated")
	}
	for _, name := range env.policy.Dump.ForbiddenFilter {
		if allowed[name] {
			t.Errorf("effective SystemCallFilter admits %s", name)
		}
	}
	for _, key := range []string{"NoNewPrivileges", "RestrictAddressFamilies", "CapabilityBoundingSet", "MemoryDenyWriteExecute"} {
		if directives[key] == "" {
			t.Errorf("helper unit lost %s", key)
		}
	}
	if directives["CapabilityBoundingSet"] != "CAP_PERFMON" {
		t.Errorf("helper may hold more than CAP_PERFMON: %q", directives["CapabilityBoundingSet"])
	}
	// Control: the evaluator must see a literal admission and a group admission.
	if got, _ := privacyEffectiveSyscalls([]string{"@system-service ptrace"}); !got["ptrace"] {
		t.Error("evaluator control: literal ptrace not seen")
	}
	if got, _ := privacyEffectiveSyscalls([]string{"@system-service ptrace", "~ptrace"}); got["ptrace"] {
		t.Error("evaluator control: deny line not applied")
	}
}
