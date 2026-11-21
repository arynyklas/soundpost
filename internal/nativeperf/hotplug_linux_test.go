//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

// CPU hotplug under a live capture (plan 04 task 09, criterion 04.09-C17; review focus 4): a CPU leaving or joining the
// online set while a capture is open must never leave a silent claim of complete coverage, and every descriptor, mapping
// and lease must come back. These tests take a REAL CPU offline and online through /sys/devices/system/cpu/cpuN/online,
// so they need root, a host with at least four online CPUs and the scheduler tracepoints; anywhere else they SKIP with a
// "NOT run" reason (they are never silently green). The CPU set is restored on every exit path (t.Cleanup) and checked.
// Run them one package at a time (go test -p 1): they change the machine's topology while they run.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
)

const hotplugOnlinePath = "/sys/devices/system/cpu/online"

// hotplugWorkloadSource is the target: three threads (two compute and sleep, one sleeps and computes briefly), all of
// them runnable work the scheduler tracepoints and the CPU clock see.
const hotplugWorkloadSource = `
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static void *spin(void *a) { (void)a; for (;;) { volatile unsigned long x = 0; for (unsigned long i = 0; i < 2000000; i++) x += i; struct timespec t = {0, 1000000}; nanosleep(&t, 0); } return 0; }
static void *nap(void *a) { (void)a; for (;;) { struct timespec t = {0, 2000000}; nanosleep(&t, 0); volatile unsigned long x = 0; for (unsigned long i = 0; i < 20000; i++) x += i; } return 0; }
int main(void) { pthread_t t[3]; pthread_create(&t[0], 0, spin, 0); pthread_create(&t[1], 0, nap, 0); pthread_create(&t[2], 0, spin, 0); printf("ready\n"); fflush(stdout); sleep(300); return 0; }
`

func hotplugFile(cpu int) string {
	return "/sys/devices/system/cpu/cpu" + strconv.Itoa(cpu) + "/online"
}

func hotplugOnlineSet(t *testing.T) string {
	t.Helper()
	b, e := os.ReadFile(hotplugOnlinePath)
	if e != nil {
		t.Fatal(e)
	}
	return strings.TrimSpace(string(b))
}

// hotplugRig is a real target, pinned to the CPU the test takes offline, and everything needed to open captures of it.
type hotplugRig struct {
	t      *testing.T
	cpu    int   // the CPU the test offlines: the highest online one, never CPU 0
	all    []int // the online CPUs before any change
	orig   string
	cmd    *exec.Cmd
	tids   []int
	target Target
	grant  func(CaptureMode) AuthorizedTargets
	cfg    Config
}

// lockHotplugHost serialises every process that cycles a CPU of this host: the online set is machine-wide, so two runs of the
// package at once (two terminals, two agents, a rerun started before the last ended) see each other's offline CPU as a topology
// change and fail (mut0402: 2 of 3 full runs on a 6.6 VM, each with a second run started at the same second). The lock is
// released, after the CPU was put back (Cleanup runs last-in first), when the test ends.
func lockHotplugHost(t *testing.T) {
	t.Helper()
	dir := "/run/lock"
	if st, e := os.Stat(dir); e != nil || !st.IsDir() {
		dir = os.TempDir()
	}
	f, e := os.OpenFile(filepath.Join(dir, "soundpost-nativeperf-hotplug.lock"), os.O_CREATE|os.O_RDWR, 0o666)
	if e != nil {
		t.Fatalf("hotplug host lock: %v", e)
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		t.Fatalf("hotplug host lock: %v", e)
	}
	t.Cleanup(func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() })
}

func newHotplugRig(t *testing.T) *hotplugRig {
	t.Helper()
	switch {
	case os.Geteuid() != 0:
		t.Skip("NOT run: CPU hotplug needs root (writes /sys/devices/system/cpu/cpuN/online)")
	}
	privacyRequireRealPerf(t)
	if !inInitialPIDNamespace(t) {
		t.Skip("NOT run: scheduler tracepoint PIDs are only attributable in the initial PID namespace")
	}
	all, e := OnlineCPUs()
	if e != nil || len(all) < 4 {
		t.Skipf("NOT run: CPU hotplug needs at least four online CPUs (have %v, %v)", all, e)
	}
	cpu := all[len(all)-1]
	if cpu == 0 {
		t.Skip("NOT run: no online CPU other than CPU 0")
	}
	if f, e := os.OpenFile(hotplugFile(cpu), os.O_WRONLY, 0); e != nil {
		t.Skipf("NOT run: CPU hotplug file not writable on this host: %v", e)
	} else {
		f.Close()
	}
	if _, e := schedulerLayouts(); e != nil {
		t.Skipf("NOT run: scheduler tracepoints unavailable: %v", e)
	}
	lockHotplugHost(t)
	all, e = OnlineCPUs() // read again under the lock: another run may have just put its CPU back
	if e != nil || len(all) < 4 {
		t.Skipf("NOT run: CPU hotplug needs at least four online CPUs (have %v, %v)", all, e)
	}
	r := &hotplugRig{t: t, cpu: cpu, all: all, orig: hotplugOnlineSet(t)}
	// every exit path (also a failed or panicking test) puts the CPU back and says so if it cannot
	t.Cleanup(r.restore)
	dir := t.TempDir()
	src, exe := filepath.Join(dir, "hotplug.c"), filepath.Join(dir, "hotplug")
	if e := os.WriteFile(src, []byte(hotplugWorkloadSource), 0o600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("cc", "-O2", "-pthread", "-fno-omit-frame-pointer", "-g", "-o", exe, src).CombinedOutput(); e != nil {
		t.Fatalf("workload build: %v\n%s", e, out)
	}
	r.cmd = exec.Command(exe)
	stdout, e := r.cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.cmd.Process.Kill(); r.cmd.Wait() })
	line := make([]byte, 6)
	if _, e = stdout.Read(line); e != nil || string(line) != "ready\n" {
		t.Fatalf("workload did not become ready: %q %v", line, e)
	}
	r.pin(cpu)
	pid := r.cmd.Process.Pid
	target, e := ResolveLocalTarget(pid)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(exe)
	if e != nil {
		t.Fatal(e)
	}
	build, e := executableBuildID(f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	target.AllowedBuildIDs = []string{build}
	cgroup, e := ResolveCgroupID(pid)
	if e != nil || cgroup == 0 {
		t.Skipf("NOT run: cgroup v2 identity unavailable on this host: %v", e)
	}
	target.CgroupID = model.Uint64(cgroup)
	r.target = target
	r.cfg = DefaultConfig(1)
	r.cfg.RingBytes = 128 << 10
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	r.grant = func(mode CaptureMode) AuthorizedTargets {
		g, e := SignStart(StartAuthorization{Installation: "hotplug-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{target}, Config: r.cfg, Mode: mode}, private)
		if e != nil {
			t.Fatal(e)
		}
		a, e := authorizeLocal(PeerCredential{UID: uint32(os.Getuid())}, CaptureRequest{Authorization: g, Targets: []Target{target}, Config: r.cfg, Mode: mode}, OperatorPolicy{Installation: "hotplug-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: []Target{target}})
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	return r
}

// pin moves every thread of the target onto one CPU, so taking that CPU offline forces the kernel to migrate them.
func (r *hotplugRig) pin(cpu int) {
	ents, _ := os.ReadDir("/proc/" + strconv.Itoa(r.cmd.Process.Pid) + "/task")
	for _, ent := range ents {
		tid, _ := strconv.Atoi(ent.Name())
		var mask [16]uint64
		mask[cpu/64] = 1 << (cpu % 64)
		syscall.Syscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(tid), uintptr(len(mask)*8), uintptr(unsafe.Pointer(&mask)))
	}
}

func (r *hotplugRig) set(on bool) {
	r.t.Helper()
	v := "0"
	if on {
		v = "1"
	}
	if e := os.WriteFile(hotplugFile(r.cpu), []byte(v), 0o644); e != nil {
		r.t.Fatalf("cpu%d online=%s: %v", r.cpu, v, e)
	}
}

// restore puts the CPU set back and fails the test when it cannot.
func (r *hotplugRig) restore() {
	if e := os.WriteFile(hotplugFile(r.cpu), []byte("1"), 0o644); e != nil {
		r.t.Errorf("CPU %d could not be put back online: %v", r.cpu, e)
	}
	if now := hotplugOnlineSet(r.t); now != r.orig {
		r.t.Errorf("online CPU set not restored: %q, was %q", now, r.orig)
	}
}

func (r *hotplugRig) reserve(a AuthorizedTargets, cpus int) *Reservation {
	r.t.Helper()
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	lease, e := NewResourceBudget().Reserve(a, r.cfg, Topology{CPUs: uint64(cpus), FDLimit: limit.Cur, OpenFDs: uint64(hotplugFDs()), PageBytes: uint64(os.Getpagesize()), LockBytes: perfLockBytes(uint64(cpus))}, MemoryUsage{HelperRSS: 8 << 20, ExportRSS: 8 << 20})
	if e != nil {
		r.t.Fatal(e)
	}
	r.t.Cleanup(func() { lease.Close() })
	return lease
}

func hotplugFDs() int {
	ents, _ := os.ReadDir("/proc/self/fd")
	return len(ents)
}

// hotplugPerfMappings counts this process's perf ring mappings.
func hotplugPerfMappings() int {
	b, _ := os.ReadFile("/proc/self/maps")
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "perf_event") {
			n++
		}
	}
	return n
}

// hotplugBaseline is the descriptor and mapping count a test must come back to.
type hotplugBaseline struct{ fds, maps int }

func takeHotplugBaseline() hotplugBaseline {
	return hotplugBaseline{hotplugFDs(), hotplugPerfMappings()}
}

func (b hotplugBaseline) mustBeRestored(t *testing.T, when string) {
	t.Helper()
	if got := takeHotplugBaseline(); got != b {
		t.Fatalf("%s: descriptors/perf mappings %+v, want the pre-capture %+v (a lease or ring leaked)", when, got, b)
	}
}

// hotplugStream drains a source in the background and keeps what it delivered.
type hotplugStream struct {
	mu       sync.Mutex
	events   []SanitizedEvent
	proofs   []AcquisitionProof
	err      error
	finished chan struct{}
}

func drainScheduler(src *schedulerSource) *hotplugStream {
	s := &hotplugStream{finished: make(chan struct{})}
	go func() {
		defer close(s.finished)
		for {
			item, e := src.NextItem(context.Background())
			s.mu.Lock()
			switch {
			case e != nil:
				s.err = e
			case item.Proof != nil:
				s.proofs = append(s.proofs, *item.Proof)
			case item.Event != nil:
				s.events = append(s.events, *item.Event)
			}
			s.mu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	return s
}

func (s *hotplugStream) snapshot() (events []SanitizedEvent, proofs []AcquisitionProof, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SanitizedEvent(nil), s.events...), append([]AcquisitionProof(nil), s.proofs...), s.err
}

// waitEnd waits for the stream to end on its own and returns the error it ended on.
func (s *hotplugStream) waitEnd(t *testing.T, d time.Duration) error {
	t.Helper()
	select {
	case <-s.finished:
	case <-time.After(d):
		_, proofs, _ := s.snapshot()
		t.Fatalf("the capture is still running %v after the CPU change and has reported nothing: %d progress proofs keep claiming complete coverage of a CPU set that no longer exists", d, len(proofs))
	}
	_, _, e := s.snapshot()
	return e
}

func hotplugNow(t *testing.T) model.MonoNano {
	t.Helper()
	n, e := schedulerNow()
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func openHotplugScheduler(t *testing.T, r *hotplugRig, lease *Reservation) *schedulerSource {
	t.Helper()
	src, e := NewNativeAcquisition(context.Background(), r.grant(ModeCPUOffCPU), r.cfg, lease)
	if e != nil {
		t.Fatalf("scheduler acquisition: %v", e)
	}
	r.t.Cleanup(func() { src.Close() })
	return src.(*schedulerSource)
}

// The whole point of the criterion: a CPU that goes away while the capture streams ends it with the closed code
// topology_changed, carrying the last instant the topology was proven, and everything is released.
func TestHotplugOfflineEndsSchedulerCaptureExplicitly(t *testing.T) {
	r := newHotplugRig(t)
	base := takeHotplugBaseline()
	lease := r.reserve(r.grant(ModeCPUOffCPU), len(r.all))
	src := openHotplugScheduler(t, r, lease)
	stream := drainScheduler(src)
	time.Sleep(700 * time.Millisecond)
	events, proofs, err := stream.snapshot()
	if err != nil || len(events) == 0 || len(proofs) < 2 {
		t.Fatalf("no healthy capture to disturb: %d events, %d proofs, %v", len(events), len(proofs), err)
	}
	r.set(false)
	offlineDone := hotplugNow(t)
	end := stream.waitEnd(t, 3*time.Second)
	if !errors.Is(end, ErrTopologyChanged) {
		t.Fatalf("a CPU left the online set (%s) and the capture ended with %v, want %v", hotplugOnlineSet(t), end, ErrTopologyChanged)
	}
	if helperErrorCode(end) != "topology_changed" {
		t.Fatalf("closed code %q", helperErrorCode(end))
	}
	proven := ProvenThroughOf(end)
	// The kernel removes the CPU's events part way through the offline write, and the capture may have proven the
	// topology until then; what it can never do is vouch for any instant after the write returned.
	if proven == 0 || proven > offlineDone {
		t.Fatalf("the error proves the topology through %d; want an instant in (0, %d]: a zero revokes the whole capture, a later one vouches for evidence of a CPU that was already gone", proven, offlineDone)
	}
	if proven < src.start {
		t.Fatalf("proof instant %d precedes the capture start %d", proven, src.start)
	}
	// the samples before the change are real and stay in the stream
	cpuSamples := 0
	for _, e := range events {
		if e.CPUEvent != nil {
			cpuSamples++
		}
	}
	if cpuSamples == 0 {
		t.Fatal("no CPU samples before the change")
	}
	r.set(true)
	src.Close()
	lease.Close()
	base.mustBeRestored(t, "after the topology error")
	if now := hotplugOnlineSet(t); now != r.orig {
		t.Fatalf("online set %q, want %q", now, r.orig)
	}
}

// A CPU that goes offline and comes straight back leaves the online set exactly as it was: no mask comparison can see
// it, and the kernel has removed every per-CPU event of that CPU in the meantime. The capture must still end explicitly.
func TestHotplugCycleBetweenIdentityChecksIsNotSilent(t *testing.T) {
	r := newHotplugRig(t)
	base := takeHotplugBaseline()
	lease := r.reserve(r.grant(ModeCPUOffCPU), len(r.all))
	src := openHotplugScheduler(t, r, lease)
	stream := drainScheduler(src)
	time.Sleep(600 * time.Millisecond)
	if _, _, err := stream.snapshot(); err != nil {
		t.Fatal(err)
	}
	// A stopped target publishes nothing, so the capture only runs its slow idle identity cadence: the cycle below is
	// over before any mask comparison could happen.
	syscall.Kill(r.cmd.Process.Pid, syscall.SIGSTOP)
	time.Sleep(300 * time.Millisecond)
	r.set(false)
	offlineDone := hotplugNow(t)
	r.set(true)
	if now := hotplugOnlineSet(t); now != r.orig {
		t.Fatalf("the cycle did not restore the set: %q", now)
	}
	syscall.Kill(r.cmd.Process.Pid, syscall.SIGCONT)
	r.pin(r.cpu)
	end := stream.waitEnd(t, 3*time.Second)
	if !errors.Is(end, ErrTopologyChanged) {
		t.Fatalf("CPU %d went offline and online under the capture and it ended with %v, want %v", r.cpu, end, ErrTopologyChanged)
	}
	if proven := ProvenThroughOf(end); proven == 0 || proven > offlineDone {
		t.Fatalf("proof instant %d, want an instant in (0, %d]: the CPU's events were gone when the offline write returned", proven, offlineDone)
	}
	src.Close()
	lease.Close()
	base.mustBeRestored(t, "after the hotplug cycle")
}

func hotplugKernel() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// A CPU capture is task-scoped (one cpu-clock event per thread, any CPU): hotplug does not change what it measures, so
// it keeps streaming real samples across an offline and an online, never reports a sample from the CPU while it is
// gone, sees the CPU again after it returns, and releases everything on close.
func TestHotplugDuringCPUCaptureKeepsSamplesAndReleases(t *testing.T) {
	r := newHotplugRig(t)
	base := takeHotplugBaseline()
	a := r.grant(ModeCPU)
	lease := r.reserve(a, len(r.all))
	src, e := NewCPUAcquisition(context.Background(), a, r.cfg, lease)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { src.Close() })
	type seen struct {
		at  model.MonoNano
		cpu uint32
	}
	var mu sync.Mutex
	var samples []seen
	var streamErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			ev, e := src.Next(context.Background())
			if e != nil {
				mu.Lock()
				streamErr = e
				mu.Unlock()
				return
			}
			if ev.CPUEvent != nil {
				mu.Lock()
				samples = append(samples, seen{ev.Time, ev.CPU})
				mu.Unlock()
			}
		}
	}()
	count := func(from, to model.MonoNano, only func(uint32) bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, s := range samples {
			if s.at >= from && s.at < to && (only == nil || only(s.cpu)) {
				n++
			}
		}
		return n
	}
	time.Sleep(600 * time.Millisecond)
	offStart := hotplugNow(t)
	if count(0, offStart, nil) == 0 {
		t.Fatal("no CPU samples before the change")
	}
	r.set(false)
	offDone := hotplugNow(t)
	time.Sleep(900 * time.Millisecond)
	onStart := hotplugNow(t)
	if n := count(offDone, onStart, nil); n == 0 {
		t.Fatal("the CPU capture stopped delivering samples while a CPU was offline")
	}
	cpu := uint32(r.cpu)
	if n := count(offDone, onStart, func(c uint32) bool { return c == cpu }); n != 0 {
		t.Fatalf("%d samples report CPU %d while it was offline", n, r.cpu)
	}
	r.set(true)
	onDone := hotplugNow(t)
	r.pin(r.cpu)
	time.Sleep(900 * time.Millisecond)
	if n := count(onDone, hotplugNow(t), func(c uint32) bool { return c == cpu }); n == 0 {
		t.Fatalf("no sample from CPU %d after it came back and the threads were pinned to it: the task events did not survive the cycle", r.cpu)
	}
	mu.Lock()
	err := streamErr
	mu.Unlock()
	if err != nil {
		t.Fatalf("a CPU capture ended on a topology change it does not depend on: %v", err)
	}
	src.Close()
	<-finished
	lease.Close()
	base.mustBeRestored(t, "after the CPU capture")
}

// A CPU that joins between the helper's admission (which charged rings and descriptors for the CPUs online then) and the
// moment the scheduler events open is refused: the charge cannot cover it, the refusal is the closed resource_limit
// code, and nothing it had opened stays open. A CPU that left in between leaves a smaller, self-consistent capture.
func TestHotplugBetweenAdmissionAndOpen(t *testing.T) {
	r := newHotplugRig(t)
	t.Run("a CPU joined: refused, nothing leaked", func(t *testing.T) {
		r.set(false)
		base := takeHotplugBaseline()
		a := r.grant(ModeCPUOffCPU)
		lease := r.reserve(a, len(r.all)-1)
		r.set(true)
		src, e := NewNativeAcquisition(context.Background(), a, r.cfg, lease)
		if src != nil || !errors.Is(e, ErrResources) || helperErrorCode(e) != "resource_limit" {
			if src != nil {
				src.Close()
			}
			t.Fatalf("a capture admitted for %d CPUs opened over %d: %v", len(r.all)-1, len(r.all), e)
		}
		if len(lease.owned) != 0 {
			t.Fatalf("the refused open left %d resources on the lease", len(lease.owned))
		}
		lease.Close()
		base.mustBeRestored(t, "after the refused open")
	})
	t.Run("a CPU left: a smaller capture that then ends on the next change", func(t *testing.T) {
		base := takeHotplugBaseline()
		a := r.grant(ModeCPUOffCPU)
		lease := r.reserve(a, len(r.all))
		r.set(false)
		src := openHotplugScheduler(t, r, lease)
		if len(src.cpus) != len(r.all)-1 {
			t.Fatalf("capture opened over CPUs %v with CPU %d offline", src.cpus, r.cpu)
		}
		stream := drainScheduler(src)
		time.Sleep(500 * time.Millisecond)
		if _, proofs, err := stream.snapshot(); err != nil || len(proofs) < 2 {
			t.Fatalf("the smaller capture is not healthy: %d proofs, %v", len(proofs), err)
		}
		r.set(true)
		if end := stream.waitEnd(t, 3*time.Second); !errors.Is(end, ErrTopologyChanged) {
			t.Fatalf("CPU %d came back and the capture ended with %v", r.cpu, end)
		}
		src.Close()
		lease.Close()
		base.mustBeRestored(t, "after the smaller capture")
	})
}

// The kernel premise of the liveness check, measured directly: a per-CPU event's enabled time grows with the clock,
// and after its CPU went offline and returned it does not grow any more (the event was detached and left OFF), while the
// events of the other CPUs keep growing. If a kernel re-attached them this test fails, and the check is not needed.
func TestHotplugKernelLeavesPerCPUEventsOffAfterACycle(t *testing.T) {
	r := newHotplugRig(t)
	layouts, e := schedulerLayouts()
	if e != nil {
		t.Skipf("NOT run: %v", e)
	}
	open := func(cpu int) *Ring {
		ring, e := openSchedulerRing(uint32(cpu), layouts[0], r.cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { ring.Close() })
		if e = enableCPU(ring); e != nil {
			t.Fatal(e)
		}
		return ring
	}
	victim, witness := open(r.cpu), open(0)
	read := func(ring *Ring) time.Duration {
		v, e := ring.enabledTime()
		if e != nil {
			t.Fatal(e)
		}
		return time.Duration(v)
	}
	v0, w0 := read(victim), read(witness)
	time.Sleep(300 * time.Millisecond)
	v1, w1 := read(victim), read(witness)
	if v1-v0 < 250*time.Millisecond || w1-w0 < 250*time.Millisecond {
		t.Fatalf("enabled time of a live event did not follow the clock: victim %v, witness %v over 300 ms", v1-v0, w1-w0)
	}
	r.set(false)
	r.set(true)
	v2, w2 := read(victim), read(witness)
	time.Sleep(400 * time.Millisecond)
	v3, w3 := read(victim), read(witness)
	if w3-w2 < 350*time.Millisecond {
		t.Fatalf("the untouched CPU's event stopped counting: %v over 400 ms", w3-w2)
	}
	if v3 != v2 {
		t.Fatalf("the cycled CPU's event kept counting (%v over 400 ms): the kernel re-attached it, so the premise of the liveness check is wrong on this kernel", v3-v2)
	}
	t.Logf("kernel %s: cycled CPU %d enabled time %v then frozen, CPU 0 %v then +%v", hotplugKernel(), r.cpu, v2, w2, w3-w2)
}
