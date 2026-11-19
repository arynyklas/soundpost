//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The real-kernel half of 04.06-C13: a process maps the same file offsets at one virtual address and later remaps
// ANOTHER object over that address (fixtures/nativeperf/export/workloads/va_reuse.c), and every sample taken while it
// ran has to be attributed to the code that really ran at that instant. It needs the kernel's perf events for a child
// of this process (a 6.1 or 6.6 kernel with perf_event_paranoid <= 1, or root); otherwise it is skipped, never passed.

type vaReuseRun struct {
	events         []SanitizedEvent
	domain         ClockDomain
	target         Target
	phaseA, phaseB [2]uint64 // function file-offset ranges, from the ELF symbol table
	aFrom, aTo     model.MonoNano
	bFrom, bTo     model.MonoNano
	exe            string
}

func vaReuseTarget(t *testing.T, pid int, exe string) Target {
	t.Helper()
	target, err := ResolveLocalTarget(pid)
	if err != nil {
		t.Skipf("the target cannot be resolved here: %v", err)
	}
	cg, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		t.Skipf("no cgroup file: %v", err)
	}
	group := ""
	for _, line := range strings.Split(string(cg), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	st, err := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if err != nil || group == "" {
		t.Skipf("cgroup v2 identity unavailable: %v", err)
	}
	target.CgroupID = model.Uint64(st.Sys().(*syscall.Stat_t).Ino)
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		t.Fatal("the workload has no GNU build ID")
	}
	notes, _ := note.Data()
	nameSize, descSize := binary.LittleEndian.Uint32(notes), binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+descSize])}
	return target
}

func compileVAReuse(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler on this host")
	}
	exe := filepath.Join(t.TempDir(), "va_reuse")
	out, err := exec.Command(cc, "-O2", "-g", "-fno-omit-frame-pointer", "-Wl,--build-id", "-o", exe, "../../fixtures/nativeperf/export/workloads/va_reuse.c").CombinedOutput()
	if err != nil {
		t.Fatalf("compiling va_reuse.c: %v\n%s", err, out)
	}
	return exe
}

// runVAReuse captures a real run of the workload and records when each phase ran.
func runVAReuse(t *testing.T) *vaReuseRun {
	t.Helper()
	exe := compileVAReuse(t)
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	lines := bufio.NewReader(stdout)
	expect := func(want string) {
		t.Helper()
		line, err := lines.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != want {
			t.Fatalf("workload said %q (%v), want %q", line, err, want)
		}
	}
	expect("ready")
	run := &vaReuseRun{exe: exe, target: vaReuseTarget(t, cmd.Process.Pid, exe)}
	run.domain, err = localCPUDomain()
	if err != nil {
		t.Skip(err)
	}
	cfg := DefaultConfig(1)
	authorized := AuthorizedTargets{targets: []Target{run.target}, mode: ModeCPU}
	lease, err := NewResourceBudget().Reserve(authorized, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	policy := DefaultSymbolPolicy(1)
	policy.AllowMappedELF = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source, err := NewProfileAcquisition(ctx, authorized, cfg, lease, policy)
	var capability *CapabilityError
	if errors.As(err, &capability) {
		t.Skipf("native CPU capture is not available here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var mu sync.Mutex
	var streamErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			item, err := source.NextItem(ctx)
			mu.Lock()
			if err != nil {
				streamErr = err
				mu.Unlock()
				return
			}
			if item.Event != nil {
				run.events = append(run.events, *item.Event)
			}
			mu.Unlock()
		}
	}()
	phase := func(command, done string) (from, to model.MonoNano) {
		t.Helper()
		var err error
		if from, err = schedulerNow(); err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(stdin, command); err != nil {
			t.Fatal(err)
		}
		expect(done)
		if to, err = schedulerNow(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond) // the consumer drains the samples of the phase
		return from, to
	}
	run.aFrom, run.aTo = phase("a", "phase_a_executed")
	run.bFrom, run.bTo = phase("b", "phase_b_same_va_executed")
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
		t.Fatalf("the capture ended with %v", streamErr)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := readELFSymbols(context.Background(), f, 8<<20, 65536)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range info.symbols {
		switch s.name {
		case "phase_a":
			run.phaseA = [2]uint64{s.start, s.end}
		case "phase_b":
			run.phaseB = [2]uint64{s.start, s.end}
		}
	}
	if run.phaseA[1] == 0 || run.phaseB[1] == 0 {
		t.Fatalf("phase_a/phase_b not in the symbol table: %v %v", run.phaseA, run.phaseB)
	}
	run.events = append([]SanitizedEvent(nil), run.events...)
	return run
}

type phaseCount struct{ a, b, other, unknown, unapproved, bare int }

// leafOwners counts, per instant window, what the leaf frame of each sample was attributed to: the function ranges of
// the two phases, any other code, "unknown" (generation_changed: the stream could not prove the owner) or a bare
// unresolved frame.
func (r *vaReuseRun) leafOwners(t *testing.T, chunk model.ProfileChunk) (inA, inB phaseCount) {
	t.Helper()
	for _, s := range chunk.Samples {
		at := model.MonoNano(s.At)
		var count *phaseCount
		switch {
		case at >= r.aFrom && at <= r.aTo:
			count = &inA
		case at >= r.bFrom && at <= r.bTo:
			count = &inB
		default:
			continue
		}
		frame := chunk.Frames[chunk.Stacks[s.Stack].Frames[0]]
		off := uint64(frame.Offset)
		switch {
		case frame.Module == "" && frame.Reason == string(FrameGeneration):
			count.unknown++
		case frame.Module == "" && frame.Reason == string(FrameUnapproved):
			// Code of a build nobody approved (libc while the workload reads its command, the vDSO): the owner at that instant IS
			// a library the helper must not name. A sample taken in the first microseconds after a phase command lands there.
			count.unapproved++
		case frame.Module == "":
			count.bare++
			if count.bare <= 3 {
				t.Logf("bare leaf frame at %d (phase A %d..%d, phase B %d..%d): reason %q", at, r.aFrom, r.aTo, r.bFrom, r.bTo, frame.Reason)
			}
		case off >= r.phaseA[0] && off < r.phaseA[1]:
			count.a++
		case off >= r.phaseB[0] && off < r.phaseB[1]:
			count.b++
		default:
			count.other++
		}
	}
	return inA, inB
}

func (r *vaReuseRun) assemble(t *testing.T, events []SanitizedEvent) model.ProfileChunk {
	t.Helper()
	limits := assemblyLimits(r.domain)
	limits.MaxSamples = 4096
	chunk, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), limits)
	if err != nil {
		t.Fatal(err)
	}
	return chunk
}

// finalSnapshotOnly is what attribution by a current /proc snapshot would have been: the mapping state at the END of
// the capture applied to every sample, with no announcements and no reconciliation.
func (r *vaReuseRun) finalSnapshotOnly(t *testing.T) []SanitizedEvent {
	t.Helper()
	epochs, err := newMappingEpochs(r.events)
	if err != nil {
		t.Fatal(err)
	}
	process := processOf(TaskKey{BootID: r.domain.BootID, PIDNamespace: r.target.PIDNamespace, TGID: r.target.TGID, ProcessStart: r.target.ProcessStart, Generation: 1})
	p := epochs.processes[process]
	if p == nil || len(p.groups) == 0 {
		t.Fatal("the capture holds no reconciliation group")
	}
	final := MappingTable{process: process, entries: p.stateAt(len(p.groups) - 1)}
	var last model.MonoNano
	for _, e := range r.events {
		last = max(last, e.Time)
	}
	// one read that "ended" after the last sample: every sample then lies inside the read, the way a snapshot taken
	// at the end and applied to the whole capture would treat it
	out := snapshotEvents(final, r.domain, 1, last+1)
	for _, e := range r.events {
		if e.Kind != EventMapping {
			out = append(out, e)
		}
	}
	for i := range out {
		out[i].Sequence = model.Uint64(i + 1)
	}
	return out
}

func TestRealKernelMappingEpochsAttributeEachPhaseOfAVirtualAddressReuseWorkload(t *testing.T) {
	run := runVAReuse(t)
	chunk := run.assemble(t, run.events)
	inA, inB := run.leafOwners(t, chunk)
	t.Logf("phase A window: %+v; phase B window: %+v", inA, inB)
	if inA.a < 10 || inB.b < 10 {
		t.Fatalf("too few samples attributed to the code that ran: A %+v B %+v", inA, inB)
	}
	if inA.b != 0 || inB.a != 0 || inA.other+inB.other+inA.bare+inB.bare != 0 {
		t.Fatalf("a frame was attributed to the wrong mapping epoch or to nothing: A %+v B %+v", inA, inB)
	}
	if inA.unapproved*10 > inA.a || inB.unapproved*10 > inB.b {
		t.Fatalf("more than a tenth of the samples are in unapproved code: A %+v B %+v", inA, inB)
	}
	if inA.unknown >= inA.a || inB.unknown >= inB.b {
		t.Fatalf("more samples unresolved than resolved: A %+v B %+v", inA, inB)
	}

	// The workload really reused the address: the samples of both phases lie in the same page. A page that only a few
	// samples of one phase touched is the code of an unapproved library (libc while the workload wakes up), not the workload.
	pages := map[bool]map[uint64]int{true: {}, false: {}}
	var firstGroup model.MonoNano
	for _, e := range run.events {
		if e.Kind == EventMapping && e.Mapping.Snapshot && (firstGroup == 0 || e.Time < firstGroup) {
			firstGroup = e.Time
		}
	}
	var groups, corrections, announcements int
	for _, e := range run.events {
		switch {
		case e.Kind == EventCPU && e.Time >= run.aFrom && e.Time <= run.aTo:
			pages[true][uint64(e.CPUEvent.IP)>>16]++
		case e.Kind == EventCPU && e.Time >= run.bFrom && e.Time <= run.bTo:
			pages[false][uint64(e.CPUEvent.IP)>>16]++
		case e.Kind == EventMapping && !e.Mapping.Snapshot:
			announcements++
		case e.Kind == EventMapping && e.Mapping.Confirm:
			groups++
		case e.Kind == EventMapping && e.Time > firstGroup:
			// a row of a later group: a range the maps changed in without an announcement
			corrections++
			if e.Time < run.bFrom || e.Mapping.BuildID != "" && e.Mapping.BuildID != run.target.AllowedBuildIDs[0] {
				t.Errorf("unexpected correction %+v at %d", e.Mapping, e.Time)
			}
		}
	}
	for page, n := range pages[true] {
		if n >= 5 && pages[false][page] < 5 {
			t.Fatalf("phase A ran in page %#x (%d samples), phase B in %v: the addresses were not reused", page, n, pages[false])
		}
	}
	t.Logf("%d reconciliation groups, %d correction rows, %d kernel announcements", groups, corrections, announcements)
	if groups < 4 || corrections < 1 {
		t.Fatalf("%d groups and %d correction rows: the remap, which the kernel does not announce, was not found by reconciliation", groups, corrections)
	}

	// Controls: the answer is not a property of the workload. Attribution by the final snapshot puts phase A's samples
	// into phase B's function, and without mapping events nothing is attributed at all.
	naiveA, naiveB := run.leafOwners(t, run.assemble(t, run.finalSnapshotOnly(t)))
	t.Logf("control, final snapshot only: A %+v B %+v", naiveA, naiveB)
	if naiveA.b < 10 || naiveA.a != 0 {
		t.Fatalf("the final-snapshot control did not misattribute phase A (A %+v): the workload did not reuse the address", naiveA)
	}
	var withoutMappings []SanitizedEvent
	for _, e := range run.events {
		if e.Kind != EventMapping {
			withoutMappings = append(withoutMappings, e)
		}
	}
	noneA, noneB := run.leafOwners(t, run.assemble(t, withoutMappings))
	t.Logf("control, no mapping events: A %+v B %+v", noneA, noneB)
	if noneA.a+noneA.b+noneB.a+noneB.b != 0 {
		t.Fatalf("frames were attributed without any mapping evidence: A %+v B %+v", noneA, noneB)
	}

	// Privacy: no event, and nothing assembled, carries the workload's path or its device identity.
	raw, _ := json.Marshal(run.events)
	exportedRaw, _ := json.Marshal(chunk)
	for _, text := range []string{run.exe, filepath.Dir(run.exe), "va_reuse"} {
		if strings.Contains(string(raw), text) || strings.Contains(string(exportedRaw), text) {
			t.Fatalf("the path text %q reached the stream or the profile", text)
		}
	}
}
