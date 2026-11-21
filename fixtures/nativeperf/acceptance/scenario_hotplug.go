//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The cpu_hotplug host scenario (plan 04 task 09, criterion 04.09-C17): REAL captures through the signed-grant helper while
// a REAL CPU leaves and rejoins the online set, written through /sys/devices/system/cpu/cpuN/online. It changes host
// state, so it runs only when asked (--host-scenarios cpu_hotplug), takes the highest-numbered online CPU other than CPU 0
// and always puts it back (a defer that also runs on a panic, and a signal handler). Three captures:
//
//   - a CPU-mode capture: task-scoped samples must keep flowing across the offline and the online, none may come from the
//     CPU while it is gone, and the CPU must be seen again after it returns;
//   - an off-CPU (scheduler) capture of a busy target whose CPU goes offline: the stream must end on the closed code
//     topology_changed with the last proven instant, the scheduler correlation must be revoked from it, and no final proof
//     or complete frame may follow (qual.JudgeTopologyChange);
//   - an off-CPU capture of a STOPPED target whose CPU goes offline and straight back: the online set is the same again, so
//     only the per-CPU events' own state can tell; the same verdict is required.
//
// Every capture must also release the helper's descriptors and perf mappings, and the host's online set must be what it was.

const (
	hotplugSysfsRoot = "/sys/devices/system/cpu"
	hotplugMinCPUs   = 4
)

func init() {
	registerHostScenario("cpu_hotplug", func(a *accept) qual.Row { return a.cpuHotplug() })
}

// hotplugHost is the CPU hotplug interface of this host.
type hotplugHost struct {
	root   string // sysfs CPU directory
	cpu    int    // the CPU the scenario takes offline
	online []int  // the online CPUs before any change
	orig   string // the online set, as the kernel prints it, before any change
}

func (h *hotplugHost) file(cpu int) string { return h.root + "/cpu" + strconv.Itoa(cpu) + "/online" }

func (h *hotplugHost) set(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile(h.file(h.cpu), []byte(v), 0o644)
}

func (h *hotplugHost) onlineSet() (string, error) {
	b, err := os.ReadFile(h.root + "/online")
	return strings.TrimSpace(string(b)), err
}

// restore puts the CPU back online and says what is wrong when the set is not what it was.
func (h *hotplugHost) restore() error {
	werr := h.set(true)
	now, rerr := h.onlineSet()
	switch {
	case rerr != nil:
		return fmt.Errorf("online set unreadable after the scenario: %v", rerr)
	case now != h.orig:
		return fmt.Errorf("online CPU set %q was not restored to %q (write: %v)", now, h.orig, werr)
	}
	return nil
}

// parseCPUList parses the kernel's CPU list format ("0-3,5,7-8").
func parseCPUList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil || first < 0 {
			return nil, fmt.Errorf("bad CPU list %q", s)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil || last < first || last > 1<<16 {
				return nil, fmt.Errorf("bad CPU list %q", s)
			}
		}
		for c := first; c <= last; c++ {
			out = append(out, c)
		}
	}
	return out, nil
}

// planHotplug decides whether this host can run the scenario and which CPU it takes offline; the reason is the precise
// "unqualified" text when it cannot.
func planHotplug(root string, euid int) (*hotplugHost, string) {
	if euid != 0 {
		return nil, fmt.Sprintf("CPU hotplug needs root: it writes %s/cpuN/online (running as uid %d)", root, euid)
	}
	raw, err := os.ReadFile(root + "/online")
	if err != nil {
		return nil, fmt.Sprintf("CPU hotplug unavailable: %s/online is unreadable: %v", root, err)
	}
	online, err := parseCPUList(string(raw))
	if err != nil {
		return nil, "CPU hotplug unavailable: " + err.Error()
	}
	if len(online) < hotplugMinCPUs {
		return nil, fmt.Sprintf("host has %d online CPUs (%s), the scenario needs at least %d so that CPU 0 and a working set remain", len(online), strings.TrimSpace(string(raw)), hotplugMinCPUs)
	}
	h := &hotplugHost{root: root, cpu: online[len(online)-1], online: online, orig: strings.TrimSpace(string(raw))}
	f, err := os.OpenFile(h.file(h.cpu), os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Sprintf("CPU hotplug unavailable: %s cannot be opened for writing: %v", h.file(h.cpu), err)
	}
	f.Close()
	return h, ""
}

// pinThreads moves every thread of a process onto one CPU, so that taking the CPU offline forces the kernel to migrate them.
func pinThreads(pid, cpu int) {
	ents, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		return
	}
	var mask [16]uint64
	mask[cpu/64] = 1 << (cpu % 64)
	for _, ent := range ents {
		if tid, err := strconv.Atoi(ent.Name()); err == nil {
			syscall.Syscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(tid), uintptr(len(mask)*8), uintptr(unsafe.Pointer(&mask)))
		}
	}
}

// hotplugInjector drives the CPU change from inside a capture's stop hook (which the capture polls every 100 ms), on its own
// goroutine so that the offline write, which blocks for tens of milliseconds, never stalls the capture's reader.
type hotplugInjector struct {
	host *hotplugHost
	kind string // "cpu", "offline" or "cycle"
	rec  func(cmd string, ran bool, note string)

	once     sync.Once
	finished atomic.Bool

	mu                                 sync.Mutex
	offStart, offDone, onStart, onDone uint64 // event clock (CLOCK_MONOTONIC) instants
	err                                error
}

func (in *hotplugInjector) stopHook(w *qual.Workload) bool {
	in.once.Do(func() { go in.run(w) })
	return in.finished.Load()
}

func (in *hotplugInjector) write(on bool) (start, done uint64) {
	start = qual.MonotonicNow()
	err := in.host.set(on)
	done = qual.MonotonicNow()
	v := "0"
	if on {
		v = "1"
	}
	in.rec(fmt.Sprintf("echo %s > %s", v, in.host.file(in.host.cpu)), err == nil, fmt.Sprint(err))
	if err != nil {
		in.mu.Lock()
		in.err = err
		in.mu.Unlock()
	}
	return
}

func (in *hotplugInjector) run(w *qual.Workload) {
	defer in.finished.Store(true)
	pid, cpu := w.PID, in.host.cpu
	time.Sleep(1200 * time.Millisecond) // the capture is established and the target is working
	pinThreads(pid, cpu)
	var stopped bool
	switch in.kind {
	case "cycle":
		// a stopped target publishes nothing, so the capture only runs its slow idle identity cadence: the cycle is over
		// before any comparison of the online set could happen
		syscall.Kill(pid, syscall.SIGSTOP)
		stopped = true
		time.Sleep(400 * time.Millisecond)
		start, done := in.write(false)
		onStart, onDone := in.write(true)
		in.mu.Lock()
		in.offStart, in.offDone, in.onStart, in.onDone = start, done, onStart, onDone
		in.mu.Unlock()
		syscall.Kill(pid, syscall.SIGCONT)
		stopped = false
		pinThreads(pid, cpu)
		time.Sleep(2500 * time.Millisecond)
	default:
		time.Sleep(500 * time.Millisecond)
		start, done := in.write(false)
		in.mu.Lock()
		in.offStart, in.offDone = start, done
		in.mu.Unlock()
		if in.kind == "cpu" {
			time.Sleep(1000 * time.Millisecond)
		} else {
			time.Sleep(800 * time.Millisecond)
		}
		onStart, onDone := in.write(true)
		in.mu.Lock()
		in.onStart, in.onDone = onStart, onDone
		in.mu.Unlock()
		pinThreads(pid, cpu)
		time.Sleep(1500 * time.Millisecond)
	}
	if stopped {
		syscall.Kill(pid, syscall.SIGCONT)
	}
}

func (in *hotplugInjector) times() (offStart, offDone, onStart, onDone uint64, err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.offStart, in.offDone, in.onStart, in.onDone, in.err
}

// cpuHotplugVerdict is the judgement of the CPU-mode capture.
type cpuHotplugVerdict struct {
	Before, While, WhileOnTheCPU, After, AfterOnTheCPU int
}

// judgeCPUHotplug judges a CPU-mode capture across one offline and one online of cpu: samples before, while the CPU was
// gone (none may name it) and after it returned (the CPU must be seen again). The returned text is empty when the capture
// behaved.
func judgeCPUHotplug(events []nativeperf.SanitizedEvent, cpu uint32, offDone, onStart, onDone uint64) (cpuHotplugVerdict, string) {
	var v cpuHotplugVerdict
	for _, e := range events {
		if e.CPUEvent == nil {
			continue
		}
		at := uint64(e.Time)
		switch {
		case at < offDone:
			v.Before++
		case at < onStart:
			v.While++
			if e.CPU == cpu {
				v.WhileOnTheCPU++
			}
		case at >= onDone:
			v.After++
			if e.CPU == cpu {
				v.AfterOnTheCPU++
			}
		}
	}
	switch {
	case offDone == 0 || onDone == 0:
		return v, "the CPU change did not happen during the capture"
	case v.Before < qual.MinHotplugSamples:
		return v, fmt.Sprintf("only %d CPU samples before the change", v.Before)
	case v.While == 0:
		return v, "the CPU capture delivered no samples while a CPU was offline"
	case v.WhileOnTheCPU != 0:
		return v, fmt.Sprintf("%d samples name CPU %d while it was offline", v.WhileOnTheCPU, cpu)
	case v.After == 0:
		return v, "the CPU capture delivered no samples after the CPU came back"
	case v.AfterOnTheCPU == 0:
		return v, fmt.Sprintf("no sample from CPU %d after it came back and the target was pinned to it", cpu)
	}
	return v, ""
}

// hotplugEvidence is what the judge reads of one scheduler capture.
func hotplugEvidence(r *scenResult, in *hotplugInjector) qual.HotplugEvidence {
	_, offDone, _, _, err := in.times()
	e := qual.HotplugEvidence{Provoked: err == nil && offDone != 0, OfflineDoneNs: offDone, ErrorCode: r.Cap.ErrorCode, Complete: r.Cap.Complete}
	for _, p := range r.Cap.Proofs {
		if p.Final {
			e.FinalProof = true
		}
		if !p.Final && !p.Progress && e.StartNs == 0 {
			e.StartNs = uint64(p.Through)
		}
	}
	if r.Corr != nil {
		e.Revoked, e.RevokedFrom, e.Intervals = r.Corr.Revoked, r.Corr.RevokedFrom, r.Corr.Intervals
		if r.Corr.FinalThrough != 0 {
			e.FinalProof = true
		}
	}
	for _, ev := range r.Cap.Events {
		if ev.CPUEvent != nil && uint64(ev.Time) <= e.RevokedFrom {
			e.CPUSamplesBefore++
		}
	}
	return e
}

// hotplugReleased says why the helper still holds descriptors after the capture ("" when it holds what it held before).
func hotplugReleased(r *scenResult) string {
	if r.HelperFDsAfter != r.HelperBefore.FDs || r.HelperPerfAfter != 0 {
		return fmt.Sprintf("helper descriptors %d before, %d after the capture (%d perf events still open)", r.HelperBefore.FDs, r.HelperFDsAfter, r.HelperPerfAfter)
	}
	return ""
}

// hotplugPhase is one capture of the scenario and its verdict: "" fail text and "" unknown text mean it passed.
type hotplugPhase struct {
	name    string
	fail    string // the criterion was not met
	unknown string // the capture could not be judged (the host or the fixture, not the product)
	pass    string // what was shown
	detail  map[string]any
}

func (a *accept) cpuHotplug() qual.Row {
	host, why := planHotplug(hotplugSysfsRoot, os.Geteuid())
	if why != "" {
		return qual.Unqualified(why, nil)
	}
	if a.caps.OffCPU != nativeperf.Supported {
		return qual.Unqualified(fmt.Sprintf("the scheduler (off-CPU) path this scenario exercises is not available on this host (probe: %s, %v)", a.caps.OffCPU, a.caps.Reasons), nil)
	}
	return a.withHotplugRestore(host, func() qual.Row { return a.runHotplugPhases(host) })
}

// withHotplugRestore runs body and, on every exit path, puts the CPU back online and checks the set: the deferred restore
// also runs when body panics (the panic then continues), and a signal restores the CPU before the process ends.
func (a *accept) withHotplugRestore(host *hotplugHost, body func() qual.Row) (row qual.Row) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		if s, ok := <-sigs; ok {
			err := host.restore()
			fmt.Fprintf(os.Stderr, "acceptance: cpu_hotplug interrupted by %v, CPU %d restored: %v\n", s, host.cpu, err)
			os.Exit(130)
		}
	}()
	defer func() {
		signal.Stop(sigs)
		close(sigs)
		rec := recover()
		err := host.restore()
		a.record(fmt.Sprintf("echo 1 > %s (restore)", host.file(host.cpu)), err == nil, fmt.Sprint(err))
		if rec != nil {
			panic(rec)
		}
		if err != nil {
			row = qual.Failed("the host's CPU set was not restored: "+err.Error(), row.Detail)
		}
	}()
	return body()
}

func (a *accept) runHotplugPhases(host *hotplugHost) qual.Row {
	cfg := nativeperf.DefaultConfig(1)
	cfg.RingBytes = schedulerRingBytes
	detail := map[string]any{"kernel": qual.KernelRelease(), "cpu_taken_offline": host.cpu, "online_before": host.orig}
	var phases []hotplugPhase

	// 1. CPU mode
	fmt.Fprintln(os.Stderr, "acceptance: cpu_hotplug cpu-mode capture")
	cin := &hotplugInjector{host: host, kind: "cpu", rec: a.record}
	cr := a.runScenarioWith("cpu_hotplug_cpu", "cpu", 10, cfg, 0, nil, nativeperf.ModeCPU, scenHooks{stopWhen: cin.stopHook})
	phases = append(phases, a.judgeHotplugCPUPhase(host, cr, cin))

	// 2. scheduler, busy target, CPU offline then online
	fmt.Fprintln(os.Stderr, "acceptance: cpu_hotplug scheduler capture, CPU offline")
	sin := &hotplugInjector{host: host, kind: "offline", rec: a.record}
	sr := a.runScenarioWith("cpu_hotplug_sched_offline", "cpu", 10, cfg, 0, nil, nativeperf.ModeCPUOffCPU, scenHooks{stopWhen: sin.stopHook})
	phases = append(phases, judgeHotplugSchedPhase("scheduler_cpu_offline", sr, sin))

	// 3. scheduler, stopped target, CPU offline and straight back
	fmt.Fprintln(os.Stderr, "acceptance: cpu_hotplug scheduler capture, CPU cycle under a stopped target")
	yin := &hotplugInjector{host: host, kind: "cycle", rec: a.record}
	yr := a.runScenarioWith("cpu_hotplug_sched_cycle", "cpu", 10, cfg, 0, nil, nativeperf.ModeCPUOffCPU, scenHooks{stopWhen: yin.stopHook})
	phases = append(phases, judgeHotplugSchedPhase("scheduler_cpu_cycle_between_identity_checks", yr, yin))

	return foldHotplug(host, detail, phases)
}

// foldHotplug restores the CPU set, reads it back and turns the phases into the row: failed when any phase failed or the set
// is not what it was, unqualified when something could not be judged, supported only when every phase passed.
func foldHotplug(host *hotplugHost, detail map[string]any, phases []hotplugPhase) qual.Row {
	back, rerr := host.restoreAndRead()
	detail["online_after"] = back
	var evidence, fails, unknowns []string
	for _, p := range phases {
		detail[p.name] = p.detail
		switch {
		case p.fail != "":
			fails = append(fails, p.name+": "+p.fail)
		case p.unknown != "":
			unknowns = append(unknowns, p.name+": "+p.unknown)
		default:
			evidence = append(evidence, p.name+": "+p.pass)
		}
	}
	if rerr != nil {
		fails = append(fails, rerr.Error())
	} else {
		evidence = append(evidence, fmt.Sprintf("host online CPU set %q before and %q after", host.orig, back))
	}
	switch {
	case len(fails) > 0:
		return qual.Failed(strings.Join(fails, "; "), detail)
	case len(unknowns) > 0:
		return qual.Unqualified("cpu_hotplug could not be judged: "+strings.Join(unknowns, "; "), detail)
	}
	return qual.Supported(evidence, detail)
}

// restoreAndRead restores the CPU set and returns what it reads back.
func (h *hotplugHost) restoreAndRead() (string, error) {
	err := h.restore()
	now, _ := h.onlineSet()
	return now, err
}

func (a *accept) judgeHotplugCPUPhase(host *hotplugHost, r *scenResult, in *hotplugInjector) hotplugPhase {
	p := hotplugPhase{name: "cpu_mode", detail: map[string]any{"scenario": r.summary()}}
	offStart, offDone, onStart, onDone, ierr := in.times()
	p.detail["injection"] = map[string]any{"offline_started_ns": offStart, "offline_returned_ns": offDone, "online_started_ns": onStart, "online_returned_ns": onDone}
	switch {
	case ierr != nil:
		p.unknown = "the CPU change could not be made: " + ierr.Error()
	case r.Err != "":
		p.unknown = "fixture error: " + r.Err
	case !r.Cap.Ready:
		p.unknown = "helper refused the CPU capture: " + r.Cap.ErrorCode + r.Cap.ReadError
	case r.Cap.ErrorCode != "" || r.Cap.ReadError != "":
		p.fail = fmt.Sprintf("the CPU capture ended on a CPU change it does not depend on (code %q, %q)", r.Cap.ErrorCode, r.Cap.ReadError)
	default:
		v, why := judgeCPUHotplug(r.Cap.Events, uint32(host.cpu), offDone, onStart, onDone)
		p.detail["samples"] = v
		if why != "" {
			p.fail = why
		} else if rel := hotplugReleased(r); rel != "" {
			p.fail = rel
		} else {
			p.pass = fmt.Sprintf("%d CPU samples before, %d while CPU %d was offline (none from it), %d after it returned (%d from it); no stream error; helper descriptors %d before and after", v.Before, v.While, host.cpu, v.After, v.AfterOnTheCPU, r.HelperBefore.FDs)
		}
	}
	return p
}

func judgeHotplugSchedPhase(name string, r *scenResult, in *hotplugInjector) hotplugPhase {
	p := hotplugPhase{name: name, detail: map[string]any{"scenario": r.summary()}}
	offStart, offDone, onStart, onDone, ierr := in.times()
	p.detail["injection"] = map[string]any{"offline_started_ns": offStart, "offline_returned_ns": offDone, "online_started_ns": onStart, "online_returned_ns": onDone}
	switch {
	case ierr != nil:
		p.unknown = "the CPU change could not be made: " + ierr.Error()
		return p
	case r.Err != "":
		p.unknown = "fixture error: " + r.Err
		return p
	case !r.Cap.Ready:
		p.unknown = "helper refused the scheduler capture: " + r.Cap.ErrorCode + r.Cap.ReadError
		return p
	}
	ev := hotplugEvidence(r, in)
	verdict := qual.JudgeTopologyChange(ev)
	p.detail["verdict"] = verdict.Verdict
	p.detail["reason"] = verdict.Reason
	p.detail["proven_through_ns"] = ev.RevokedFrom
	p.detail["capture_start_ns"] = ev.StartNs
	p.detail["stream_end_code"] = r.Cap.ErrorCode
	switch verdict.Verdict {
	case qual.VerdictFail:
		p.fail = verdict.Reason
	case qual.VerdictPass:
		if rel := hotplugReleased(r); rel != "" {
			p.fail = rel
		} else {
			p.pass = fmt.Sprintf("%s; helper descriptors %d before and after", verdict.Reason, r.HelperBefore.FDs)
		}
	default:
		p.unknown = verdict.Reason
	}
	return p
}
