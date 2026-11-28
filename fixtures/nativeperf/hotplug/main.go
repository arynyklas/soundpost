//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Command hotplug is the CPU hotplug harness of the native profiling qualification (task 04.09, deployment
// conformance 07.06 "cpu_hotplug"). It takes a real CPU offline and back WHILE a real capture of a real CPU-bound
// workload runs through the product's own acquisition path (the helper as a child process, the signed start, the
// scheduler and CPU acquisitions), then holds the capture to the plan's behaviour: CPU hotplug resets the correlation
// generation, is refused or reported explicitly (never a silently complete capture), leaves no negative interval and
// none that crosses the boundary, never takes the helper or the target down, and a capture opened on the restored
// topology starts a clean new epoch.
//
// Offlining a CPU is a change of host state, so it is opt-in and privileged: root and SOUNDPOST_QUALIFY_HOST_MUTATION=1.
// cpu0 is never touched, the CPU is back online before every exit path (deferred restore, signal handler, the caller's
// own check), and without the opt-in the harness reports "not exercised" and changes nothing.
//
// Scenarios (all by default):
//
//	control   scheduler capture, no hotplug: must complete with a final proof (the capture path itself works here)
//	hold      scheduler capture; the CPU goes offline, stays offline for -hold, comes back: must end with the closed
//	          code topology_changed, no final proof, a correction covering the change, then a capture on the restored
//	          topology on the SAME helper must complete with a final proof over the full online set
//	flap      the same with nothing between the offline and online writes: must be refused the same way, or, when the
//	          capture completes, the CPU's stream must demonstrably still deliver (the target runs there)
//	cpu_only  per-thread CPU capture: the hotplug must not end it and samples must continue after the CPU is back
//
// Output: one JSON object on stdout. Exit codes: 0 every scenario passed, 1 a scenario failed, 2 usage, 3 not exercised.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	hostMutationEnv  = "SOUNDPOST_QUALIFY_HOST_MUTATION"
	exitPass         = 0
	exitFail         = 1
	exitUsage        = 2
	exitNotExercised = 3
)

type options struct {
	workload string
	scenario string
	cpu      int
	hold     time.Duration
	settle   time.Duration
	after    time.Duration
	seconds  float64
	// sparseRuns is how many captures the flap_sparse scenario takes.
	sparseRuns int
}

func main() {
	if handled, code := qual.HelperRole(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(run())
}

type report struct {
	Harness      string           `json:"harness"`
	Kernel       string           `json:"kernel"`
	CPU          uint32           `json:"cpu"`
	OnlineBefore string           `json:"online_before"`
	OnlineAfter  string           `json:"online_after"`
	CPURestored  bool             `json:"cpu_restored"`
	HostMutation string           `json:"host_mutation"`
	Scenarios    []scenarioResult `json:"scenarios"`
	Failed       int              `json:"scenarios_failed"`
	NotExercised int              `json:"scenarios_not_exercised"`
	Pass         bool             `json:"pass"`
}

func run() int {
	var o options
	flag.StringVar(&o.workload, "workload", "fixtures/nativeperf/acceptance/workloads", "compiled acceptance workloads binary (fixtures/nativeperf/acceptance/workloads.c)")
	flag.StringVar(&o.scenario, "scenarios", "control,hold,flap,flap_sparse,cpu_only", "comma-separated scenarios")
	flag.IntVar(&o.cpu, "cpu", -1, "CPU to take offline (default: the highest online CPU other than cpu0)")
	flag.DurationVar(&o.hold, "hold", 800*time.Millisecond, "how long the CPU stays offline in the hold scenario")
	flag.DurationVar(&o.settle, "settle", 1500*time.Millisecond, "capture time before the CPU goes offline")
	flag.DurationVar(&o.after, "after", 2*time.Second, "capture time after the CPU is back before the capture is stopped")
	flag.Float64Var(&o.seconds, "seconds", 20, "length of the workload's hot loop")
	flag.IntVar(&o.sparseRuns, "sparse-runs", 8, "how many captures the flap_sparse scenario takes (each loses its CPU for a few tens of milliseconds at a random point of the capture's check period)")
	flag.Parse()
	if flag.NArg() != 0 || o.hold < 0 || o.hold > 10*time.Second || o.settle < time.Second || o.after < time.Second || o.seconds < 10 || o.sparseRuns < 1 || o.sparseRuns > 50 {
		fmt.Fprintln(os.Stderr, "hotplug: usage: -hold 0..10s, -settle >= 1s, -after >= 1s, -seconds >= 10, no positional arguments")
		return exitUsage
	}
	kinds, err := parseScenarios(o.scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hotplug:", err)
		return exitUsage
	}
	if os.Getenv(hostMutationEnv) != "1" || os.Geteuid() != 0 {
		return notExercised("taking a CPU offline writes /sys/devices/system/cpu/cpuN/online: it needs root and an explicit " + hostMutationEnv + "=1; neither is given, nothing was changed")
	}
	before, online, err := readOnline()
	if err != nil {
		return notExercised("the kernel's online CPU set is unreadable: " + err.Error())
	}
	cpu, err := pickCPU(online, o.cpu, hasSwitch)
	if err != nil {
		return notExercised("no CPU can be taken offline: " + err.Error())
	}
	if _, err := os.Stat(o.workload); err != nil {
		fmt.Fprintln(os.Stderr, "hotplug: workload binary missing; compile fixtures/nativeperf/acceptance/workloads.c first")
		return exitUsage
	}
	scratch, err := os.MkdirTemp("", "soundpost-hotplug-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "hotplug:", err)
		return exitFail
	}
	defer os.RemoveAll(scratch)

	hp := &hotplugger{cpu: cpu}
	// The CPU must be online again whatever happens: on a signal here, on return below, and (for a kill -9) by the caller's check.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		s := <-signals
		hp.restore()
		code := 130
		if sig, ok := s.(syscall.Signal); ok {
			code = 128 + int(sig)
		}
		os.Exit(code)
	}()
	defer hp.restore()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	app := &app{ctx: ctx, o: o, cpu: cpu, hp: hp, scratch: scratch, cfg: nativeperf.DefaultConfig(1)}
	rep := report{Harness: "cpu_hotplug", Kernel: qual.KernelRelease(), CPU: cpu, OnlineBefore: before,
		HostMutation: fmt.Sprintf("root, %s=1: cpu%d online switch written 0 then 1 under live captures; cpu0 untouched; restored on every exit path", hostMutationEnv, cpu)}
	for _, kind := range kinds {
		runs := 1
		if kind == kindFlapSparse {
			runs = o.sparseRuns
		}
		for i := 1; i <= runs; i++ {
			r := app.scenario(kind)
			if runs > 1 {
				r.Name = fmt.Sprintf("%s#%d", kind, i)
			}
			judge(&r)
			rep.Scenarios = append(rep.Scenarios, r)
			switch {
			case r.NotExercised != "":
				rep.NotExercised++
			case !r.Pass:
				rep.Failed++
			}
			fmt.Fprintf(os.Stderr, "hotplug: %-13s pass=%t %s\n", r.Name, r.Pass, strings.Join(r.Failures, "; "))
		}
	}
	hp.restore()
	rep.OnlineAfter, _, _ = readOnline()
	rep.CPURestored = rep.OnlineAfter == rep.OnlineBefore
	rep.Pass = rep.Failed == 0 && rep.NotExercised == 0 && rep.CPURestored
	if err := json.NewEncoder(os.Stdout).Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, "hotplug:", err)
		return exitFail
	}
	switch {
	case !rep.CPURestored:
		fmt.Fprintf(os.Stderr, "hotplug: the online set is %q, it was %q\n", rep.OnlineAfter, rep.OnlineBefore)
		return exitFail
	case rep.Failed > 0:
		return exitFail
	case rep.NotExercised > 0:
		return exitNotExercised
	}
	return exitPass
}

func notExercised(reason string) int {
	json.NewEncoder(os.Stdout).Encode(struct {
		Harness      string `json:"harness"`
		NotExercised string `json:"not_exercised"`
	}{"cpu_hotplug", reason})
	fmt.Fprintln(os.Stderr, "hotplug: not exercised:", reason)
	return exitNotExercised
}

func parseScenarios(text string) ([]scenarioKind, error) {
	var out []scenarioKind
	for _, name := range strings.Split(text, ",") {
		switch k := scenarioKind(strings.TrimSpace(name)); k {
		case kindControl, kindHold, kindFlap, kindFlapSparse, kindCPUOnly:
			out = append(out, k)
		default:
			return nil, fmt.Errorf("unknown scenario %q", name)
		}
	}
	return out, nil
}

type app struct {
	ctx     context.Context
	o       options
	cpu     uint32
	hp      *hotplugger
	scratch string
	cfg     nativeperf.Config
}

// timeline is what the hotplug goroutine did, read by the capture goroutine after the capture ended.
type timeline struct {
	mu       sync.Mutex
	offline  window
	online   window
	repinned uint64
	ran      bool
	// ctxAtRepin is the target's context-switch count when it was put back on the CPU.
	ctxAtRepin uint64
	err        string
	done       bool
	doneAt     time.Time
}

func (t *timeline) snapshot() (offline, online window, repinned uint64, ran bool, ctxAtRepin uint64, err string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offline, t.online, t.repinned, t.ran, t.ctxAtRepin, t.err
}

func (t *timeline) finished(after time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.done && time.Since(t.doneAt) >= after
}

// sequence takes the CPU offline and back, then puts the target back on it (the kernel reset its affinity when the CPU
// went away) and notes that it really runs there.
func (a *app) sequence(w *qual.Workload, hold time.Duration, tl *timeline) {
	defer func() {
		tl.mu.Lock()
		tl.done, tl.doneAt = true, time.Now()
		tl.mu.Unlock()
	}()
	time.Sleep(a.o.settle)
	off := window{Start: qual.MonotonicNow()}
	err := a.hp.offline()
	off.End = qual.MonotonicNow()
	if err != nil {
		tl.mu.Lock()
		tl.err = "offline: " + err.Error()
		tl.mu.Unlock()
		a.hp.restore()
		return
	}
	tl.mu.Lock()
	tl.offline = off
	tl.mu.Unlock()
	time.Sleep(hold)
	on := window{Start: qual.MonotonicNow()}
	err = a.hp.online()
	on.End = qual.MonotonicNow()
	if err != nil {
		tl.mu.Lock()
		tl.err = "online: " + err.Error()
		tl.mu.Unlock()
		a.hp.restore()
		return
	}
	tl.mu.Lock()
	tl.online = on
	tl.mu.Unlock()
	pinned, perr := pinThreads(w.PID, a.cpu)
	at := qual.MonotonicNow()
	ctxAtRepin := ctxSwitches(w.PID)
	ran := false
	for i := 0; perr == nil && pinned > 0 && i < 100 && !ran; i++ {
		ran = runningOn(w.PID, a.cpu)
		if !ran {
			time.Sleep(20 * time.Millisecond)
		}
	}
	tl.mu.Lock()
	tl.repinned, tl.ran, tl.ctxAtRepin = at, ran, ctxAtRepin
	if perr != nil {
		tl.err = "repin: " + perr.Error()
	}
	tl.mu.Unlock()
}

func procAlive(pid int) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	text := string(raw)
	end := strings.LastIndexByte(text, ')')
	return end >= 0 && end+2 < len(text) && text[end+2] != 'Z' && text[end+2] != 'X'
}

func fdCount(pid int) int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return -1
	}
	return len(entries)
}

// ctxSwitches is the number of context switches the threads of pid have made so far (voluntary plus involuntary).
func ctxSwitches(pid int) uint64 {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0
	}
	var total uint64
	for _, entry := range entries {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/status", pid, entry.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if name, value, ok := strings.Cut(line, ":"); ok && (name == "voluntary_ctxt_switches" || name == "nonvoluntary_ctxt_switches") {
				n, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
				total += n
			}
		}
	}
	return total
}

// scenario runs one scenario: a fresh workload (pinned to the CPU that will be taken offline) under a fresh helper.
func (a *app) scenario(kind scenarioKind) (r scenarioResult) {
	r = scenarioResult{Name: string(kind), Kind: kind, Mode: string(nativeperf.ModeCPUOffCPU), CPU: a.cpu}
	mode := nativeperf.ModeCPUOffCPU
	hotplug := kind != kindControl
	if kind == kindCPUOnly {
		mode = nativeperf.ModeCPU
		r.Mode = string(mode)
	}
	// the busy workload (a hot thread and a coordinator polling every millisecond) makes thousands of scheduler events
	// a second; the blocking one about ten
	workloadMode := "cpu"
	if kind == kindFlapSparse {
		workloadMode = "blocking"
	}
	hold := time.Duration(0)
	if kind == kindHold || kind == kindCPUOnly {
		hold = a.o.hold
		r.HoldMS = hold.Milliseconds()
	}
	r.OnlineBefore, _, _ = readOnline()
	defer func() { a.hp.restore(); r.OnlineAfter, _, _ = readOnline() }()

	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: a.o.workload, Mode: workloadMode, Seconds: a.o.seconds, Dir: a.scratch})
	if err != nil {
		r.SetupError = "launch: " + err.Error()
		return r
	}
	defer w.Kill()
	if n, err := pinThreads(w.PID, a.cpu); err != nil || n == 0 {
		r.SetupError = fmt.Sprintf("pin the workload to cpu%d: %v (%d threads)", a.cpu, err, n)
		return r
	}
	h, err := qual.StartHelper([]nativeperf.Target{w.Target}, 0)
	if err != nil {
		r.SetupError = "helper: " + err.Error()
		return r
	}
	defer h.Stop()
	baselineFDs := fdCount(h.PID)

	tl := &timeline{}
	tp := newTap(a.cpu, mode == nativeperf.ModeCPUOffCPU, a.cfg)
	var sequenceDone chan struct{}
	readyAt := time.Time{}
	limit := 2 * time.Second
	if hotplug {
		limit = a.o.settle + hold + a.o.after + 2*time.Second
	}
	opts := qual.CaptureOptions{Config: a.cfg, Mode: mode, Duration: limit + 60*time.Second, Sink: tp,
		OnReady: func() {
			readyAt = time.Now()
			w.Go()
			if hotplug {
				sequenceDone = make(chan struct{})
				go func() { defer close(sequenceDone); a.sequence(w, hold, tl) }()
			}
		},
		StopWhen: func() bool {
			if w.DoneSeen() || !readyAt.IsZero() && time.Since(readyAt) >= limit+5*time.Second {
				return true
			}
			if hotplug {
				return tl.finished(a.o.after)
			}
			return !readyAt.IsZero() && time.Since(readyAt) >= limit
		}}
	res := qual.Capture(a.ctx, h, opts)
	if sequenceDone != nil {
		<-sequenceDone
	}
	if err := a.hp.restore(); err != nil {
		r.SetupError = "restore: " + err.Error()
	}
	offline, online, repinned, ran, ctxAtRepin, herr := tl.snapshot()
	// The target is pinned to that CPU: every context switch it made after it was put back there happened there.
	ran = ran || repinned != 0 && ctxSwitches(w.PID) > ctxAtRepin
	r.Offline, r.Online, r.Repinned, r.RanAfterRepin = offline, online, repinned, ran
	if herr != "" {
		if !offline.done() || !online.done() {
			r.NotExercised = "the kernel refused the CPU hotplug: " + herr
		} else {
			r.SetupError = herr
		}
	}
	r.Capture = tp.view(res, r.Offline, r.Online, r.Repinned)
	r.TargetAlive = procAlive(w.PID)
	r.HelperAlive = procAlive(h.PID)
	r.HelperFDsReleased = waitFDs(h.PID, baselineFDs)

	if (kind == kindHold || kind == kindFlap || kind == kindFlapSparse) && r.NotExercised == "" && r.SetupError == "" {
		// The topology is whole again: a capture on the SAME helper is a new epoch and must run to a final proof over
		// every online CPU, with the CPU that was lost delivering again.
		tp2 := newTap(a.cpu, true, a.cfg)
		started := time.Time{}
		res2 := qual.Capture(a.ctx, h, qual.CaptureOptions{Config: a.cfg, Mode: nativeperf.ModeCPUOffCPU, Duration: 60 * time.Second, Sink: tp2,
			OnReady:  func() { started = time.Now() },
			StopWhen: func() bool { return !started.IsZero() && time.Since(started) >= 1500*time.Millisecond }})
		v := tp2.view(res2, window{}, window{}, 0)
		r.Recapture = &v
	}
	return r
}

func waitFDs(pid, baseline int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := fdCount(pid); n >= 0 && n == baseline {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
