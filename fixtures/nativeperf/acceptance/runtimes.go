//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// runtimeSecs is each runtime fixture's own run time (60% CPU loop, then waits).
const runtimeSecs = 8.0

// dbAddrEnv names the PostgreSQL server (host:port) the runtime fixtures wait on over the wire protocol; unset, there is no
// database wait. The address is passed through to the fixtures and is never recorded in a report.
const dbAddrEnv = "SOUNDPOST_FIXTURE_DB_ADDR"

// runPlan is what one runtime-column run exercises: the fixture's phases (cpu, http, db) and its run time.
type runPlan struct {
	phases  string
	seconds float64
}

// httpPlan is the capture of a runtime column: a CPU loop and the loopback HTTP wait.
var httpPlan = runPlan{phases: "cpu,http", seconds: runtimeSecs}

// dbWaitPlan is the capture of a column's database wait, taken in a run of its own: a shorter CPU loop (the engine row needs
// its function) and the queries. A capture of its own because the scheduler evidence of a wait phase is held in the
// consumer's allowance (qual.ConsumerAllowanceBytes), which the HTTP capture of a runtime whose profiler wakes its event
// loop a thousand times a second already uses most of; and because a whole run that outlives JavaScriptCore's idle helper
// threads ends in a thread exit the native helper reports as a coverage change.
var dbWaitPlan = runPlan{phases: "cpu,db", seconds: 4}

// runtimeSpec is one runtime column: the binary that runs the fixture script, its
// extra environment, and the label of the build it stands for.
type runtimeSpec struct {
	name   string // python, node or bun: the column the release gate requires
	label  string // the build, for the log and the not-run list
	expect string // the version prefix the build has to report ("" when any build stands for the column)
	script string
	find   func() (bin string, env []string, why string)
}

func isELF(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func firstELF(paths ...string) string {
	for _, p := range paths {
		if p != "" && isELF(p) {
			return p
		}
	}
	return ""
}

// lookELF is the first of the named binaries on PATH that is a Linux ELF.
func lookELF(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil && isELF(p) {
			return p
		}
	}
	return ""
}

// pythonBuilds are the CPython builds a qualification host provides, one interpreter
// per column, named by the same environment variables the runtime suite uses (each
// points at an interpreter that has the SDK's dependencies).
var pythonBuilds = []struct{ version, env string }{
	{"3.12", "SOUNDPOST_QUAL_PYTHON_312_LINUX_AMD64"},
	{"3.13", "SOUNDPOST_QUAL_PYTHON_313_LINUX_AMD64"},
	{"3.14", "SOUNDPOST_QUAL_PYTHON_314_LINUX_AMD64"},
}

// nodeBuilds are the Node majors that are columns of their own, each named by an environment variable pointing at that
// major's binary. A host that names neither is run with whichever Node SOUNDPOST_NODE or the PATH provides, as one column
// whose build version the report records.
var nodeBuilds = []struct{ major, env string }{
	{"22", "SOUNDPOST_NODE22"},
	{"24", "SOUNDPOST_NODE24"},
}

func bunBinary(root string) string {
	return firstELF(os.Getenv("SOUNDPOST_BUN"), "/opt/bun/bin/bun", filepath.Join(root, ".tools/bun-1.3.14/package/bin/bun"), lookELF("bun"))
}

// namedNodeBuilds are the Node columns this run was given explicitly.
func namedNodeBuilds() (given []struct{ major, env string }) {
	for _, b := range nodeBuilds {
		if os.Getenv(b.env) != "" {
			given = append(given, b)
		}
	}
	return given
}

func (a *accept) runtimeSpecs() []runtimeSpec {
	root, _ := os.Getwd()
	var specs []runtimeSpec
	for _, b := range pythonBuilds {
		if os.Getenv(b.env) == "" {
			continue
		}
		path := os.Getenv(b.env)
		specs = append(specs, runtimeSpec{name: "python", label: "python " + b.version, expect: b.version + ".", script: "python.py", find: func() (string, []string, string) {
			if !isELF(path) {
				return "", nil, b.env + "=" + path + " is not a Linux ELF interpreter"
			}
			return path, nil, ""
		}})
	}
	if len(specs) == 0 {
		specs = append(specs, runtimeSpec{name: "python", label: "python3", script: "python.py", find: func() (string, []string, string) {
			if p := lookELF("python3"); p != "" {
				return p, nil, ""
			}
			return "", nil, "python3 is not available as a Linux ELF binary"
		}})
	}
	// the Node fixture compiles the SDK module with the pinned Bun
	nodeEnv := func() []string {
		if bun := bunBinary(root); bun != "" {
			return []string{"SOUNDPOST_BUN=" + bun}
		}
		return nil
	}
	if given := namedNodeBuilds(); len(given) > 0 {
		for _, b := range given {
			path := os.Getenv(b.env)
			specs = append(specs, runtimeSpec{name: "node", label: "node " + b.major, expect: "v" + b.major + ".", script: "node.mjs", find: func() (string, []string, string) {
				if !isELF(path) {
					return "", nil, b.env + "=" + path + " is not a Linux ELF Node binary"
				}
				return path, nodeEnv(), ""
			}})
		}
	} else {
		specs = append(specs, runtimeSpec{name: "node", label: "node", script: "node.mjs", find: func() (string, []string, string) {
			p := firstELF(os.Getenv("SOUNDPOST_NODE"), filepath.Join(root, ".tools/linux/node-v22.23.4-linux-x64/bin/node"), lookELF("node"))
			if p == "" {
				return "", nil, "no Linux Node ELF binary (set SOUNDPOST_NODE or put node on PATH)"
			}
			return p, nodeEnv(), ""
		}})
	}
	specs = append(specs, runtimeSpec{name: "bun", label: "bun", script: "bun.ts", find: func() (string, []string, string) {
		if p := bunBinary(root); p != "" {
			return p, nil, ""
		}
		return "", nil, "no Linux Bun ELF binary (set SOUNDPOST_BUN)"
	}})
	return specs
}

type runtimeReport struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
	Engine  struct {
		Method        string         `json:"method"`
		Units         string         `json:"units"`
		Status        string         `json:"status"`
		Reason        string         `json:"reason"`
		Started       bool           `json:"started"`
		SampleCount   int            `json:"sample_count"`
		LeafSamples   map[string]int `json:"leaf_samples"`
		Supplement    string         `json:"supplement"`
		NativeExt     string         `json:"native_extension_work"`
		Trampolines   string         `json:"trampolines"`
		Coverage      any            `json:"coverage"`
		Interval      any            `json:"interval"`
		AchievedUs    any            `json:"achieved_interval_us"`
		Losses        any            `json:"losses"`
		TimeDeltaUnit string         `json:"time_delta_unit"`
	} `json:"engine"`
	CPU struct {
		LoopSeconds float64 `json:"loop_seconds"`
		Function    string  `json:"function"`
	} `json:"cpu"`
	Wait waitReport `json:"wait"`
}

// waitReport is the wait part of every runtime fixture's report: the event-loop thread and the wait phases it ran.
type waitReport struct {
	LoopTID  uint32    `json:"loop_tid"`
	HTTP     waitPhase `json:"http"`
	Database waitPhase `json:"database"`
}

// waitPhase is what a fixture recorded of one wait phase (loopback HTTP requests, or database queries). A phase that did
// not run says so in Status (not_run, error) with the reason; the server's own account of its hold exists for the database.
type waitPhase struct {
	Status         string    `json:"status,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Kind           string    `json:"kind,omitempty"`
	Requests       int       `json:"requests,omitempty"`
	WaitTotal      float64   `json:"wait_seconds_total,omitempty"`
	WaitMin        float64   `json:"wait_seconds_min,omitempty"`
	ServerDelay    float64   `json:"server_delay_s,omitempty"`
	ServerReported float64   `json:"server_reported_s_total,omitempty"`
	ServerVersion  string    `json:"server_version,omitempty"`
	WindowNs       [2]uint64 `json:"window_ns"`
}

// noteMemory logs this process's resident size, live heap and goroutines: the admission charge of the next capture is
// the resident size, and a column that leaves memory or goroutines behind shows up here.
func noteMemory(what string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	u, _ := qual.ReadProc(0)
	fmt.Fprintf(os.Stderr, "acceptance: memory %s: rss %d KiB, heap in use %d KiB, heap alloc %d KiB, goroutines %d\n", what, u.RSSKiB, m.HeapInuse>>10, m.HeapAlloc>>10, runtime.NumGoroutine())
}

func (a *accept) runRuntimes() {
	want := map[string]bool{}
	for _, n := range strings.Split(a.o.runtimes, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	scriptDir, _ := filepath.Abs(a.o.runtimeDir)
	for _, sp := range a.runtimeSpecs() {
		if !want[sp.name] {
			continue
		}
		col := a.runtimeColumn(sp, scriptDir, httpPlan)
		if os.Getenv(dbAddrEnv) != "" {
			col = a.withDatabaseWait(col, sp, scriptDir)
		}
		a.res.Runtimes = append(a.res.Runtimes, col)
	}
	if want["python"] {
		for _, b := range pythonBuilds {
			if os.Getenv(b.env) == "" {
				a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "CPython " + b.version + " column", Reason: b.env + " is not set: no interpreter of that version was given to this run"})
			}
		}
	}
	if len(namedNodeBuilds()) > 0 {
		for _, b := range nodeBuilds {
			if want["node"] && os.Getenv(b.env) == "" {
				a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "Node " + b.major + " column", Reason: b.env + " is not set: no Node " + b.major + " binary was given to this run"})
			}
		}
	} else if want["node"] {
		a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "Node 22 and Node 24 columns", Reason: "neither SOUNDPOST_NODE22 nor SOUNDPOST_NODE24 is set: only the Node build found on this host was exercised (its version is in runtime_columns)"})
	}
	if os.Getenv(dbAddrEnv) == "" {
		a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "database wait in the Python/Node/Bun columns", Reason: dbAddrEnv + " is not set: no PostgreSQL server was given to this run, so only the loopback HTTP wait was exercised"})
	}
	if asked, _ := parseHostScenarios(a.o.hostScenarios); !asked["python_trampolines"] {
		a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "CPython native-extension work and perf trampolines on/off", Reason: "opt-in host scenario python_trampolines was not requested (--host-scenarios python_trampolines)"})
	}
	a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "runtime columns on arm64", Reason: "no arm64 host; amd64 cannot qualify arm64"})
}

func (a *accept) runtimeColumn(sp runtimeSpec, scriptDir string, plan runPlan) qual.RuntimeColumn {
	col := qual.RuntimeColumn{Runtime: sp.name, Arch: qual.GOARCHName()}
	unq := func(reason string) {
		col.Engine, col.Native, col.Wait = qual.Unqualified(reason, nil), qual.Unqualified(reason, nil), qual.Unqualified(reason, nil)
	}
	bin, env, why := sp.find()
	if bin == "" {
		unq("runtime_unavailable: " + why)
		return col
	}
	fmt.Fprintf(os.Stderr, "acceptance: runtime column %s (%s)\n", sp.label, bin)
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: bin, Dir: a.scratch, Nonce: a.nonce, ProcExe: true, Env: env, Argv: []string{filepath.Join(scriptDir, sp.script), fmt.Sprint(plan.seconds), plan.phases}})
	if err != nil {
		unq("runtime_launch_failed: " + err.Error())
		return col
	}
	defer w.Kill()
	h, err := qual.StartHelper([]nativeperf.Target{w.Target}, 0)
	if err != nil {
		unq("helper_failed: " + err.Error())
		return col
	}
	defer h.Stop()

	// One capture of the runtime process: its CPU samples, and, where the scheduler path is available, the
	// scheduler events of the same capture, correlated as they arrive.
	rc := a.captureRuntimeProcess(sp.label, w, h, plan.seconds, a.needles(), nil)
	cap, exit, werr := rc.cap, rc.exit, rc.werr
	cfg, adm, helperBefore, helperAfter, clientAfter := rc.cfg, rc.adm, rc.helperBefore, rc.helperAfter, rc.clientAfter
	if !cap.Ready {
		col.Native = qual.Failed("helper refused the signed request: "+cap.ErrorCode+cap.ReadError, nil)
		col.Wait = qual.Failed("helper refused the signed request: "+cap.ErrorCode+cap.ReadError, nil)
	}
	sum, _, _ := qual.FileSHA256(w.Exe)
	var rep runtimeReport
	reportOK := werr == nil && json.Unmarshal([]byte(strings.TrimSpace(lastLine(w.Output()))), &rep) == nil
	version := rep.Version
	col.Build = qual.RuntimeBuild{Runtime: sp.name, Version: version, Arch: qual.GOARCHName(), BuildID: w.BuildID, SHA256: sum, Path: filepath.Base(w.Exe)}
	if _, ok := a.res.RuntimeBuild[sp.name]; !ok {
		a.res.RuntimeBuild[sp.name] = col.Build
	}
	a.res.RuntimeBuild[sp.name+" "+version] = col.Build

	// engine column: the C09 supplement's own samples, independent of the native capture
	switch {
	case !reportOK:
		col.Engine = qual.Failed(fmt.Sprintf("runtime fixture printed no report (exit %d)", exit), nil)
	case !rep.Engine.Started || rep.Engine.SampleCount == 0 || exit != 0:
		col.Engine = qual.Failed(fmt.Sprintf("engine supplement %s/%s with %d samples (exit %d)", rep.Engine.Status, rep.Engine.Reason, rep.Engine.SampleCount, exit), map[string]any{"report": rep})
	case rep.Engine.LeafSamples[rep.CPU.Function] == 0:
		col.Engine = qual.Failed("the CPU loop function "+rep.CPU.Function+" has no engine samples", map[string]any{"report": rep})
	default:
		col.Engine = qual.Supported([]string{fmt.Sprintf("%s: %d runtime engine samples (%s), loop function %s sampled %d times; these are NOT native samples", rep.Engine.Supplement, rep.Engine.SampleCount, rep.Engine.Method, rep.CPU.Function, rep.Engine.LeafSamples[rep.CPU.Function])},
			map[string]any{"method": rep.Engine.Method, "units": rep.Engine.Units, "time_delta_unit": rep.Engine.TimeDeltaUnit, "leaf_samples": rep.Engine.LeafSamples, "coverage": rep.Engine.Coverage, "interval": rep.Engine.Interval, "losses": rep.Engine.Losses, "native_extension_work": rep.Engine.NativeExt, "trampolines": rep.Engine.Trampolines})
	}
	// native column: real helper capture of the runtime process
	if cap.Ready {
		cpuSeconds := rep.CPU.LoopSeconds
		err := qual.CheckCapture(qual.CaptureEvidence{Events: cap.Events, TargetTGID: w.Target.TGID, WorkloadCPUSeconds: cpuSeconds, InExecutable: w.Resolver().InAnyExecutable, KnownThread: w.KnownThread})
		classes := map[string]int{}
		resolved := 0
		tids := map[uint32]bool{}
		for _, e := range cap.Events {
			if e.CPUEvent == nil {
				continue
			}
			tids[e.Task.TID] = true
			classes[w.Resolver().Classify(uint64(e.CPUEvent.IP))]++
			if w.Resolver().Resolve(uint64(e.CPUEvent.IP)) != "" {
				resolved++
			}
		}
		keys := make([]string, 0, len(classes))
		for k := range classes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		samples := 0
		for _, k := range keys {
			samples += classes[k]
		}
		detail := map[string]any{"cpu_samples": samples, "threads_observed": len(tids), "sample_ip_region": classes, "samples_resolved_to_a_target_symbol": resolved,
			"helper_error_code": cap.ErrorCode, "stream_end": cap.ReadError, "loss_events": cap.LossEvents, "canary_hits": cap.NeedleHits, "interpreter_symbols": "frames inside JIT code, stripped binaries and libraries are reported unresolved, never named",
			"suspended_task_ancestry": "not available: thread callchains only"}
		switch {
		case err != nil:
			col.Native = qual.Failed("native capture rejected: "+err.Error(), detail)
		case cap.NeedleHits != 0:
			col.Native = qual.Failed(fmt.Sprintf("privacy canary found in %d frames", cap.NeedleHits), detail)
		default:
			col.Native = qual.Supported([]string{fmt.Sprintf("%d real native CPU samples from %d threads of the %s process through the signed-grant helper (frames mostly unresolved: JIT/stripped)", samples, len(tids), sp.label)}, detail)
		}
	}
	a.rtFrames += cap.Frames
	a.rtHits += cap.NeedleHits

	// wait row: the runtime really waited (on loopback HTTP requests and, when a database was named, on real queries);
	// the native blocked time of its event-loop thread in each phase's window has to match what the runtime itself
	// measured
	if cap.Ready {
		corr := rc.corr
		col.Wait, _ = a.runtimeWaitRow(sp, w, &rep, reportOK, cap, corr, ledgerFor(cfg, adm, corr, cap, helperBefore, helperAfter, clientAfter))
		if col.Wait.Detail != nil && corr != nil {
			col.Wait.Detail["capture_rates"] = captureRates(cap, corr, helperBefore, helperAfter)
		}
		if col.Wait.Detail == nil {
			col.Wait.Detail = map[string]any{}
		}
		col.Wait.Detail["column"] = sp.label
	}
	// a column stands for the build it was given: an interpreter that is not the version the environment named is no
	// evidence for that version
	if reportOK && sp.expect != "" && !strings.HasPrefix(rep.Version, sp.expect) {
		unq(fmt.Sprintf("build_mismatch: the %s column was given a %s binary reporting version %q (want a version starting %q)", sp.label, sp.name, rep.Version, sp.expect))
	}
	return col
}

// runtimeCapture is one capture of a runtime process: what the helper streamed, the scheduler intervals correlated from
// it (nil when the scheduler path is unavailable on this host) and what the capture cost.
type runtimeCapture struct {
	cfg                                    nativeperf.Config
	adm                                    qual.AdmissionMemory
	cap                                    qual.CaptureResult
	corr                                   *qual.Correlation
	exit                                   int
	werr                                   error
	helperBefore, helperAfter, clientAfter qual.ProcUsage
}

// captureRuntimeProcess runs one capture of the fixture process w through helper h: the CPU samples and, where the
// scheduler path is available, the scheduler events of the same capture, correlated as they arrive and scoped to the
// event-loop thread's wait phase. The fixture is released when the helper is ready and closed when it has reported its
// phases; beforeFinish (may be nil) runs once the capture has ended and the fixture is still alive, before it is let go.
func (a *accept) captureRuntimeProcess(label string, w *qual.Workload, h *qual.HelperProc, seconds float64, needles [][]byte, beforeFinish func()) runtimeCapture {
	rc := runtimeCapture{cfg: nativeperf.DefaultConfig(1)}
	mode := nativeperf.ModeCPU
	sched := a.caps.OffCPU == nativeperf.Supported
	if sched {
		rc.cfg.RingBytes = schedulerRingBytes
		mode = nativeperf.ModeCPUOffCPU
	}
	qual.SettleMemory()
	noteMemory("before " + label)
	rc.helperBefore, _ = qual.ReadProc(h.PID)
	clientBefore, _ := qual.ReadProc(0)
	threads := 0
	if ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.PID)); err == nil {
		threads = len(ents)
	}
	rc.adm = qual.AdmissionMemory{Targets: 1, Threads: uint64(threads), HelperRSS: rc.helperBefore.RSSKiB << 10, ClientRSS: clientBefore.RSSKiB << 10}
	cfg, adm := rc.cfg, rc.adm
	opts := qual.CaptureOptions{Config: cfg, Mode: mode, Duration: time.Duration(seconds+40) * time.Second, Needles: needles, OnReady: func() { w.Go() }, StopWhen: w.DoneSeen}
	var stream *qual.StreamCorrelation
	if sched {
		stream = qual.NewStreamCorrelation(cfg, func(cpus uint64) (uint64, error) { return qual.CorrelationReservation(cfg, adm, cpus) })
		stream.DropStacks()
		// The wait row reads the event-loop thread (the process's main thread) inside the fixture's wait phase only:
		// the intervals of the runtime's other threads and the loop thread's own CPU-phase intervals (thousands for
		// Bun) are released as the correlator returns them, so the consumer never holds more than the evidence.
		// Coverage corrections are kept: they say where evidence was revoked.
		stream.KeepOnly(qual.KeepWaitWindow(uint32(w.PID), w.Output))
		stream.Scope(uint32(w.PID)) // only the event-loop thread's scheduler events reach the correlator
		opts.Sink = stream
	}
	rc.cap = qual.Capture(a.ctx, h, opts)
	if rc.cap.Ready {
		if beforeFinish != nil {
			beforeFinish()
		}
		w.Finish() // the fixture idles after its report so the capture could be closed with its final proof
		rc.exit, rc.werr = w.Wait(60 * time.Second)
		if stream != nil {
			c := stream.Result()
			rc.corr = &c
		}
	} else {
		w.Kill()
		rc.exit, rc.werr = -1, fmt.Errorf("the helper refused the capture")
	}
	rc.clientAfter, _ = qual.ReadProc(0)
	rc.helperAfter, _ = qual.ReadProc(h.PID)
	return rc
}

// captureRates is what the capture cost the helper: scheduler events delivered a second (every switch and wakeup the
// helper published, before the consumer's scoping), the kernel loss events, and the helper's CPU time.
func captureRates(cap qual.CaptureResult, corr *qual.Correlation, before, after qual.ProcUsage) map[string]any {
	secs := float64(cap.EndedNs-cap.StartedNs) / 1e9
	events := corr.SwitchEvents + corr.WakeupEvents
	m := map[string]any{"capture_seconds": secs, "scheduler_events": events, "loss_events": corr.LossEvents,
		"helper_cpu_ms": (after.CPUTicks - before.CPUTicks) * 1000 / qual.ClockTicksPerSecond}
	if secs > 0 {
		m["scheduler_events_per_s"] = float64(events) / secs
		m["helper_cpu_percent"] = float64(after.CPUTicks-before.CPUTicks) * 1000 / qual.ClockTicksPerSecond / (secs * 10)
	}
	return m
}

// ledgerFor is the memory ledger input of a runtime capture that ran with cfg.
func ledgerFor(cfg nativeperf.Config, adm qual.AdmissionMemory, corr *qual.Correlation, cap qual.CaptureResult, helperBefore, helperAfter, clientAfter qual.ProcUsage) qual.LedgerInput {
	in := qual.LedgerInput{Config: cfg, Admission: adm, HelperHWM: helperAfter.HWMKiB << 10, ClientHWM: clientAfter.HWMKiB << 10, Retained: qual.EventsFootprint(cap.Events)}
	if corr != nil {
		in.CPUs, in.Correlator, in.Intervals = uint64(corr.CPUs), corr.ReservationBytes, corr.IntervalBytes
	}
	return in
}

// the wait phases of a runtime fixture, in the order they run
const (
	phaseHTTP     = "http"
	phaseDatabase = "database"
)

// databaseEndpointKind says, without naming the address, whether the database the fixture waited on is a process of
// another host or this one: a remote server is the stronger evidence (nothing of it runs in the measured process's host).
func databaseEndpointKind() string {
	host, _, err := net.SplitHostPort(os.Getenv(dbAddrEnv))
	if err != nil {
		return "unknown"
	}
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return "loopback_host"
	}
	return "other_host"
}

// phaseTruth turns what a fixture recorded of one wait phase into the facts CompareRuntimeWait judges.
func phaseTruth(kind string, loopTID uint32, p waitPhase) qual.RuntimeWaitTruth {
	return qual.RuntimeWaitTruth{Kind: kind, TID: loopTID, StartNs: p.WindowNs[0], EndNs: p.WindowNs[1], Requests: p.Requests,
		ServerDelayNs: uint64(p.ServerDelay * 1e9), ServerReportedNs: uint64(p.ServerReported * 1e9), WaitTotalNs: uint64(p.WaitTotal * 1e9)}
}

// combineWaitRows is the wait row of a column from the rows of its phases: failed when any phase failed, otherwise
// unqualified when any phase could not be judged, otherwise supported on the evidence of every phase.
func combineWaitRows(phases map[string]qual.Row, detail map[string]any) qual.Row {
	names := make([]string, 0, len(phases))
	for name := range phases {
		names = append(names, name)
	}
	sort.Strings(names)
	detail["phase_rows"] = phases
	var evidence, failed, unjudged []string
	for _, name := range names {
		row := phases[name]
		switch row.State {
		case qual.StateSupported:
			evidence = append(evidence, row.Evidence...)
		case qual.StateFailed:
			failed = append(failed, name+": "+row.Reason)
		default:
			unjudged = append(unjudged, name+": "+row.Reason)
		}
	}
	switch {
	case len(names) == 0:
		return qual.Unqualified("no wait phase ran in this fixture", detail)
	case len(failed) > 0:
		return qual.Failed(strings.Join(failed, "; "), detail)
	case len(unjudged) > 0:
		return qual.Unqualified(strings.Join(unjudged, "; "), detail)
	}
	return qual.Supported(evidence, detail)
}

// runtimeWaitRow judges the wait row of one runtime column: every wait phase the fixture ran (loopback HTTP requests,
// database queries) is compared with the scheduler evidence of its own window. It returns the column's row and the row of
// each phase that was requested.
func (a *accept) runtimeWaitRow(sp runtimeSpec, w *qual.Workload, rep *runtimeReport, reportOK bool, cap qual.CaptureResult, corr *qual.Correlation, ledger qual.LedgerInput) (qual.Row, map[string]qual.Row) {
	recorded := map[string]any{"runtime_recorded": rep.Wait}
	requested := map[string]bool{phaseHTTP: rep.Wait.HTTP.Status != "not_run", phaseDatabase: rep.Wait.Database.Status != "not_run"}
	every := func(row qual.Row) (qual.Row, map[string]qual.Row) {
		phases := map[string]qual.Row{}
		for name, ok := range requested {
			if ok || !reportOK {
				phases[name] = row
			}
		}
		return row, phases
	}
	if corr == nil {
		reason, _ := a.schedulerReason()
		recorded["native_blocked_intervals"] = "not acquirable: scheduler path unavailable on this host"
		return every(qual.Unqualified(reason, recorded))
	}
	cfgCorr := map[string]any{"error": corr.Err, "consume_errors": corr.ConsumeErrors, "first_consume_error": corr.FirstError, "scheduler_switch_events": corr.SwitchEvents,
		"scheduler_wakeup_events": corr.WakeupEvents, "loss_events": corr.LossEvents, "progress_proofs_applied": corr.ProgressProofs, "peak_buffered_events": corr.PeakHeapEvents, "max_buffered_events": corr.MaxHeapEvents, "events_consumed": corr.Consumed, "events_scoped_out": corr.ScopedOut, "cpus": corr.CPUs}
	recorded["correlation"] = cfgCorr
	recorded["admission"] = map[string]any{"targets": ledger.Admission.Targets, "target_threads": ledger.Admission.Threads, "helper_rss_bytes": ledger.Admission.HelperRSS, "client_rss_bytes": ledger.Admission.ClientRSS}
	switch {
	case !reportOK:
		return every(qual.Failed("the runtime printed no report, so there is no recorded wait to compare", recorded))
	case corr.Err != "":
		return every(qual.Failed("scheduler capture could not be correlated: "+corr.Err+" (stream end: "+cap.ErrorCode+cap.ReadError+")", recorded))
	case corr.ConsumeErrors > 0:
		return every(qual.Failed(fmt.Sprintf("the scheduler correlation overflowed its bounded buffer %d time(s) (first: %s), so its coverage was revoked", corr.ConsumeErrors, corr.FirstError), recorded))
	}
	if why := ledgerVerdict(ledger, recorded, sp.label); why != "" {
		return every(qual.Failed(why, recorded))
	}
	if uint32(w.PID) != rep.Wait.LoopTID {
		return every(qual.Unqualified(fmt.Sprintf("scheduler_evidence_unknown: the fixture reported event-loop thread %d, but the target's main thread is %d (the intervals kept are the main thread's)", rep.Wait.LoopTID, w.PID), recorded))
	}
	var native []nativeperf.Interval
	for _, iv := range corr.Intervals {
		if iv.Task.TGID == w.Target.TGID || iv.Correction && iv.Task == (nativeperf.TaskKey{}) {
			native = append(native, iv)
		}
	}
	var corrections []map[string]any
	for _, iv := range native {
		if iv.Correction && len(corrections) < 12 {
			corrections = append(corrections, map[string]any{"tid": iv.Task.TID, "start_ns": uint64(iv.Start), "end_ns": uint64(iv.End), "reason": string(iv.Reason), "kind": string(iv.Kind)})
		}
	}
	recorded["coverage_corrections_in_evidence"] = corrections

	phases := map[string]qual.Row{}
	for _, ph := range []struct {
		name, kind string
		p          waitPhase
	}{{phaseHTTP, qual.WaitKindHTTP, rep.Wait.HTTP}, {phaseDatabase, qual.WaitKindDatabase, rep.Wait.Database}} {
		label := sp.label + " " + ph.name + " wait"
		detail := map[string]any{"runtime_recorded": ph.p}
		if ph.name == phaseDatabase {
			detail["database_endpoint"] = databaseEndpointKind()
		}
		switch ph.p.Status {
		case "not_run":
			continue
		case "":
		case "error":
			// a database that cannot be reached is a host without the resource; one that failed the fixture after it had
			// been reached failed the criterion
			if strings.HasPrefix(ph.p.Reason, "database_unreachable") {
				phases[ph.name] = qual.Unqualified(ph.p.Reason, detail)
			} else {
				phases[ph.name] = qual.Failed(label+": "+ph.p.Reason, detail)
			}
			continue
		default:
			phases[ph.name] = qual.Failed(label+": the fixture recorded the unknown phase status "+ph.p.Status, detail)
			continue
		}
		truth := phaseTruth(ph.kind, rep.Wait.LoopTID, ph.p)
		if truth.StartNs < cap.StartedNs || truth.EndNs > cap.EndedNs {
			// the fixture's clock is not the scheduler events' clock, or its window is not inside the capture
			detail["window_check"] = map[string]any{"window_ns": ph.p.WindowNs, "capture_ns": [2]uint64{cap.StartedNs, cap.EndedNs}}
			phases[ph.name] = qual.Unqualified("scheduler_evidence_unknown: the "+ph.name+" wait window the runtime reported lies outside the monotonic capture window, so its clock cannot be compared with the scheduler events", detail)
			continue
		}
		cmp := qual.CompareRuntimeWait(truth, native)
		detail["comparison"] = map[string]any{"verdict": cmp.Verdict, "reason": cmp.Reason, "kind": ph.kind, "loop_tid": truth.TID, "requests": truth.Requests, "window_ns": truth.EndNs - truth.StartNs,
			"native_blocked_ns": cmp.NativeNs, "lower_bound_ns": cmp.LowerNs, "upper_bound_ns": cmp.UpperNs, "runnable_ns": cmp.RunnableNs, "unknown_split_ns": cmp.UnknownNs, "censored_ns": cmp.CensoredNs, "tolerance": qual.BlockedTolerance}
		switch cmp.Verdict {
		case qual.VerdictPass:
			held := fmt.Sprintf("%d requests held %d ns server-side", truth.Requests, truth.ServerDelayNs)
			if ph.name == phaseDatabase {
				held = fmt.Sprintf("%d queries (pg_sleep %.1f s each) that PostgreSQL %s itself reported holding for %d ns in all", truth.Requests, ph.p.ServerDelay, ph.p.ServerVersion, truth.ServerReportedNs)
			}
			phases[ph.name] = qual.Supported([]string{fmt.Sprintf("%s: native blocked time of the event-loop thread %d ns inside the %s wait window, between the %d ns the loop was idle on %s (-%.0f%%) and the %d ns of round trips the runtime observed (+%.0f%%)", sp.label, cmp.NativeNs, ph.name, cmp.LowerNs, held, qual.BlockedTolerance*100, cmp.UpperNs, qual.BlockedTolerance*100)}, detail)
		case qual.VerdictFail:
			phases[ph.name] = qual.Failed(label+": "+cmp.Reason, detail)
		default:
			phases[ph.name] = qual.Unqualified("scheduler_evidence_unknown: "+label+": "+cmp.Reason, detail)
		}
	}
	return combineWaitRows(phases, recorded), phases
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
