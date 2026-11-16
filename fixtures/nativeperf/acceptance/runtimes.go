//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
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

// runtimeSpec is one runtime column: the binary that runs the fixture script, its
// extra environment, and the label of the build it stands for.
type runtimeSpec struct {
	name   string // python, node or bun: the column the release gate requires
	label  string // the build, for the log and the not-run list
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

func bunBinary(root string) string {
	return firstELF(os.Getenv("SOUNDPOST_BUN"), "/opt/bun/bin/bun", filepath.Join(root, ".tools/bun-1.3.14/package/bin/bun"), lookELF("bun"))
}

func (a *accept) runtimeSpecs() []runtimeSpec {
	root, _ := os.Getwd()
	var specs []runtimeSpec
	for _, b := range pythonBuilds {
		if os.Getenv(b.env) == "" {
			continue
		}
		path := os.Getenv(b.env)
		specs = append(specs, runtimeSpec{"python", "python " + b.version, "python.py", func() (string, []string, string) {
			if !isELF(path) {
				return "", nil, b.env + "=" + path + " is not a Linux ELF interpreter"
			}
			return path, nil, ""
		}})
	}
	if len(specs) == 0 {
		specs = append(specs, runtimeSpec{"python", "python3", "python.py", func() (string, []string, string) {
			if p := lookELF("python3"); p != "" {
				return p, nil, ""
			}
			return "", nil, "python3 is not available as a Linux ELF binary"
		}})
	}
	specs = append(specs,
		runtimeSpec{"node", "node", "node.mjs", func() (string, []string, string) {
			p := firstELF(os.Getenv("SOUNDPOST_NODE"), filepath.Join(root, ".tools/linux/node-v22.23.4-linux-x64/bin/node"), lookELF("node"))
			if p == "" {
				return "", nil, "no Linux Node ELF binary (set SOUNDPOST_NODE or put node on PATH)"
			}
			// the Node fixture compiles the SDK module with the pinned Bun
			var env []string
			if bun := bunBinary(root); bun != "" {
				env = []string{"SOUNDPOST_BUN=" + bun}
			}
			return p, env, ""
		}},
		runtimeSpec{"bun", "bun", "bun.ts", func() (string, []string, string) {
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
	Wait struct {
		Kind         string    `json:"kind"`
		Requests     int       `json:"requests"`
		WaitTotal    float64   `json:"wait_seconds_total"`
		WaitMin      float64   `json:"wait_seconds_min"`
		ServerDelay  float64   `json:"server_delay_s"`
		DatabaseWait string    `json:"database_wait"`
		WindowNs     [2]uint64 `json:"window_ns"`
		LoopTID      uint32    `json:"loop_tid"`
	} `json:"wait"`
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
		a.res.Runtimes = append(a.res.Runtimes, a.runtimeColumn(sp, scriptDir))
	}
	if want["python"] {
		for _, b := range pythonBuilds {
			if os.Getenv(b.env) == "" {
				a.res.NotRun = append(a.res.NotRun, qual.NotRunItem{Item: "CPython " + b.version + " column", Reason: b.env + " is not set: no interpreter of that version was given to this run"})
			}
		}
	}
	a.res.NotRun = append(a.res.NotRun,
		qual.NotRunItem{Item: "Node 24 column", Reason: "only the Node build found on this host was exercised (the columns' build versions are in runtime_columns)"},
		qual.NotRunItem{Item: "CPython native-extension work and perf trampolines on/off", Reason: "no native-extension workload and no 3.12 trampoline comparison were built"},
		qual.NotRunItem{Item: "database wait in the Python/Node/Bun columns", Reason: "no database engine fixture; only a loopback HTTP wait was exercised"},
		qual.NotRunItem{Item: "runtime columns on arm64", Reason: "no arm64 host; amd64 cannot qualify arm64"})
}

func (a *accept) runtimeColumn(sp runtimeSpec, scriptDir string) qual.RuntimeColumn {
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
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: bin, Dir: a.scratch, Nonce: a.nonce, ProcExe: true, Env: env, Argv: []string{filepath.Join(scriptDir, sp.script), fmt.Sprint(runtimeSecs)}})
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
	cfg := nativeperf.DefaultConfig(1)
	mode := nativeperf.ModeCPU
	sched := a.caps.OffCPU == nativeperf.Supported
	if sched {
		cfg.RingBytes = 256 << 10
		mode = nativeperf.ModeCPUOffCPU
	}
	qual.SettleMemory()
	noteMemory("before " + sp.label)
	helperBefore, _ := qual.ReadProc(h.PID)
	clientBefore, _ := qual.ReadProc(0)
	threads := 0
	if ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.PID)); err == nil {
		threads = len(ents)
	}
	adm := qual.AdmissionMemory{Targets: 1, Threads: uint64(threads), HelperRSS: helperBefore.RSSKiB << 10, ClientRSS: clientBefore.RSSKiB << 10}
	opts := qual.CaptureOptions{Config: cfg, Mode: mode, Duration: time.Duration(runtimeSecs+40) * time.Second, Needles: a.needles(), OnReady: func() { w.Go() }, StopWhen: w.DoneSeen}
	var stream *qual.StreamCorrelation
	if sched {
		stream = qual.NewStreamCorrelation(cfg, func(cpus uint64) (uint64, error) { return qual.CorrelationReservation(cfg, adm, cpus) })
		// The wait row reads the event-loop thread (the process's main thread) only: the intervals of the runtime's
		// other threads, thousands for a sampler thread that wakes every few milliseconds, are released as they are
		// returned. Coverage corrections are kept: they say where evidence was revoked.
		stream.KeepOnly(func(iv nativeperf.Interval) bool { return iv.Correction || iv.Task.TID == uint32(w.PID) })
		stream.Scope(uint32(w.PID)) // only the event-loop thread's scheduler events reach the correlator
		opts.Sink = stream
	}
	cap := qual.Capture(a.ctx, h, opts)
	var exit int
	var werr error
	if cap.Ready {
		w.Finish() // the fixture idles after its report so the capture could be closed with its final proof
		exit, werr = w.Wait(60 * time.Second)
	} else {
		w.Kill()
		exit, werr = -1, fmt.Errorf("the helper refused the capture")
	}
	clientAfter, _ := qual.ReadProc(0)
	helperAfter, _ := qual.ReadProc(h.PID)
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

	// wait row: the runtime really waited on loopback requests; the native blocked time of its event-loop thread
	// in that window has to match what the runtime itself measured
	if cap.Ready {
		var corr *qual.Correlation
		if stream != nil {
			c := stream.Result()
			corr = &c
		}
		col.Wait = a.runtimeWaitRow(sp, w, &rep, reportOK, cap, corr, ledgerFor(adm, corr, cap, helperBefore, helperAfter, clientAfter))
	}
	return col
}

// ledgerFor is the memory ledger input of a runtime capture.
func ledgerFor(adm qual.AdmissionMemory, corr *qual.Correlation, cap qual.CaptureResult, helperBefore, helperAfter, clientAfter qual.ProcUsage) qual.LedgerInput {
	in := qual.LedgerInput{Config: nativeperf.DefaultConfig(1), Admission: adm, HelperHWM: helperAfter.HWMKiB << 10, ClientHWM: clientAfter.HWMKiB << 10, Retained: qual.EventsFootprint(cap.Events)}
	if corr != nil {
		in.CPUs, in.Correlator, in.Intervals = uint64(corr.CPUs), corr.ReservationBytes, corr.IntervalBytes
	}
	return in
}

// runtimeWaitRow judges the wait row of one runtime column.
func (a *accept) runtimeWaitRow(sp runtimeSpec, w *qual.Workload, rep *runtimeReport, reportOK bool, cap qual.CaptureResult, corr *qual.Correlation, ledger qual.LedgerInput) qual.Row {
	recorded := map[string]any{"runtime_recorded": rep.Wait}
	if corr == nil {
		reason, _ := a.schedulerReason()
		recorded["native_blocked_intervals"] = "not acquirable: scheduler path unavailable on this host"
		return qual.Unqualified(reason, recorded)
	}
	cfgCorr := map[string]any{"error": corr.Err, "consume_errors": corr.ConsumeErrors, "first_consume_error": corr.FirstError, "scheduler_switch_events": corr.SwitchEvents,
		"scheduler_wakeup_events": corr.WakeupEvents, "loss_events": corr.LossEvents, "progress_proofs_applied": corr.ProgressProofs, "peak_buffered_events": corr.PeakHeapEvents, "cpus": corr.CPUs}
	recorded["correlation"] = cfgCorr
	recorded["admission"] = map[string]any{"targets": ledger.Admission.Targets, "target_threads": ledger.Admission.Threads, "helper_rss_bytes": ledger.Admission.HelperRSS, "client_rss_bytes": ledger.Admission.ClientRSS}
	switch {
	case !reportOK:
		return qual.Failed("the runtime printed no report, so there is no recorded wait to compare", recorded)
	case corr.Err != "":
		return qual.Failed("scheduler capture could not be correlated: "+corr.Err+" (stream end: "+cap.ErrorCode+cap.ReadError+")", recorded)
	case corr.ConsumeErrors > 0:
		return qual.Failed(fmt.Sprintf("the scheduler correlation overflowed its bounded buffer %d time(s) (first: %s), so its coverage was revoked", corr.ConsumeErrors, corr.FirstError), recorded)
	}
	if why := ledgerVerdict(ledger, recorded, sp.label); why != "" {
		return qual.Failed(why, recorded)
	}
	truth := qual.RuntimeWaitTruth{TID: rep.Wait.LoopTID, StartNs: rep.Wait.WindowNs[0], EndNs: rep.Wait.WindowNs[1], Requests: rep.Wait.Requests,
		ServerDelayNs: uint64(rep.Wait.ServerDelay * 1e9), WaitTotalNs: uint64(rep.Wait.WaitTotal * 1e9)}
	if uint32(w.PID) != truth.TID {
		return qual.Unqualified(fmt.Sprintf("scheduler_evidence_unknown: the fixture reported event-loop thread %d, but the target's main thread is %d (the intervals kept are the main thread's)", truth.TID, w.PID), recorded)
	}
	if truth.StartNs < cap.StartedNs || truth.EndNs > cap.EndedNs {
		// the fixture's clock is not the scheduler events' clock, or its window is not inside the capture
		recorded["window_check"] = map[string]any{"window_ns": rep.Wait.WindowNs, "capture_ns": [2]uint64{cap.StartedNs, cap.EndedNs}}
		return qual.Unqualified("scheduler_evidence_unknown: the wait window the runtime reported lies outside the monotonic capture window, so its clock cannot be compared with the scheduler events", recorded)
	}
	var native []nativeperf.Interval
	for _, iv := range corr.Intervals {
		if iv.Task.TGID == w.Target.TGID || iv.Correction && iv.Task == (nativeperf.TaskKey{}) {
			native = append(native, iv)
		}
	}
	cmp := qual.CompareRuntimeWait(truth, native)
	recorded["comparison"] = map[string]any{"verdict": cmp.Verdict, "reason": cmp.Reason, "loop_tid": truth.TID, "requests": truth.Requests, "window_ns": truth.EndNs - truth.StartNs,
		"native_blocked_ns": cmp.NativeNs, "lower_bound_ns": cmp.LowerNs, "upper_bound_ns": cmp.UpperNs, "runnable_ns": cmp.RunnableNs, "unknown_split_ns": cmp.UnknownNs, "censored_ns": cmp.CensoredNs, "tolerance": qual.BlockedTolerance}
	switch cmp.Verdict {
	case qual.VerdictPass:
		return qual.Supported([]string{fmt.Sprintf("%s: native blocked time of the event-loop thread %d ns inside the wait window, between the %d ns the loop was idle on %d requests held %d ns server-side (-%.0f%%) and the %d ns of round trips the runtime observed (+%.0f%%)", sp.label, cmp.NativeNs, cmp.LowerNs, truth.Requests, truth.ServerDelayNs, qual.BlockedTolerance*100, cmp.UpperNs, qual.BlockedTolerance*100)}, recorded)
	case qual.VerdictFail:
		return qual.Failed(sp.label+": "+cmp.Reason, recorded)
	}
	return qual.Unqualified("scheduler_evidence_unknown: "+cmp.Reason, recorded)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
