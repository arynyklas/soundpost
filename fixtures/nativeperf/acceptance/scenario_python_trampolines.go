//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func init() { registerHostScenario("python_trampolines", (*accept).pythonTrampolines) }

const (
	// trampolineSecs is the run time handed to the fixture: 40% Python CPU loop, 40% native-extension work, then the
	// asyncio wait.
	trampolineSecs = 6.0
	// sampleRateTolerance is how far the samples a CPU second produced may be from the helper's 99 Hz, and how far the
	// trampolines-on rate may be from the trampolines-off one: the same ±25% as the approved blocked-time window.
	sampleRateTolerance = qual.BlockedTolerance
	// phaseSlackNs is the margin around a phase's window (the fixture's own clock reads around the phase) inside which a
	// sample still belongs to it.
	phaseSlackNs = 10_000_000
	// minPhaseSamples is the fewest samples a CPU phase has to show: 99 Hz over the 2.4 s it ran is about 237.
	minPhaseSamples = 100
	// minShare is the share of a phase's samples that have to show what the phase is about (the native extension's hot
	// function at the leaf and its callers in the chain; the trampoline of the running Python function).
	minShare = 0.8
	// idleWaitShare is the most a wait window may be CPU-sampled, as a share of the samples a busy thread would give.
	idleWaitShare = 0.15
)

// trampolineReport is what python_trampolines.py prints about its own run.
type trampolineReport struct {
	Version        string `json:"version"`
	PID            int    `json:"pid"`
	PerfMapPresent bool   `json:"perf_map_present"`
	Trampoline     struct {
		Mode      string `json:"mode"`
		Available bool   `json:"available"`
		Active    bool   `json:"active"`
		Backend   string `json:"backend"`
		Error     string `json:"error"`
	} `json:"trampoline"`
	CPUPhase struct {
		Function   string    `json:"function"`
		WindowNs   [2]uint64 `json:"window_ns"`
		CPUSeconds float64   `json:"cpu_seconds"`
	} `json:"cpu_phase"`
	NativePhase struct {
		Function   string    `json:"function"`
		Extension  string    `json:"extension"`
		WindowNs   [2]uint64 `json:"window_ns"`
		CPUSeconds float64   `json:"cpu_seconds"`
	} `json:"native_phase"`
	Wait waitReport `json:"wait"`
}

// pyExtension is the native-extension workload compiled for one interpreter.
type pyExtension struct {
	dir, so, buildID, includeDir, compiler string
}

// buildPyExtension compiles fixtures/nativeperf/runtime/spnative.c against the interpreter's own headers, with frame
// pointers, debug info and a GNU build ID (the identity the operator approves for the helper).
func buildPyExtension(py, runtimeDir, dir string) (pyExtension, error) {
	ext := pyExtension{dir: dir, so: filepath.Join(dir, "spnative.so")}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ext, err
	}
	raw, err := exec.Command(py, "-c", "import sysconfig;print(sysconfig.get_paths()['include'])").Output()
	if err != nil {
		return ext, fmt.Errorf("the interpreter did not name its include directory: %w", err)
	}
	ext.includeDir = strings.TrimSpace(string(raw))
	if _, err := os.Stat(filepath.Join(ext.includeDir, "Python.h")); err != nil {
		return ext, fmt.Errorf("no Python.h in the interpreter's include directory %s", ext.includeDir)
	}
	ext.compiler = ccVersion()
	out, err := exec.Command("cc", "-O2", "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer", "-g", "-shared", "-fPIC", "-Wl,--build-id", "-I", ext.includeDir, "-o", ext.so, filepath.Join(runtimeDir, "spnative.c")).CombinedOutput()
	if err != nil {
		return ext, fmt.Errorf("compiling the extension failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if ext.buildID, err = qual.BuildIDOf(ext.so); err != nil || ext.buildID == "" {
		return ext, fmt.Errorf("the extension carries no GNU build ID")
	}
	return ext, nil
}

// openWatch reports every open or read of one file by any process, through inotify, from the moment it is set: the
// interpreter writes its perf map and never reads it, so anything it records is somebody else reading the map.
type openWatch struct{ fd int }

func watchOpens(path string) (*openWatch, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	if _, err := syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN|syscall.IN_ACCESS|syscall.IN_CLOSE_NOWRITE); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &openWatch{fd: fd}, nil
}

// stop ends the watch and names what it saw ("open", "read", "close_read").
func (w *openWatch) stop() []string {
	defer syscall.Close(w.fd)
	var seen []string
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(w.fd, buf)
		if err != nil || n <= 0 {
			return seen
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			switch {
			case ev.Mask&syscall.IN_OPEN != 0:
				seen = append(seen, "open")
			case ev.Mask&syscall.IN_ACCESS != 0:
				seen = append(seen, "read")
			case ev.Mask&syscall.IN_CLOSE_NOWRITE != 0:
				seen = append(seen, "close_read")
			}
			off += syscall.SizeofInotifyEvent + int(ev.Len)
		}
	}
}

// trampolineRun is everything one run of python_trampolines.py under one capture showed.
type trampolineRun struct {
	mode        string
	report      trampolineReport
	failures    []string
	unavailable string // the trampoline could not be activated in this interpreter: why
	unjudged    []string
	samples     int
	cpu, native phaseStats
	wait        phaseStats
	rates       map[string]float64
	waitRow     qual.Row
	detail      map[string]any
}

func (r *trampolineRun) fail(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// check records a failure unless ok.
func (r *trampolineRun) check(ok bool, format string, args ...any) {
	if !ok {
		r.fail(format, args...)
	}
}

func share(n, of int) float64 {
	if of == 0 {
		return 0
	}
	return float64(n) / float64(of)
}

// run captures python_trampolines.py once with the trampoline on or off and judges what the capture shows.
func (a *accept) trampolineRun(label, py, runtimeDir string, ext pyExtension, mode string) *trampolineRun {
	r := &trampolineRun{mode: mode, rates: map[string]float64{}, detail: map[string]any{}}
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: py, Dir: a.scratch, Nonce: a.nonce, ProcExe: true, Argv: []string{filepath.Join(runtimeDir, "python_trampolines.py"), fmt.Sprint(trampolineSecs), mode, ext.dir}})
	if err != nil {
		r.fail("launch: %v", err)
		return r
	}
	defer w.Kill()
	// the operator approves the interpreter (LaunchWorkload) and the extension object by GNU build ID
	w.Target.AllowedBuildIDs = append(w.Target.AllowedBuildIDs, ext.buildID)
	extSymbols := newELFOffsets(ext.so)
	mapPath := fmt.Sprintf("/tmp/perf-%d.map", w.PID)
	var watch *openWatch
	if mode == "on" {
		if watch, err = watchOpens(mapPath); err != nil {
			r.fail("the perf map cannot be watched: %v", err)
		}
	}
	h, err := qual.StartHelper([]nativeperf.Target{w.Target}, 0)
	if err != nil {
		r.fail("helper: %v", err)
		return r
	}
	defer h.Stop()
	// the privacy canaries: the run's nonce, and what only the interpreter's perf map and script names hold (a Python function
	// name, the perf map's path, the script's file name) must never reach the helper's stream
	needles := append(a.needles(), []byte(fmt.Sprintf("perf-%d.map", w.PID)), []byte("py::"), []byte("spy_cpu_loop"), []byte("spy_native_phase"), []byte("spy_http_wait"), []byte("python_trampolines"))
	var perfMap []byte
	var opened []string
	var perfMapStat error
	var table nativeperf.MappingTable
	var tableErr error
	rc := a.captureRuntimeProcess(label, w, h, trampolineSecs, needles, func() {
		if watch != nil {
			opened = watch.stop()
		}
		perfMap, _ = os.ReadFile(mapPath)
		_, perfMapStat = os.Stat(mapPath)
		// the product's own mapping table of the live process, for the product to resolve the captured samples with
		table, tableErr = productMappingTable(a.ctx, w.Target)
	})
	cap := rc.cap
	if !cap.Ready {
		r.fail("the helper refused the capture: %s%s", cap.ErrorCode, cap.ReadError)
		return r
	}
	reportOK := rc.werr == nil && json.Unmarshal([]byte(strings.TrimSpace(lastLine(w.Output()))), &r.report) == nil
	if !reportOK || rc.exit != 0 {
		r.fail("python_trampolines.py printed no report or failed (exit %d, %v)", rc.exit, rc.werr)
		return r
	}
	rep := r.report
	if mode == "on" && (rep.Trampoline.Error != "" || !rep.Trampoline.Active) {
		r.unavailable = rep.Trampoline.Error
		if r.unavailable == "" {
			r.unavailable = "sys.is_stack_trampoline_active() is false after sys.activate_stack_trampoline(\"perf\")"
		}
		return r
	}
	r.check(mode != "off" || !rep.Trampoline.Active, "the trampoline is active in the off run")

	for _, e := range cap.Events {
		if e.CPUEvent != nil {
			r.samples++
		}
	}
	cpuSeconds := rep.CPUPhase.CPUSeconds + rep.NativePhase.CPUSeconds
	if err := qual.CheckCapture(qual.CaptureEvidence{Events: cap.Events, TargetTGID: w.Target.TGID, WorkloadCPUSeconds: cpuSeconds, InExecutable: w.Resolver().InAnyExecutable, KnownThread: w.KnownThread}); err != nil {
		r.fail("the capture was rejected as not genuine: %v", err)
	}
	r.check(cap.NeedleHits == 0, "%d privacy canaries (a Python function name, the perf map's path or the script's name) reached the helper's stream", cap.NeedleHits)

	if tableErr != nil {
		r.fail("the product's mapping table could not be built: %v", tableErr)
		return r
	}
	perf := parsePerfMap(perfMap)
	// every CPU sample is resolved by the product (ResolveCPUObservation over its own mapping table): approved code comes
	// back as a module and an offset, everything else as a closed reason
	var observed []observedSample
	productHits := 0
	for _, e := range cap.Events {
		if e.CPUEvent == nil {
			continue
		}
		obs, err := nativeperf.ResolveCPUObservation(a.ctx, e.Task, *e.CPUEvent, table, nil)
		if err != nil {
			r.fail("the product could not resolve a sample: %v", err)
			return r
		}
		observed = append(observed, observedSample{at: uint64(e.Time), ips: userInstructionPointers(e.CPUEvent), frames: obs.Frames})
		raw, _ := json.Marshal(obs)
		productHits += qual.CountNeedles(raw, needles)
	}
	r.check(productHits == 0, "%d privacy canaries (a Python function name, the perf map's path or the script's name) are in the frames the product resolved", productHits)
	verifier := func(ip uint64) string { return w.Resolver().Classify(ip) }
	phase := func(window [2]uint64) phaseStats {
		return analyzePhase(observed, w.BuildID, ext.buildID, extSymbols, verifier, perf, window, phaseSlackNs)
	}
	r.cpu, r.native, r.wait = phase(rep.CPUPhase.WindowNs), phase(rep.NativePhase.WindowNs), phase(rep.Wait.HTTP.WindowNs)
	r.rates["python_cpu_loop_samples_per_cpu_second"] = sampleRate(r.cpu.Samples, rep.CPUPhase.CPUSeconds)
	r.rates["native_extension_samples_per_cpu_second"] = sampleRate(r.native.Samples, rep.NativePhase.CPUSeconds)

	// samples are retained in both modes, at the rate the helper samples a CPU second
	r.check(r.cpu.Samples >= minPhaseSamples && r.native.Samples >= minPhaseSamples, "too few samples retained: %d in the Python CPU loop, %d in the native-extension phase (need %d)", r.cpu.Samples, r.native.Samples, minPhaseSamples)
	for name, rate := range r.rates {
		r.check(rate >= 99*(1-sampleRateTolerance) && rate <= 99*(1+sampleRateTolerance), "%s is %.1f, not within ±%.0f%% of 99 Hz", name, rate, sampleRateTolerance*100)
	}
	// the native-extension hot function is in genuine callchains: the product resolved those frames to the module of the
	// extension's approved build ID, and the verifier's own ELF lookup of the object names the functions
	n := r.native
	r.check(share(n.LeafInExtension, n.Samples) >= minShare, "only %d of %d native-extension samples are in the extension module the product resolved from its approved build ID", n.LeafInExtension, n.Samples)
	r.check(share(n.LeafHotFunction, n.Samples) >= minShare, "only %d of %d native-extension samples have spext_hot at the leaf", n.LeafHotFunction, n.Samples)
	// The whole extension chain spext_hot <- spext_mix <- spext_burn is required: the object keeps a frame record in its leaf
	// (spnative.c), so a frame-pointer unwind names every caller; a missing middle frame would be a lost frame.
	r.check(share(n.ChainHasMix, n.Samples) >= minShare, "the extension's middle function spext_mix is in %d of %d native-extension callchains", n.ChainHasMix, n.Samples)
	r.check(share(n.ChainHasBurn, n.Samples) >= minShare, "the extension's outermost function spext_burn is in %d of %d native-extension callchains", n.ChainHasBurn, n.Samples)
	// no frame the product could not resolve is given a name or an identity, and the product and the verifier's own
	// /proc/<pid>/maps agree on which frames are anonymous code
	for name, st := range map[string]phaseStats{"python loop": r.cpu, "native extension": r.native, "asyncio wait": r.wait} {
		r.check(st.AnonymousNamedOrIdent == 0, "%s: %d anonymous-code frames carry a module, an offset or a symbol", name, st.AnonymousNamedOrIdent)
		r.check(st.AnonymousDisagreements == 0, "%s: the product and the verifier's own /proc/pid/maps disagree on %d frames about anonymous code", name, st.AnonymousDisagreements)
	}
	switch mode {
	case "on":
		r.check(len(perf) > 0 && strings.Contains(string(perfMap), "py::spy_cpu_loop"), "the interpreter's perf map is missing or holds no entry of the fixture's functions")
		r.check(len(opened) == 0, "something other than the interpreter opened or read its perf map during the capture: %v", opened)
		r.check(r.cpu.WithAnonymousMemory > 0 && share(r.cpu.TrampolineByFunction["spy_cpu_loop"], r.cpu.Samples) >= minShare, "the Python CPU loop's samples show its own trampoline in %d of %d callchains (per the verifier's reading of the perf map)", r.cpu.TrampolineByFunction["spy_cpu_loop"], r.cpu.Samples)
		r.check(share(r.native.TrampolineByFunction["spy_native_phase"], r.native.Samples) >= minShare, "the native-extension samples show the calling Python function's trampoline in %d of %d callchains", r.native.TrampolineByFunction["spy_native_phase"], r.native.Samples)
	case "off":
		r.check(!rep.PerfMapPresent && os.IsNotExist(perfMapStat), "a perf map exists in the off run (%s)", mapPath)
		r.check(r.cpu.WithAnonymousMemory+r.native.WithAnonymousMemory+r.wait.WithAnonymousMemory == 0, "anonymous executable code is in the callchains of the off run")
	}
	// the asyncio wait: the loop sat in the kernel's wait, the scheduler evidence agrees with what asyncio measured, and the
	// CPU sampler did not see a busy thread
	if rc.corr == nil {
		reason, _ := a.schedulerReason()
		r.waitRow = qual.Unqualified(reason, nil)
	} else {
		fixture := runtimeReport{Version: rep.Version, Wait: rep.Wait}
		row, phases := a.runtimeWaitRow(runtimeSpec{name: "python", label: label}, w, &fixture, true, cap, rc.corr, ledgerFor(rc.cfg, rc.adm, rc.corr, cap, rc.helperBefore, rc.helperAfter, rc.clientAfter))
		r.waitRow = row
		if p, ok := phases[phaseHTTP]; ok {
			r.waitRow = p
		}
	}
	switch r.waitRow.State {
	case qual.StateSupported:
	case qual.StateFailed:
		r.fail("asyncio wait: %s", r.waitRow.Reason)
	default:
		r.unjudged = append(r.unjudged, fmt.Sprintf("asyncio wait: %s (%s)", r.waitRow.State, r.waitRow.Reason))
	}
	window := float64(rep.Wait.HTTP.WindowNs[1]-rep.Wait.HTTP.WindowNs[0]) / 1e9
	r.check(float64(r.wait.Samples) <= idleWaitShare*99*window, "the asyncio wait window holds %d CPU samples over %.1f s: the loop was not idle", r.wait.Samples, window)

	r.detail = map[string]any{
		"python": rep.Version, "trampoline_active": rep.Trampoline.Active, "perf_map_entries": len(perf), "perf_map_opened_by_others": opened,
		"cpu_samples_total": r.samples, "python_cpu_loop": r.cpu, "native_extension": r.native, "asyncio_wait": r.wait, "samples_per_cpu_second": r.rates,
		"capture_loss_events": cap.LossEvents, "privacy_canary_hits": cap.NeedleHits, "privacy_canary_hits_in_product_frames": productHits,
		"threads_with_samples": len(distinctThreads(cap.Events)),
	}
	return r
}

func distinctThreads(events []nativeperf.SanitizedEvent) map[uint32]bool {
	out := map[uint32]bool{}
	for _, e := range events {
		if e.CPUEvent != nil {
			out[e.Task.TID] = true
		}
	}
	return out
}

// pythonTrampolines is the python_trampolines scenario: for each CPython the host was given (3.12, 3.13, 3.14) the
// interpreter runs a Python CPU loop, a native-extension workload (a real extension module, compiled here against that
// interpreter's headers) and an asyncio wait, twice under the real helper: with the perf trampoline off and on. In both
// runs the samples are retained at the rate the helper samples a CPU second, the extension's hot function is in the
// callchains by the verifier's ELF lookup of the extension, and the asyncio wait agrees with the scheduler evidence. With
// the trampoline on, its frames (anonymous executable code, named only by the interpreter's perf map, which the verifier
// reads and the helper must not) are announced by the helper with the closed reason
// jit_or_anonymous_map_unavailable and no identity, stay unresolved, and nothing of the perf map reaches the stream.
func (a *accept) pythonTrampolines() qual.Row {
	if a.caps.CPU != nativeperf.Supported {
		return qual.Unqualified("cpu_sampling_unavailable: the CPU path is not supported on this host (see the cpu row)", nil)
	}
	if _, err := exec.LookPath("cc"); err != nil {
		return qual.Unqualified("build_toolchain_unavailable: no C compiler (cc) to build the native extension", nil)
	}
	runtimeDir, _ := filepath.Abs(a.o.runtimeDir)
	var evidence, failed, unjudged []string
	versions := map[string]any{}
	for _, b := range pythonBuilds {
		py := os.Getenv(b.env)
		if py == "" {
			unjudged = append(unjudged, fmt.Sprintf("CPython %s: interpreter_not_given: %s is not set", b.version, b.env))
			continue
		}
		if !isELF(py) {
			unjudged = append(unjudged, fmt.Sprintf("CPython %s: %s=%s is not a Linux ELF interpreter", b.version, b.env, py))
			continue
		}
		ext, err := buildPyExtension(py, runtimeDir, filepath.Join(a.scratch, "spnative-"+b.version))
		if err != nil {
			unjudged = append(unjudged, fmt.Sprintf("CPython %s: extension_build_failed: %v", b.version, err))
			continue
		}
		off := a.trampolineRun("python "+b.version+" trampolines off", py, runtimeDir, ext, "off")
		on := a.trampolineRun("python "+b.version+" trampolines on", py, runtimeDir, ext, "on")
		version := on.report.Version
		if version == "" {
			version = off.report.Version
		}
		vd := map[string]any{"version": version, "extension_build_id": ext.buildID, "extension_compiler": ext.compiler, "extension_flags": "-O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -shared -fPIC -Wl,--build-id", "trampolines_off": off.detail, "trampolines_on": on.detail}
		versions["python "+b.version] = vd
		fmt.Fprintf(os.Stderr, "acceptance: python_trampolines %s (%s): off %d failures, on %d failures, unavailable %q\n", b.version, version, len(off.failures), len(on.failures), on.unavailable)
		if !strings.HasPrefix(version, b.version+".") {
			failed = append(failed, fmt.Sprintf("CPython %s: build_mismatch: %s=%s reports version %q", b.version, b.env, py, version))
			continue
		}
		for _, run := range []*trampolineRun{off, on} {
			if len(run.failures) > 0 {
				failed = append(failed, fmt.Sprintf("CPython %s trampolines %s: %s", b.version, run.mode, strings.Join(run.failures, "; ")))
			}
			if len(run.unjudged) > 0 {
				unjudged = append(unjudged, fmt.Sprintf("CPython %s trampolines %s: %s", b.version, run.mode, strings.Join(run.unjudged, "; ")))
			}
		}
		if on.unavailable != "" {
			unjudged = append(unjudged, fmt.Sprintf("CPython %s: trampoline_unavailable: %s", b.version, on.unavailable))
		}
		if len(off.failures)+len(on.failures)+len(off.unjudged)+len(on.unjudged) > 0 || on.unavailable != "" {
			continue
		}
		// trampolines on do not change what the capture sees of the work: the samples a CPU second produced, phase by phase,
		// are within the tolerance of the trampolines-off run's
		compared := true
		for _, k := range []string{"python_cpu_loop_samples_per_cpu_second", "native_extension_samples_per_cpu_second"} {
			rOff, rOn := off.rates[k], on.rates[k]
			vd["rate_"+k] = map[string]float64{"off": rOff, "on": rOn}
			if rOff == 0 || rOn < rOff*(1-sampleRateTolerance) || rOn > rOff*(1+sampleRateTolerance) {
				failed = append(failed, fmt.Sprintf("CPython %s: %s is %.1f with the trampoline on and %.1f with it off (more than ±%.0f%% apart)", b.version, k, rOn, rOff, sampleRateTolerance*100))
				compared = false
			}
		}
		if !compared {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("CPython %s: trampoline off %d / on %d CPU samples (%d / %d of them in the native extension's hot function spext_hot, resolved from the extension object, build ID %s); on-run callchains show the trampoline of the running Python function in %d of %d Python-loop samples and %d of %d native-extension samples, announced by the helper as jit_or_anonymous_map_unavailable and left unresolved, with no perf-map name, path or identity in the stream and no process but the interpreter touching the map; samples per CPU second %.1f off, %.1f on (Python loop); asyncio wait agrees with the scheduler evidence in both runs",
			version, off.samples, on.samples, off.native.LeafHotFunction, on.native.LeafHotFunction, ext.buildID[:12],
			on.cpu.TrampolineByFunction["spy_cpu_loop"], on.cpu.Samples, on.native.TrampolineByFunction["spy_native_phase"], on.native.Samples,
			off.rates["python_cpu_loop_samples_per_cpu_second"], on.rates["python_cpu_loop_samples_per_cpu_second"]))
	}
	detail := map[string]any{"versions": versions, "frames": "interpreter, trampoline (anonymous executable code), libc and JIT/native-only frames are reported unresolved, never named; suspended-task ancestry of asyncio tasks is not available (thread callchains only)"}
	switch {
	case len(failed) > 0:
		return qual.Failed(strings.Join(failed, "; "), detail)
	case len(unjudged) > 0:
		return qual.Unqualified(strings.Join(unjudged, "; "), detail)
	}
	return qual.Supported(evidence, detail)
}
