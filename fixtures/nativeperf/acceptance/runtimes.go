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
	"sort"
	"strings"
	"time"

	"soundpost/fixtures/nativeperf/qual"
	"soundpost/internal/nativeperf"
)

// runtimeSecs is each runtime fixture's own run time (60% CPU loop, then waits).
const runtimeSecs = 8.0

type runtimeSpec struct {
	name   string
	script string
	find   func() (string, string) // binary path, reason when unavailable
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

func (a *accept) runtimeSpecs() []runtimeSpec {
	root, _ := os.Getwd()
	return []runtimeSpec{
		{"python", "python.py", func() (string, string) {
			p, err := exec.LookPath("python3")
			if err != nil || !isELF(p) {
				return "", "python3 is not available as a Linux ELF binary"
			}
			return p, ""
		}},
		{"node", "node.mjs", func() (string, string) {
			if p := firstELF(os.Getenv("SOUNDPOST_NODE"), filepath.Join(root, ".tools/linux/node-v22.23.4-linux-x64/bin/node")); p != "" {
				return p, ""
			}
			return "", "no Linux Node ELF binary (set SOUNDPOST_NODE or unpack node-v22.23.4-linux-x64 under .tools/linux)"
		}},
		{"bun", "bun.ts", func() (string, string) {
			if p := firstELF(os.Getenv("SOUNDPOST_BUN"), "/opt/bun/bin/bun"); p != "" {
				return p, ""
			}
			return "", "no Linux Bun ELF binary (set SOUNDPOST_BUN)"
		}},
	}
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
		Kind         string  `json:"kind"`
		Requests     int     `json:"requests"`
		WaitTotal    float64 `json:"wait_seconds_total"`
		WaitMin      float64 `json:"wait_seconds_min"`
		ServerDelay  float64 `json:"server_delay_s"`
		DatabaseWait string  `json:"database_wait"`
	} `json:"wait"`
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
	a.res.NotRun = append(a.res.NotRun,
		qual.NotRunItem{Item: "CPython 3.13 and 3.14 columns", Reason: "only CPython 3.12.3 exists on this host"},
		qual.NotRunItem{Item: "Node 24 column", Reason: "only Node 22.23.4 was exercised"},
		qual.NotRunItem{Item: "CPython native-extension work and perf trampolines on/off", Reason: "no native-extension workload and no 3.12 trampoline comparison were built"},
		qual.NotRunItem{Item: "database wait in the Python/Node/Bun columns", Reason: "no database engine fixture; only a loopback HTTP wait was exercised"},
		qual.NotRunItem{Item: "runtime columns on arm64", Reason: "no arm64 host; amd64 cannot qualify arm64"})
}

func (a *accept) runtimeColumn(sp runtimeSpec, scriptDir string) qual.RuntimeColumn {
	col := qual.RuntimeColumn{Runtime: sp.name, Arch: qual.GOARCHName()}
	unq := func(reason string) {
		col.Engine, col.Native, col.Wait = qual.Unqualified(reason, nil), qual.Unqualified(reason, nil), qual.Unqualified(reason, nil)
	}
	bin, why := sp.find()
	if bin == "" {
		unq("runtime_unavailable: " + why)
		return col
	}
	fmt.Fprintf(os.Stderr, "acceptance: runtime column %s\n", sp.name)
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: bin, Dir: a.scratch, Nonce: a.nonce, ProcExe: true, Argv: []string{filepath.Join(scriptDir, sp.script), fmt.Sprint(runtimeSecs)}})
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
	cap := qual.Capture(a.ctx, h, qual.CaptureOptions{Config: nativeperf.DefaultConfig(1), Duration: time.Duration(runtimeSecs+40) * time.Second, Needles: a.needles(), OnReady: func() { w.Go() }})
	exit, werr := w.Wait(60 * time.Second)
	if !cap.Ready {
		col.Native = qual.Failed("helper refused the signed request: "+cap.ErrorCode+cap.ReadError, nil)
	}
	sum, _, _ := qual.FileSHA256(w.Exe)
	var rep runtimeReport
	reportOK := werr == nil && json.Unmarshal([]byte(strings.TrimSpace(lastLine(w.Output()))), &rep) == nil
	version := rep.Version
	col.Build = qual.RuntimeBuild{Runtime: sp.name, Version: version, Arch: qual.GOARCHName(), BuildID: w.BuildID, SHA256: sum, Path: filepath.Base(w.Exe)}
	a.res.RuntimeBuild[sp.name] = col.Build

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
		threads := map[uint32]bool{}
		for _, e := range cap.Events {
			if e.CPUEvent == nil {
				continue
			}
			threads[e.Task.TID] = true
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
		detail := map[string]any{"cpu_samples": samples, "threads_observed": len(threads), "sample_ip_region": classes, "samples_resolved_to_a_target_symbol": resolved,
			"helper_error_code": cap.ErrorCode, "stream_end": cap.ReadError, "loss_events": cap.LossEvents, "canary_hits": cap.NeedleHits, "interpreter_symbols": "frames inside JIT code, stripped binaries and libraries are reported unresolved, never named",
			"suspended_task_ancestry": "not available: thread callchains only"}
		switch {
		case err != nil:
			col.Native = qual.Failed("native capture rejected: "+err.Error(), detail)
		case cap.NeedleHits != 0:
			col.Native = qual.Failed(fmt.Sprintf("privacy canary found in %d frames", cap.NeedleHits), detail)
		default:
			col.Native = qual.Supported([]string{fmt.Sprintf("%d real native CPU samples from %d threads of the %s process through the signed-grant helper (frames mostly unresolved: JIT/stripped)", samples, len(threads), sp.name)}, detail)
		}
	}
	a.rtFrames += cap.Frames
	a.rtHits += cap.NeedleHits
	// wait column: the runtime really waited; the native blocked-time evidence cannot be acquired here
	wd := map[string]any{"runtime_recorded": rep.Wait, "native_blocked_intervals": "not acquirable: scheduler path unavailable on this host"}
	reason, _ := a.schedulerReason()
	col.Wait = qual.Unqualified(reason, wd)
	return col
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
