//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"soundpost/fixtures/nativeperf/qual"
	"soundpost/internal/nativeperf"
)

type scenSpec struct {
	name, mode, hot string
	expected        []string // true call chain, leaf first
	frac            float64  // share of --duration
}

var (
	fpChain   = []string{"spqual_hot", "spqual_hash_block", "spqual_serve", "spqual_worker_loop"}
	nofpChain = []string{"spqual_nofp_hot", "spqual_nofp_mid", "spqual_nofp_serve", "spqual_nofp_entry", "spqual_worker_loop"}
)

var specs = []scenSpec{
	{"cpu", "cpu", "spqual_hot", fpChain, 0.38},
	{"nofp", "nofp", "spqual_nofp_hot", nofpChain, 0.12},
	{"contend", "contend", "spqual_hot", fpChain, 0.12},
	{"migrate", "migrate", "spqual_hot", fpChain[:3], 0.10},
	{"exec", "exec", "spqual_hot", fpChain, 0.12},
	{"blocking", "blocking", "", nil, 0.10},
}

type accept struct {
	o       options
	res     *qual.QualificationResult
	scratch string
	ctx     context.Context
	nonce   string
	rng     *rand.Rand
	results map[string]*scenResult

	injections   map[string]*scenResult
	caps         nativeperf.Capabilities
	probeErr     string
	probeErr2    error
	canaryInComm bool
	canaryInArgv bool
	rtFrames     int
	rtHits       int
	dropHelper   bool
	dropWorkload bool
}

// scenResult is everything one scenario observed.
type scenResult struct {
	Name, Mode      string
	Seconds         float64
	Cap             qual.CaptureResult
	GT              []qual.GroundTruthLine
	WorkloadExit    int
	SelfVerified    bool
	Stats           qual.StackStats
	CPUSeconds      float64
	Windows         [][2]uint64
	CheckErr        error
	HelperBefore    qual.ProcUsage
	HelperPeak      qual.ProcUsage
	HelperTicks     uint64
	HelperFDsAfter  int
	HelperPerfAfter int
	ClientHWMKiB    uint64
	ClientTicks     uint64
	Threads         int
	DistinctCPUs    int
	Failures        []string
	Err             string
	Extra           map[string]any
	Resolver        *qual.Resolver
	Blocked         []qual.BlockedTruth
	Corr            *qual.Correlation
	TargetTID       uint32
}

func (r *scenResult) fail(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

func (a *accept) needles() [][]byte {
	n := a.nonce
	return [][]byte{[]byte(n), []byte("work" + n[:10]), []byte("main" + n[:10]), []byte("stk" + n)}
}

func helperFDs(pid int) (total, perf int) {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, 0
	}
	for _, e := range ents {
		total++
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name())); err == nil && strings.Contains(l, "perf_event") {
			perf++
		}
	}
	return
}

type stall struct {
	after int
	dur   time.Duration
}

// runScenario runs one workload under one real helper process and one capture.
func (a *accept) runScenario(name, mode string, seconds float64, cfg nativeperf.Config, noFile uint64, st *stall, cm nativeperf.CaptureMode) *scenResult {
	r := &scenResult{Name: name, Mode: mode, Seconds: seconds, Extra: map[string]any{}}
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: a.o.workload, Mode: mode, Seconds: seconds, Dir: a.scratch, Nonce: a.nonce, RunAs: unprivilegedUID, DropToUID: a.dropWorkload})
	if err != nil {
		r.Err = "launch: " + err.Error()
		return r
	}
	defer w.Kill()
	r.Resolver = w.Resolver()
	h, err := qual.StartHelperAs([]nativeperf.Target{w.Target}, noFile, unprivilegedUID, a.dropHelper)
	if err != nil {
		r.Err = "helper: " + err.Error()
		return r
	}
	defer h.Stop()
	r.HelperBefore, _ = qual.ReadProc(h.PID)
	clientBefore, _ := qual.ReadProc(0)

	var mu sync.Mutex
	stopSample := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopSample:
				return
			case <-t.C:
				u, err := qual.ReadProc(h.PID)
				if err == nil {
					mu.Lock()
					if u.FDs > r.HelperPeak.FDs {
						r.HelperPeak.FDs = u.FDs
					}
					if u.RSSKiB > r.HelperPeak.RSSKiB {
						r.HelperPeak.RSSKiB = u.RSSKiB
					}
					mu.Unlock()
				}
			}
		}
	}()
	opts := qual.CaptureOptions{Config: cfg, Mode: cm, Duration: time.Duration(seconds+45) * time.Second, Needles: a.needles(), OnReady: func() { w.Go() }, StopWhen: w.DoneSeen}
	if st != nil {
		opts.StallAfter, opts.StallFor = st.after, st.dur
	}
	r.Cap = qual.Capture(a.ctx, h, opts)
	close(stopSample)
	<-sampled
	final, _ := qual.ReadProc(h.PID)
	if final.HWMKiB > r.HelperPeak.HWMKiB {
		r.HelperPeak.HWMKiB = final.HWMKiB
	}
	r.HelperTicks = final.CPUTicks - r.HelperBefore.CPUTicks
	if r.Cap.Ready {
		w.Finish()
		r.WorkloadExit, _ = w.Wait(30 * time.Second)
	} else {
		w.Kill()
		r.WorkloadExit = -1
	}
	clientAfter, _ := qual.ReadProc(0)
	r.ClientHWMKiB, r.ClientTicks = clientAfter.HWMKiB, clientAfter.CPUTicks-clientBefore.CPUTicks
	// the helper releases on its own goroutine after the stream ends
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.HelperFDsAfter, r.HelperPerfAfter = helperFDs(h.PID)
		if r.HelperFDsAfter == r.HelperBefore.FDs || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if gt, err := qual.ReadGroundTruth(w.GTPath); err == nil {
		r.GT = gt
	}
	if sum, _, err := qual.FileSHA256(w.GTPath); err == nil {
		r.Extra["ground_truth_sha256"] = sum
	}
	var summaryWindow [][2]uint64
	for _, l := range r.GT {
		switch {
		case l.Kind == "summary":
			r.SelfVerified = l.Verified
			summaryWindow = [][2]uint64{{l.StartNs, l.EndNs}}
		case strings.HasPrefix(l.Kind, "cpu_phase"):
			r.CPUSeconds += float64(l.Extra) / 1e9
			r.Windows = append(r.Windows, [2]uint64{l.StartNs, l.EndNs})
		}
	}
	if len(r.Windows) == 0 {
		r.Windows = summaryWindow // no CPU phase recorded (migrate/blocking): the whole run
	}
	threads := map[uint32]bool{}
	cpus := map[uint32]bool{}
	for _, e := range r.Cap.Events {
		if e.CPUEvent != nil {
			threads[e.Task.TID] = true
			cpus[e.CPU] = true
		}
	}
	r.Threads, r.DistinctCPUs = len(threads), len(cpus)
	if cm == nativeperf.ModeCPUOffCPU && r.Cap.Ready {
		c := qual.Correlate(r.Cap, cfg)
		r.Corr = &c
	}
	r.TargetTID = uint32(w.PID)
	if spec := findSpec(mode); spec != nil && r.Cap.Ready {
		r.Stats = qual.Analyze(r.Cap.Events, w.Resolver(), spec.hot, spec.expected, r.Windows)
	}
	if r.Cap.Ready && mode != "blocking" {
		r.CheckErr = qual.CheckCapture(qual.CaptureEvidence{Events: r.Cap.Events, TargetTGID: w.Target.TGID, WorkloadCPUSeconds: r.CPUSeconds, InExecutable: w.Resolver().InAnyExecutable, KnownThread: w.KnownThread})
	}
	return r
}

func findSpec(name string) *scenSpec {
	for i := range specs {
		if specs[i].name == name {
			return &specs[i]
		}
	}
	return nil
}

func (r *scenResult) summary() map[string]any {
	m := map[string]any{
		"mode": r.Mode, "seconds": r.Seconds, "workload_exit": r.WorkloadExit, "workload_self_verified": r.SelfVerified,
		"helper_ready": r.Cap.Ready, "helper_error_code": r.Cap.ErrorCode, "stream_end": r.Cap.ReadError,
		"frames_read": r.Cap.Frames, "cpu_samples": r.Stats.CPUSamples, "threads_observed": r.Threads, "distinct_cpus": r.DistinctCPUs,
		"loss_events": r.Cap.LossEvents, "lost_samples": r.Cap.LostSamples, "workload_cpu_seconds": r.CPUSeconds,
		"samples_in_ground_truth_phase": r.Stats.InWindow, "samples_hot_function_at_ip": r.Stats.HotSamples, "samples_hot_function_in_chain": r.Stats.ChainsWithHot,
		"samples_3_or_more_frames": r.Stats.Samples3Frames, "frames_resolved_to_workload": r.Stats.ResolvedFrames, "frames_unresolved": r.Stats.UnresolvedFrames,
		"function_samples": r.Stats.FunctionSamples, "non_leaf_functions": r.Stats.NonLeaf, "truncated_samples": r.Stats.TruncatedSamples,
		"helper_cpu_ms": r.HelperTicks * 1000 / qual.ClockTicksPerSecond, "helper_peak_rss_kib": r.HelperPeak.RSSKiB, "helper_hwm_kib": r.HelperPeak.HWMKiB,
		"helper_fds_before": r.HelperBefore.FDs, "helper_fds_peak": r.HelperPeak.FDs, "helper_fds_after": r.HelperFDsAfter, "helper_perf_fds_after": r.HelperPerfAfter,
		"client_hwm_kib": r.ClientHWMKiB,
	}
	if r.Err != "" {
		m["error"] = r.Err
	}
	if len(r.Failures) > 0 {
		m["failures"] = r.Failures
	}
	for k, v := range r.Extra {
		m[k] = v
	}
	return m
}

// runAll runs every scenario in a seed-determined order, then the injections,
// the runtime columns and derives the rows.
func (a *accept) runAll() {
	a.results = map[string]*scenResult{}
	order := append([]scenSpec(nil), specs...)
	a.rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	a.probeHost()
	cfg := nativeperf.DefaultConfig(1)
	for _, sp := range order {
		secs := a.o.duration.Seconds() * sp.frac
		if secs < 3 {
			secs = 3
		}
		fmt.Fprintf(os.Stderr, "acceptance: scenario %s (%.1fs)\n", sp.name, secs)
		r := a.runScenario(sp.name, sp.mode, secs, cfg, 0, nil, nativeperf.ModeCPU)
		a.assert(sp, r)
		a.results[sp.name] = r
	}
	if a.caps.OffCPU == nativeperf.Supported {
		a.runSchedulerScenarios(cfg)
	}
	a.runInjections()
	a.runPermissionCases(cfg)
	a.runRuntimes()
	a.deriveRows()
}

func (a *accept) record(cmd string, ran bool, note string) {
	a.res.Commands = append(a.res.Commands, qual.Command{Command: cmd, Ran: ran, Note: note})
}
