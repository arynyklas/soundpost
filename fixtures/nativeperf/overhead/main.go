//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command overhead measures the cost of the real native CPU capture (signed-grant
// helper process, real perf events at 99 Hz) on a profiled workload. It alternates
// baseline and capture runs of the same workload, reports the target's CPU time
// and throughput separately from the collector's CPU (helper process and this
// client), the sample and loss distributions, helper+client RSS with ring
// accounting and open FDs, and evaluates the measured numbers against the
// approved budgets (<= 3% workload CPU overhead, <= 64 MiB acquisition/export
// memory). Budgets are never adjusted: a failure is reported as measured.
//
//	go run ./fixtures/nativeperf/overhead --manifest fixtures/nativeperf/qualification.json --hz 99 --seconds 120 --repeats 5
//
// Exit codes: 0 every budget held on every fixture; 1 a budget failed or a run
// failed; 2 usage. A run shorter than 120 s or with fewer than 5 repeats is
// marked reduced in the report and can never be recorded as the full run.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	cpuOverheadBudgetPercent = 3.0
	memoryBudgetBytes        = nativeperf.MaxMemoryBytes
)

type run struct {
	Mode           string  `json:"mode"` // baseline | capture
	Order          int     `json:"order"`
	WallSeconds    float64 `json:"phase_wall_seconds"`
	Iterations     uint64  `json:"iterations"`
	ThroughputPS   float64 `json:"throughput_per_second"`
	TargetCPUSec   float64 `json:"target_cpu_seconds"`
	CPUNsPerIter   float64 `json:"target_cpu_ns_per_iteration"`
	HelperCPUSec   float64 `json:"helper_cpu_seconds,omitempty"`
	ClientCPUSec   float64 `json:"client_cpu_seconds,omitempty"`
	Samples        int     `json:"samples,omitempty"`
	AchievedHz     float64 `json:"achieved_hz_per_thread,omitempty"`
	LossEvents     int     `json:"loss_events,omitempty"`
	LostRecords    uint64  `json:"lost_records,omitempty"`
	GapP50Ms       float64 `json:"sample_gap_p50_ms,omitempty"`
	GapP99Ms       float64 `json:"sample_gap_p99_ms,omitempty"`
	HelperHWMKiB   uint64  `json:"helper_hwm_kib,omitempty"`
	HelperAnonKiB  uint64  `json:"helper_anon_rss_kib,omitempty"`
	HelperFileKiB  uint64  `json:"helper_file_rss_kib,omitempty"`
	HelperShmemKiB uint64  `json:"helper_shmem_rss_kib,omitempty"`
	ClientHWMKiB   uint64  `json:"client_hwm_kib,omitempty"`
	ClientStartKiB uint64  `json:"client_start_rss_kib,omitempty"`
	RingBytes      uint64  `json:"ring_bytes_accounted,omitempty"`
	HelperFDsPeak  int     `json:"helper_fds_peak,omitempty"`
	ClientFDs      int     `json:"client_fds,omitempty"`
	Threads        int     `json:"threads_sampled,omitempty"`
	StreamEnd      string  `json:"stream_end,omitempty"`
}

type stat struct {
	Mean   float64 `json:"mean"`
	Stdev  float64 `json:"stdev"`
	StdErr float64 `json:"stderr"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type fixtureResult struct {
	Fixture        string         `json:"fixture"`
	Mode           string         `json:"workload_mode"`
	Seconds        float64        `json:"seconds_per_run"`
	Repeats        int            `json:"repeats"`
	Reduced        bool           `json:"reduced"`
	Runs           []run          `json:"runs"`
	BaselineCPUNs  stat           `json:"baseline_cpu_ns_per_iteration"`
	CaptureCPUNs   stat           `json:"capture_cpu_ns_per_iteration"`
	BaselineThru   stat           `json:"baseline_throughput_per_second"`
	CaptureThru    stat           `json:"capture_throughput_per_second"`
	OverheadPct    float64        `json:"workload_cpu_overhead_percent"`
	OverheadSEPct  float64        `json:"workload_cpu_overhead_stderr_percent"`
	ThroughputPct  float64        `json:"throughput_change_percent"`
	CollectorCPUPc float64        `json:"collector_cpu_percent_of_one_core"`
	HelperCPUSec   stat           `json:"helper_cpu_seconds_per_run"`
	ClientCPUSec   stat           `json:"client_cpu_seconds_per_run"`
	Samples        stat           `json:"samples_per_run"`
	AchievedHz     stat           `json:"achieved_hz_per_thread"`
	LossEvents     stat           `json:"loss_events_per_run"`
	GapP50Ms       stat           `json:"sample_gap_p50_ms"`
	GapP99Ms       stat           `json:"sample_gap_p99_ms"`
	MemoryBytes    uint64         `json:"combined_conservative_memory_bytes_max"`
	PeakFDs        int            `json:"helper_fds_peak_max"`
	CPUBudgetOK    bool           `json:"cpu_overhead_budget_met"`
	MemoryBudgetOK bool           `json:"memory_budget_met"`
	Refusal        *refusal       `json:"admission_refusal,omitempty"`
	Failures       []string       `json:"failures,omitempty"`
	Detail         map[string]any `json:"detail,omitempty"`
}

type report struct {
	Manifest    string          `json:"manifest"`
	KernelBuild string          `json:"kernel_build"`
	Arch        string          `json:"arch"`
	Hz          int             `json:"hz_requested"`
	Command     string          `json:"command"`
	FullCommand string          `json:"full_command"`
	FullRun     bool            `json:"full_run_executed"`
	Reduction   string          `json:"reduction,omitempty"`
	Budgets     map[string]any  `json:"budgets"`
	Fixtures    []fixtureResult `json:"fixtures"`
	Caveats     []string        `json:"caveats"`
	Verdict     string          `json:"verdict"`
}

func main() {
	if handled, code := qual.HelperRole(os.Args[1:]); handled {
		os.Exit(code)
	}
	// the client's resident size is part of the measured sum (D53); same opt-out as the acceptance runner
	if err := qual.DisableTransparentHugePages(); err != nil {
		fmt.Fprintln(os.Stderr, "overhead: transparent huge pages left on:", err)
	}
	manifest := flag.String("manifest", "fixtures/nativeperf/qualification.json", "qualification manifest")
	hz := flag.Int("hz", 99, "requested sampling frequency (the engine is fixed at 99)")
	seconds := flag.Int("seconds", 120, "seconds per run")
	repeats := flag.Int("repeats", 5, "baseline/capture pairs")
	workload := flag.String("workload", "fixtures/nativeperf/acceptance/workloads", "compiled workloads binary")
	fixtures := flag.String("fixtures", "cpu", "comma separated workload modes to measure (cpu, fanout, fanout16, fanout64, fanout256)")
	out := flag.String("out", "", "write the JSON report here instead of stdout")
	flag.Parse()
	if *hz != 99 || *seconds < 3 || *repeats < 1 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: --hz must be 99 (the engine requests a fixed 99 Hz), --seconds >= 3, --repeats >= 1")
		os.Exit(qual.ExitUsage)
	}
	if _, err := os.Stat(*workload); err != nil {
		fmt.Fprintln(os.Stderr, "overhead: workload binary missing; compile fixtures/nativeperf/acceptance/workloads.c first")
		os.Exit(qual.ExitUsage)
	}
	rep := &report{Manifest: *manifest, KernelBuild: qual.KernelRelease(), Arch: qual.GOARCHName(), Hz: *hz,
		Command:     "overhead " + strings.Join(os.Args[1:], " "),
		FullCommand: "go run ./fixtures/nativeperf/overhead --manifest fixtures/nativeperf/qualification.json --hz 99 --seconds 120 --repeats 5",
		FullRun:     *seconds >= 120 && *repeats >= 5,
		Budgets:     map[string]any{"workload_cpu_overhead_percent_max": cpuOverheadBudgetPercent, "acquisition_export_memory_bytes_max": memoryBudgetBytes},
		Caveats: []string{
			"measured on a shared WSL2 host: other processes compete for CPU and memory bandwidth, and the host kernel is a hypervisor guest",
			"target CPU time is the process's user+system time from wait4, which includes kernel time spent in the perf sampling interrupt on the target's behalf",
			"the helper and this client are measured separately as collector CPU; the sink is the client socket reader only (no network export), whose cost the 04.08 verify fixture covers",
		}}
	if !rep.FullRun {
		rep.Reduction = fmt.Sprintf("REDUCED: %d s x %d repeats instead of the approved 120 s x 5; the full command above was NOT run for this report", *seconds, *repeats)
	}
	ok := true
	for _, name := range strings.Split(*fixtures, ",") {
		name = strings.TrimSpace(name)
		if name != "cpu" && name != "fanout" && name != "fanout16" && name != "fanout64" && name != "fanout256" {
			fmt.Fprintln(os.Stderr, "usage: unknown fixture", name)
			os.Exit(qual.ExitUsage)
		}
		fmt.Fprintf(os.Stderr, "overhead: fixture %s, %d pairs of %d s\n", name, *repeats, *seconds)
		fr := measure(*workload, name, float64(*seconds), *repeats)
		fr.Reduced = !rep.FullRun
		ok = ok && fixtureOK(&fr)
		rep.Fixtures = append(rep.Fixtures, fr)
	}
	rep.Verdict = "budgets_met"
	if !ok {
		rep.Verdict = "budget_failed_or_run_failed"
	}
	raw, _ := json.MarshalIndent(rep, "", "  ")
	raw = append(raw, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write report:", err)
			os.Exit(qual.ExitFail)
		}
	} else {
		os.Stdout.Write(raw)
	}
	if !ok {
		os.Exit(qual.ExitFail)
	}
}

func summarize(v []float64) stat {
	if len(v) == 0 {
		return stat{}
	}
	s := stat{Min: v[0], Max: v[0]}
	for _, x := range v {
		s.Mean += x
		s.Min, s.Max = math.Min(s.Min, x), math.Max(s.Max, x)
	}
	s.Mean /= float64(len(v))
	if len(v) > 1 {
		for _, x := range v {
			s.Stdev += (x - s.Mean) * (x - s.Mean)
		}
		s.Stdev = math.Sqrt(s.Stdev / float64(len(v)-1))
		s.StdErr = s.Stdev / math.Sqrt(float64(len(v)))
	}
	return s
}

func measure(workload, mode string, seconds float64, repeats int) fixtureResult {
	fr := fixtureResult{Fixture: mode, Mode: mode, Seconds: seconds, Repeats: repeats}
	scratch, err := os.MkdirTemp("", "soundpost-overhead-")
	if err != nil {
		fr.Failures = append(fr.Failures, err.Error())
		return fr
	}
	defer os.RemoveAll(scratch)
	var base, capt []run
	for i := 0; i < repeats; i++ {
		// alternate: baseline first in even pairs, capture first in odd pairs, so a
		// slow drift of the host cannot favor either mode
		order := []string{"baseline", "capture"}
		if i%2 == 1 {
			order = []string{"capture", "baseline"}
		}
		for _, m := range order {
			r, err := oneRun(workload, mode, m, seconds, scratch)
			r.Order = len(base) + len(capt) + 1
			var refused *refusedError
			if errors.As(err, &refused) {
				if by := classifyRefusal(refused.code, refused.threads); by != nil {
					// the plan's own admission bound: the fixture is reported as refused, there is nothing to measure
					fr.Refusal = by
					fr.Runs = append(fr.Runs, r)
					return fr
				}
			}
			if err != nil {
				fr.Failures = append(fr.Failures, fmt.Sprintf("%s run %d: %v", m, i+1, err))
			}
			fr.Runs = append(fr.Runs, r)
			if err != nil {
				continue
			}
			if m == "baseline" {
				base = append(base, r)
			} else {
				capt = append(capt, r)
			}
		}
	}
	evaluate(&fr, base, capt, seconds)
	return fr
}

// evaluate computes the summaries and the budget verdicts of one fixture from
// its measured baseline and capture runs. The budgets are constants of this
// package and are never parameters.
func evaluate(fr *fixtureResult, base, capt []run, seconds float64) {
	col := func(rs []run, f func(run) float64) []float64 {
		var o []float64
		for _, r := range rs {
			o = append(o, f(r))
		}
		return o
	}
	fr.BaselineCPUNs = summarize(col(base, func(r run) float64 { return r.CPUNsPerIter }))
	fr.CaptureCPUNs = summarize(col(capt, func(r run) float64 { return r.CPUNsPerIter }))
	fr.BaselineThru = summarize(col(base, func(r run) float64 { return r.ThroughputPS }))
	fr.CaptureThru = summarize(col(capt, func(r run) float64 { return r.ThroughputPS }))
	fr.HelperCPUSec = summarize(col(capt, func(r run) float64 { return r.HelperCPUSec }))
	fr.ClientCPUSec = summarize(col(capt, func(r run) float64 { return r.ClientCPUSec }))
	fr.Samples = summarize(col(capt, func(r run) float64 { return float64(r.Samples) }))
	fr.AchievedHz = summarize(col(capt, func(r run) float64 { return r.AchievedHz }))
	fr.LossEvents = summarize(col(capt, func(r run) float64 { return float64(r.LossEvents) }))
	fr.GapP50Ms = summarize(col(capt, func(r run) float64 { return r.GapP50Ms }))
	fr.GapP99Ms = summarize(col(capt, func(r run) float64 { return r.GapP99Ms }))
	if len(base) == 0 || len(capt) == 0 || fr.BaselineCPUNs.Mean == 0 {
		fr.Failures = append(fr.Failures, "no complete baseline and capture runs to compare")
		return
	}
	fr.OverheadPct = (fr.CaptureCPUNs.Mean/fr.BaselineCPUNs.Mean - 1) * 100
	// standard error of the ratio of means (delta method)
	b, c := fr.BaselineCPUNs, fr.CaptureCPUNs
	fr.OverheadSEPct = 100 * math.Sqrt(math.Pow(c.StdErr/b.Mean, 2)+math.Pow(c.Mean*b.StdErr/(b.Mean*b.Mean), 2))
	fr.ThroughputPct = (fr.CaptureThru.Mean/fr.BaselineThru.Mean - 1) * 100
	fr.CollectorCPUPc = 100 * (fr.HelperCPUSec.Mean + fr.ClientCPUSec.Mean) / seconds
	var worst memoryLedger
	for _, r := range capt {
		if l := ledgerOf(r); l.ConservativeBytes > worst.ConservativeBytes {
			worst = l
		}
		if r.HelperFDsPeak > fr.PeakFDs {
			fr.PeakFDs = r.HelperFDsPeak
		}
	}
	fr.MemoryBytes = worst.ConservativeBytes
	// compared without a percentage division so a whole-number boundary is exact
	fr.CPUBudgetOK = fr.CaptureCPUNs.Mean*100 <= fr.BaselineCPUNs.Mean*(100+cpuOverheadBudgetPercent)
	fr.MemoryBudgetOK = fr.MemoryBytes <= memoryBudgetBytes
	if !fr.CPUBudgetOK {
		fr.Failures = append(fr.Failures, fmt.Sprintf("workload CPU overhead %.2f%% exceeds the %.0f%% budget (stderr %.2f%%)", fr.OverheadPct, cpuOverheadBudgetPercent, fr.OverheadSEPct))
	}
	if !fr.MemoryBudgetOK {
		fr.Failures = append(fr.Failures, fmt.Sprintf("combined helper+client+ring memory %d bytes exceeds %d", fr.MemoryBytes, memoryBudgetBytes))
	}
	fr.Detail = map[string]any{
		"overhead_confidence": "point estimate with delta-method standard error; compare |overhead| with stderr before reading a 1-3% difference as real",
		"memory_ledger":       worst,
	}
}

func oneRun(workload, mode, which string, seconds float64, scratch string) (run, error) {
	r := run{Mode: which}
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: workload, Mode: mode, Seconds: seconds, Dir: scratch})
	if err != nil {
		return r, err
	}
	defer w.Kill()
	var (
		helper             *qual.HelperProc
		cap                qual.CaptureResult
		stats              captureStats
		helperTicks0       uint64
		clientBefore       qual.ProcUsage
		launchThreads      = countTasks(w.PID)
		stopSample, sample = make(chan struct{}), make(chan struct{})
	)
	if which == "capture" {
		// this process's resident high-water mark describes this capture, not the garbage and the peaks of the runs before it
		qual.SettleMemory()
		if helper, err = qual.StartHelper([]nativeperf.Target{w.Target}, 0); err != nil {
			return r, err
		}
		defer helper.Stop()
		u, _ := qual.ReadProc(helper.PID)
		helperTicks0 = u.CPUTicks
		clientBefore, _ = qual.ReadProc(0)
		go func() {
			defer close(sample)
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopSample:
					return
				case <-t.C:
					if u, err := qual.ReadProc(helper.PID); err == nil && u.FDs > r.HelperFDsPeak {
						r.HelperFDsPeak = u.FDs
					}
				}
			}
		}()
		cap = qual.Capture(context.Background(), helper, qual.CaptureOptions{Config: nativeperf.DefaultConfig(1), Duration: time.Duration(seconds+60) * time.Second, OnReady: func() { w.Go() }, StopWhen: w.DoneSeen, Sink: &stats})
		close(stopSample)
		<-sample
		if !cap.Ready {
			return r, &refusedError{code: cap.ErrorCode, threads: launchThreads, msg: fmt.Sprintf("helper refused the capture: %s%s", cap.ErrorCode, cap.ReadError)}
		}
		hu, _ := qual.ReadProc(helper.PID)
		r.HelperCPUSec = float64(hu.CPUTicks-helperTicks0) / qual.ClockTicksPerSecond
		r.HelperHWMKiB, r.HelperAnonKiB, r.HelperFileKiB, r.HelperShmemKiB = hu.HWMKiB, hu.AnonKiB, hu.FileKiB, hu.ShmemKiB
		cu, _ := qual.ReadProc(0)
		r.ClientCPUSec = float64(cu.CPUTicks-clientBefore.CPUTicks) / qual.ClockTicksPerSecond
		r.ClientHWMKiB, r.ClientStartKiB, r.ClientFDs = cu.HWMKiB, clientBefore.RSSKiB, cu.FDs
	} else {
		if err := w.Go(); err != nil {
			return r, err
		}
		for !w.DoneSeen() {
			time.Sleep(50 * time.Millisecond)
		}
	}
	w.Finish()
	exit, werr := w.Wait(60 * time.Second)
	if werr != nil || exit != 0 {
		return r, fmt.Errorf("workload exit %d (%v)", exit, werr)
	}
	gt, err := qual.ReadGroundTruth(w.GTPath)
	if err != nil {
		return r, err
	}
	var cpuNs uint64
	var first, last uint64
	for _, l := range gt {
		switch l.Kind {
		case "iterations":
			r.Iterations += l.Extra
			if first == 0 || l.StartNs < first {
				first = l.StartNs
			}
			if l.EndNs > last {
				last = l.EndNs
			}
		case "cpu_phase":
			cpuNs += l.Extra
		case "summary":
			if !l.Verified {
				return r, fmt.Errorf("workload did not verify its own ground truth")
			}
		}
	}
	r.WallSeconds = float64(last-first) / 1e9
	r.TargetCPUSec = float64(cpuNs) / 1e9
	if r.Iterations == 0 || r.WallSeconds <= 0 {
		return r, fmt.Errorf("no iterations recorded")
	}
	r.ThroughputPS = float64(r.Iterations) / r.WallSeconds
	r.CPUNsPerIter = float64(cpuNs) / float64(r.Iterations)
	if which == "capture" {
		r.Samples, r.Threads, r.LossEvents, r.LostRecords = stats.samples, stats.threads(), cap.LossEvents, cap.LostSamples
		r.StreamEnd = cap.ErrorCode + cap.ReadError
		if r.Threads > 0 && r.TargetCPUSec > 0 {
			r.AchievedHz = float64(r.Samples) / r.TargetCPUSec
		}
		p50, p99 := qual.Percentiles(stats.gaps)
		r.GapP50Ms, r.GapP99Ms = float64(p50)/1e6, float64(p99)/1e6
		// the helper opens one ring per thread of the target: those that never ran are charged too
		r.RingBytes = uint64(max(r.Threads, launchThreads)) * (nativeperf.DefaultConfig(1).RingBytes + uint64(os.Getpagesize()))
	}
	return r, nil
}

// captureStats is the EventSink of an overhead capture: it counts the CPU samples, the threads that produced them and
// the per-thread gaps between samples as they stream in and retains no event. The capture used to keep every event
// (a callchain of up to 128 frames each) for the whole run, which made this process's resident size, the "client" term of
// the memory budget, grow with the sample count: a harness artifact, not the exporting peer's working set.
type captureStats struct {
	samples int
	last    map[uint32]uint64
	gaps    []uint64
}

func (s *captureStats) Event(e nativeperf.SanitizedEvent) bool {
	if e.CPUEvent == nil {
		return false
	}
	s.samples++
	if s.last == nil {
		s.last = map[uint32]uint64{}
	}
	if p, ok := s.last[e.Task.TID]; ok && uint64(e.Time) >= p {
		s.gaps = append(s.gaps, uint64(e.Time)-p)
	}
	s.last[e.Task.TID] = uint64(e.Time)
	return false
}

func (s *captureStats) Proof(nativeperf.AcquisitionProof) {}

func (s *captureStats) threads() int { return len(s.last) }

// countTasks is the number of threads of a live process.
func countTasks(pid int) int {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0
	}
	return len(ents)
}

// refusedError is a capture the helper refused at admission.
type refusedError struct {
	code    string
	threads int
	msg     string
}

func (e *refusedError) Error() string { return e.msg }

// refusal records a fixture whose target the helper refused at admission because it cannot fit the session's fixed
// descriptor ceiling (plan 04 Task 2: 256 per session; every perf ring, three descriptors per target and two for the
// session count against it). The plan requires that refusal to be explicit (resource_limit, never a partly sampled
// target), so it is an outcome of the fixture, not a failed measurement.
type refusal struct {
	Code        string `json:"code"`
	Threads     int    `json:"target_threads"`
	FDsRequired uint64 `json:"session_fds_required"`
	FDCeiling   uint64 `json:"session_fd_ceiling"`
	Reason      string `json:"reason"`
}

// classifyRefusal returns the refusal record when code is resource_limit and a target of that many threads cannot fit the
// session's descriptor ceiling, and nil otherwise: a refusal of a target that does fit is a defect and stays a failure.
func classifyRefusal(code string, threads int) *refusal {
	if code != "resource_limit" || threads <= 0 {
		return nil
	}
	need := uint64(threads) + 5
	if need <= nativeperf.MaxSessionFDs {
		return nil
	}
	return &refusal{Code: code, Threads: threads, FDsRequired: need, FDCeiling: nativeperf.MaxSessionFDs,
		Reason: "plan 04 Task 2 fixes the descriptor ceiling of a session at 256: one ring per target thread plus 5, so at most 251 threads per target; a larger target is refused explicitly"}
}

// fixtureOK is the verdict of one fixture: its budgets held and no run failed, or the plan's own admission bound refused it
// and nothing else failed.
func fixtureOK(fr *fixtureResult) bool {
	if fr.Refusal != nil {
		return len(fr.Failures) == 0
	}
	return len(fr.Failures) == 0 && fr.CPUBudgetOK && fr.MemoryBudgetOK
}

// memoryLedger is the breakdown of the worst capture run's combined memory: the helper's and this process's resident
// high-water marks, the helper's resident size split by kind at the end of the run, and the rings accounted on top (the
// budget counts them again on purpose).
type memoryLedger struct {
	Threads            int    `json:"target_threads"`
	HelperHWMBytes     uint64 `json:"helper_hwm_bytes"`
	HelperAnonBytes    uint64 `json:"helper_anon_rss_bytes"`
	HelperFileBytes    uint64 `json:"helper_file_rss_bytes"`
	HelperShmemBytes   uint64 `json:"helper_shmem_rss_bytes"`
	ClientHWMBytes     uint64 `json:"client_hwm_bytes"`
	ClientStartBytes   uint64 `json:"client_rss_at_capture_start_bytes"`
	RingBytesAccounted uint64 `json:"ring_bytes_accounted"`
	ConservativeBytes  uint64 `json:"conservative_total_bytes"`
	BudgetBytes        uint64 `json:"budget_bytes"`
}

func ledgerOf(r run) memoryLedger {
	l := memoryLedger{Threads: r.Threads, HelperHWMBytes: r.HelperHWMKiB << 10, HelperAnonBytes: r.HelperAnonKiB << 10, HelperFileBytes: r.HelperFileKiB << 10,
		HelperShmemBytes: r.HelperShmemKiB << 10, ClientHWMBytes: r.ClientHWMKiB << 10, ClientStartBytes: r.ClientStartKiB << 10, RingBytesAccounted: r.RingBytes, BudgetBytes: memoryBudgetBytes}
	l.ConservativeBytes = l.HelperHWMBytes + l.ClientHWMBytes + l.RingBytesAccounted
	return l
}
