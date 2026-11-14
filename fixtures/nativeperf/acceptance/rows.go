//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// assert applies the per-scenario acceptance assertions.
func (a *accept) assert(sp scenSpec, r *scenResult) {
	if r.Err != "" {
		r.fail("%s", r.Err)
		return
	}
	if !r.Cap.Ready {
		r.fail("helper refused the signed request: %s%s", r.Cap.ErrorCode, r.Cap.ReadError)
		return
	}
	if r.WorkloadExit != 0 || !r.SelfVerified {
		r.fail("workload did not verify its own ground truth (exit %d, self_verified=%v)", r.WorkloadExit, r.SelfVerified)
	}
	if sp.mode != "blocking" && r.CheckErr != nil {
		r.fail("capture rejected: %v", r.CheckErr)
	}
	s := r.Stats
	frac := func(n int) float64 {
		if s.CPUSamples == 0 {
			return 0
		}
		return float64(n) / float64(s.CPUSamples)
	}
	switch sp.name {
	case "cpu":
		if float64(s.CPUSamples) < 0.5*99*r.CPUSeconds {
			r.fail("only %d samples for %.1f s on CPU (<50%% of 99 Hz)", s.CPUSamples, r.CPUSeconds)
		}
		if frac(s.ChainsWithHot) < 0.8 {
			r.fail("hot function %s in only %.0f%% of callchains (need >= 80%%)", sp.hot, 100*frac(s.ChainsWithHot))
		}
		if frac(s.FunctionSamples["spqual_serve"]) < 0.5 {
			r.fail("resolved caller spqual_serve in only %.0f%% of callchains (need >= 50%%)", 100*frac(s.FunctionSamples["spqual_serve"]))
		}
		if frac(s.Samples3Frames) < 0.5 {
			r.fail("only %.0f%% of stacks have 3 or more frames", 100*frac(s.Samples3Frames))
		}
		if frac(s.InWindow) < 0.95 {
			r.fail("only %.0f%% of sample timestamps lie in the workload's recorded CPU phase", 100*frac(s.InWindow))
		}
	case "nofp":
		if frac(s.HotSamples) < 0.8 {
			r.fail("leaf function %s at the sample IP in only %.0f%% of samples", sp.hot, 100*frac(s.HotSamples))
		}
		for _, hidden := range []string{"spqual_nofp_mid", "spqual_nofp_serve"} {
			if s.NonLeaf[hidden] != 0 {
				r.fail("frame %s (compiled without frame pointers) appears as a caller in %d callchains: invented frame", hidden, s.NonLeaf[hidden])
			}
		}
	case "contend":
		runnable := uint64(0)
		for _, l := range r.GT {
			if l.Kind == "runnable_delay" {
				runnable += l.EndNs
			}
		}
		r.Extra["runnable_delay_truth_ns"] = runnable
		if runnable == 0 {
			r.fail("no runnable-delay ground truth recorded")
		}
		if frac(s.ChainsWithHot) < 0.8 {
			r.fail("hot function in only %.0f%% of callchains", 100*frac(s.ChainsWithHot))
		}
	case "migrate":
		for _, l := range r.GT {
			if l.Kind == "migration" {
				r.Extra["ground_truth_migrations"] = l.Extra >> 32
				r.Extra["ground_truth_distinct_cpus"] = l.Extra & 0xffffffff
			}
		}
		if r.DistinctCPUs < 2 {
			r.fail("samples came from %d CPU(s); migration ground truth needs >= 2", r.DistinctCPUs)
		}
		if frac(s.ChainsWithHot) < 0.8 {
			r.fail("hot function in only %.0f%% of callchains across migrations", 100*frac(s.ChainsWithHot))
		}
	case "exec":
		a.assertExec(r)
	case "blocking":
		a.assertBlocking(r)
	}
	if sp.mode != "blocking" && r.Cap.NeedleHits != 0 {
		r.fail("privacy canary found in %d socket frame(s)", r.Cap.NeedleHits)
	}
}

func (a *accept) assertExec(r *scenResult) {
	var execAt uint64
	for _, l := range r.GT {
		if l.Kind == "exec" {
			execAt = l.StartNs
		}
	}
	if execAt == 0 {
		r.fail("no exec ground truth recorded")
		return
	}
	var pre, post []nativeperf.SanitizedEvent
	gens := map[uint64]bool{}
	for _, e := range r.Cap.Events {
		if e.CPUEvent == nil {
			continue
		}
		gens[uint64(e.Task.Generation)] = true
		switch {
		case uint64(e.Time)+100_000_000 < execAt:
			pre = append(pre, e)
		case uint64(e.Time) > execAt+100_000_000:
			post = append(post, e)
		}
	}
	r.Extra["exec_samples_before"], r.Extra["exec_samples_after"], r.Extra["generations_observed"] = len(pre), len(post), len(gens)
	if len(pre) == 0 {
		r.fail("no samples before the exec")
		return
	}
	if r.Cap.ErrorCode != "" {
		r.Extra["session_ended_with_code"] = r.Cap.ErrorCode
	}
	// No post-exec sample may carry the pre-exec generation's frames: the old
	// image's function (spqual_hot) must not be joined to the new process.
	if len(post) > 0 && r.Resolver != nil {
		st := qual.Analyze(post, r.Resolver, "spqual_hot_after_exec", []string{"spqual_hot", "spqual_hot_after_exec"}, nil)
		r.Extra["post_exec_old_image_function_samples"] = st.ExpectedPresent["spqual_hot"]
		r.Extra["post_exec_new_image_function_samples"] = st.ExpectedPresent["spqual_hot_after_exec"]
		if st.ExpectedPresent["spqual_hot"] != 0 {
			r.fail("%d post-exec samples resolve to the pre-exec function: old stacks joined to the new image", st.ExpectedPresent["spqual_hot"])
		}
	}
	if len(post) == 0 && r.Cap.ErrorCode == "" && r.Cap.ReadError == "" {
		r.fail("no post-exec samples and no explicit session end after exec")
	}
}

func (a *accept) assertBlocking(r *scenResult) {
	kinds := map[string]int{}
	var windows []qual.BlockedTruth
	var total uint64
	for _, l := range r.GT {
		switch l.Kind {
		case "timed_sleep", "pipe_wait", "futex_wait":
			kinds[l.Kind]++
			windows = append(windows, qual.BlockedTruth{TID: uint32(l.TID), Start: l.StartNs, End: l.EndNs})
			total += l.EndNs - l.StartNs
		}
	}
	r.Blocked = windows
	r.Extra["blocking_intervals"], r.Extra["blocking_kinds"], r.Extra["blocking_truth_total_ns"] = len(windows), kinds, total
	if len(windows) < qual.MinBlockedIntervals {
		r.fail("only %d ground-truth blocking intervals recorded (need >= %d)", len(windows), qual.MinBlockedIntervals)
	}
	for _, k := range []string{"timed_sleep", "pipe_wait", "futex_wait"} {
		if kinds[k] == 0 {
			r.fail("no %s intervals recorded", k)
		}
	}
	// A CPU-clock sampler must not tick while the thread is blocked; a
	// wall-clock sampler would produce ~99 samples per blocked second.
	inside := 0
	for _, e := range r.Cap.Events {
		if e.CPUEvent == nil {
			continue
		}
		for _, w := range windows {
			if uint64(e.Time) > w.Start+2_000_000 && uint64(e.Time) < w.End {
				inside++
				break
			}
		}
	}
	r.Extra["cpu_samples_inside_blocked_intervals"] = inside
	r.Extra["wall_clock_sampler_would_produce_approx"] = int(99 * float64(total) / 1e9)
	if inside > 5 {
		r.fail("%d CPU samples inside blocked intervals: the sampler is not a CPU-clock sampler", inside)
	}
}

// ---- host probe ----

func (a *accept) probeHost() {
	w, err := qual.LaunchWorkload(qual.LaunchOptions{Bin: a.o.workload, Mode: "cpu", Seconds: 1, Dir: a.scratch, Nonce: a.nonce})
	if err != nil {
		a.probeErr = err.Error()
		return
	}
	defer w.Kill()
	// positive control for the privacy needles: they really are present in the
	// workload's observable state (thread name, argument vector).
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", w.PID)); err == nil {
		a.canaryInComm = bytes.Contains(comm, []byte("main"+a.nonce[:10]))
	}
	if argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", w.PID)); err == nil {
		a.canaryInArgv = bytes.Contains(argv, []byte(a.nonce))
	}
	target := nativeperf.Target{PIDNamespace: w.Target.PIDNamespace, TGID: w.Target.TGID, ProcessStart: w.Target.ProcessStart}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	a.caps, a.probeErr2 = nativeperf.Probe(ctx, []nativeperf.Target{target})
	a.res.Permissions = qual.SnapshotPermissions(a.caps)
	a.res.PolicyRevision = 1
}

// ---- injections ----

func (a *accept) runInjections() {
	a.injections = map[string]*scenResult{}
	cfg := nativeperf.DefaultConfig(1)
	run := func(name, mode string, secs float64, c nativeperf.Config, noFile uint64, st *stall) {
		fmt.Fprintf(os.Stderr, "acceptance: injection %s\n", name)
		r := a.runScenario(name, mode, secs, c, noFile, st, nativeperf.ModeCPU)
		a.injections[name] = r
	}
	loss := cfg
	loss.RingBytes = 4096
	run("loss_ring_4096_reader_stall", "fanout", 8, loss, 0, &stall{after: 5, dur: 4 * time.Second})
	run("fd_limit_40", "fanout", 3, cfg, 40, nil)
	run("fd_limit_64", "fanout", 3, cfg, 64, nil)
	run("fd_limit_128", "fanout", 3, cfg, 128, nil)
	for _, mem := range []uint64{1 << 20, 8 << 20} {
		c := cfg
		c.MaxMemory = mem
		run(fmt.Sprintf("memory_budget_%dMiB", mem>>20), "cpu", 3, c, 0, nil)
	}
}

var closedCodes = map[string]bool{"authorization_denied": true, "topology_changed": true, "source_canceled": true, "resource_limit": true, "thread_coverage_changed": true, "generation_changed": true, "loss": true, "event_unavailable": true, "permission_denied": true, "acquisition_failed": true}

// explicitInjection classifies an injected-limit run: refused with a closed
// code and every resource released, or admitted and within the stated limit.
func explicitInjection(r *scenResult, withinLimit func(*scenResult) (bool, string)) (ok bool, outcome string) {
	released := r.HelperFDsAfter == r.HelperBefore.FDs && r.HelperPerfAfter == 0
	switch {
	case r.Err != "":
		return false, "fixture error: " + r.Err
	case !r.Cap.Ready:
		if !closedCodes[r.Cap.ErrorCode] {
			return false, "refusal without a closed error code (" + r.Cap.ErrorCode + r.Cap.ReadError + ")"
		}
		if len(r.Cap.Events) != 0 || !released {
			return false, "refused but events delivered or resources not released"
		}
		return true, "refused:" + r.Cap.ErrorCode
	case r.Cap.ErrorCode != "" && !closedCodes[r.Cap.ErrorCode]:
		return false, "stream ended with a non-closed code " + r.Cap.ErrorCode
	}
	if !released {
		return false, "resources not released after the capture"
	}
	if ok, why := withinLimit(r); !ok {
		return false, "admitted but " + why
	}
	return true, "admitted_within_limit"
}

// ---- rows ----

func (a *accept) deriveRows() {
	res := a.res
	var failures []string
	var evidence []string
	detail := map[string]any{}
	names := make([]string, 0, len(a.results))
	for n := range a.results {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := a.results[n]
		detail[n] = r.summary()
		for _, f := range r.Failures {
			failures = append(failures, n+": "+f)
		}
		if sha, ok := r.Extra["ground_truth_sha256"].(string); ok {
			res.Evidence = append(res.Evidence, qual.EvidenceRef{Name: "ground truth " + n, SHA256: sha})
		}
	}
	cpu := a.results["cpu"]
	if cpu != nil && cpu.Cap.Ready {
		evidence = append(evidence, fmt.Sprintf("%d real software_cpu_clock samples through the signed-grant helper process for %.1f s on CPU; hot function %s in %d chains", cpu.Stats.CPUSamples, cpu.CPUSeconds, "spqual_hot", cpu.Stats.ChainsWithHot))
	}
	failures = append(failures, permissionFailures(res.Permissions.Cases)...)
	if len(failures) > 0 {
		res.CPU = qual.Failed(strings.Join(failures, "; "), detail)
	} else {
		res.CPU = qual.Supported(evidence, detail)
	}

	// frame coverage with and without frame pointers
	fpCov, nofpCov := 0.0, 0.0
	if cpu != nil {
		fpCov = cpu.Stats.Coverage(fpChain)
	}
	nofp := a.results["nofp"]
	if nofp != nil {
		nofpCov = nofp.Stats.Coverage(nofpChain)
	}
	fcDetail := map[string]any{
		"with_frame_pointers_coverage":    fpCov,
		"with_frame_pointers_expected":    fpChain,
		"without_frame_pointers_coverage": nofpCov,
		"without_frame_pointers_expected": nofpChain,
		"rule":                            "coverage = mean over the true call chain of the share of samples whose resolved chain contains the frame; frames the unwinder cannot see are absent and counted unresolved, never invented",
	}
	if cpu != nil {
		fcDetail["with_frame_pointers_unresolved_frames"] = cpu.Stats.UnresolvedFrames
		fcDetail["with_frame_pointers_truncated_samples"] = cpu.Stats.TruncatedSamples
	}
	if nofp != nil {
		fcDetail["without_frame_pointers_unresolved_frames"] = nofp.Stats.UnresolvedFrames
		fcDetail["without_frame_pointers_non_leaf"] = nofp.Stats.NonLeaf
	}
	switch {
	case cpu == nil || nofp == nil || cpu.Stats.CPUSamples == 0 || nofp.Stats.CPUSamples == 0:
		res.FrameCoverage = qual.Failed("frame-pointer and no-frame-pointer captures are both required", fcDetail)
	case fpCov < 0.75:
		res.FrameCoverage = qual.Failed(fmt.Sprintf("frame-pointer build resolved only %.2f of its true chain (need >= 0.75)", fpCov), fcDetail)
	case nofpCov >= fpCov || nofpCov > 0.6:
		res.FrameCoverage = qual.Failed(fmt.Sprintf("no-frame-pointer build reported coverage %.2f against %.2f with frame pointers: partial coverage not shown", nofpCov, fpCov), fcDetail)
	case len(nofp.Failures) > 0:
		res.FrameCoverage = qual.Failed("no-frame-pointer scenario: "+strings.Join(nofp.Failures, "; "), fcDetail)
	default:
		res.FrameCoverage = qual.Supported([]string{
			fmt.Sprintf("frame-pointer build: %.2f of the true chain resolved from real callchains", fpCov),
			fmt.Sprintf("no-frame-pointer build: %.2f resolved; spqual_nofp_mid/spqual_nofp_serve absent from every chain (partial, not invented)", nofpCov)}, fcDetail)
	}

	a.deriveSchedulerRows(res)
	a.deriveInjectionRows(res, cpu)
	a.derivePrivacy(res)
	res.Overhead = qual.Row{State: qual.StateNotRun, Reason: "not_measured_here: run fixtures/nativeperf/overhead (99 Hz, alternating baseline/capture) and merge its report with fixtures/nativeperf/qualification --results"}
}

func (a *accept) deriveSchedulerRows(res *qual.QualificationResult) {
	caps, perm := a.caps, res.Permissions
	detail := map[string]any{
		"kernel": res.KernelBuild, "tracefs_mount": perm.TracefsMount, "tracefs_access": perm.TracefsAccess,
		"probe_off_cpu": string(caps.OffCPU), "probe_runqueue_split": string(caps.RunqueueSplit), "probe_reasons": caps.Reasons,
		"probe_scheduler_event_open": string(caps.Permissions.SchedulerEventOpen), "cap_eff": perm.CapEff, "perf_event_paranoid": perm.PerfEventParanoid, "probe_error": fmt.Sprint(a.probeErr2),
	}
	if caps.OffCPU == nativeperf.Supported {
		a.deriveSchedulerFromCaptures(res, detail)
		return
	}
	reason, _ := a.schedulerReason()
	truth := map[string]any{"blocking_ground_truth_recorded": false}
	if b := a.results["blocking"]; b != nil {
		truth = map[string]any{"blocking_intervals_recorded_by_workload": len(b.Blocked), "blocking_truth_total_ns": b.Extra["blocking_truth_total_ns"], "comparison": "not performed: no native blocked intervals can be acquired"}
	}
	if c := a.results["contend"]; c != nil {
		truth["runnable_delay_truth_ns"] = c.Extra["runnable_delay_truth_ns"]
	}
	detail["ground_truth"] = truth
	res.OffCPU = qual.Unqualified(reason, detail)
	res.RunqueueSplit = qual.Unqualified(reason, detail)
}

// schedulerReason names why the scheduler path is unavailable on this host (and
// whether the probe nevertheless reported it supported).
func (a *accept) schedulerReason() (string, bool) {
	if a.caps.OffCPU == nativeperf.Supported {
		return "scheduler_runner_not_exercised", true
	}
	access := a.res.Permissions.TracefsAccess
	switch {
	case strings.Contains(access, "EACCES") || strings.Contains(access, "EPERM"):
		return "tracefs_denied", false
	case containsReason(a.caps.Reasons, nativeperf.ReasonTraceFS):
		return "tracefs_unavailable", false
	case strings.Contains(a.res.Permissions.PIDNamespace, "initial namespace: false"):
		return "scheduler_pid_namespace_not_initial", false
	}
	return "scheduler_event_unavailable", false
}

func containsReason(rs []nativeperf.Reason, r nativeperf.Reason) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func (a *accept) deriveInjectionRows(res *qual.QualificationResult, cpu *scenResult) {
	// loss
	lossRun := a.injections["loss_ring_4096_reader_stall"]
	lossDetail := map[string]any{}
	if lossRun != nil {
		lossDetail["loss_ring_4096_reader_stall"] = lossRun.summary()
	}
	cpuLoss := 0
	if cpu != nil {
		cpuLoss = cpu.Cap.LossEvents
	}
	lossDetail["loss_events_in_normal_cpu_capture"] = cpuLoss
	switch {
	case lossRun == nil || lossRun.Err != "":
		res.Loss = qual.Failed("loss injection could not run", lossDetail)
	case !lossRun.Cap.Ready:
		res.Loss = qual.Failed("loss injection helper refused: "+lossRun.Cap.ErrorCode, lossDetail)
	case lossRun.Cap.LossEvents > 0:
		bad := 0
		for _, e := range lossRun.Cap.Events {
			if e.Loss != nil && (e.Validate() != nil || e.Loss.Count == 0) {
				bad++
			}
		}
		if bad > 0 {
			res.Loss = qual.Failed(fmt.Sprintf("%d malformed loss events", bad), lossDetail)
			break
		}
		delivered := 0
		for _, e := range lossRun.Cap.Events {
			if e.CPUEvent != nil {
				delivered++
			}
		}
		lossDetail["cpu_samples_delivered_alongside_loss"] = delivered
		res.Loss = qual.Supported([]string{fmt.Sprintf("injected loss (4 KiB ring, reader stalled 4 s, 16 hot threads): %d explicit loss events, %d lost records, %d samples still delivered", lossRun.Cap.LossEvents, lossRun.Cap.LostSamples, delivered)}, lossDetail)
	case lossRun.Cap.ErrorCode == "loss":
		res.Loss = qual.Supported([]string{"injected loss ended the stream with the explicit closed code loss"}, lossDetail)
	default:
		res.Loss = qual.Unqualified("loss_not_provoked: the stalled-reader injection produced no loss event or loss code", lossDetail)
	}

	// FDs
	fdDetail := map[string]any{}
	var fdFail []string
	for _, n := range []string{"fd_limit_40", "fd_limit_64", "fd_limit_128"} {
		r := a.injections[n]
		if r == nil {
			fdFail = append(fdFail, n+" not run")
			continue
		}
		limit := map[string]uint64{"fd_limit_40": 40, "fd_limit_64": 64, "fd_limit_128": 128}[n]
		ok, outcome := explicitInjection(r, func(r *scenResult) (bool, string) {
			if uint64(r.HelperPeak.FDs) > limit {
				return false, fmt.Sprintf("peak FDs %d exceed RLIMIT_NOFILE %d", r.HelperPeak.FDs, limit)
			}
			return true, ""
		})
		s := r.summary()
		s["outcome"] = outcome
		s["rlimit_nofile_in_helper_child"] = limit
		fdDetail[n] = s
		if !ok {
			fdFail = append(fdFail, n+": "+outcome)
		}
	}
	norm := []string{"cpu", "nofp", "contend", "migrate", "exec", "blocking"}
	allReleased := true
	for _, n := range norm {
		if r := a.results[n]; r != nil && r.Cap.Ready && (r.HelperFDsAfter != r.HelperBefore.FDs || r.HelperPerfAfter != 0) {
			allReleased = false
			fdFail = append(fdFail, fmt.Sprintf("%s: helper FDs %d -> %d, perf FDs %d after the capture", n, r.HelperBefore.FDs, r.HelperFDsAfter, r.HelperPerfAfter))
		}
	}
	fdDetail["all_scenarios_helper_fds_returned_to_baseline"] = allReleased
	if cpu != nil {
		fdDetail["cpu_scenario_helper_fds_before"], fdDetail["cpu_scenario_helper_fds_peak"], fdDetail["cpu_scenario_helper_fds_after"] = cpu.HelperBefore.FDs, cpu.HelperPeak.FDs, cpu.HelperFDsAfter
	}
	if len(fdFail) == 0 {
		res.FDs = qual.Supported([]string{"helper FDs and perf FDs returned to their pre-capture count after every capture", "RLIMIT_NOFILE injection in the helper child produced explicit closed-code refusals or in-limit sessions"}, fdDetail)
	} else {
		res.FDs = qual.Failed(strings.Join(fdFail, "; "), fdDetail)
	}

	// memory
	memDetail := map[string]any{}
	var memFail []string
	if cpu != nil && cpu.Cap.Ready {
		cfg := nativeperf.DefaultConfig(1)
		rings := uint64(cpu.Threads) * (cfg.RingBytes + 4096)
		total := cpu.HelperPeak.HWMKiB<<10 + cpu.ClientHWMKiB<<10 + rings
		memDetail["measured"] = map[string]any{"helper_hwm_kib": cpu.HelperPeak.HWMKiB, "client_hwm_kib": cpu.ClientHWMKiB, "ring_bytes_accounted": rings, "combined_conservative_bytes": total, "budget_bytes": nativeperf.MaxMemoryBytes}
		if total > nativeperf.MaxMemoryBytes {
			memFail = append(memFail, fmt.Sprintf("combined helper+client+ring memory %d bytes exceeds the %d byte budget", total, nativeperf.MaxMemoryBytes))
		}
	} else {
		memFail = append(memFail, "no successful CPU capture to measure")
	}
	for _, n := range []string{"memory_budget_1MiB", "memory_budget_8MiB"} {
		r := a.injections[n]
		if r == nil {
			memFail = append(memFail, n+" not run")
			continue
		}
		budget := map[string]uint64{"memory_budget_1MiB": 1 << 20, "memory_budget_8MiB": 8 << 20}[n]
		ok, outcome := explicitInjection(r, func(r *scenResult) (bool, string) {
			used := r.HelperPeak.HWMKiB<<10 + r.ClientHWMKiB<<10
			if used > budget {
				return false, fmt.Sprintf("helper+client RSS %d exceeds the %d byte budget it was admitted under", used, budget)
			}
			return true, ""
		})
		s := r.summary()
		s["outcome"], s["configured_max_memory_bytes"] = outcome, budget
		memDetail[n] = s
		if !ok {
			memFail = append(memFail, n+": "+outcome)
		}
	}
	if len(memFail) == 0 {
		res.Memory = qual.Supported([]string{"measured combined helper+client+ring memory within 64 MiB during the CPU capture", "tiny MaxMemory budgets in the signed request were refused with resource_limit or honored"}, memDetail)
	} else {
		res.Memory = qual.Failed(strings.Join(memFail, "; "), memDetail)
	}
}

func (a *accept) derivePrivacy(res *qual.QualificationResult) {
	frames, bytesSeen, hits := 0, 0, 0
	for _, set := range []map[string]*scenResult{a.results, a.injections} {
		for _, r := range set {
			frames += r.Cap.Frames
			bytesSeen += r.Cap.Bytes
			hits += r.Cap.NeedleHits
		}
	}
	frames += a.rtFrames
	hits += a.rtHits
	detail := map[string]any{
		"scope":                 "CPU acquisition socket frames (helper -> client). The scheduler path and export/storage/read are NOT covered here (see not_run and the 04.08 report).",
		"socket_frames_scanned": frames, "socket_bytes_scanned": bytesSeen, "canary_hits": hits,
		"needles": []string{"nonce (argv, environment, stack local)", "main<nonce> and work<nonce> thread names"},
		"positive_control_canary_in_workload_thread_name": a.canaryInComm, "positive_control_canary_in_workload_argv": a.canaryInArgv,
	}
	switch {
	case hits > 0:
		res.Privacy = qual.Failed(fmt.Sprintf("canary found in %d socket frames", hits), detail)
	case frames == 0 || !a.canaryInComm || !a.canaryInArgv:
		res.Privacy = qual.Failed("privacy audit not vacuous: no frames scanned or the canary was not present in the workload", detail)
	default:
		res.Privacy = qual.Supported([]string{fmt.Sprintf("%d helper socket frames (%d bytes) contained none of the per-run canaries, which were present in the workload's thread names and argv", frames, bytesSeen)}, detail)
	}
}
