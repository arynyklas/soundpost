// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// initialPIDNamespaceInode is the inode of the initial PID namespace; raw
// scheduler tracepoints carry init-namespace PIDs, so a nested namespace cannot
// attribute them (04.09 finding).
const initialPIDNamespaceInode = 0xEFFFFFFC

// kernelSeries maps "6.6.87.2-microsoft-standard-WSL2" to "6.6".
func kernelSeries(release string) string {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// nativeGate decides whether this host may exercise a native row. Required
// rows need a genuine Linux runner of that kernel series and architecture;
// the WSL2 functional rows (family wsl2-linux-kernel) need a WSL2 host. A row
// never falls back to another architecture or kernel series.
func (rc *runCtx) nativeGate(spec RowSpec) (*Build, string) {
	sub := rc.subject(spec)
	h := rc.host
	functional := sub.Family == "wsl2-linux-kernel"
	switch {
	case h.OS != "linux":
		return nil, fmt.Sprintf("host is %s: native Linux capture cannot run here", h.OS)
	case sub.Arch != h.Arch:
		return nil, fmt.Sprintf("no %s runner or build on this host (it is %s): one architecture's result is never extrapolated to another", sub.Arch, h.Arch)
	case kernelSeries(h.Kernel) != sub.Version:
		return nil, fmt.Sprintf("this host runs kernel %s (series %s); there is no Linux %s runner here", h.Kernel, kernelSeries(h.Kernel), sub.Version)
	case !functional && h.Class == "wsl2":
		return nil, fmt.Sprintf("this host is WSL2 on Windows (kernel %s); design section 13 says Windows/WSL does not implicitly qualify a Linux %s %s row, so the capability is measured only as functional evidence under the wsl2-linux-kernel rows", h.Kernel, sub.Version, sub.Arch)
	case functional && h.Class != "wsl2":
		return nil, "functional WSL2 evidence is only produced on a WSL2 host; a genuine Linux runner fills the required rows instead"
	}
	return &Build{Family: sub.Family, Version: h.Kernel, OS: "linux", Arch: h.Arch, ID: "kernel-release:" + h.Kernel, Host: h.Class}, ""
}

// schedulerBlocker states why scheduler (off-CPU/runqueue) capture is not
// attributable on this host, from the namespace itself rather than from a log.
func schedulerBlocker() string {
	if link, err := os.Readlink("/proc/self/ns/pid"); err == nil {
		var inode uint64
		if _, err := fmt.Sscanf(link, "pid:[%d]", &inode); err == nil && inode != initialPIDNamespaceInode {
			return fmt.Sprintf("scheduler_pid_namespace_not_initial (pid namespace inode %d is not the initial namespace: raw sched_switch/sched_wakeup PIDs are init-namespace PIDs and no authorized TID can match)", inode)
		}
	}
	return ""
}

func (rc *runCtx) goBin() (string, string) {
	if p := os.Getenv("SOUNDPOST_GO"); p != "" {
		return p, ""
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p, ""
	}
	return "", "no Go toolchain on PATH (set SOUNDPOST_GO) to build the committed nativeperf harnesses"
}

// goBuild builds one committed harness command into the work directory.
func (rc *runCtx) goBuild(name, pkg string) (string, string) {
	key := "tool:" + name
	if v, ok := rc.cache[key]; ok {
		r := v.([2]string)
		return r[0], r[1]
	}
	out, why := filepath.Join(rc.work, name), ""
	if gobin, w := rc.goBin(); w != "" {
		why = w
	} else if res := rc.exec(15*time.Minute, rc.root, nil, gobin, "build", "-o", out, pkg); res.Exit != 0 {
		why, out = "building "+pkg+" failed: "+tail(rc.rel(res.Stderr), 300), ""
	}
	rc.cache[key] = [2]string{out, why}
	return out, why
}

// ccBuild compiles one committed C workload exactly as its harness documents.
func (rc *runCtx) ccBuild(name, src string) (string, string) {
	key := "cc:" + name
	if v, ok := rc.cache[key]; ok {
		r := v.([2]string)
		return r[0], r[1]
	}
	out, why := filepath.Join(rc.work, name), ""
	cc, err := exec.LookPath("cc")
	if err != nil {
		why = "no C compiler on PATH to build the committed workload " + src
	} else if res := rc.exec(5*time.Minute, rc.root, nil, cc, "-O2", "-pthread", "-fno-omit-frame-pointer", "-g", "-o", out, src); res.Exit != 0 {
		why, out = "compiling "+src+" failed: "+tail(rc.rel(res.Stderr), 300), ""
	}
	_ = os.Chmod(out, 0o755)
	rc.cache[key] = [2]string{out, why}
	return out, why
}

type nativeRun struct {
	Result  *qual.QualificationResult
	Exit    int
	Command string
	Elapsed time.Duration
	Why     string // the run could not be attempted
	Failure string // the run was attempted and produced no usable result
	Raw     []byte
}

// acceptance runs the committed 04.09 acceptance runner once per RunSuite.
func (rc *runCtx) acceptance() *nativeRun {
	if v, ok := rc.cache["acceptance"]; ok {
		return v.(*nativeRun)
	}
	run := &nativeRun{}
	rc.cache["acceptance"] = run
	workloads, why := rc.ccBuild("workloads", "fixtures/nativeperf/acceptance/workloads.c")
	if why != "" {
		run.Why = why
		return run
	}
	bin, why := rc.goBuild("acceptance", "./fixtures/nativeperf/acceptance")
	if why != "" {
		run.Why = why
		return run
	}
	outPath := filepath.Join(rc.reportDir, "evidence", "native-acceptance.json")
	args := []string{"--manifest", "fixtures/nativeperf/qualification.json", "--workload", workloads, "--duration", rc.workloads.NativeAcceptance.Duration,
		"--seed", strconv.FormatInt(rc.workloads.NativeAcceptance.Seed, 10), "--out", outPath}
	res := rc.exec(40*time.Minute, rc.root, nil, bin, args...)
	run.Exit, run.Elapsed = res.Exit, res.Duration
	run.Command = fmt.Sprintf("acceptance --manifest fixtures/nativeperf/qualification.json --workload <built workloads> --duration %s --seed %d", rc.workloads.NativeAcceptance.Duration, rc.workloads.NativeAcceptance.Seed)
	raw, err := os.ReadFile(outPath)
	var r qual.QualificationResult
	if err != nil || json.Unmarshal(raw, &r) != nil {
		run.Failure = fmt.Sprintf("acceptance exited %d without a readable machine report: %s", res.Exit, tail(rc.rel(res.Stderr), 240))
		return run
	}
	run.Result, run.Raw = &r, raw
	return run
}

// flattenNumbers records every numeric leaf below v as a one-point series (a
// numeric list becomes one series). Strings and everything else are dropped:
// only numbers leave the harness result.
func flattenNumbers(prefix string, v any, out *[]Series, depth int) {
	const maxSeries = 160
	if len(*out) >= maxSeries || depth > 4 {
		return
	}
	switch t := v.(type) {
	case float64:
		*out = append(*out, Series{Name: prefix, Unit: "value", Values: []float64{t}})
	case []any:
		var nums []float64
		for _, e := range t {
			if f, ok := e.(float64); ok {
				nums = append(nums, f)
			}
		}
		if len(nums) > 0 && len(nums) == len(t) {
			*out = append(*out, Series{Name: prefix, Unit: "value", Values: nums})
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			flattenNumbers(name, t[k], out, depth+1)
		}
	}
}

// mapQualRow converts one 04.09 row into a matrix row. Supported is the only
// state that becomes exercised/passed; denied stays denied, an unqualified or
// not-run row stays not_exercised with the harness' own reason, and a failed
// or errored attempt is a measured failure.
func (rc *runCtx) mapQualRow(run *nativeRun, name string, qr qual.Row, build *Build) Row {
	row := Row{Build: build, Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}}
	r := run.Result
	if r.KernelConfig.SHA256 != "" {
		b := *build
		b.ID = "kernel-config-sha256:" + r.KernelConfig.SHA256 + ";workload-build:" + r.TargetBuild.BuildID
		row.Build = &b
	}
	raw, _ := json.Marshal(qr.Detail)
	var detail any
	_ = json.Unmarshal(raw, &detail)
	switch qr.State {
	case qual.StateSupported:
		row.State, row.Outcome = StateExercised, OutcomePassed
		row.Evidence = append(append([]string(nil), qr.Evidence...), "machine report evidence/native-acceptance.json row "+name)
	case qual.StateFailed, qual.StateError:
		row.State, row.Outcome = StateExercised, OutcomeFailed
		row.Failures = []string{qr.Reason}
		row.Evidence = []string{"machine report evidence/native-acceptance.json row " + name}
	case qual.StateDenied:
		row.State, row.Reason = StateDenied, qr.Reason
		row.Evidence = []string{"machine report evidence/native-acceptance.json row " + name}
		row.Readings = []Reading{{Name: name, Availability: AvailDenied, Reason: qr.Reason}}
		row.Command = nil
		row.Build = build
		return row
	default:
		reason := qr.Reason
		if reason == "" {
			reason = string(qr.State)
		}
		return notExercised(reason)
	}
	flattenNumbers("", detail, &row.Series, 0)
	if name == "cpu" {
		req := 1e6 / 99
		row.Interval = &IntervalReport{RequestedUS: &req, Note: "requested 99 Hz (fixed engine rate); the observed per-thread interval is measured by the overhead suite"}
	}
	if name == "loss" || name == "cpu" {
		row.Loss = strings.Join(qr.Evidence, "; ")
	}
	row.Limits = []string{fmt.Sprintf("acceptance --duration %s (reduced against the 60 s documented smoke)", rc.workloads.NativeAcceptance.Duration), "frame-pointer-less builds are partial by design (recorded in frame_coverage)"}
	return row
}

// runNativeCapability maps one required 04.09 row (cpu, off_cpu, runqueue_split,
// frame_coverage, loss, memory, fds, privacy, overhead) or one runtime-column
// row to the matrix, after the host gate.
func runNativeCapability(rc *runCtx, spec RowSpec) Row {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return notExercised(why)
	}
	run := rc.acceptance()
	if run.Why != "" {
		return notExercised(run.Why)
	}
	if run.Result == nil {
		return Row{State: StateExercised, Outcome: OutcomeFailed, Build: build, Failures: []string{run.Failure}, Evidence: []string{"acceptance attempt"},
			Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}}
	}
	capability := spec.Params["capability"]
	if problems := qual.ReleaseProblems(run.Result); len(problems) > 0 && run.Exit == qual.ExitContaminated {
		return Row{State: StateExercised, Outcome: OutcomeFailed, Build: build, Failures: []string{"acceptance report unusable: " + strings.Join(problems, "; ")},
			Evidence: []string{"machine report evidence/native-acceptance.json"}, Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}}
	}
	switch {
	case strings.HasPrefix(capability, "permission:"):
		return rc.permissionRow(run, strings.TrimPrefix(capability, "permission:"), build)
	case strings.HasPrefix(capability, "runtime:"):
		parts := strings.Split(capability, ":")
		if len(parts) != 3 {
			return notExercised("malformed runtime capability " + capability)
		}
		for _, col := range run.Result.Runtimes {
			if col.Runtime == parts[1] {
				qr := map[string]qual.Row{"engine_samples": col.Engine, "native_cpu": col.Native, "wait_row": col.Wait}[parts[2]]
				return rc.mapQualRow(run, capability, qr, build)
			}
		}
		return notExercised("the acceptance report has no " + parts[1] + " runtime column")
	}
	qr, ok := run.Result.Rows()[capability]
	if !ok {
		return notExercised("unknown native capability " + capability)
	}
	return rc.mapQualRow(run, capability, *qr, build)
}

// permissionRow keeps a permission denial a distinct result: a helper without
// capabilities refused with permission_denied is a denied row, never a pass
// and never a failure of the capability itself.
func (rc *runCtx) permissionRow(run *nativeRun, name string, build *Build) Row {
	for _, c := range run.Result.Permissions.Cases {
		if c.Name != name {
			continue
		}
		row := Row{Build: build, Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()},
			Evidence: []string{fmt.Sprintf("helper %q against target %q: outcome %q code %q, resources released=%v", c.Helper, c.Target, c.Outcome, c.ErrorCode, c.FDsReleased)}}
		switch {
		case c.ErrorCode == "permission_denied":
			row.State, row.Reason = StateDenied, "the unprivileged helper was refused with the closed code permission_denied (distinct from unsupported, never promoted to a pass)"
			row.Readings = []Reading{{Name: "cpu_samples", Unit: "samples", Availability: AvailDenied, Reason: "permission_denied"}}
			row.Command = nil
		case c.Samples > 0 && c.FDsReleased:
			row.State, row.Outcome = StateExercised, OutcomePassed
			row.Series = []Series{{Name: "cpu_samples", Unit: "samples", Values: []float64{float64(c.Samples)}}}
		default:
			row.State, row.Outcome = StateExercised, OutcomeFailed
			row.Failures = []string{fmt.Sprintf("permission case %s: outcome %q code %q samples %d released=%v", c.Name, c.Outcome, c.ErrorCode, c.Samples, c.FDsReleased)}
		}
		return row
	}
	return notExercised("the acceptance report has no permission case " + name)
}

// runNativeControls proves, in this process, that the capture-authenticity
// check rejects every staged, empty, synthetic and no-op sampler and still
// accepts a genuine-looking capture (04.09 qual.CheckCapture). A runner whose
// control is accepted cannot be trusted, so the row fails.
func runNativeControls(rc *runCtx, spec RowSpec) Row {
	return rc.nativeControlsRow(qual.RunNegativeControls())
}

// nativeControlsRow judges the controls: each must have behaved as required and
// every required control must be present.
func (rc *runCtx) nativeControlsRow(controls []qual.NegativeControl) Row {
	row := Row{State: StateExercised, Outcome: OutcomePassed,
		Build:   &Build{Family: "go", Version: strings.TrimPrefix(rc.host.GoBuild, "go"), OS: rc.host.OS, Arch: rc.host.Arch, ID: "toolchain:" + rc.host.GoBuild, Host: rc.host.Class},
		Command: &CommandRun{Command: "qual.RunNegativeControls() + qual.RequiredNegativeControls"}}
	rejected := 0.0
	seen := map[string]bool{}
	for _, c := range controls {
		seen[c.Name] = true
		if c.Behaved {
			rejected++
			row.Evidence = append(row.Evidence, fmt.Sprintf("control %s behaved: %s", c.Name, c.Reason))
		} else {
			row.Outcome = OutcomeFailed
			row.Failures = append(row.Failures, fmt.Sprintf("control %s did not behave (rejected=%v): %s", c.Name, c.Rejected, c.Reason))
		}
	}
	for _, need := range qual.RequiredNegativeControls {
		if !seen[need] {
			row.Outcome = OutcomeFailed
			row.Failures = append(row.Failures, "required control missing: "+need)
		}
	}
	row.Series = []Series{{Name: "controls_behaved", Unit: "count", Values: []float64{rejected}}, {Name: "controls_total", Unit: "count", Values: []float64{float64(len(qual.RequiredNegativeControls))}}}
	row.Limits = []string{"in-process contaminated captures; the real native rows additionally run the same controls inside the acceptance runner before the real path"}
	return row
}

// ---- native overhead (04.09 overhead runner) ----

type nativeOverheadRunRow struct {
	Mode         string  `json:"mode"`
	CPUNsPerIter float64 `json:"target_cpu_ns_per_iteration"`
	Throughput   float64 `json:"throughput_per_second"`
	Samples      int     `json:"samples"`
	AchievedHz   float64 `json:"achieved_hz_per_thread"`
	LossEvents   int     `json:"loss_events"`
	LostRecords  uint64  `json:"lost_records"`
	GapP50Ms     float64 `json:"sample_gap_p50_ms"`
	GapP99Ms     float64 `json:"sample_gap_p99_ms"`
	HelperHWMKiB uint64  `json:"helper_hwm_kib"`
	ClientHWMKiB uint64  `json:"client_hwm_kib"`
	RingBytes    uint64  `json:"ring_bytes_accounted"`
	FDsPeak      int     `json:"helper_fds_peak"`
}

type nativeOverheadFixture struct {
	Fixture     string                 `json:"fixture"`
	Seconds     float64                `json:"seconds_per_run"`
	Repeats     int                    `json:"repeats"`
	Reduced     bool                   `json:"reduced"`
	Runs        []nativeOverheadRunRow `json:"runs"`
	HarnessPct  float64                `json:"workload_cpu_overhead_percent"`
	CollectorPc float64                `json:"collector_cpu_percent_of_one_core"`
	MemoryBytes float64                `json:"combined_conservative_memory_bytes_max"`
	Failures    []string               `json:"failures"`
}

type nativeOverheadReport struct {
	KernelBuild string                  `json:"kernel_build"`
	Arch        string                  `json:"arch"`
	Hz          int                     `json:"hz_requested"`
	FullCommand string                  `json:"full_command"`
	FullRun     bool                    `json:"full_run_executed"`
	Reduction   string                  `json:"reduction"`
	Fixtures    []nativeOverheadFixture `json:"fixtures"`
	Caveats     []string                `json:"caveats"`
}

type nativeOverheadRun struct {
	Report  *nativeOverheadReport
	Raw     []byte
	Exit    int
	Command string
	Elapsed time.Duration
	Why     string
	Failure string
}

func (rc *runCtx) nativeOverhead() *nativeOverheadRun {
	if v, ok := rc.cache["native-overhead"]; ok {
		return v.(*nativeOverheadRun)
	}
	run := &nativeOverheadRun{}
	rc.cache["native-overhead"] = run
	workloads, why := rc.ccBuild("workloads", "fixtures/nativeperf/acceptance/workloads.c")
	if why != "" {
		run.Why = why
		return run
	}
	bin, why := rc.goBuild("overhead", "./fixtures/nativeperf/overhead")
	if why != "" {
		run.Why = why
		return run
	}
	w := rc.workloads.NativeOverhead
	outPath := filepath.Join(rc.reportDir, "evidence", "native-overhead.json")
	args := []string{"--manifest", "fixtures/nativeperf/qualification.json", "--hz", strconv.Itoa(w.Hz), "--seconds", strconv.Itoa(w.Seconds),
		"--repeats", strconv.Itoa(w.Repeats), "--workload", workloads, "--fixtures", w.Fixtures, "--out", outPath}
	res := rc.exec(time.Duration(w.Seconds*w.Repeats*2+600)*time.Second, rc.root, nil, bin, args...)
	run.Exit, run.Elapsed = res.Exit, res.Duration
	run.Command = fmt.Sprintf("overhead --hz %d --seconds %d --repeats %d --fixtures %s", w.Hz, w.Seconds, w.Repeats, w.Fixtures)
	raw, err := os.ReadFile(outPath)
	var rep nativeOverheadReport
	if err != nil || json.Unmarshal(raw, &rep) != nil || len(rep.Fixtures) == 0 {
		run.Failure = fmt.Sprintf("overhead runner exited %d without a readable report: %s", res.Exit, tail(rc.rel(res.Stderr), 240))
		return run
	}
	run.Report, run.Raw = &rep, raw
	return run
}

func column(runs []nativeOverheadRunRow, mode string, pick func(nativeOverheadRunRow) float64) []float64 {
	var out []float64
	for _, r := range runs {
		if r.Mode == mode {
			out = append(out, pick(r))
		}
	}
	return out
}

// runOverheadNative evaluates the native CPU loop capture against the <=3 % per
// target workload and 64 MiB budgets from the raw per-run numbers of a real
// (reduced) run of the committed overhead runner; or states why not.
func runOverheadNative(rc *runCtx, spec RowSpec) Row {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return notExercised(why)
	}
	switch spec.Params["capability"] {
	case "blocked_runqueue":
		reason := "no committed overhead harness drives the timed block/runqueue workload with off-CPU tracking (the overhead runner has only the cpu and fanout modes)"
		if s := schedulerBlocker(); s != "" {
			reason += "; scheduler capture is additionally unavailable on this host: " + s
		}
		return notExercised(reason)
	case "cpu_loop":
	default:
		return notExercised("unknown overhead capability " + spec.Params["capability"])
	}
	run := rc.nativeOverhead()
	if run.Why != "" {
		return notExercised(run.Why)
	}
	cmd := &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}
	if run.Report == nil {
		return Row{State: StateExercised, Outcome: OutcomeFailed, Build: build, Command: cmd, Failures: []string{run.Failure}, Evidence: []string{"overhead attempt"}}
	}
	fx := run.Report.Fixtures[0]
	base := column(fx.Runs, "baseline", func(r nativeOverheadRunRow) float64 { return r.CPUNsPerIter })
	capt := column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.CPUNsPerIter })
	row := Row{State: StateExercised, Build: build, Command: cmd, Evidence: []string{"machine report evidence/native-overhead.json", fmt.Sprintf("fixture %s: %d alternating baseline/capture pairs of %.0f s each", fx.Fixture, fx.Repeats, fx.Seconds)}}
	if len(base) == 0 || len(capt) == 0 {
		row.Outcome, row.Failures = OutcomeFailed, []string{"the overhead report carries no baseline/capture runs"}
		return row
	}
	row.Series = []Series{
		{Name: "target_cpu_per_iteration", Unit: "ns", Mode: "baseline", Values: base},
		{Name: "target_cpu_per_iteration", Unit: "ns", Mode: "capture", Values: capt},
		{Name: "throughput", Unit: "iterations/s", Mode: "baseline", Values: column(fx.Runs, "baseline", func(r nativeOverheadRunRow) float64 { return r.Throughput })},
		{Name: "throughput", Unit: "iterations/s", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.Throughput })},
		{Name: "samples", Unit: "count", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.Samples) })},
		{Name: "achieved_rate_per_thread", Unit: "Hz", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.AchievedHz })},
		{Name: "sample_gap_p50", Unit: "ms", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.GapP50Ms })},
		{Name: "sample_gap_p99", Unit: "ms", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.GapP99Ms })},
		{Name: "loss_events", Unit: "count", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.LossEvents) })},
		{Name: "lost_records", Unit: "count", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.LostRecords) })},
		{Name: "helper_rss_high_water", Unit: "KiB", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.HelperHWMKiB) })},
		{Name: "client_rss_high_water", Unit: "KiB", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.ClientHWMKiB) })},
		{Name: "helper_fds_peak", Unit: "count", Mode: "capture", Values: column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.FDsPeak) })},
	}
	kept := row.Series[:0]
	for _, s := range row.Series {
		if len(s.Values) > 0 {
			kept = append(kept, s)
		}
	}
	row.Series = kept
	pct := percentIncrease(mean(base), mean(capt))
	if math.IsNaN(pct) {
		row.Outcome, row.Failures = OutcomeFailed, []string{"baseline CPU per iteration is zero: the ratio is not measurable"}
		return row
	}
	row.Budgets = []BudgetResult{
		rc.budget("native_cpu_overhead_percent", pct, "mean target CPU ns/iteration, capture vs baseline, recomputed from the raw runs"),
		rc.budget("native_memory_bytes", fx.MemoryBytes, "max combined helper + client + ring accounting over the capture runs"),
	}
	req := 1e6 / float64(run.Report.Hz)
	var gaps []float64
	for _, hz := range column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return r.AchievedHz }) {
		if hz > 0 {
			gaps = append(gaps, 1e6/hz)
		}
	}
	row.Interval = &IntervalReport{RequestedUS: &req, Note: "requested 99 Hz; observed = mean of 1e6 / achieved Hz per thread"}
	if len(gaps) > 0 {
		obs := mean(gaps)
		row.Interval.ObservedUS = &obs
	}
	lossRuns := column(fx.Runs, "capture", func(r nativeOverheadRunRow) float64 { return float64(r.LossEvents) })
	row.Loss = fmt.Sprintf("loss events per capture run: %v; coverage: CPU capture of the profiled loop only (scheduler off-CPU is not part of this run)", lossRuns)
	row.Outcome = OutcomePassed
	for _, b := range row.Budgets {
		if !b.Within {
			row.Outcome = OutcomeFailed
		}
	}
	if len(fx.Failures) > 0 {
		row.Outcome = OutcomeFailed
		row.Failures = append(row.Failures, fx.Failures...)
	}
	row.Limits = []string{
		fmt.Sprintf("REDUCED real run: %d s x %d pairs, cpu fixture only; the full command was NOT run: %s", int(fx.Seconds), fx.Repeats, run.Report.FullCommand),
		"collector CPU (" + strconv.FormatFloat(fx.CollectorPc, 'f', 2, 64) + " % of one core) is reported by the runner but is not part of the per-target <=3 % budget",
		"the fanout fixture and the timed block/runqueue workload with off-CPU tracking were not run",
		fmt.Sprintf("harness' own overhead figure %.2f %% (recomputed above from the raw runs)", fx.HarnessPct),
	}
	return row
}

// ccBuildFlags compiles one committed C fixture with the flags its own task
// documented (04.06: identity fixtures).
func (rc *runCtx) ccBuildFlags(name, src string, flags ...string) (string, string) {
	key := "cc:" + name
	if v, ok := rc.cache[key]; ok {
		r := v.([2]string)
		return r[0], r[1]
	}
	out, why := filepath.Join(rc.work, name), ""
	cc, err := exec.LookPath("cc")
	if err != nil {
		why = "no C compiler on PATH to build the committed fixture " + src
	} else if res := rc.exec(5*time.Minute, rc.root, nil, cc, append(append(flags, "-o", out), src)...); res.Exit != 0 {
		why, out = "compiling "+src+" failed: "+tail(rc.rel(res.Stderr), 300), ""
	}
	rc.cache[key] = [2]string{out, why}
	return out, why
}

// identityScenarios maps a native capability to its 04.06 identity smoke scenario.
var identityScenarios = map[string]string{
	"identity_exit": "exit", "identity_exec": "exec", "pid_reuse": "pid-reuse", "namespaces": "namespaces", "no_frame_pointers": "no-frame-pointers",
}

// runNativeIdentity runs one real identity scenario (exit, exec, PID reuse,
// namespaces, frame-pointer-less capture) of the committed 04.06 smoke.
func runNativeIdentity(rc *runCtx, spec RowSpec) Row {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return notExercised(why)
	}
	scenario, ok := identityScenarios[spec.Params["capability"]]
	if !ok {
		return notExercised("unknown identity capability " + spec.Params["capability"])
	}
	reuse, why := rc.ccBuildFlags("identity-reuse", "fixtures/nativeperf/identity/reuse.c", "-O2", "-g", "-pthread", "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls", "-Wl,--build-id")
	if why != "" {
		return notExercised(why)
	}
	noFP, why := rc.ccBuildFlags("identity-reuse-no-fp", "fixtures/nativeperf/identity/reuse.c", "-O2", "-g", "-pthread", "-fomit-frame-pointer", "-fno-optimize-sibling-calls", "-Wl,--build-id")
	if why != "" {
		return notExercised(why)
	}
	execBin, why := rc.ccBuildFlags("identity-exec", "fixtures/nativeperf/identity/exec.c", "-O2", "-g", "-pthread", "-fno-omit-frame-pointer", "-Wl,--build-id")
	if why != "" {
		return notExercised(why)
	}
	smoke, why := rc.goBuild("identity-smoke", "./fixtures/nativeperf/identity/smoke")
	if why != "" {
		return notExercised(why)
	}
	res := rc.exec(10*time.Minute, rc.root, nil, smoke, "--scenario", scenario, "--workload", reuse, "--exec-workload", execBin, "--no-fp-workload", noFP)
	return rc.identityRow(build, scenario, res)
}

// pidReuseNotObserved is the smoke's closed code when the kernel never handed
// out a recycled PID within the attempt budget.
const pidReuseNotObserved = "actual_numeric_pid_reuse_not_observed_within_budget"

// identityRow turns one identity smoke run into a row. A PID-reuse scenario
// whose precondition never occurred was not exercised: it is neither a pass
// nor a failure of the product.
func (rc *runCtx) identityRow(build *Build, scenario string, res execResult) Row {
	if scenario == "pid-reuse" && res.Exit != 0 && strings.Contains(res.Stderr, pidReuseNotObserved) {
		return notExercised("real PID reuse was not observed within the smoke's allocation-attempt budget (it may not write pid_max or ns_last_pid), so the scenario's precondition never occurred; this is not a pass")
	}
	row := Row{State: StateExercised, Build: build, Command: &CommandRun{Command: "identity/smoke --scenario " + scenario, ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}}
	row.Evidence = []string{fmt.Sprintf("real %s scenario of fixtures/nativeperf/identity/smoke: exit %d", scenario, res.Exit)}
	if obj, raw := lastJSONObjectMultiline(res.Stdout); obj != nil {
		row.Evidence = append(row.Evidence, rc.writeEvidence("native-identity-"+scenario+".json", raw))
		flattenNumbers("", any(obj), &row.Series, 0)
	}
	if res.Exit == 0 && res.Err == nil {
		row.Outcome = OutcomePassed
	} else {
		row.Outcome = OutcomeFailed
		row.Failures = []string{fmt.Sprintf("identity scenario %s exited %d: %s", scenario, res.Exit, tail(rc.rel(res.Stderr), 240))}
	}
	row.Limits = []string{"PID reuse is a real allocation race within the smoke's attempt budget (no pid_max or ns_last_pid writes), not a forced collision"}
	return row
}

// nativeGaps are required native cases for which no harness exists or which
// cannot be exercised without changing the host.
var nativeGaps = map[string]string{
	"cpu_hotplug":     "no committed harness hot-unplugs a CPU under a live capture, and offlining a CPU means writing /sys/devices/system/cpu/*/online, a host configuration change this qualification must not make",
	"container_modes": "no container/cgroup-restricted or seccomp-restricted capture fixture exists (design 13 requires audited Compose/Kubernetes recipes and denied-permission rows); only the host-process helper is exercised",
}

// runNativeGap is a required native case with no harness: always not_exercised,
// with the gate reason first when the host could not run it anyway.
func runNativeGap(rc *runCtx, spec RowSpec) Row {
	gap, ok := nativeGaps[spec.Params["capability"]]
	if !ok {
		return notExercised("unknown native gap " + spec.Params["capability"])
	}
	if _, why := rc.nativeGate(spec); why != "" {
		return notExercised(gap + "; additionally: " + why)
	}
	return notExercised(gap)
}
