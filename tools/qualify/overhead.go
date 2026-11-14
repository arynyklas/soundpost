// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Budget is one limit of design section 13, loaded from workloads.yaml and never
// edited by the code that compares against it.
type Budget struct {
	Limit  float64 `yaml:"limit"`
	Unit   string  `yaml:"unit"`
	Source string  `yaml:"source"`
}

// Workloads is the decoded workloads.yaml.
type Workloads struct {
	Schema  string            `yaml:"schema"`
	Budgets map[string]Budget `yaml:"budgets"`

	SDKServer struct {
		RPS           int    `yaml:"requests_per_second"`
		DurationS     int    `yaml:"duration_s"`
		Runs          int    `yaml:"runs"`
		Only          string `yaml:"only"`
		HandlerHashes []int  `yaml:"handler_hashes"`
		FullCommand   string `yaml:"full_command"`
	} `yaml:"sdk_server"`

	NativeAcceptance struct {
		Duration string `yaml:"duration"`
		Seed     int64  `yaml:"seed"`
	} `yaml:"native_acceptance"`

	NativeOverhead struct {
		Hz          int    `yaml:"hz"`
		Seconds     int    `yaml:"seconds"`
		Repeats     int    `yaml:"repeats"`
		Fixtures    string `yaml:"fixtures"`
		FullCommand string `yaml:"full_command"`
	} `yaml:"native_overhead"`

	NativePrivacy struct {
		Seconds int `yaml:"seconds"`
	} `yaml:"native_privacy"`
}

// WorkloadsSchema is the schema identifier of workloads.yaml.
const WorkloadsSchema = "soundpost-qualification-workloads/1"

// RequiredBudgets are the design section 13 limits every workloads file must pin.
var RequiredBudgets = []string{
	"server_p95_latency_percent", "server_cpu_percent", "sdk_queue_bytes",
	"browser_core_gzip_bytes", "browser_replay_gzip_bytes", "browser_recorder_batch_p95_ms", "browser_recorder_queue_bytes",
	"native_cpu_overhead_percent", "native_memory_bytes",
}

// LoadWorkloads decodes workloads.yaml strictly.
func LoadWorkloads(path string) (Workloads, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Workloads{}, err
	}
	var w Workloads
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&w); err != nil {
		return Workloads{}, fmt.Errorf("workloads %s: %w", path, err)
	}
	if w.Schema != WorkloadsSchema {
		return Workloads{}, fmt.Errorf("workloads %s: schema %q, want %q", path, w.Schema, WorkloadsSchema)
	}
	for _, name := range RequiredBudgets {
		if b, ok := w.Budgets[name]; !ok || b.Limit <= 0 || b.Unit == "" || b.Source == "" {
			return Workloads{}, fmt.Errorf("workloads %s: budget %s missing or incomplete", path, name)
		}
	}
	if w.SDKServer.RPS <= 0 || w.SDKServer.DurationS <= 0 || w.SDKServer.Runs <= 1 || len(w.SDKServer.HandlerHashes) == 0 ||
		w.NativeAcceptance.Duration == "" || w.NativeOverhead.Hz <= 0 || w.NativeOverhead.Seconds <= 0 || w.NativeOverhead.Repeats <= 0 || w.NativePrivacy.Seconds <= 0 {
		return Workloads{}, fmt.Errorf("workloads %s: a workload parameter is missing", path)
	}
	return w, nil
}

// budget compares one observed number with its pinned limit. The verdict is
// computed here and re-derived by ValidateRow; nothing can adjust the limit.
func (rc *runCtx) budget(name string, observed float64, method string) BudgetResult {
	b := rc.workloads.Budgets[name]
	return BudgetResult{Name: name, Source: b.Source, Unit: b.Unit, Limit: b.Limit, Observed: round4(observed), Within: round4(observed) <= b.Limit, Method: method}
}

func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

func mean(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// percentIncrease is (with-without)/without in percent. A zero baseline has no
// ratio: NaN, which callers report as not measurable rather than as 0 %.
func percentIncrease(baseline, with float64) float64 {
	if baseline == 0 || math.IsNaN(baseline) || math.IsNaN(with) {
		return math.NaN()
	}
	return (with - baseline) / baseline * 100
}

type statBlock struct {
	Values []float64 `json:"values"`
}

type sdkHTTPRow struct {
	HandlerHashes int             `json:"handler_hashes"`
	P95           modePair        `json:"p95_latency_ms"`
	P99           modePair        `json:"p99_latency_ms"`
	CPU           modePair        `json:"process_cpu_us_per_request"`
	ELU           modePair        `json:"event_loop_active_us_per_request"`
	Achieved      modePair        `json:"achieved_rps"`
	Errors        json.RawMessage `json:"errors"`
	RPS           float64         `json:"requests_per_second_requested"`
	QueueFull     []float64       `json:"queue_full_drops"`
}

type modePair struct {
	Baseline statBlock `json:"baseline"`
	Capture  statBlock `json:"capture"`
}

type sdkQueueRow struct {
	Max     float64 `json:"max_queue_bytes"`
	Budget  float64 `json:"budget_bytes"`
	Dropped any     `json:"diagnostics"`
}

type sdkBundle struct {
	Raw  float64 `json:"raw_bytes"`
	Gzip float64 `json:"gzip_bytes"`
}

type sdkOverhead struct {
	RecordedAt   string `json:"recorded_at"`
	Command      string `json:"command"`
	MachineClass struct {
		Platform string  `json:"platform"`
		Arch     string  `json:"arch"`
		CPUs     float64 `json:"logical_cpus"`
		Noise    struct {
			CV float64 `json:"cv_percent"`
		} `json:"fixed_work_noise"`
		Node string `json:"node"`
	} `json:"machine_class"`
	Rows struct {
		// HTTP is the saturated mode (the server never flushes; spans are dropped once the queue is full). It is kept as
		// evidence only: the budget is judged on Delivered, the state a real application is in.
		HTTP      []sdkHTTPRow `json:"node_http_server_core_capture"`
		Delivered []sdkHTTPRow `json:"node_http_server_delivered_capture"`
		Acking    sdkQueueRow  `json:"node_queue_acking_transport"`
		Stalled   sdkQueueRow  `json:"node_queue_cap_stalled_transport"`
		Bundles   struct {
			Index   sdkBundle `json:"browser_index"`
			Replay  sdkBundle `json:"replay_only"`
			Profile sdkBundle `json:"profile_module"`
		} `json:"browser_bundle_sizes"`
	} `json:"rows"`
}

type sdkOverheadRun struct {
	Result  *sdkOverhead
	Raw     []byte
	Exit    int
	Command string
	Elapsed time.Duration
	Failure string
}

// sdkOverheadRun runs the committed overhead harness (03.09) once per build.
func (rc *runCtx) sdkOverhead(spec RowSpec) (*sdkOverheadRun, *probeResult, string) {
	p := rc.probe(spec.Build)
	if !p.Found {
		return nil, p, p.Reason
	}
	if why := rc.needsMissing(spec); why != "" {
		return nil, p, why
	}
	key := "sdk-overhead:" + spec.Build
	if v, ok := rc.cache[key]; ok {
		return v.(*sdkOverheadRun), p, ""
	}
	var env []string
	for _, need := range spec.Needs {
		if nb := rc.probe(need); nb.Build.Family == "bun" {
			env = append(env, "SOUNDPOST_BUN="+rc.nativePath(nb.Build.OS, nb.Path))
		}
	}
	w := rc.workloads.SDKServer
	args := []string{"fixtures/sdk/overhead.mjs", "--requests-per-second", strconv.Itoa(w.RPS), "--duration-s", strconv.Itoa(w.DurationS), "--runs", strconv.Itoa(w.Runs), "--only", w.Only}
	var hashes []string
	for _, h := range w.HandlerHashes {
		hashes = append(hashes, strconv.Itoa(h))
	}
	args = append(args, "--handler-hashes", strings.Join(hashes, ","))
	res := rc.exec(45*time.Minute, rc.root, env, p.Path, args...)
	run := &sdkOverheadRun{Exit: res.Exit, Command: "node " + strings.Join(args, " "), Elapsed: res.Duration}
	var out sdkOverhead
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	if err := dec.Decode(&out); err != nil || res.Exit != 0 {
		run.Failure = fmt.Sprintf("overhead harness exited %d without a usable result: %s", res.Exit, tail(rc.rel(res.Stderr), 240))
	} else {
		run.Result, run.Raw = &out, []byte(res.Stdout)
	}
	rc.cache[key] = run
	return run, p, ""
}

func floatsOf(v []float64) []float64 { return append([]float64(nil), v...) }

func (rc *runCtx) sdkRowBase(p *probeResult, run *sdkOverheadRun, evidenceName string) Row {
	row := Row{State: StateExercised, Build: &p.Build, Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}}
	if len(run.Raw) > 0 {
		row.Evidence = append(row.Evidence, rc.writeEvidence(evidenceName, run.Raw))
	}
	row.Evidence = append(row.Evidence, fmt.Sprintf("overhead harness fixtures/sdk/overhead.mjs: %d alternating runs per mode, %d s measured after 1 s warm-up, open-loop %d req/s from a separate load process",
		rc.workloads.SDKServer.Runs, rc.workloads.SDKServer.DurationS, rc.workloads.SDKServer.RPS))
	return row
}

// runOverheadSDKServer measures core capture on a deterministic HTTP handler
// with and without capture and compares p95 latency and process CPU per
// request against the <=5 % budgets.
func runOverheadSDKServer(rc *runCtx, spec RowSpec) Row {
	run, p, why := rc.sdkOverhead(spec)
	if why != "" {
		return notExercised(why)
	}
	row := rc.sdkRowBase(p, run, "sdk-overhead-"+spec.Build+".json")
	if run.Result == nil {
		row.Outcome, row.Failures = OutcomeFailed, []string{run.Failure}
		return row
	}
	want, _ := strconv.Atoi(spec.Params["handler_hashes"])
	var hr, saturated *sdkHTTPRow
	for i := range run.Result.Rows.Delivered {
		if run.Result.Rows.Delivered[i].HandlerHashes == want {
			hr = &run.Result.Rows.Delivered[i]
		}
	}
	for i := range run.Result.Rows.HTTP {
		if run.Result.Rows.HTTP[i].HandlerHashes == want {
			saturated = &run.Result.Rows.HTTP[i]
		}
	}
	if hr == nil {
		row.Outcome, row.Failures = OutcomeFailed, []string{fmt.Sprintf("the harness result has no delivered-mode handler_hashes=%d row", want)}
		return row
	}
	row.Series = []Series{
		{Name: "p95_latency", Unit: "ms", Mode: "baseline", Values: floatsOf(hr.P95.Baseline.Values)},
		{Name: "p95_latency", Unit: "ms", Mode: "capture", Values: floatsOf(hr.P95.Capture.Values)},
		{Name: "process_cpu_per_request", Unit: "us", Mode: "baseline", Values: floatsOf(hr.CPU.Baseline.Values)},
		{Name: "process_cpu_per_request", Unit: "us", Mode: "capture", Values: floatsOf(hr.CPU.Capture.Values)},
		{Name: "event_loop_active_per_request", Unit: "us", Mode: "baseline", Values: floatsOf(hr.ELU.Baseline.Values)},
		{Name: "event_loop_active_per_request", Unit: "us", Mode: "capture", Values: floatsOf(hr.ELU.Capture.Values)},
		{Name: "achieved_rps", Unit: "req/s", Mode: "baseline", Values: floatsOf(hr.Achieved.Baseline.Values)},
		{Name: "achieved_rps", Unit: "req/s", Mode: "capture", Values: floatsOf(hr.Achieved.Capture.Values)},
	}
	for i := len(row.Series) - 1; i >= 0; i-- {
		if len(row.Series[i].Values) == 0 {
			row.Series = append(row.Series[:i], row.Series[i+1:]...)
		}
	}
	if len(hr.P95.Baseline.Values) == 0 || len(hr.P95.Capture.Values) == 0 {
		row.Outcome, row.Failures = OutcomeFailed, []string{"the harness result carries no p95 series"}
		return row
	}
	reqUS := 1e6 / float64(rc.workloads.SDKServer.RPS)
	obsUS := 1e6 / mean(hr.Achieved.Capture.Values)
	row.Interval = &IntervalReport{RequestedUS: &reqUS, ObservedUS: &obsUS, Note: "request interval of the open-loop load (capture mode)"}
	method := "mean of the alternating runs; increase = (capture - baseline) / baseline"
	p95 := percentIncrease(mean(hr.P95.Baseline.Values), mean(hr.P95.Capture.Values))
	cpu := percentIncrease(mean(hr.CPU.Baseline.Values), mean(hr.CPU.Capture.Values))
	if math.IsNaN(p95) || math.IsNaN(cpu) {
		row.Outcome, row.Failures = OutcomeFailed, []string{"a baseline reads zero (clock too coarse): the ratio is not measurable, so no budget claim is made"}
		return row
	}
	row.Budgets = []BudgetResult{rc.budget("server_p95_latency_percent", p95, method), rc.budget("server_cpu_percent", cpu, method+"; process.cpuUsage")}
	row.Outcome = OutcomePassed
	for _, b := range row.Budgets {
		if !b.Within {
			row.Outcome = OutcomeFailed
		}
	}
	dropped := 0.0
	for _, n := range hr.QueueFull {
		dropped += n
	}
	if dropped > 0 {
		// A capture that keeps up only by dropping spans has not delivered its workload; its cost is not the claim.
		row.Outcome = OutcomeFailed
		row.Failures = append(row.Failures, fmt.Sprintf("delivered mode dropped %.0f records as queue_full: the exporter did not keep up", dropped))
	}
	row.Loss = fmt.Sprintf("load error counters (harness-reported): %s; delivered mode: flush() every 100 ms through an in-process ACKing receipt transport, queue_full drops per run %v", string(hr.Errors), hr.QueueFull)
	if saturated != nil {
		row.Evidence = append(row.Evidence, fmt.Sprintf("saturated mode (never flushed, spans dropped as queue_full once the queue fills), not judged: p95 %+.1f %%, process CPU %+.1f %%",
			percentIncrease(mean(saturated.P95.Baseline.Values), mean(saturated.P95.Capture.Values)), percentIncrease(mean(saturated.CPU.Baseline.Values), mean(saturated.CPU.Capture.Values))))
	}
	row.Limits = []string{
		fmt.Sprintf("handler = %d x sha256 over 1 KiB + 16-field JSON; loopback HTTP; no TLS or network export cost measured", want),
		fmt.Sprintf("host %s %s, %.0f logical CPUs, fixed-work noise CV %.0f %% on a shared workstation (other jobs ran concurrently); %s",
			run.Result.MachineClass.Platform, run.Result.MachineClass.Arch, run.Result.MachineClass.CPUs, run.Result.MachineClass.Noise.CV, separation(hr.P95, hr.CPU)),
		"event-loop active time is recorded as a separate high-resolution series without a budget",
		"full workload of design section 13 (representative 1k req/s handler) is approximated by a synthetic handler; " + rc.workloads.SDKServer.FullCommand,
	}
	if p.Build.OS == "windows" {
		row.Limits = append(row.Limits, "process CPU on Windows has a ~15.6 ms tick (coarse for short windows)")
	}
	return row
}

// runOverheadSDKQueue compares the SDK queue high-water mark (acking and
// stalled transports) with the 2 MiB default queue budget.
func runOverheadSDKQueue(rc *runCtx, spec RowSpec) Row {
	run, p, why := rc.sdkOverhead(spec)
	if why != "" {
		return notExercised(why)
	}
	row := rc.sdkRowBase(p, run, "sdk-overhead-"+spec.Build+".json")
	if run.Result == nil {
		row.Outcome, row.Failures = OutcomeFailed, []string{run.Failure}
		return row
	}
	q := run.Result.Rows
	row.Series = []Series{{Name: "max_queue_bytes", Unit: "bytes", Mode: "acking_transport", Values: []float64{q.Acking.Max}}, {Name: "max_queue_bytes", Unit: "bytes", Mode: "stalled_transport", Values: []float64{q.Stalled.Max}}}
	row.Budgets = []BudgetResult{
		rc.budget("sdk_queue_bytes", q.Acking.Max, "high-water mark with an ACKing transport"),
		rc.budget("sdk_queue_bytes", q.Stalled.Max, "high-water mark with a stalled transport (queue_full drops)"),
	}
	row.Budgets[0].Name, row.Budgets[1].Name = "sdk_queue_bytes_acking", "sdk_queue_bytes_stalled"
	row.Outcome = OutcomePassed
	for _, b := range row.Budgets {
		if !b.Within {
			row.Outcome = OutcomeFailed
		}
	}
	row.Loss = fmt.Sprintf("stalled-transport diagnostics: %v", q.Stalled.Dropped)
	row.Limits = []string{"the record-count cap binds before the byte cap, so the byte high-water mark is a lower bound of the cap"}
	return row
}

// runOverheadBundle compares gzip sizes of the browser entries with the 40 KiB
// (core) and 60 KiB (replay) budgets.
func runOverheadBundle(rc *runCtx, spec RowSpec) Row {
	run, p, why := rc.sdkOverhead(spec)
	if why != "" {
		return notExercised(why)
	}
	row := rc.sdkRowBase(p, run, "sdk-overhead-"+spec.Build+".json")
	if run.Result == nil {
		row.Outcome, row.Failures = OutcomeFailed, []string{run.Failure}
		return row
	}
	b := run.Result.Rows.Bundles
	row.Series = []Series{
		{Name: "browser_index_gzip", Unit: "bytes", Values: []float64{b.Index.Gzip}},
		{Name: "browser_index_raw", Unit: "bytes", Values: []float64{b.Index.Raw}},
		{Name: "replay_only_gzip", Unit: "bytes", Values: []float64{b.Replay.Gzip}},
		{Name: "replay_only_raw", Unit: "bytes", Values: []float64{b.Replay.Raw}},
	}
	row.Budgets = []BudgetResult{
		rc.budget("browser_core_gzip_bytes", b.Index.Gzip, "gzip -9 of the minified core entry @soundpost/browser (it imports neither the replay recorder nor the profiler)"),
		rc.budget("browser_replay_gzip_bytes", b.Replay.Gzip, "gzip -9 of the minified replay entry @soundpost/browser/replay (recorder, stream and client delivery)"),
	}
	row.Outcome = OutcomePassed
	for _, br := range row.Budgets {
		if !br.Within {
			row.Outcome = OutcomeFailed
		}
	}
	row.Limits = []string{"each budget is measured on its own published entry bundled alone; an application that imports several entries ships their sum"}
	return row
}

// separation says, from the raw series alone, whether capture and baseline runs
// overlap: when every capture run is above every baseline run the delta is not
// explained by run-to-run noise; when they overlap it is.
func separation(p95, cpu modePair) string {
	one := func(name string, m modePair) string {
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, v := range m.Capture.Values {
			lo = math.Min(lo, v)
		}
		for _, v := range m.Baseline.Values {
			hi = math.Max(hi, v)
		}
		if lo > hi {
			return fmt.Sprintf("%s: every capture run (min %.4g) is above every baseline run (max %.4g)", name, lo, hi)
		}
		return fmt.Sprintf("%s: capture runs (min %.4g) overlap baseline runs (max %.4g), so the delta is NOT separated from run-to-run noise", name, lo, hi)
	}
	return one("p95", p95) + "; " + one("cpu/request", cpu)
}
