//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command qualification is the task 04.09 release gate. It reads the
// qualification manifest, the machine reports written by the acceptance runner
// (QualificationResult) and the overhead runner, merges the measured overhead,
// and evaluates the required kernel/architecture matrix and every required row.
//
//	go run ./fixtures/nativeperf/qualification --manifest fixtures/nativeperf/qualification.json \
//	    --results acceptance.json,overhead.json --require-all
//
// Modes: the default (and --report-only) writes the combined machine report and
// exits 0 unless an input is invalid. --require-all is the gate: it lists every
// unqualified required row and exits ExitUnexercised (10) when required rows were
// not exercised, or ExitFail (1) when an exercised row failed or a report is
// invalid. It cannot pass vacuously: with no result at all every matrix row is
// unqualified. Node success never qualifies Bun, amd64 never qualifies arm64,
// and a source-only or functional-evidence row never qualifies an LTS row.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

type manifest struct {
	Rows               []qual.ManifestRow `json:"rows"`
	AdvertisedFixtures []string           `json:"advertised_fixtures"`
	RequiredRuntimes   []string           `json:"required_runtimes"`
	// RequiredScenarios are the operational scenarios (qual.QualificationResult.Scenarios) every qualifying result must
	// have exercised to a supported row; empty means none is required.
	RequiredScenarios []string `json:"required_scenarios"`
	// ReleasePlatforms lists the os/arch pairs the release contains (decision D10: linux/amd64). A matrix row of another
	// architecture is reported as out_of_release_scope with that decision as its reason, never as qualified, and is not a
	// required row; empty means every row is in scope.
	ReleasePlatforms []string `json:"release_platforms"`
}

type overheadFixture struct {
	Fixture        string   `json:"fixture"`
	Seconds        float64  `json:"seconds_per_run"`
	Repeats        int      `json:"repeats"`
	Reduced        bool     `json:"reduced"`
	OverheadPct    float64  `json:"workload_cpu_overhead_percent"`
	OverheadSEPct  float64  `json:"workload_cpu_overhead_stderr_percent"`
	ThroughputPct  float64  `json:"throughput_change_percent"`
	CollectorPct   float64  `json:"collector_cpu_percent_of_one_core"`
	MemoryBytes    uint64   `json:"combined_conservative_memory_bytes_max"`
	CPUBudgetOK    bool     `json:"cpu_overhead_budget_met"`
	MemoryBudgetOK bool     `json:"memory_budget_met"`
	Failures       []string `json:"failures"`
}

type overheadReport struct {
	KernelBuild     string            `json:"kernel_build"`
	Arch            string            `json:"arch"`
	HostID          string            `json:"host_id"`
	KernelConfigSHA string            `json:"kernel_config_sha256"`
	RunDigest       string            `json:"run_digest"`
	FullRun         bool              `json:"full_run_executed"`
	Command         string            `json:"command"`
	Fixtures        []overheadFixture `json:"fixtures"`
}

type matrixRow struct {
	KernelSeries string `json:"kernel_series"`
	Arch         string `json:"arch"`
	Qualified    bool   `json:"qualified"`
	Reason       string `json:"reason,omitempty"`
}

// outOfScopeReason is the reason an out-of-release row carries (decision D10).
const outOfScopeReason = "out_of_release_scope: decision D10 limits this release to linux/amd64; this row is not exercised and not claimed"

type combined struct {
	Manifest    string                      `json:"manifest"`
	Mode        string                      `json:"mode"`
	Results     []*qual.QualificationResult `json:"results"`
	Matrix      []matrixRow                 `json:"matrix"`
	Unqualified []string                    `json:"unqualified_required_rows"`
	OutOfScope  []matrixRow                 `json:"out_of_release_scope_rows,omitempty"`
	Problems    []string                    `json:"report_problems,omitempty"`
	ExitCode    int                         `json:"exit_code"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is main with injectable streams so the gate is testable.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qualification", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "fixtures/nativeperf/qualification.json", "qualification manifest")
	results := fs.String("results", "", "comma separated acceptance (QualificationResult) and overhead report files")
	requireAll := fs.Bool("require-all", false, "release gate: fail unless every required row on the full runner matrix is supported")
	reportOnly := fs.Bool("report-only", false, "write the machine report and exit 0 unless an input is invalid (default)")
	out := fs.String("out", "", "write the combined machine report here instead of stdout")
	if fs.Parse(args) != nil {
		return qual.ExitUsage
	}
	if fs.NArg() != 0 || *requireAll && *reportOnly {
		fmt.Fprintln(stderr, "usage: --require-all and --report-only are exclusive; no positional arguments")
		return qual.ExitUsage
	}
	var m manifest
	raw, err := os.ReadFile(*manifestPath)
	if err != nil || json.Unmarshal(raw, &m) != nil {
		fmt.Fprintln(stderr, "qualification: manifest unreadable or invalid")
		return qual.ExitUsage
	}
	if len(m.AdvertisedFixtures) == 0 {
		m.AdvertisedFixtures = []string{"cpu"}
	}
	if len(m.RequiredRuntimes) == 0 {
		m.RequiredRuntimes = []string{"python", "node", "bun"}
	}
	c := &combined{Manifest: *manifestPath, Mode: "report-only"}
	if *requireAll {
		c.Mode = "require-all"
	}
	var overheads []overheadReport
	for _, path := range strings.Split(*results, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			c.Problems = append(c.Problems, "unreadable result "+path)
			continue
		}
		var probe struct {
			Fixtures []json.RawMessage `json:"fixtures"`
			Verdict  string            `json:"verdict"`
			CPU      *json.RawMessage  `json:"cpu"`
		}
		if json.Unmarshal(data, &probe) != nil {
			c.Problems = append(c.Problems, "result is not JSON: "+path)
			continue
		}
		switch {
		case probe.CPU != nil:
			var r qual.QualificationResult
			if err := json.Unmarshal(data, &r); err != nil {
				c.Problems = append(c.Problems, "invalid acceptance result "+path)
				continue
			}
			c.Results = append(c.Results, &r)
		case probe.Fixtures != nil:
			var o overheadReport
			if err := json.Unmarshal(data, &o); err != nil {
				c.Problems = append(c.Problems, "invalid overhead report "+path)
				continue
			}
			overheads = append(overheads, o)
		default:
			c.Problems = append(c.Problems, "unrecognized result file "+path)
		}
	}
	for _, r := range c.Results {
		var reports []overheadReport
		for _, o := range overheads {
			if o.KernelBuild == r.KernelBuild && o.Arch == r.Arch {
				reports = append(reports, o)
			}
		}
		for _, problem := range mergeOverheads(r, reports, m.AdvertisedFixtures) {
			c.Problems = append(c.Problems, r.KernelBuild+"/"+r.Arch+": overhead report not bound to this result: "+problem)
		}
		for _, p := range qual.ReleaseProblems(r) {
			c.Problems = append(c.Problems, r.KernelBuild+"/"+r.Arch+": "+p)
		}
	}
	inScope := make([]qual.ManifestRow, 0, len(m.Rows))
	for _, row := range m.Rows {
		if len(m.ReleasePlatforms) > 0 && strings.HasSuffix(row.KernelSeries, "LTS") && !slices.Contains(m.ReleasePlatforms, "linux/"+row.Arch) {
			c.OutOfScope = append(c.OutOfScope, matrixRow{KernelSeries: row.KernelSeries, Arch: row.Arch, Reason: outOfScopeReason})
			continue
		}
		inScope = append(inScope, row)
	}
	missing := qual.MatrixVerdict(inScope, c.Results)
	missingSet := map[string]bool{}
	for _, line := range missing {
		missingSet[line] = true
	}
	for _, row := range inScope {
		if !strings.HasSuffix(row.KernelSeries, "LTS") {
			continue
		}
		prefix := fmt.Sprintf("kernel %s %s:", row.KernelSeries, row.Arch)
		mr := matrixRow{KernelSeries: row.KernelSeries, Arch: row.Arch, Qualified: true}
		for line := range missingSet {
			if strings.HasPrefix(line, prefix) {
				mr.Qualified, mr.Reason = false, strings.TrimPrefix(line, prefix+" ")
			}
		}
		c.Matrix = append(c.Matrix, mr)
	}
	exit := qual.ExitOK
	for _, r := range c.Results {
		label := r.KernelBuild + "/" + r.Arch
		for _, line := range r.UnqualifiedRequired() {
			c.Unqualified = append(c.Unqualified, label+" "+line)
		}
		for _, line := range qual.RuntimeRequirements(r, m.RequiredRuntimes) {
			c.Unqualified = append(c.Unqualified, label+" "+line)
		}
		for _, line := range qual.ScenarioRequirements(r, m.RequiredScenarios) {
			c.Unqualified = append(c.Unqualified, label+" "+line)
		}
		switch r.ExitCode() {
		case qual.ExitFail:
			exit = qual.ExitFail
		case qual.ExitUnexercised:
			if exit == qual.ExitOK {
				exit = qual.ExitUnexercised
			}
		}
	}
	for _, mr := range c.Matrix {
		if !mr.Qualified {
			c.Unqualified = append(c.Unqualified, fmt.Sprintf("matrix kernel %s %s: %s", mr.KernelSeries, mr.Arch, mr.Reason))
			if exit == qual.ExitOK {
				exit = qual.ExitUnexercised
			}
		}
	}
	if len(c.Results) == 0 && exit == qual.ExitOK {
		exit = qual.ExitUnexercised
	}
	if len(c.Problems) > 0 {
		exit = qual.ExitFail
	}
	if len(c.Unqualified) > 0 && exit == qual.ExitOK {
		exit = qual.ExitUnexercised
	}
	sort.Strings(c.Unqualified)
	c.ExitCode = exit
	data, _ := json.MarshalIndent(c, "", "  ")
	data = append(data, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fmt.Fprintln(stderr, "qualification: write report:", err)
			return qual.ExitFail
		}
	} else {
		stdout.Write(data)
	}
	for _, p := range c.Problems {
		fmt.Fprintln(stderr, "qualification: problem:", p)
	}
	if *requireAll {
		if len(c.Unqualified) > 0 {
			fmt.Fprintf(stderr, "qualification: --require-all FAILED, %d unqualified required row(s):\n", len(c.Unqualified))
			for _, line := range c.Unqualified {
				fmt.Fprintln(stderr, "  "+line)
			}
		}
		return exit
	}
	if len(c.Problems) > 0 {
		return qual.ExitFail
	}
	return qual.ExitOK
}

// mergeOverheads folds every overhead report measured for one result into its Overhead row. The CPU capture mode and the
// scheduler (off-CPU) capture mode are separate runs of the overhead runner and so separate reports: each must be bound to
// the result on its own (host, kernel build pin, run digest; an unbound one is refused and listed, it never supplies a
// fixture), and together they must measure every advertised fixture once. A fixture present in two reports is refused:
// the gate does not pick the better of two measurements.
func mergeOverheads(r *qual.QualificationResult, reports []overheadReport, advertised []string) []string {
	var problems []string
	var bound []overheadReport
	for _, o := range reports {
		if problem := overheadUnbound(r, o); problem != "" {
			problems = append(problems, problem)
			continue
		}
		bound = append(bound, o)
	}
	if len(bound) == 0 {
		return problems
	}
	pooled := bound[0]
	pooled.Fixtures = nil
	pooled.FullRun = true
	var commands, digests []string
	seen := map[string]bool{}
	for _, o := range bound {
		commands = append(commands, o.Command)
		digests = append(digests, o.RunDigest)
		pooled.FullRun = pooled.FullRun && o.FullRun
		for _, f := range o.Fixtures {
			if seen[f.Fixture] {
				problems = append(problems, "fixture "+f.Fixture+" measured in two reports")
				continue
			}
			seen[f.Fixture] = true
			pooled.Fixtures = append(pooled.Fixtures, f)
		}
	}
	pooled.Command = strings.Join(commands, "; ")
	pooled.RunDigest = overheadDigest(pooled)
	if problem := mergeOverhead(r, pooled, advertised); problem != "" {
		problems = append(problems, problem)
	}
	if r.Overhead.Detail != nil {
		r.Overhead.Detail["report_run_digests"] = digests
	}
	return problems
}

// mergeOverhead folds a measured overhead report into the acceptance result it is bound to (same host identity, kernel
// build pin and run digest; otherwise it returns why and changes nothing). The Overhead row is supported only when the
// FULL approved run (120 s x 5 repeats) is what the report's fixtures measured; the report's own full_run_executed is not
// trusted. A reduced run keeps its measured numbers but is never promoted. A failed budget fails the row (and Memory),
// as measured.
func mergeOverhead(r *qual.QualificationResult, o overheadReport, advertised []string) string {
	if problem := overheadUnbound(r, o); problem != "" {
		return problem
	}
	byName := map[string]overheadFixture{}
	for _, f := range o.Fixtures {
		byName[f.Fixture] = f
	}
	// The full run is what the fixtures measured (120 s x 5 repeats, none marked reduced), never the report's own flag.
	fullRun := len(advertised) > 0
	for _, name := range advertised {
		f, ok := byName[name]
		if !ok || f.Seconds < fullRunSeconds || f.Repeats < fullRunRepeats || f.Reduced {
			fullRun = false
		}
	}
	detail := map[string]any{"command": o.Command, "full_run_executed": fullRun, "full_run_reported": o.FullRun, "host_id": o.HostID, "kernel_config_sha256": o.KernelConfigSHA, "run_digest": o.RunDigest, "fixtures": o.Fixtures}
	var failures, evidence []string
	for _, name := range advertised {
		f, ok := byName[name]
		switch {
		case !ok:
			failures = append(failures, "advertised fixture "+name+" has no overhead result")
		case !f.CPUBudgetOK || !f.MemoryBudgetOK || len(f.Failures) > 0:
			failures = append(failures, fmt.Sprintf("fixture %s: overhead %.2f%% (stderr %.2f%%), memory %d bytes: %s", name, f.OverheadPct, f.OverheadSEPct, f.MemoryBytes, strings.Join(f.Failures, "; ")))
		default:
			evidence = append(evidence, fmt.Sprintf("fixture %s: workload CPU overhead %.2f%% (stderr %.2f%%, budget 3%%), throughput change %.2f%%, collector %.1f%% of one core, memory %d bytes (budget %d)", name, f.OverheadPct, f.OverheadSEPct, f.ThroughputPct, f.CollectorPct, f.MemoryBytes, 64<<20))
		}
	}
	switch {
	case len(failures) > 0:
		r.Overhead = qual.Failed(strings.Join(failures, "; "), detail)
		for _, f := range o.Fixtures {
			if !f.MemoryBudgetOK {
				r.Memory = qual.Failed(fmt.Sprintf("fixture %s: combined helper+client+ring memory %d bytes exceeds the 64 MiB budget", f.Fixture, f.MemoryBytes), r.Memory.Detail)
			}
		}
	case !fullRun:
		r.Overhead = qual.Row{State: qual.StateUnqualified, Reason: "reduced_run_only: the budgets held in the measured reduced run but the approved 120 s x 5 repeats run was not executed; " + strings.Join(evidence, "; "), Detail: detail}
	default:
		r.Overhead = qual.Supported(evidence, detail)
	}
	return ""
}

// The approved full overhead run (task 04.09): 120 s per run, 5 baseline/capture pairs.
const (
	fullRunSeconds = 120
	fullRunRepeats = 5
)

// overheadDigest recomputes the run digest the overhead runner wrote (qual.OverheadRunDigest) from the report's own fields.
func overheadDigest(o overheadReport) string {
	fixtures := make([]qual.OverheadDigestFixture, 0, len(o.Fixtures))
	for _, f := range o.Fixtures {
		fixtures = append(fixtures, qual.OverheadDigestFixture{Name: f.Fixture, Seconds: f.Seconds, Repeats: f.Repeats, Reduced: f.Reduced, OverheadPct: f.OverheadPct, ThroughputPct: f.ThroughputPct, CollectorPct: f.CollectorPct, MemoryBytes: f.MemoryBytes})
	}
	return qual.OverheadRunDigest(o.HostID, o.KernelBuild, o.KernelConfigSHA, o.Arch, o.Command, fixtures)
}

// overheadUnbound says why an overhead report is not the measurement of this acceptance result ("" when it is): the same
// host, the same kernel build and config pin, and a run digest that matches the report's own numbers.
func overheadUnbound(r *qual.QualificationResult, o overheadReport) string {
	switch {
	case o.HostID == "" || o.HostID != r.HostID:
		return "host identity differs or is missing"
	case o.KernelConfigSHA == "" || o.KernelConfigSHA != r.KernelConfig.SHA256:
		return "kernel build pin (config digest) differs or is missing"
	case o.RunDigest == "" || o.RunDigest != overheadDigest(o):
		return "run digest is missing or does not match the report's content"
	}
	return ""
}
