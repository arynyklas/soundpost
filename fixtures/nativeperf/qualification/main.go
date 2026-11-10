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
	"sort"
	"strings"

	"soundpost/fixtures/nativeperf/qual"
)

type manifest struct {
	Rows               []qual.ManifestRow `json:"rows"`
	AdvertisedFixtures []string           `json:"advertised_fixtures"`
	RequiredRuntimes   []string           `json:"required_runtimes"`
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
	KernelBuild string            `json:"kernel_build"`
	Arch        string            `json:"arch"`
	FullRun     bool              `json:"full_run_executed"`
	Command     string            `json:"command"`
	Fixtures    []overheadFixture `json:"fixtures"`
}

type matrixRow struct {
	KernelSeries string `json:"kernel_series"`
	Arch         string `json:"arch"`
	Qualified    bool   `json:"qualified"`
	Reason       string `json:"reason,omitempty"`
}

type combined struct {
	Manifest    string                      `json:"manifest"`
	Mode        string                      `json:"mode"`
	Results     []*qual.QualificationResult `json:"results"`
	Matrix      []matrixRow                 `json:"matrix"`
	Unqualified []string                    `json:"unqualified_required_rows"`
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
		for _, o := range overheads {
			if o.KernelBuild == r.KernelBuild && o.Arch == r.Arch {
				mergeOverhead(r, o, m.AdvertisedFixtures)
			}
		}
		for _, p := range qual.ReleaseProblems(r) {
			c.Problems = append(c.Problems, r.KernelBuild+"/"+r.Arch+": "+p)
		}
	}
	missing := qual.MatrixVerdict(m.Rows, c.Results)
	missingSet := map[string]bool{}
	for _, line := range missing {
		missingSet[line] = true
	}
	for _, row := range m.Rows {
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

// mergeOverhead folds a measured overhead report into the acceptance result of
// the same kernel and architecture. The Overhead row is supported only when the
// FULL approved run (120 s x 5 repeats) was executed and every advertised
// fixture met both budgets; a reduced run keeps its measured numbers but is
// never promoted. A failed budget fails the row (and Memory), as measured.
func mergeOverhead(r *qual.QualificationResult, o overheadReport, advertised []string) {
	detail := map[string]any{"command": o.Command, "full_run_executed": o.FullRun, "fixtures": o.Fixtures}
	byName := map[string]overheadFixture{}
	for _, f := range o.Fixtures {
		byName[f.Fixture] = f
	}
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
	case !o.FullRun:
		r.Overhead = qual.Row{State: qual.StateUnqualified, Reason: "reduced_run_only: the budgets held in the measured reduced run but the approved 120 s x 5 repeats run was not executed; " + strings.Join(evidence, "; "), Detail: detail}
	default:
		r.Overhead = qual.Supported(evidence, detail)
	}
}
