// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
	"github.com/arynyklas/soundpost/internal/conformance/query/smoke"
)

// runSmoke executes the declarative smoke case files against real installations:
// one node (single) and three in-process voters joined over mTLS (distributed),
// plus the cross-node scenario on the distributed layout. Anything it cannot run
// (flows without a runner) is reported as NOT run and fails the command: it
// never counts as a pass.
func runSmoke(args []string) error {
	f := flag.NewFlagSet("smoke", flag.ContinueOnError)
	cases := f.String("cases", "", "comma-separated case files")
	storage := f.String("storage", "", "must be real")
	control := f.String("control", "", "must be real")
	modes := f.String("modes", "single", "comma-separated layouts: single, distributed")
	ownHTTP := f.Bool("own-http", false, "use the owned C06 routes (always true)")
	restart := f.Bool("restart", false, "require restart stages")
	compact := f.Bool("compact", false, "require compaction stages")
	reportPath := f.String("report", "", "write the smoke report here")
	binary := f.String("production-binary", "", "optional path to a built cmd/soundpost to check by symbol table")
	goTool := f.String("go", "go", "go executable used for `go tool nm` on --production-binary")
	moduleRoot := f.String("module-root", ".", "module root for the production closure check")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *storage != "real" || *control != "real" {
		return fmt.Errorf("smoke requires --storage real --control real: no mock storage or control is permitted")
	}
	_ = *ownHTTP
	if *cases == "" {
		return fmt.Errorf("smoke requires --cases")
	}
	ctx := context.Background()
	report := q.SmokeReport{Schema: "soundpost-smoke-report/1", Storage: "real", Control: "real"}
	var layouts []smoke.Layout
	for _, m := range strings.Split(*modes, ",") {
		switch layout := smoke.Layout(strings.TrimSpace(m)); layout {
		case smoke.Single, smoke.Distributed:
			if !slices.Contains(layouts, layout) {
				layouts = append(layouts, layout)
				report.Modes = append(report.Modes, string(layout))
			}
		default:
			return fmt.Errorf("unknown mode %q", m)
		}
	}
	// A step of the single layout keeps its plain name; every other layout is
	// namespaced, so one report can carry several layouts without aliasing.
	named := func(layout smoke.Layout, name string) string {
		if layout == smoke.Single {
			return name
		}
		return string(layout) + "/" + name
	}
	var failed int
	run := func(layout smoke.Layout, name string, steps []smoke.StepResult, err error) {
		name = named(layout, name)
		if err != nil {
			failed++
			report.Steps = append(report.Steps, q.ScenarioOutcome{Name: name, Passed: false, Detail: err.Error()})
			return
		}
		for _, s := range steps {
			report.Steps = append(report.Steps, q.ScenarioOutcome{Name: name + ":" + s.Name, Passed: s.Passed && !s.NotRun, Detail: s.Detail})
			if s.NotRun {
				report.NotSatisfied = append(report.NotSatisfied, name+":"+s.Name+": "+s.Detail)
			}
		}
		failed += smoke.Failed(steps)
	}
	seen := map[string]bool{}
	for _, layout := range layouts {
		for _, path := range strings.Split(*cases, ",") {
			path = strings.TrimSpace(path)
			if !seen[path] {
				seen[path] = true
				report.CaseFiles = append(report.CaseFiles, path)
			}
			var head struct {
				Schema string `json:"schema"`
			}
			if err := q.ReadJSON(path, &head); err != nil {
				return err
			}
			err := func() error {
				dir, err := os.MkdirTemp("", "soundpost-smoke-")
				if err != nil {
					return err
				}
				defer os.RemoveAll(dir)
				base := filepath.Base(path)
				switch head.Schema {
				case "soundpost-owned-query-smoke/1":
					steps, err := smoke.RunOwned(ctx, layout, dir, path)
					run(layout, base, steps, err)
				case "soundpost-live-smoke/1":
					steps, notRun, err := smoke.RunLive(ctx, layout, dir, path)
					run(layout, base, steps, err)
					for _, n := range notRun {
						report.NotSatisfied = append(report.NotSatisfied, named(layout, base)+": "+n)
					}
				case "soundpost-rule-smoke/1":
					steps, err := smoke.RunRules(ctx, layout, dir, path)
					run(layout, base, steps, err)
				case "soundpost-persisted-path/1":
					res, err := smoke.RunPersisted(ctx, layout, dir, path)
					run(layout, base, res.Steps, err)
					report.Persistence = mergeOutcomes(report.Persistence, res.Persistence)
					report.Normalization = append(report.Normalization, res.Normalization...)
				case "soundpost-profile-cross-products/1":
					steps, err := smoke.RunCross(ctx, layout, dir, path)
					run(layout, base, steps, err)
				default:
					return fmt.Errorf("%s: no smoke runner for schema %q", path, head.Schema)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		if layout == smoke.Distributed {
			dir, err := os.MkdirTemp("", "soundpost-smoke-")
			if err != nil {
				return err
			}
			steps, err := smoke.RunDistributed(ctx, dir)
			_ = os.RemoveAll(dir)
			run(layout, "cluster", steps, err)
		}
	}
	if !*restart || !*compact {
		report.NotSatisfied = append(report.NotSatisfied, "--restart/--compact were not both requested; the persisted-path runner always includes both stages")
	}
	// Isolation outcomes: collated from the executed flows, never assumed.
	report.Isolation = collateIsolation(report.Steps)
	// No production path starts or contacts an oracle: import/identifier closure.
	closure := q.ScenarioOutcome{Name: "no-production-path-reaches-an-oracle"}
	roots, err := q.ProductionRoots(*moduleRoot, "github.com/arynyklas/soundpost")
	if err == nil {
		var rep q.ClosureReport
		if rep, err = q.ProductionClosure(*moduleRoot, "github.com/arynyklas/soundpost", roots); err == nil {
			closure.Passed = len(rep.Violation) == 0
			closure.Detail = fmt.Sprintf("%d production packages, %d files; violations: %v", len(rep.Packages), rep.Files, rep.Violation)
		}
	}
	if err != nil {
		closure.Detail = err.Error()
	}
	if *binary != "" {
		out, nmErr := exec.Command(*goTool, "tool", "nm", *binary).Output()
		if nmErr != nil {
			closure.Passed, closure.Detail = false, "binary symbol check failed: "+nmErr.Error()
		} else if bad := q.ForbiddenBinarySymbols(string(out), "github.com/arynyklas/soundpost"); len(bad) > 0 {
			closure.Passed, closure.Detail = false, fmt.Sprintf("binary carries harness/upstream symbols: %v", bad)
		} else {
			closure.Detail += "; binary symbol table clean"
		}
	} else {
		report.NotSatisfied = append(report.NotSatisfied, "binary call-graph check not run: no --production-binary given (source import/identifier closure only)")
	}
	report.Isolation = append(report.Isolation, closure)
	if !closure.Passed {
		failed++
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if *reportPath != "" {
		if err = os.WriteFile(*reportPath, raw, 0o644); err != nil {
			return err
		}
	}
	if _, err = os.Stdout.Write(append(raw, '\n')); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("smoke: %d failing steps", failed)
	}
	if len(report.NotSatisfied) > 0 {
		return fmt.Errorf("smoke: %d requirements NOT satisfied (see report)", len(report.NotSatisfied))
	}
	return nil
}

// collateIsolation derives the named isolation scenarios from executed steps.
func collateIsolation(steps []q.ScenarioOutcome) []q.ScenarioOutcome {
	find := func(substr string) (found, passed bool) {
		passed = true
		for _, s := range steps {
			if strings.Contains(s.Name, substr) {
				found = true
				passed = passed && s.Passed
			}
		}
		return
	}
	var out []q.ScenarioOutcome
	for scenario, substr := range map[string]string{
		"foreign-project-fails-closed":     "foreign-project",
		"revocation-during-compute":        "revocation-during-compute",
		"cancellation-releases-everything": "cancellation-releases-everything",
	} {
		found, passed := find(substr)
		out = append(out, q.ScenarioOutcome{Name: scenario, Passed: found && passed})
	}
	found, passed := find("unavailable-shard-is-unknown-not-recovery")
	_, passed2 := find("complete-data-recovers")
	out = append(out, q.ScenarioOutcome{Name: "complete-rules-never-use-partial-data", Passed: found && passed && passed2})
	return out
}

// mergeOutcomes folds more outcomes into base by name. A scenario run on several
// layouts passes only if it passed on every one of them.
func mergeOutcomes(base, more []q.ScenarioOutcome) []q.ScenarioOutcome {
	for _, o := range more {
		merged := false
		for i := range base {
			if base[i].Name == o.Name {
				base[i].Passed = base[i].Passed && o.Passed
				merged = true
			}
		}
		if !merged {
			base = append(base, o)
		}
	}
	return base
}
