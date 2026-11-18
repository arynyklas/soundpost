// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
)

func greenSmoke() q.SmokeReport {
	pass := func(names ...string) []q.ScenarioOutcome {
		var out []q.ScenarioOutcome
		for _, n := range names {
			out = append(out, q.ScenarioOutcome{Name: n, Passed: true})
		}
		return out
	}
	rec := q.InputRecord{Kind: "float", Timestamp: "1", Name: "m", Bits: "3ff0000000000000"}
	stale := q.InputRecord{Kind: "float", Timestamp: "2", Name: "m", Bits: q.StaleBits}
	return q.SmokeReport{
		Schema: "soundpost-smoke-report/1", CaseFiles: []string{"conformance/query/cases/persisted-path.json", "conformance/query/cases/profile-cross-products.json"},
		Storage: "real", Control: "real", Modes: []string{"single", "distributed"}, ModesNotRun: []string{},
		Persistence:   pass("hot-read", "flush", "compaction", "restart", "receipt-manifest-reconciles"),
		Isolation:     pass("foreign-project-fails-closed", "revocation-during-compute", "cancellation-releases-everything", "complete-rules-never-use-partial-data", "no-production-path-reaches-an-oracle"),
		Normalization: []q.NormalizationCheck{{ID: "c", Profile: "promql-prometheus-3.13.5", Source: []q.InputRecord{rec, stale}, Normalized: []q.InputRecord{rec, stale}}},
		Steps:         pass("persisted-path.json:hot/promql-prometheus-3.13.5/q1"),
		NotSatisfied:  []string{},
	}
}

func runReleaseWithSmoke(t *testing.T, smoke any) (q.Report, error) {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(smoke)
	if err != nil {
		t.Fatal(err)
	}
	smokePath, reportPath := filepath.Join(dir, "smoke.json"), filepath.Join(dir, "report.json")
	if err = os.WriteFile(smokePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	runErr := runRelease([]string{"--policy", queryDir("release-policy.json"), "--all-profiles", "--all-feature-sets", "--require-locked", "--require-zero-unbound", "--require-zero-skips", "--require-zero-mismatches", "--smoke-report", smokePath, "--report", reportPath})
	var rep q.Report
	if body, err := os.ReadFile(reportPath); err == nil {
		if err = json.Unmarshal(body, &rep); err != nil {
			t.Fatal(err)
		}
	}
	return rep, runErr
}

func mentions(rep q.Report, text string) bool {
	for _, f := range rep.Failures {
		if strings.Contains(f, text) {
			return true
		}
	}
	return false
}

// The release command hands the smoke report to the gate whole: whatever the
// smoke run reported as unmet, failed or unrun is a reason the gate rejects, even
// when the persistence and isolation lists inside the report say "passed".
func TestReleaseHoldsTheSmokeReportToWhatItSays(t *testing.T) {
	rep, err := runReleaseWithSmoke(t, greenSmoke())
	if err == nil || !strings.Contains(err.Error(), "release gate rejected") {
		t.Fatalf("without an oracle runtime the gate must reject: %v", err)
	}
	for _, f := range rep.Failures {
		if strings.HasPrefix(f, "smoke:") || strings.Contains(f, "scenario") || strings.Contains(f, "input normalization") {
			t.Errorf("a complete green smoke report was held against: %s", f)
		}
	}
	if len(rep.Persistence) != 5 || len(rep.Isolation) != 5 || rep.InputNormalizationID == "" {
		t.Errorf("the smoke evidence did not reach the report: %d persistence %d isolation %q", len(rep.Persistence), len(rep.Isolation), rep.InputNormalizationID)
	}
	for name, mutate := range map[string]func(s *q.SmokeReport){
		"a requirement NOT satisfied": func(s *q.SmokeReport) {
			s.NotSatisfied = []string{"binary call-graph check not run: no --production-binary given"}
		},
		"a layout not run": func(s *q.SmokeReport) { s.Modes = []string{"distributed"} },
		"a failing step": func(s *q.SmokeReport) {
			s.Steps[0].Passed, s.Steps[0].Detail = false, "got 1 want 2"
		},
		"fake control": func(s *q.SmokeReport) { s.Control = "fake" },
		"an extra scenario that failed": func(s *q.SmokeReport) {
			s.Persistence = append(s.Persistence, q.ScenarioOutcome{Name: "adapter-loki-push", Passed: false})
		},
	} {
		s := greenSmoke()
		mutate(&s)
		rep, err := runReleaseWithSmoke(t, s)
		if err == nil || !mentions(rep, "smoke:") && !mentions(rep, "adapter-loki-push") {
			t.Errorf("%s: the gate did not hold the smoke report against it: %v %q", name, err, rep.Failures)
		}
	}
}

// A smoke report this command does not fully understand is not evidence.
func TestReleaseRefusesASmokeReportItCannotFullyRead(t *testing.T) {
	s := greenSmoke()
	raw, _ := json.Marshal(s)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["layouts_skipped"] = []string{"distributed"}
	if _, err := runReleaseWithSmoke(t, doc); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a smoke report with a field this tool does not know was accepted: %v", err)
	}
}

// Isolation outcomes are listed in a fixed order, so two runs of the same smoke
// write the same report.
func TestCollateIsolationIsDeterministic(t *testing.T) {
	steps := []q.ScenarioOutcome{
		{Name: "persisted-path.json:foreign-project/a", Passed: true},
		{Name: "live-smoke.json:revocation-during-compute/x", Passed: true},
		{Name: "live-smoke.json:cancellation-releases-everything/y", Passed: true},
		{Name: "rule-smoke.json:unavailable-shard-is-unknown-not-recovery", Passed: true},
		{Name: "rule-smoke.json:complete-data-recovers", Passed: true},
	}
	first := collateIsolation(steps)
	var names []string
	for _, o := range first {
		names = append(names, o.Name)
		if !o.Passed {
			t.Errorf("%s did not pass", o.Name)
		}
	}
	if want := []string{"foreign-project-fails-closed", "revocation-during-compute", "cancellation-releases-everything", "complete-rules-never-use-partial-data"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("isolation outcomes %v, want %v", names, want)
	}
	for i := range 30 {
		if again := collateIsolation(steps); !reflect.DeepEqual(again, first) {
			t.Fatalf("collateIsolation answered differently on run %d: %v vs %v", i, again, first)
		}
	}
	// A scenario whose steps never ran is not passed, and one failing step fails it.
	steps[1].Passed = false
	// The recovery step is cut off, so "complete rules never use partial data" is
	// not passed although the unavailable-shard step passed.
	got := collateIsolation(steps[:4])
	if len(got) != 4 || !got[0].Passed || got[1].Passed || !got[2].Passed || got[3].Passed {
		t.Fatalf("a failing step and a step that never ran must each fail their own scenario and nothing else: %v", got)
	}
}
