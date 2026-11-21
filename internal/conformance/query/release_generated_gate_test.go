// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// distinctRows is n generated rows of the first PromQL profile, each its own case.
func distinctRows(n int) []GeneratedRow {
	const p = "promql-prometheus-3.1.0"
	rows := make([]GeneratedRow, 0, n)
	for i := range n {
		id := fmt.Sprintf("gen/%s/case-%03d", p, i)
		rows = append(rows, GeneratedRow{
			Row:    ReleaseCase{ID: id, Profile: p, Expected: SemanticResult{Kind: "phase-case", Type: tagPromEvaluation}},
			Phase:  tagPromEvaluation,
			Source: Case{ID: id, Kind: "valid", Language: "promql", Profile: p, Expression: fmt.Sprintf("m + %d", i)},
		})
	}
	return rows
}

// The report names at most the first fifty mismatching and the first fifty unrun
// rows of a seed (it counts all of them), in the order the rows were planned.
func TestGeneratedGateSamplesAtMostFiftyRowsOfEachKindInPlanOrder(t *testing.T) {
	cfg := releaseFixture(t)
	run := fixtureGeneratedRun(cfg, 20261110, 0)
	run.Rows = distinctRows(160)
	index := map[string]int{}
	for i, r := range run.Rows {
		index[r.Row.ID] = i
	}
	run.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		switch i := index[c.ID]; {
		case i < 60:
			return SemanticResult{}, PhaseProblems{"value: reference 1, owned 2"}
		case i < 130:
			return SemanticResult{}, errors.Join(ErrNotObserved, errors.New("not run"))
		}
		return c.Expected, nil
	}
	cfg.Generated = []GeneratedRun{run}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	g := rep.Generated[0]
	if g.Generated != 160 || g.Mismatched != 60 || g.Unrun != 70 || g.Matched != 30 || g.Executed != 90 {
		t.Fatalf("counts %+v", g.GeneratedCounts)
	}
	if len(g.MismatchedRows) != generatedSampleLimit || g.MismatchedRows[0] != run.Rows[0].Row.ID || g.MismatchedRows[generatedSampleLimit-1] != run.Rows[generatedSampleLimit-1].Row.ID {
		t.Fatalf("mismatch sample %d rows from %q", len(g.MismatchedRows), g.MismatchedRows)
	}
	if len(g.UnrunRows) != generatedSampleLimit || g.UnrunRows[0] != run.Rows[60].Row.ID || g.UnrunRows[generatedSampleLimit-1] != run.Rows[60+generatedSampleLimit-1].Row.ID {
		t.Fatalf("unrun sample %d rows from %q", len(g.UnrunRows), g.UnrunRows)
	}
	// Fewer rows than the limit are all named.
	run.Rows = run.Rows[:20]
	cfg.Generated = []GeneratedRun{run}
	rep, _ = runGate(t, cfg)
	if g = rep.Generated[0]; len(g.MismatchedRows) != 20 || len(g.UnrunRows) != 0 {
		t.Fatalf("sample of 20 mismatching rows: %d %d", len(g.MismatchedRows), len(g.UnrunRows))
	}
}

// Every mismatching case is minimized once per seed, however many of its rows
// disagree; the same case in another seed is minimized again.
func TestGeneratedGateMinimizesEachMismatchingCaseOncePerSeed(t *testing.T) {
	cfg := releaseFixture(t)
	var sources []string
	cfg.Minimize = func(_ context.Context, m GeneratedMismatch) (Regression, error) {
		sources = append(sources, fmt.Sprintf("%d:%s", m.Seed, m.Row.Source.ID))
		return Regression{ID: m.Row.Source.ID, Seed: m.Seed}, nil
	}
	mk := func(seed uint64) GeneratedRun {
		run := fixtureGeneratedRun(cfg, seed, 0)
		rows := distinctRows(2)
		second := rows[0]
		second.Row.ID += "#second-feature-set" // a second row of the first case
		run.Rows = []GeneratedRow{rows[0], second, rows[1]}
		run.Own = func(context.Context, ReleaseCase) (SemanticResult, error) {
			return SemanticResult{}, PhaseProblems{"value: reference 1, owned 2"}
		}
		return run
	}
	cfg.Generated = []GeneratedRun{mk(1), mk(2)}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	want := []string{"1:gen/promql-prometheus-3.1.0/case-000", "1:gen/promql-prometheus-3.1.0/case-001", "2:gen/promql-prometheus-3.1.0/case-000", "2:gen/promql-prometheus-3.1.0/case-001"}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("minimized %q, want %q", sources, want)
	}
	for _, g := range rep.Generated {
		if g.Mismatched != 3 || len(g.Regressions) != 2 {
			t.Fatalf("seed %d: %d mismatched, %d regressions", g.Seed, g.Mismatched, len(g.Regressions))
		}
	}
	// A minimizer that fails is a gate failure, not a dropped mismatch.
	cfg.Minimize = func(context.Context, GeneratedMismatch) (Regression, error) {
		return Regression{}, errors.New("minimized case no longer reproduces")
	}
	rep, err = runGate(t, cfg)
	requireRejected(t, rep, err, "seed 1: minimizing gen/promql-prometheus-3.1.0/case-000: minimized case no longer reproduces")
	if len(rep.Generated[0].Regressions) != 0 {
		t.Fatalf("a regression was recorded for a failed minimization: %+v", rep.Generated[0].Regressions)
	}
}

func TestGeneratedGateRefusesEmptyAndRepeatedSeeds(t *testing.T) {
	cfg := releaseFixture(t)
	cfg.Generated = []GeneratedRun{fixtureGeneratedRun(cfg, 7, 3), fixtureGeneratedRun(cfg, 7, 3)}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "duplicate generated run for seed 7")
	cfg.Generated = []GeneratedRun{fixtureGeneratedRun(cfg, 7, 3), fixtureGeneratedRun(cfg, 8, 0)}
	rep, err = runGate(t, cfg)
	requireRejected(t, rep, err, "seed 8: no generated cases")
	if failureContains(rep, "seed 7") {
		t.Fatalf("a seed that ran was blamed: %q", rep.Failures)
	}
}

// The problems the minimizer is handed are the runner's own: a PhaseProblems error
// is unwrapped (also when wrapped), any other error is one problem, and an empty
// PhaseProblems still is a disagreement.
func TestGeneratedGateHandsTheMinimizerTheOwnedSidesIndividualProblems(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want []string
	}{
		"several problems":         {PhaseProblems{"a: x", "b: y"}, []string{"a: x", "b: y"}},
		"a wrapped problem list":   {fmt.Errorf("row 1: %w", PhaseProblems{"a: x", "b: y"}), []string{"a: x", "b: y"}},
		"a plain error":            {errors.New("boom"), []string{"boom"}},
		"an empty problem list":    {PhaseProblems{}, []string{""}},
		"a joined error is a text": {errors.Join(errors.New("one"), errors.New("two")), []string{"one\ntwo"}},
	} {
		cfg := releaseFixture(t)
		run := fixtureGeneratedRun(cfg, 5, 0)
		run.Rows = distinctRows(1)
		run.Own = func(context.Context, ReleaseCase) (SemanticResult, error) { return SemanticResult{}, c.err }
		var handed []string
		cfg.Minimize = func(_ context.Context, m GeneratedMismatch) (Regression, error) {
			handed = m.Problems
			return Regression{}, nil
		}
		cfg.Generated = []GeneratedRun{run}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		if !reflect.DeepEqual(handed, c.want) || rep.Generated[0].Mismatched != 1 {
			t.Errorf("%s: the minimizer was handed %q, want %q (mismatched %d)", name, handed, c.want, rep.Generated[0].Mismatched)
		}
	}
	// A row whose oracle and owned answers both differ from its authored expectation
	// names the field of each comparison.
	cfg := releaseFixture(t)
	run := fixtureGeneratedRun(cfg, 5, 0)
	run.Rows = distinctRows(1)
	innerOracle := run.Oracle
	run.Oracle = func(ctx context.Context, p SourceProfile, c ReleaseCase) (SemanticResult, error) {
		r, err := innerOracle(ctx, p, c)
		r.Type = "something else"
		return r, err
	}
	run.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		r := c.Expected
		r.Type = "something else"
		return r, nil
	}
	var handed []string
	cfg.Minimize = func(_ context.Context, m GeneratedMismatch) (Regression, error) {
		handed = m.Problems
		return Regression{}, nil
	}
	cfg.Generated = []GeneratedRun{run}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	if joined := strings.Join(handed, "|"); joined != "oracle: type|owned: type" {
		t.Fatalf("the problems of a row whose answers differ from its authored expectation: %q", handed)
	}
}
