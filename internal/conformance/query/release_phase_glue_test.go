// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPhaseOracleServesOnlyRowsThePinnedOracleObserved(t *testing.T) {
	id := OracleIdentity{Profile: "p", Revision: "abcdef0", Version: "1", ImageSHA256: "i", ConfigurationSHA256: "c"}
	res := PhaseResults{
		PhaseKey("p", "seen"):    {Phase: "promql:syntax", Identity: &id},
		PhaseKey("p", "blind"):   {Phase: "promql:syntax"},
		PhaseKey("p", "problem"): {Phase: "promql:syntax", Identity: &id, Problems: []string{"x"}},
	}
	oracle := res.PhaseOracle()
	got, err := oracle(context.Background(), SourceProfile{ID: "p"}, ReleaseCase{ID: "seen", Profile: "p"})
	if err != nil || got.Kind != "phase-case" || got.Type != "promql:syntax" || got.Oracle == nil || *got.Oracle != id {
		t.Fatalf("%v %+v", err, got)
	}
	got.Oracle.Profile = "tampered"
	if id.Profile != "p" || res[PhaseKey("p", "seen")].Identity.Profile != "p" {
		t.Fatal("the served identity aliases the recorded one")
	}
	if got, err = oracle(context.Background(), SourceProfile{ID: "p"}, ReleaseCase{ID: "problem", Profile: "p"}); err != nil || got.Oracle == nil {
		t.Fatalf("a row whose owned side disagreed was still observed by the oracle: %v", err)
	}
	for _, c := range []struct {
		profile, id string
	}{{"p", "blind"}, {"p", "absent"}, {"other", "seen"}} {
		if _, err := oracle(context.Background(), SourceProfile{ID: c.profile}, ReleaseCase{ID: c.id}); !errors.Is(err, ErrNotObserved) {
			t.Errorf("%s/%s: %v, want ErrNotObserved", c.profile, c.id, err)
		}
	}
}

func TestPhaseOwnReportsEveryProblemTheRunnerFound(t *testing.T) {
	res := PhaseResults{
		PhaseKey("p", "ok"):  {Phase: "t"},
		PhaseKey("p", "bad"): {Phase: "t", Problems: []string{"first: reference 1, owned 2", "second: reference a, owned b"}},
	}
	own := res.PhaseOwn()
	if got, err := own(context.Background(), ReleaseCase{ID: "ok", Profile: "p"}); err != nil || got.Kind != "phase-case" || got.Type != "t" || got.Oracle != nil {
		t.Fatalf("%v %+v", err, got)
	}
	_, err := own(context.Background(), ReleaseCase{ID: "bad", Profile: "p"})
	var problems PhaseProblems
	if !errors.As(err, &problems) || !reflect.DeepEqual([]string(problems), []string{"first: reference 1, owned 2", "second: reference a, owned b"}) {
		t.Fatalf("the owned side lost the runner's individual problems: %v", err)
	}
	if err.Error() != "first: reference 1, owned 2; second: reference a, owned b" || errors.Is(err, ErrNotObserved) {
		t.Fatalf("%q", err)
	}
	for _, c := range []ReleaseCase{{ID: "absent", Profile: "p"}, {ID: "ok", Profile: "q"}} {
		if _, err := own(context.Background(), c); !errors.Is(err, ErrNotObserved) {
			t.Errorf("%s/%s: %v, want ErrNotObserved", c.Profile, c.ID, err)
		}
	}
}

func TestReleasePhaseGlueKeysEveryRunnerRowByProfileAndCase(t *testing.T) {
	id := &OracleIdentity{Profile: "p"}
	type call struct{ kind, path, profiles, runtime, phase string }
	var calls []call
	run := phaseRunners{
		syntax: func(_ context.Context, _ SourceLock, path, profiles, runtime string) (SyntaxPhaseReport, error) {
			calls = append(calls, call{"syntax", path, profiles, runtime, ""})
			return SyntaxPhaseReport{Cases: []SyntaxCaseComparison{
				{ID: "s1", Profile: "promql-prometheus-3.1.0", Identity: id},
				{ID: "s2", Profile: "promql-prometheus-3.13.5", Identity: id, Mismatches: []string{"owned/reference acceptance differs", "owned type differs from authored case"}},
			}}, nil
		},
		configuration: func(_ context.Context, _ SourceLock, paths []string, runtime string) (ConfigurationPhaseReport, error) {
			calls = append(calls, call{"configuration", strings.Join(paths, ","), "", runtime, ""})
			return ConfigurationPhaseReport{Cases: []ConfigurationCaseComparison{{ID: "k1", Profile: "promql-prometheus-3.13.5", Oracle: id, Mismatches: []string{"scrape_interval differs"}}}}, nil
		},
		evaluation: func(_ context.Context, _ SourceLock, paths []string, profiles, runtime string) (EvaluationPhaseReport, error) {
			calls = append(calls, call{"evaluation", strings.Join(paths, ","), profiles, runtime, ""})
			return EvaluationPhaseReport{Cases: []EvaluationCaseComparison{{ID: "e1", Profile: "promql-prometheus-3.1.0", Oracle: id, Mismatches: []Mismatch{{Field: "values", Want: 1, Got: 2}, {Field: "annotations", Want: "w", Got: "g"}}}}}, nil
		},
		logql: func(_ context.Context, _ SourceLock, path, profiles, runtime, phase string) (LogQLPhaseReport, error) {
			calls = append(calls, call{"logql", path, profiles, runtime, phase})
			return LogQLPhaseReport{Cases: []LogQLComparison{{ID: "l1", Oracle: id, Mismatches: []Mismatch{{Field: "stream", Want: "a", Got: "b"}}}, {ID: "l2", Oracle: id}}}, nil
		},
	}
	m := ReleaseCaseManifest{Schema: "soundpost-query-release-cases/1", Files: []ReleasePhaseFile{
		{Path: "cases/a.json", Language: "promql", Phase: "syntax"},
		{Path: "cases/b.json", Language: "promql", Phase: "configuration"},
		{Path: "cases/c.json", Language: "promql", Phase: "evaluation"},
		{Path: "cases/d.json", Language: "logql", Phase: "syntax,pipeline"},
	}}
	res, err := runReleasePhases(context.Background(), run, SourceLock{}, "qdir", "pdir", "/rt", m)
	if err != nil {
		t.Fatal(err)
	}
	want := PhaseResults{
		PhaseKey("promql-prometheus-3.1.0", "s1"):  {Phase: "promql:syntax", Identity: id},
		PhaseKey("promql-prometheus-3.13.5", "s2"): {Phase: "promql:syntax", Identity: id, Problems: []string{"owned/reference acceptance differs", "owned type differs from authored case"}},
		PhaseKey("promql-prometheus-3.13.5", "k1"): {Phase: "promql:configuration", Identity: id, Problems: []string{"scrape_interval differs"}},
		PhaseKey("promql-prometheus-3.1.0", "e1"):  {Phase: "promql:evaluation", Identity: id, Problems: []string{"values: reference 1, owned 2", "annotations: reference w, owned g"}},
		PhaseKey(logQLProfile, "l1"):               {Phase: "logql:syntax,pipeline", Identity: id, Problems: []string{"stream: reference a, owned b"}},
		PhaseKey(logQLProfile, "l2"):               {Phase: "logql:syntax,pipeline", Identity: id},
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("outcomes:\n got %+v\nwant %+v", res, want)
	}
	j := func(name string) string { return filepath.Join("qdir", "cases", name) }
	wantCalls := []call{{"syntax", j("a.json"), "pdir", "/rt", ""}, {"configuration", j("b.json"), "", "/rt", ""}, {"evaluation", j("c.json"), "pdir", "/rt", ""}, {"logql", j("d.json"), "pdir", "/rt", "syntax,pipeline"}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("runner calls:\n got %+v\nwant %+v", calls, wantCalls)
	}
}

func TestReleasePhaseGlueDistinguishesAnEmptyRunFromAPartialOne(t *testing.T) {
	id := &OracleIdentity{Profile: "p"}
	boom := errors.New("container runtime missing")
	run := phaseRunners{
		syntax: func(_ context.Context, _ SourceLock, path, _, _ string) (SyntaxPhaseReport, error) {
			if strings.HasSuffix(path, "partial.json") {
				return SyntaxPhaseReport{Cases: []SyntaxCaseComparison{{ID: "s1", Profile: "p", Identity: id}}}, boom // compared one row, then failed
			}
			return SyntaxPhaseReport{}, fmt.Errorf("%s: %w", filepath.Base(path), boom)
		},
		configuration: func(context.Context, SourceLock, []string, string) (ConfigurationPhaseReport, error) {
			return ConfigurationPhaseReport{}, boom
		},
		evaluation: func(context.Context, SourceLock, []string, string, string) (EvaluationPhaseReport, error) {
			return EvaluationPhaseReport{}, boom
		},
		logql: func(context.Context, SourceLock, string, string, string, string) (LogQLPhaseReport, error) {
			return LogQLPhaseReport{}, boom
		},
	}
	m := ReleaseCaseManifest{Files: []ReleasePhaseFile{
		{Path: "cases/empty.json", Language: "promql", Phase: "syntax"},
		{Path: "cases/partial.json", Language: "promql", Phase: "syntax"},
		{Path: "cases/cfg.json", Language: "promql", Phase: "configuration"},
		{Path: "cases/ev.json", Language: "promql", Phase: "evaluation"},
		{Path: "cases/lq.json", Language: "logql", Phase: "pipeline"},
	}}
	res, err := runReleasePhases(context.Background(), run, SourceLock{}, "q", "p", "r", m)
	if err == nil || !strings.HasPrefix(err.Error(), "phase runs observed nothing: ") {
		t.Fatalf("%v", err)
	}
	for _, f := range []string{"cases/empty.json", "cases/cfg.json", "cases/ev.json", "cases/lq.json"} {
		if !strings.Contains(err.Error(), f+": ") {
			t.Errorf("the error does not name the empty run of %s: %v", f, err)
		}
	}
	if strings.Contains(err.Error(), "cases/partial.json") || strings.Count(err.Error(), "; ") != 3 {
		t.Errorf("a run that observed a row is not an empty run, and the failures are joined by \"; \": %v", err)
	}
	if len(res) != 1 || res[PhaseKey("p", "s1")].Identity != id {
		t.Fatalf("the row the failing runner did compare was dropped: %+v", res)
	}
}

func TestReleasePhaseGlueDoesNotLetAnotherFileOverwriteAnObservedRow(t *testing.T) {
	id := &OracleIdentity{Profile: "p"}
	run := phaseRunners{syntax: func(_ context.Context, _ SourceLock, path, _, _ string) (SyntaxPhaseReport, error) {
		mismatches := []string(nil)
		if strings.HasSuffix(path, "first.json") {
			mismatches = []string{"owned/reference acceptance differs"}
		}
		return SyntaxPhaseReport{Cases: []SyntaxCaseComparison{{ID: "dup", Profile: "p", Identity: id, Mismatches: mismatches}}}, nil
	}}
	m := ReleaseCaseManifest{Files: []ReleasePhaseFile{{Path: "cases/first.json", Language: "promql", Phase: "syntax"}, {Path: "cases/second.json", Language: "promql", Phase: "syntax"}}}
	res, err := runReleasePhases(context.Background(), run, SourceLock{}, "q", "p", "r", m)
	if err != nil {
		t.Fatal(err)
	}
	o := res[PhaseKey("p", "dup")]
	joined := strings.Join(o.Problems, "|")
	if !strings.Contains(joined, "owned/reference acceptance differs") || !strings.Contains(joined, "observed by two case files") {
		t.Fatalf("a passing row of a later file hid the failing row of an earlier one: %+v", o)
	}
}

// Every row of the real release manifest becomes one differential case: its
// expectation is "no disagreement" for its own phase, never an expectation of its own.
func TestReleaseManifestRowsBecomeDifferentialCases(t *testing.T) {
	inRepoRoot(t)
	cfg, err := LoadReleaseConfig("conformance/query", "conformance/query/release-policy.json", nil, []uint64{20261110})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Cases) < 2000 {
		t.Fatalf("%d release rows", len(cfg.Cases))
	}
	tags := map[string]bool{"promql:syntax": true, "promql:evaluation": true, "promql:configuration": true, "logql:syntax": true, "logql:pipeline": true, "logql:syntax,pipeline": true, "logql:logql-template": true, "logql:logql-metric": true}
	var keys []string
	for _, c := range cfg.Cases {
		if _, pinned := exactPins[c.Profile]; !pinned || c.ID == "" {
			t.Fatalf("row %+v is not scoped to a pinned profile", c)
		}
		if c.Expected.Kind != "phase-case" || !tags[c.Expected.Type] || c.Skip != "" || c.Ordering != (OrderingFreedom{}) || len(c.Expected.Values) != 0 || c.Expected.Oracle != nil {
			t.Fatalf("row %s/%s carries an expectation of its own: %+v", c.Profile, c.ID, c)
		}
		var in struct{ File, Phase string }
		if err := json.Unmarshal(c.Input, &in); err != nil || in.Phase != c.Expected.Type || !strings.HasPrefix(in.File, "cases/") {
			t.Fatalf("row %s/%s names its file %q and phase %q: %v", c.Profile, c.ID, in.File, in.Phase, err)
		}
		keys = append(keys, c.Profile+"\x00"+c.ID)
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatal("the release rows are not in (profile, id) order")
	}
}

// ---- the minimizer, through the phase results and the gate -------------------

// minimizerFixture is a real generated case (stale marker, subquery, metadata
// mutation) in its first row, and a runner that disagrees with the owned engine
// only while the query still holds label_replace over a series with a stale marker.
func minimizerFixture(t *testing.T, problems []string, flaky bool) (ReleaseConfig, GeneratedRow, GeneratedMinimizer, func() int) {
	t.Helper()
	spec, ledger, domains := loadPlanInputs(t)
	cases, err := generateForRelease(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	var target Case
	for _, c := range cases {
		if c.Kind == "valid" && c.Language == "promql" && c.Profile == "promql-prometheus-3.13.5" && c.Coordinate["sample_kind"] == "stale" && c.Coordinate["time_window"] == "subquery" && c.Coordinate["metadata_mutation"] == "metadata" {
			target = c
		}
	}
	if target.ID == "" {
		t.Fatal("no stale subquery case")
	}
	rows, err := rowsFor(target, domainSets(domains))
	if err != nil || len(rows) == 0 {
		t.Fatalf("%v", err)
	}
	cfg := releaseFixture(t)
	identities := map[string]*OracleIdentity{}
	for _, p := range cfg.Lock.Profiles {
		identities[p.ID] = &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-"), ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}
	}
	sightings := map[string]int{}
	runs := 0
	runner := func(_ context.Context, rs []GeneratedRow) (PhaseResults, error) {
		runs++
		res := PhaseResults{}
		for _, r := range rs {
			ev := r.payload.(EvaluationCase)
			stale := false
			for _, s := range ev.Series {
				for _, sm := range s.Samples {
					stale = stale || (sm.Float != nil && uint64(*sm.Float) == 0x7ff0000000000002)
				}
			}
			o := PhaseOutcome{Phase: r.Phase, Identity: identities[r.Row.Profile]}
			raw, _ := json.Marshal(ev)
			key := r.Row.ID + string(raw)
			sightings[key]++
			if stale && strings.Contains(ev.Query, "label_replace") && strings.Count(ev.Query, "(") == strings.Count(ev.Query, ")") && (!flaky || sightings[key] == 1) {
				o.Problems = problems
			}
			res[PhaseKey(r.Row.Profile, r.Row.ID)] = o
		}
		return res, nil
	}
	return cfg, rows[0], GeneratedMinimizer{Domains: domains, RunRows: runner}, func() int { return runs }
}

// A row can disagree in several fields at once, so the runner reports several
// problems; the minimizer must still recognise the mismatch it was handed.
func TestAMismatchOfSeveralProblemsIsMinimizedThroughTheGate(t *testing.T) {
	problems := []string{"value: reference 1, owned 2", "annotations: reference [], owned [x]"}
	cfg, row, minimizer, _ := minimizerFixture(t, problems, false)
	first, err := minimizer.RunRows(context.Background(), []GeneratedRow{row})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Generated = []GeneratedRun{{Seed: 20261110, Rows: []GeneratedRow{row}, Oracle: first.PhaseOracle(), Own: first.PhaseOwn()}}
	var handed []string
	cfg.Minimize = func(ctx context.Context, m GeneratedMismatch) (Regression, error) {
		handed = m.Problems
		return minimizer.Minimize(ctx, m)
	}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	if !reflect.DeepEqual(handed, problems) {
		t.Fatalf("the minimizer was handed %q, not the runner's individual problems %q", handed, problems)
	}
	g := rep.Generated[0]
	if g.Mismatched != 1 || g.Executed != 1 || len(g.Regressions) != 1 || failureContains(rep, "minimizing") {
		t.Fatalf("the mismatch was not minimized: %+v %q", g.GeneratedCounts, rep.Failures)
	}
	reg := g.Regressions[0]
	if len(reg.Case.Input) != 1 || len(reg.Case.Expression) >= len(row.Source.Expression) || !strings.Contains(reg.Case.Expression, "label_replace") || !reflect.DeepEqual(reg.Problems, problems) {
		t.Fatalf("not minimized or problems lost: %+v", reg)
	}
}

// A regression is recorded only for a mismatch that still reproduces on the
// minimized case. If the final run no longer disagrees, nothing is recorded,
// and the original problems are not attached to a case that does not have them.
func TestAMinimizedCaseThatNoLongerFailsIsNotRecordedAsARegression(t *testing.T) {
	_, row, minimizer, _ := minimizerFixture(t, []string{"value: reference 1, owned 2"}, true)
	gm := GeneratedMismatch{Seed: 20261110, Row: row, Problems: []string{"value: reference 1, owned 2"}}
	reg, err := minimizer.Minimize(context.Background(), gm)
	if err == nil {
		t.Fatalf("a regression was recorded for a case that no longer fails: %+v", reg)
	}
	if !strings.Contains(err.Error(), "no longer reproduces") {
		t.Fatalf("%v", err)
	}
}

func TestAMinimizerRunThatObservedNothingIsNotTheSameMismatch(t *testing.T) {
	_, row, minimizer, _ := minimizerFixture(t, []string{"value: reference 1, owned 2"}, false)
	gm := GeneratedMismatch{Seed: 1, Row: row, Problems: []string{"value: reference 1, owned 2"}}
	// The runner returns nothing at all: the mismatch does not reproduce.
	minimizer.RunRows = func(context.Context, []GeneratedRow) (PhaseResults, error) {
		return PhaseResults{}, errors.New("runtime missing")
	}
	if _, err := minimizer.Minimize(context.Background(), gm); err == nil {
		t.Fatal("a regression was recorded although the runner observed nothing")
	}
	// The runner returns rows without an oracle identity: no oracle observed them.
	minimizer.RunRows = func(_ context.Context, rs []GeneratedRow) (PhaseResults, error) {
		res := PhaseResults{}
		for _, r := range rs {
			res[PhaseKey(r.Row.Profile, r.Row.ID)] = PhaseOutcome{Phase: r.Phase, Problems: []string{"value: reference 1, owned 2"}}
		}
		return res, nil
	}
	if _, err := minimizer.Minimize(context.Background(), gm); err == nil {
		t.Fatal("a mismatch no oracle observed was minimized")
	}
}

func TestRegressionIdentityNamesItsSeedAndCase(t *testing.T) {
	_, row, minimizer, _ := minimizerFixture(t, []string{"value: reference 1, owned 2"}, false)
	gm := GeneratedMismatch{Seed: 77, Row: row, Problems: []string{"value: reference 1, owned 2"}}
	reg, err := minimizer.Minimize(context.Background(), gm)
	if err != nil {
		t.Fatal(err)
	}
	if reg.ID != fmt.Sprintf("%s/seed-77", row.Source.ID) || reg.Seed != 77 || reg.Profile != row.Row.Profile || reg.Phase != row.Phase || reg.FeatureSet != row.Source.FeatureSet || !reflect.DeepEqual(reg.Enabled, row.Enabled) || reg.Original != row.Source.Expression {
		t.Fatalf("%+v", reg)
	}
}
