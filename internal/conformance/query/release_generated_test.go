// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureGeneratedRun is n generated rows over the three exact profiles with a
// fake oracle that returns the locked identity and a fake owned engine that
// agrees. Row i names its expression "e<i>", so a test can poison one row.
func fixtureGeneratedRun(cfg ReleaseConfig, seed uint64, n int) GeneratedRun {
	profiles := []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5", "logql-loki-3.5.2"}
	tags := []string{tagPromEvaluation, tagPromSyntax, tagLogMetric}
	run := GeneratedRun{Seed: seed}
	for i := 0; i < n; i++ {
		p, tag := profiles[i%3], tags[i%3]
		id := "gen/" + p + "/c" + string(rune('0'+i))
		run.Rows = append(run.Rows, GeneratedRow{
			Row:    ReleaseCase{ID: id, Profile: p, Expected: SemanticResult{Kind: "phase-case", Type: tag}},
			Phase:  tag,
			Source: Case{ID: id, Language: "promql", Profile: p, Expression: "sum(m) + e" + string(rune('0'+i)), Input: []InputRecord{{Kind: "float", Timestamp: "10"}}},
		})
	}
	run.Oracle = func(_ context.Context, p SourceProfile, c ReleaseCase) (SemanticResult, error) {
		r := c.Expected
		version := strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-")
		r.Oracle = &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: version, ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}
		return r, nil
	}
	run.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) { return c.Expected, nil }
	return run
}

func TestReleaseCountsGeneratedCasesPerSeed(t *testing.T) {
	cfg := releaseFixture(t)
	cfg.Generated = []GeneratedRun{fixtureGeneratedRun(cfg, 20261110, 6), fixtureGeneratedRun(cfg, 20270101, 3)}
	rep, err := ReleaseGate(context.Background(), cfg)
	if err != nil || len(rep.Generated) != 2 {
		t.Fatalf("%v %+v", err, rep.Generated)
	}
	g := rep.Generated[0]
	if g.Seed != 20261110 || g.Generated != 6 || g.Executed != 6 || g.Matched != 6 || g.Mismatched != 0 || g.Unrun != 0 || g.ByPhase[tagPromSyntax].Executed != 2 {
		t.Fatalf("counts: %+v", g)
	}
	if rep.Generated[1].Seed != 20270101 || rep.Generated[1].Executed != 3 {
		t.Fatalf("second seed: %+v", rep.Generated[1])
	}
}

func TestReleaseRejectsAMismatchingGeneratedCaseAndMinimizesIt(t *testing.T) {
	cfg := releaseFixture(t)
	run := fixtureGeneratedRun(cfg, 20261110, 3)
	run.Rows[1].Source.Expression = "sum(m) + BAD"
	run.Rows[1].Source.Input = []InputRecord{{Kind: "float", Timestamp: "1"}, {Kind: "float", Timestamp: "2", Bits: StaleBits}}
	run.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		if c.ID == run.Rows[1].Row.ID {
			return SemanticResult{}, errors.New("value: reference 1, owned 2")
		}
		return c.Expected, nil
	}
	cfg.Generated = []GeneratedRun{run}
	predicate := func(c Case) (bool, error) {
		stale := false
		for _, in := range c.Input {
			stale = stale || in.Bits == StaleBits
		}
		return stale && strings.Contains(c.Expression, "BAD"), nil
	}
	cfg.Minimize = func(ctx context.Context, m GeneratedMismatch) (Regression, error) {
		min, err := Minimize(ctx, CaseMismatch{Case: m.Row.Source}, predicate)
		return Regression{ID: m.Row.Source.ID + "/seed", Seed: m.Seed, Profile: m.Row.Row.Profile, Phase: m.Row.Phase, Problems: m.Problems, Original: m.Row.Source.Expression, Case: min}, err
	}
	rep, err := ReleaseGate(context.Background(), cfg)
	if !errors.Is(err, ErrReleaseRejected) || rep.UnresolvedCount == 0 {
		t.Fatalf("a mismatching generated case did not fail the gate: %v", err)
	}
	g := rep.Generated[0]
	if g.Mismatched != 1 || g.Matched != 2 || g.Executed != 3 || g.Unrun != 0 || len(g.MismatchedRows) != 1 {
		t.Fatalf("counts: %+v", g.GeneratedCounts)
	}
	if len(g.Regressions) != 1 {
		t.Fatalf("regressions: %+v", g.Regressions)
	}
	r := g.Regressions[0]
	if len(r.Case.Input) != 1 || r.Case.Input[0].Bits != StaleBits || len(r.Case.Expression) >= len(r.Original) || !strings.Contains(r.Case.Expression, "BAD") || len(r.Problems) == 0 {
		t.Fatalf("not minimized: %+v", r)
	}
}

func TestReleaseCountsAnUnobservedGeneratedCaseAsUnrun(t *testing.T) {
	cfg := releaseFixture(t)
	run := fixtureGeneratedRun(cfg, 20261110, 3)
	run.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		if c.ID == run.Rows[2].Row.ID {
			return SemanticResult{}, errors.Join(ErrNotObserved, errors.New("the owned engine was not run"))
		}
		return c.Expected, nil
	}
	cfg.Generated = []GeneratedRun{run}
	rep, err := ReleaseGate(context.Background(), cfg)
	g := rep.Generated[0]
	if !errors.Is(err, ErrReleaseRejected) || g.Unrun != 1 || g.Mismatched != 0 || g.Executed != 2 || g.Executed+g.Unrun != g.Generated || len(g.UnrunRows) != 1 {
		t.Fatalf("%v %+v", err, g.GeneratedCounts)
	}
	// An oracle observation with the wrong image identity is not an execution either.
	cfg = releaseFixture(t)
	run = fixtureGeneratedRun(cfg, 20261110, 3)
	good := run.Oracle
	run.Oracle = func(ctx context.Context, p SourceProfile, c ReleaseCase) (SemanticResult, error) {
		r, err := good(ctx, p, c)
		if c.ID == run.Rows[0].Row.ID {
			r.Oracle.ImageSHA256 = strings.Repeat("0", 64)
		}
		return r, err
	}
	cfg.Generated = []GeneratedRun{run}
	if rep, err = ReleaseGate(context.Background(), cfg); !errors.Is(err, ErrReleaseRejected) || rep.Generated[0].Unrun != 1 {
		t.Fatalf("%v %+v", err, rep.Generated[0].GeneratedCounts)
	}
}

func TestReleaseRejectsZeroExecutedGeneratedCases(t *testing.T) {
	// No generated run at all.
	cfg := releaseFixture(t)
	cfg.Generated = nil
	if _, err := ReleaseGate(context.Background(), cfg); !errors.Is(err, ErrReleaseRejected) {
		t.Fatalf("no generated run passed: %v", err)
	}
	// Rows generated, but the oracle never ran.
	cfg = releaseFixture(t)
	run := fixtureGeneratedRun(cfg, 20261110, 3)
	run.Oracle = nil
	cfg.Generated = []GeneratedRun{run}
	rep, err := ReleaseGate(context.Background(), cfg)
	if !errors.Is(err, ErrReleaseRejected) || rep.Generated[0].Executed != 0 || rep.Generated[0].Unrun != 3 || !failureContains(rep, "zero generated cases executed") {
		t.Fatalf("%v %+v %v", err, rep.Generated[0].GeneratedCounts, rep.Failures)
	}
	// A seed that generated nothing.
	cfg = releaseFixture(t)
	cfg.Generated = []GeneratedRun{fixtureGeneratedRun(cfg, 20261110, 3), fixtureGeneratedRun(cfg, 20270101, 0)}
	rep, err = ReleaseGate(context.Background(), cfg)
	if !errors.Is(err, ErrReleaseRejected) || !failureContains(rep, "no generated cases") {
		t.Fatalf("%v %v", err, rep.Failures)
	}
}

func failureContains(r Report, text string) bool {
	for _, f := range r.Failures {
		if strings.Contains(f, text) {
			return true
		}
	}
	return false
}

func loadPlanInputs(t testing.TB) (GenerationSpec, Ledger, []GateDomain) {
	t.Helper()
	spec, err := LoadGenerationSpec(queryRoot("generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ledger Ledger
	if err = ReadJSON(queryRoot("obligations.json"), &ledger); err != nil {
		t.Fatal(err)
	}
	var domains struct {
		Domains []GateDomain `json:"domains"`
	}
	if err = ReadJSON(queryRoot("gate-domains.json"), &domains); err != nil {
		t.Fatal(err)
	}
	return spec, ledger, domains.Domains
}

func renderRows(t testing.TB, rows []GeneratedRow) map[string]string {
	t.Helper()
	byTag := map[string][]GeneratedRow{}
	for _, r := range rows {
		byTag[r.Phase] = append(byTag[r.Phase], r)
	}
	out := map[string]string{}
	for tag, rs := range byTag {
		name, raw, err := phaseFile(tag, rs)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(raw)
	}
	return out
}

func TestPlannedGeneratedRowsAreDeterministicAndCoverEveryPhaseAndFeatureSet(t *testing.T) {
	spec, ledger, domains := loadPlanInputs(t)
	a, err := PlanGenerated(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PlanGenerated(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	c, err := PlanGenerated(spec, ledger, domains, 20270101)
	if err != nil {
		t.Fatal(err)
	}
	ra, rb, rc := renderRows(t, a), renderRows(t, b), renderRows(t, c)
	same := len(ra) == len(rb)
	for k := range ra {
		same = same && ra[k] == rb[k]
	}
	if !same {
		t.Fatal("the same seed produced different rows")
	}
	differs := false
	for k := range ra {
		differs = differs || ra[k] != rc[k]
	}
	if !differs {
		t.Fatal("different seeds produced identical rows")
	}
	tags := map[string]int{}
	setsOf := map[string]map[string]bool{}
	for _, r := range a {
		tags[r.Phase]++
		if setsOf[r.Row.Profile] == nil {
			setsOf[r.Row.Profile] = map[string]bool{}
		}
		setsOf[r.Row.Profile][r.Source.FeatureSet] = true
	}
	for _, tag := range []string{tagPromEvaluation, tagPromSyntax, tagLogSyntax, tagLogPipeline, tagLogMetric} {
		if tags[tag] == 0 {
			t.Fatalf("no generated rows for phase %s: %v", tag, tags)
		}
	}
	for _, d := range domains {
		if len(setsOf[d.Profile]) != len(d.FeatureSets) {
			t.Fatalf("%s: rows cover %d of %d registered feature sets", d.Profile, len(setsOf[d.Profile]), len(d.FeatureSets))
		}
	}
}

// Every concrete-input kind the task names appears in the generated rows.
func TestPlannedGeneratedRowsCarryTheConcreteInputKinds(t *testing.T) {
	spec, ledger, domains := loadPlanInputs(t)
	rows, err := PlanGenerated(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	all := renderRows(t, rows)
	joined := ""
	for _, v := range all {
		joined += v
	}
	for name, needle := range map[string]string{
		"stale marker":      `"7ff0000000000002"`,
		"NaN":               `"7ff8000000000001"`,
		"native histogram":  `"positive_buckets"`,
		"counter reset":     `"count": "6"`,
		"tie across series": `"worker"`,
		"newline label":     `a\nb`,
		"topk ties":         `topk(1,`,
		"disabled gate":     `m + fill(0) m`,
	} {
		if !strings.Contains(joined, needle) {
			t.Errorf("no generated row carries %s (%s)", name, needle)
		}
	}
}

// The generated files are accepted by the strict runner readers only through
// the content lock written for them; changing a byte afterwards is refused.
func TestGeneratedFilesAreContentLockedForTheRunners(t *testing.T) {
	spec, ledger, domains := loadPlanInputs(t)
	rows, err := PlanGenerated(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	var sample []GeneratedRow
	seen := map[string]int{}
	for _, r := range rows {
		if seen[r.Phase+r.Row.Profile] < 6 {
			seen[r.Phase+r.Row.Profile]++
			sample = append(sample, r)
		}
	}
	env := GeneratedEnv{Lock: loadRealLock(t), QueryDir: queryRoot(), ProfilesDir: filepath.Join(queryRoot(), "..", "..", "profiles", "query")}
	env.Lock.LedgerPath = queryRoot("obligations.json")
	lock, qdir, manifest, cleanup, err := env.prepare(sample)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err = Inventory(context.Background(), lock); err != nil {
		t.Fatalf("mirror lock does not pass the inventory: %v", err)
	}
	for _, f := range manifest.Files {
		path := filepath.Join(qdir, filepath.FromSlash(f.Path))
		var n int
		switch {
		case f.Language == "promql" && f.Phase == "syntax":
			cs, e := readLockedSyntaxCases(lock, path)
			n, err = len(cs), e
		case f.Language == "promql":
			cs, e := readEvaluationCases(lock, []string{path})
			n, err = len(cs), e
		default:
			cs, e := readLogQLCases(lock, path, f.Phase)
			n, err = len(cs), e
		}
		if err != nil || n == 0 {
			t.Fatalf("%s: %d cases, %v", f.Path, n, err)
		}
	}
	first := filepath.Join(qdir, filepath.FromSlash(manifest.Files[0].Path))
	raw, _ := os.ReadFile(first)
	if err = os.WriteFile(first, append(raw, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	var sink json.RawMessage
	if err = ReadLockedJSON(lock, "cases/"+filepath.Base(first), first, &sink); err == nil {
		t.Fatal("a tampered generated file was read")
	}
}

func TestGeneratedMinimizerShrinksThroughThePhaseRunners(t *testing.T) {
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
	runs := 0
	// The fake runner reports a mismatch while the query still holds label_replace
	// AND the series still holds a stale marker.
	fake := func(_ context.Context, rows []GeneratedRow) (PhaseResults, error) {
		runs++
		res := PhaseResults{}
		for _, r := range rows {
			ev := r.payload.(EvaluationCase)
			stale := false
			for _, s := range ev.Series {
				for _, sm := range s.Samples {
					stale = stale || (sm.Float != nil && uint64(*sm.Float) == 0x7ff0000000000002)
				}
			}
			o := PhaseOutcome{Phase: r.Phase, Identity: &OracleIdentity{}}
			switch {
			case strings.Count(ev.Query, "(") != strings.Count(ev.Query, ")"):
				// A shrunk query that no longer parses disagrees too, but it is
				// a different mismatch and must not be accepted as the same one.
				o.Problems = []string{"error.unclassified: reference parse-error 1:30, owned syntax 29"}
			case stale && strings.Contains(ev.Query, "label_replace"):
				o.Problems = []string{"value: reference 1, owned 2"}
			}
			res[PhaseKey(r.Row.Profile, r.Row.ID)] = o
		}
		return res, nil
	}
	rows, err := rowsFor(target, domainSets(domains))
	if err != nil || len(rows) == 0 {
		t.Fatalf("%v", err)
	}
	gm := GeneratedMismatch{Seed: 20261110, Row: rows[0], Problems: []string{"value: reference 1, owned 2"}}
	reg, err := GeneratedMinimizer{Domains: domains, RunRows: fake}.Minimize(context.Background(), gm)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Case.Input) != 1 || reg.Case.Input[0].Bits != StaleBits || len(reg.Case.Expression) >= len(target.Expression) || !strings.Contains(reg.Case.Expression, "label_replace") || strings.Count(reg.Case.Expression, "(") != strings.Count(reg.Case.Expression, ")") || reg.FeatureSet != gm.Row.Source.FeatureSet || runs < 2 {
		t.Fatalf("not minimized through the runners (%d runs): %+v", runs, reg)
	}
	// A mismatch that does not reproduce is refused, not recorded.
	none := func(context.Context, []GeneratedRow) (PhaseResults, error) { return PhaseResults{}, nil }
	if _, err = (GeneratedMinimizer{Domains: domains, RunRows: none}).Minimize(context.Background(), gm); err == nil {
		t.Fatal("a mismatch that does not reproduce was minimized")
	}
}

func TestWriteRegressionsCreatesCaseFilesAndMergesTheIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"schema":"soundpost-query-regressions/1","description":"x","regressions":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := Regression{ID: "gen/promql-prometheus-3.13.5/k@fsabcd0123/seed-1", Seed: 1, Profile: "promql-prometheus-3.13.5", Phase: tagPromEvaluation, Problems: []string{"p"}, Original: "long", Case: Case{ID: "gen/k", Expression: "m"}}
	for i := 0; i < 2; i++ { // writing twice must not duplicate the entry
		if err := WriteRegressions(dir, []Regression{reg}); err != nil {
			t.Fatal(err)
		}
	}
	var idx struct {
		Regressions []map[string]any `json:"regressions"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if err := json.Unmarshal(raw, &idx); err != nil || len(idx.Regressions) != 1 {
		t.Fatalf("%v %s", err, raw)
	}
	file, _ := idx.Regressions[0]["file"].(string)
	var back Regression
	body, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil || json.Unmarshal(body, &back) != nil || back.Case.Expression != "m" || back.Seed != 1 {
		t.Fatalf("%v %s", err, body)
	}
	empty := t.TempDir()
	if err = WriteRegressions(empty, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(empty, "index.json")); err == nil {
		t.Fatal("an empty regression set created an index")
	}
}
