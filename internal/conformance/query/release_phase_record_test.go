// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A row several case files observed keeps what every one of them found, however
// many files there are and in whatever order they fail, and names the collision once.
func TestPhaseGlueKeepsEveryFilesVerdictOfARowSeveralFilesObserved(t *testing.T) {
	id := &OracleIdentity{Profile: "p"}
	problemsOf := map[string][]string{"a.json": nil, "b.json": {"b: reference 1, owned 2"}, "c.json": nil, "d.json": {"d: reference x, owned y"}}
	run := phaseRunners{syntax: func(_ context.Context, _ SourceLock, path, _, _ string) (SyntaxPhaseReport, error) {
		return SyntaxPhaseReport{Cases: []SyntaxCaseComparison{{ID: "row", Profile: "p", Identity: id, Mismatches: problemsOf[filepath.Base(path)]}}}, nil
	}}
	files := func(names ...string) ReleaseCaseManifest {
		m := ReleaseCaseManifest{}
		for _, n := range names {
			m.Files = append(m.Files, ReleasePhaseFile{Path: "cases/" + n, Language: "promql", Phase: "syntax"})
		}
		return m
	}
	for name, c := range map[string]struct {
		files []string
		want  []string
	}{
		"the second file fails":                  {[]string{"a.json", "b.json"}, []string{"b: reference 1, owned 2", observedByTwoCaseFiles}},
		"the first fails":                        {[]string{"b.json", "a.json"}, []string{"b: reference 1, owned 2", observedByTwoCaseFiles}},
		"two files fail":                         {[]string{"b.json", "d.json"}, []string{"b: reference 1, owned 2", "d: reference x, owned y", observedByTwoCaseFiles}},
		"three files, the collision named once":  {[]string{"a.json", "b.json", "c.json"}, []string{"b: reference 1, owned 2", observedByTwoCaseFiles}},
		"four files, two failing":                {[]string{"a.json", "b.json", "c.json", "d.json"}, []string{"b: reference 1, owned 2", "d: reference x, owned y", observedByTwoCaseFiles}},
		"two passing files are still a conflict": {[]string{"a.json", "c.json"}, []string{observedByTwoCaseFiles}},
	} {
		res, err := runReleasePhases(context.Background(), run, SourceLock{}, "q", "p", "r", files(c.files...))
		if err != nil {
			t.Fatal(err)
		}
		got := res[PhaseKey("p", "row")]
		// Which problem comes first depends on the order of the files; what matters is
		// that each is there and that the collision is named exactly once.
		have, want := slices.Clone(got.Problems), slices.Clone(c.want)
		slices.Sort(have)
		slices.Sort(want)
		if !slices.Equal(have, want) || got.Identity != id || got.Phase != "promql:syntax" {
			t.Errorf("%s: %+v, want problems %q", name, got, c.want)
		}
	}
	// A row only one file observed carries no collision.
	res, err := runReleasePhases(context.Background(), run, SourceLock{}, "q", "p", "r", files("b.json"))
	if err != nil || !reflect.DeepEqual(res[PhaseKey("p", "row")].Problems, []string{"b: reference 1, owned 2"}) {
		t.Fatalf("%v %+v", err, res)
	}
	// Recording does not write through the backing array of an earlier outcome.
	backing := make([]string, 1, 4)
	backing[0] = "x"
	rec := PhaseResults{}
	rec.record("k", PhaseOutcome{Problems: backing})
	rec.record("k", PhaseOutcome{Problems: []string{"y"}})
	if spare := backing[:2]; spare[1] != "" {
		t.Fatalf("an earlier outcome's backing array was written through: %q", spare)
	}
}

// The evidence stream is read from the query directory: absent is not an error
// (every observation then stays unobserved and the gate says so), unreadable is.
func TestGoTestEvidenceIsLoadedFromTheQueryDirectory(t *testing.T) {
	dir := t.TempDir()
	if raw, err := loadGoTestEvidence(dir); raw != nil || err != nil {
		t.Fatalf("a stream that was never recorded: %q %v", raw, err)
	}
	stream := goTestStream("TestA", "TestB")
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(goTestEvidenceFile)), stream, 0o644); err != nil {
		t.Fatal(err)
	}
	if raw, err := loadGoTestEvidence(dir); err != nil || string(raw) != string(stream) {
		t.Fatalf("the recorded stream: %q %v", raw, err)
	}
	broken := t.TempDir()
	if err := os.MkdirAll(filepath.Join(broken, filepath.FromSlash(goTestEvidenceFile)), 0o755); err != nil {
		t.Fatal(err)
	}
	if raw, err := loadGoTestEvidence(broken); err == nil {
		t.Fatalf("an unreadable stream was reported as absent: %q", raw)
	}
}

// The regression records what the minimized case itself does: the problems of the
// final verifying run, not the text of the original, larger case.
func TestARegressionCarriesTheProblemsOfItsMinimizedCase(t *testing.T) {
	_, row, base, _ := minimizerFixture(t, nil, false)
	identity := &OracleIdentity{Profile: row.Row.Profile}
	problem := func(expression string) string { return fmt.Sprintf("syntax error at 1:%d", len(expression)) }
	runner := func(_ context.Context, rs []GeneratedRow) (PhaseResults, error) {
		res := PhaseResults{}
		for _, r := range rs {
			ev := r.payload.(EvaluationCase)
			o := PhaseOutcome{Phase: r.Phase, Identity: identity}
			if strings.Contains(ev.Query, "label_replace") && strings.Count(ev.Query, "(") == strings.Count(ev.Query, ")") {
				o.Problems = []string{problem(ev.Query), "annotations: reference [], owned [x]"}
			}
			res[PhaseKey(r.Row.Profile, r.Row.ID)] = o
		}
		return res, nil
	}
	m := GeneratedMinimizer{Domains: base.Domains, RunRows: runner}
	reg, err := m.Minimize(context.Background(), GeneratedMismatch{Seed: 3, Row: row, Problems: []string{problem(row.Source.Expression)}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{problem(reg.Case.Expression), "annotations: reference [], owned [x]"}
	if len(reg.Case.Expression) >= len(row.Source.Expression) || !reflect.DeepEqual(reg.Problems, want) {
		t.Fatalf("minimized %q (from %q), problems %q, want %q", reg.Case.Expression, row.Source.Expression, reg.Problems, want)
	}
}
