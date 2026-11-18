// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func cloneSpec(t testing.TB, s GenerationSpec) GenerationSpec {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out GenerationSpec
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func realSpec(t testing.TB) GenerationSpec {
	t.Helper()
	spec, err := LoadGenerationSpec(queryRoot("generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// A declaration the generator cannot honour must be an error. Silently dropping
// it (a negative form for a language nothing generates, an exclusion of nothing,
// a higher-order "tuple" of one coordinate that every case trivially contains)
// shrinks the coverage the gate believes it demands.
func TestGenerationSpecValidateRejectsEveryUnsoundDeclaration(t *testing.T) {
	faults := []struct {
		name   string
		mutate func(s *GenerationSpec)
		want   string
	}{
		{"unknown schema", func(s *GenerationSpec) { s.Schema = "soundpost-query-generation/2" }, "invalid generation spec"},
		{"no language", func(s *GenerationSpec) { s.Languages = nil }, "invalid generation spec"},
		{"a language nothing generates", func(s *GenerationSpec) { s.Languages[0].Language = "sql" }, "language sql is not a query language"},
		{"a language declared twice", func(s *GenerationSpec) { s.Languages = append(s.Languages, s.Languages[0]) }, "language promql declared twice"},
		{"a language without profiles", func(s *GenerationSpec) { s.Languages[0].Profiles = nil }, "language promql has no profiles"},
		{"an unknown profile", func(s *GenerationSpec) { s.Languages[0].Profiles[0] = "promql-prometheus-9.9.9" }, "unknown profile promql-prometheus-9.9.9"},
		{"another language's profile", func(s *GenerationSpec) { s.Languages[0].Profiles = []string{"logql-loki-3.5.2"} }, "profile logql-loki-3.5.2 is not a promql profile"},
		{"a profile named twice", func(s *GenerationSpec) {
			s.Languages[0].Profiles = []string{"promql-prometheus-3.1.0", "promql-prometheus-3.1.0"}
		}, "names profile promql-prometheus-3.1.0 twice"},
		{"a single axis", func(s *GenerationSpec) { s.Languages[0].Axes = s.Languages[0].Axes[:1] }, "needs two or more axes"},
		{"an axis without an id", func(s *GenerationSpec) { s.Languages[0].Axes[0].ID = "" }, "axis"},
		{"a duplicate axis", func(s *GenerationSpec) { s.Languages[0].Axes[1].ID = s.Languages[0].Axes[0].ID }, "axis"},
		{"an axis of one value", func(s *GenerationSpec) { s.Languages[0].Axes[0].Values = s.Languages[0].Axes[0].Values[:1] }, "axis"},
		{"an empty axis value", func(s *GenerationSpec) { s.Languages[0].Axes[0].Values[0] = "" }, "duplicate axis value"},
		{"a duplicate axis value", func(s *GenerationSpec) { s.Languages[0].Axes[0].Values[1] = s.Languages[0].Axes[0].Values[0] }, "duplicate axis value"},
		{"an exclusion in an undeclared language", func(s *GenerationSpec) { s.Excluded[0].Language = "sql" }, "undeclared language sql"},
		{"an exclusion of one coordinate", func(s *GenerationSpec) { s.Excluded[0].Pair = s.Excluded[0].Pair[:1] }, "exactly two"},
		{"an exclusion of three coordinates", func(s *GenerationSpec) {
			s.Excluded[0].Pair = append(s.Excluded[0].Pair, "time_window=none")
		}, "exactly two"},
		{"an exclusion of an undeclared coordinate", func(s *GenerationSpec) { s.Excluded[0].Pair[0] = "sample_kind=gauge" }, "undeclared coordinate sample_kind=gauge"},
		{"an exclusion of two values of one axis", func(s *GenerationSpec) {
			s.Excluded[0].Pair = []string{"sample_kind=float", "sample_kind=stale"}
		}, "one axis"},
		{"an exclusion without a reason", func(s *GenerationSpec) { s.Excluded[0].Reason = "" }, "no reason"},
		{"a higher-order tuple in an undeclared language", func(s *GenerationSpec) { s.HigherOrder[0].Language = "sql" }, "undeclared language sql"},
		{"a higher-order tuple of two coordinates", func(s *GenerationSpec) { s.HigherOrder[0].Tuple = s.HigherOrder[0].Tuple[:2] }, "fewer than three"},
		{"a higher-order tuple of nothing", func(s *GenerationSpec) { s.HigherOrder[0].Tuple = nil }, "fewer than three"},
		{"a higher-order tuple of an undeclared coordinate", func(s *GenerationSpec) { s.HigherOrder[0].Tuple[0] = "sample_kind=gauge" }, "undeclared coordinate sample_kind=gauge"},
		{"a higher-order tuple that repeats an axis", func(s *GenerationSpec) {
			s.HigherOrder[0].Tuple = []string{"sample_kind=float", "sample_kind=stale", "time_window=none"}
		}, "repeats axis sample_kind"},
		{"a negative form without an id", func(s *GenerationSpec) { s.NegativeForms[0].ID = "" }, "negative form without an id"},
		{"a negative form for an undeclared language", func(s *GenerationSpec) { s.NegativeForms[0].Language = "sql" }, "undeclared language sql"},
		{"a negative form without a placeholder", func(s *GenerationSpec) { s.NegativeForms[0].Wrap = "(" }, "exactly one %s"},
		{"a negative form with two placeholders", func(s *GenerationSpec) { s.NegativeForms[0].Wrap = "%s +%s" }, "exactly one %s"},
		{"a negative form without a category", func(s *GenerationSpec) { s.NegativeForms[0].Category = "" }, "no category"},
		{"a negative form declared twice", func(s *GenerationSpec) { s.NegativeForms = append(s.NegativeForms, s.NegativeForms[0]) }, "declared twice"},
		{"a gate probe for an unknown profile", func(s *GenerationSpec) { s.GateProbes[0].Profile = "promql-prometheus-9.9.9" }, "unknown profile promql-prometheus-9.9.9"},
		{"a gate probe without a gate", func(s *GenerationSpec) { s.GateProbes[0].Gate = "" }, "needs a gate, an expression and a category"},
		{"a gate probe without an expression", func(s *GenerationSpec) { s.GateProbes[0].Expression = "" }, "needs a gate, an expression and a category"},
		{"a gate probe without a category", func(s *GenerationSpec) { s.GateProbes[0].Category = "" }, "needs a gate, an expression and a category"},
		{"a gate probe declared twice", func(s *GenerationSpec) { s.GateProbes = append(s.GateProbes, s.GateProbes[0]) }, "declared twice"},
	}
	if err := realSpec(t).Validate(); err != nil {
		t.Fatalf("the locked spec must validate: %v", err)
	}
	for _, f := range faults {
		s := cloneSpec(t, realSpec(t))
		f.mutate(&s)
		err := s.Validate()
		if err == nil {
			t.Errorf("%s: the unsound spec validated", f.name)
		} else if !strings.Contains(err.Error(), f.want) {
			t.Errorf("%s: error %q does not mention %q", f.name, err, f.want)
		}
	}
}

// Generate refuses a spec declaring a value or axis the generator's builders
// cannot express: a coordinate that changes nothing would be counted as covered.
func TestGenerateRefusesDeclarationsItCannotImplement(t *testing.T) {
	_, ledger, domains, registry, _ := genFixture(t)
	faults := []struct {
		name   string
		mutate func(s *GenerationSpec)
		want   string
	}{
		{"an axis value no builder implements", func(s *GenerationSpec) {
			a := &s.Languages[0].Axes[1]
			a.Values = append(a.Values, "bogus")
		}, "bogus"},
		{"an axis no builder reads", func(s *GenerationSpec) {
			s.Languages[1].Axes = append(s.Languages[1].Axes, AxisSpec{ID: "weather", Values: []string{"dry", "wet"}})
		}, "weather"},
		{"an axis value no builder knows by that name", func(s *GenerationSpec) {
			s.Languages[0].Axes[1].Values[0] = "wibble"
		}, "wibble"},
	}
	for _, f := range faults {
		s := cloneSpec(t, realSpec(t))
		f.mutate(&s)
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: the fixture spec must be structurally sound: %v", f.name, err)
		}
		if _, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{Spec: s, Domains: domains}); err == nil || !strings.Contains(err.Error(), f.want) {
			t.Errorf("%s: Generate answered %v, want an error naming %q", f.name, err, f.want)
		}
	}
	// A gate probe needs a registered domain of its profile, and a gate that domain owns.
	probes := []struct {
		name    string
		domains func() []GateDomain
		mutate  func(s *GenerationSpec)
		want    string
	}{
		{"a probe whose profile has no domain", func() []GateDomain {
			var out []GateDomain
			for _, d := range domains {
				if d.Profile != "promql-prometheus-3.13.5" {
					out = append(out, d)
				}
			}
			return out
		}, func(*GenerationSpec) {}, "no registered gate domain"},
		{"a probe of a gate the domain does not have", func() []GateDomain { return domains }, func(s *GenerationSpec) {
			s.GateProbes[0].Gate = "promql-no-such-gate"
		}, "promql-no-such-gate"},
	}
	for _, p := range probes {
		s := cloneSpec(t, realSpec(t))
		p.mutate(&s)
		if _, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{Spec: s, Domains: p.domains()}); err == nil || !strings.Contains(err.Error(), p.want) {
			t.Errorf("%s: Generate answered %v, want an error naming %q", p.name, err, p.want)
		}
	}
	if _, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{Spec: realSpec(t), Domains: domains}); err != nil {
		t.Fatalf("the locked spec must generate: %v", err)
	}
}

func TestGenerateHonoursTheCaseBudgetExactly(t *testing.T) {
	spec, ledger, domains, registry, _ := genFixture(t)
	all, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{Spec: spec, Domains: domains})
	if err != nil {
		t.Fatal(err)
	}
	n := len(all)
	if got, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{MaxCases: n, Spec: spec, Domains: domains}); err != nil || len(got) != n {
		t.Fatalf("a budget of exactly the required set was refused: %v %d/%d", err, len(got), n)
	}
	if _, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{MaxCases: n - 1, Spec: spec, Domains: domains}); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("a budget one short of the required set was not an error: %v", err)
	}
	// Cancelling stops generation with the context's error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Generate(ctx, registry, ledger, 1, GenerationBudget{Spec: spec, Domains: domains}); err == nil {
		t.Fatal("generation continued on a cancelled context")
	}
}

// Seed-drawn extras supplement the exhaustive set: one valid case per profile of
// each language per extra, never negative, never a duplicate ID.
func TestGenerateSeedDrawnExtrasSupplementAndNeverReplace(t *testing.T) {
	_, ledger, domains, registry, _ := genFixture(t)
	spec := realSpec(t)
	base, err := Generate(context.Background(), registry, ledger, 5, GenerationBudget{Spec: spec, Domains: domains})
	if err != nil {
		t.Fatal(err)
	}
	const random = 5
	more, err := Generate(context.Background(), registry, ledger, 5, GenerationBudget{Spec: spec, Domains: domains, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	profilesPerRun := 0
	for _, l := range spec.Languages {
		profilesPerRun += len(l.Profiles)
	}
	if len(more) != len(base)+random*profilesPerRun {
		t.Fatalf("%d cases with %d extras, %d without: want %d more", len(more), random, len(base), random*profilesPerRun)
	}
	ids := map[string]bool{}
	var extras int
	for _, c := range more {
		if ids[c.ID] {
			t.Fatalf("duplicate case ID %s", c.ID)
		}
		ids[c.ID] = true
		if strings.Contains(c.ID, "#extra") {
			extras++
			if c.Kind != "valid" || spec.ValidateCombination(c.Language, c.Coordinate) != nil {
				t.Fatalf("extra %s is not a valid-combination valid case: %+v", c.ID, c)
			}
		}
	}
	if extras != random*profilesPerRun {
		t.Fatalf("%d extras, want %d", extras, random*profilesPerRun)
	}
	for _, c := range base {
		if !ids[c.ID] {
			t.Fatalf("the exhaustive case %s was replaced by the extras", c.ID)
		}
	}
	for _, c := range base {
		if c.Seed != 5 {
			t.Fatalf("case %s carries seed %d, not the seed it was generated from", c.ID, c.Seed)
		}
	}
}

// Every declared value of every axis changes what is generated. A value that
// does not (a typo'd or unimplemented one) would be counted as a covered
// coordinate while exercising nothing.
func TestEveryDeclaredAxisValueChangesWhatIsGenerated(t *testing.T) {
	spec := realSpec(t)
	for _, l := range spec.Languages {
		base := map[string]string{}
		for _, a := range l.Axes {
			base[a.ID] = a.Values[0]
		}
		for _, a := range l.Axes {
			seen := map[string]string{}
			for _, v := range a.Values {
				c := map[string]string{}
				for k, x := range base {
					c[k] = x
				}
				c[a.ID] = v
				r := &splitmix{s: 7}
				var expr string
				var in []InputRecord
				if l.Language == "promql" {
					expr, in = promExpression(c, r), promInput(c)
				} else {
					expr, in = logExpression(c, r), logInput(c)
				}
				raw, _ := json.Marshal(in)
				key := expr + "\x00" + string(raw)
				if prev, dup := seen[key]; dup {
					t.Errorf("%s: %s=%s generates the same case as %s=%s", l.Language, a.ID, v, a.ID, prev)
				}
				seen[key] = v
			}
		}
	}
}

func tinySpec() GenerationSpec {
	return GenerationSpec{
		Schema: "soundpost-query-generation/1",
		Languages: []LanguageSpec{{
			Language: "promql", Profiles: []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"},
			Axes: []AxisSpec{{ID: "a", Values: []string{"x", "y"}}, {ID: "b", Values: []string{"p", "q"}}, {ID: "c", Values: []string{"m", "n"}}},
		}},
		Excluded:    []ExcludedCombo{{Language: "promql", Pair: []string{"a=x", "b=q"}, Reason: "x and q never meet"}},
		HigherOrder: []TupleSpec{{Language: "promql", Tuple: []string{"a=y", "b=q", "c=n"}}},
	}
}

// tinyCases are the valid cases of the tiny spec: every non-excluded assignment.
func tinyCases(spec GenerationSpec) []Case {
	l := spec.Languages[0]
	var out []Case
	for _, tuple := range tuples(l) {
		if spec.ValidateCombination(l.Language, tuple) == nil {
			out = append(out, Case{Kind: "valid", Language: l.Language, Profile: l.Profiles[0], Coordinate: tuple})
		}
	}
	return out
}

func TestCoverageCountsExactlyTheApplicableInteractionsTheCasesCarry(t *testing.T) {
	spec := tinySpec()
	cases := tinyCases(spec)
	if len(cases) != 6 {
		t.Fatalf("the tiny spec has %d valid tuples, want 6", len(cases))
	}
	// 3 applicable a-b pairs (one excluded) + 4 a-c + 4 b-c + 1 higher-order tuple.
	if cov := Coverage(spec, cases); cov.Required != 12 || cov.Covered != 12 || len(cov.Missing) != 0 {
		t.Fatalf("full cross product: %+v", cov)
	}
	carries := func(c Case) bool {
		return c.Coordinate["a"] == "y" && c.Coordinate["b"] == "q" && c.Coordinate["c"] == "n"
	}
	without := func(drop func(Case) bool) []Case {
		var out []Case
		for _, c := range cases {
			if !drop(c) {
				out = append(out, c)
			}
		}
		return out
	}
	// The only valid case with b=q and c=n also is the higher-order tuple.
	cov := Coverage(spec, without(carries))
	if cov.Required != 12 || cov.Covered != 10 || len(cov.Missing) != 2 || cov.Missing[0] != "promql:b=q|c=n" || cov.Missing[1] != "promql:a=y|b=q|c=n" {
		t.Fatalf("one case removed: %+v", cov)
	}
	// Only valid cases count: a negative or gate case carrying the coordinates is not coverage.
	var wrongKind []Case
	for _, c := range cases {
		if carries(c) {
			c.Kind = "negative"
		}
		wrongKind = append(wrongKind, c)
	}
	if cov := Coverage(spec, wrongKind); cov.Covered != 10 {
		t.Fatalf("a negative case counted as coverage: %+v", cov)
	}
	// Only the first profile's cases count, and only for their own language.
	other := append([]Case(nil), cases...)
	for i := range other {
		other[i].Profile = "promql-prometheus-3.13.5"
	}
	if cov := Coverage(spec, other); cov.Covered != 0 || len(cov.Missing) != 12 {
		t.Fatalf("cases of the second profile counted: %+v", cov)
	}
	foreign := append([]Case(nil), cases...)
	for i := range foreign {
		foreign[i].Language = "logql"
	}
	if cov := Coverage(spec, foreign); cov.Covered != 0 {
		t.Fatalf("cases of another language counted: %+v", cov)
	}
	// A case that does not state its coordinates carries no interaction.
	blank := append([]Case(nil), cases...)
	for i := range blank {
		blank[i].Coordinate = nil
	}
	if cov := Coverage(spec, blank); cov.Covered != 0 {
		t.Fatalf("cases without coordinates counted: %+v", cov)
	}
	if cov := Coverage(spec, nil); cov.Required != 12 || cov.Covered != 0 {
		t.Fatalf("no cases: %+v", cov)
	}
	// A higher-order tuple is covered only when one case carries all of it.
	split := tinySpec()
	split.HigherOrder = []TupleSpec{{Language: "promql", Tuple: []string{"a=x", "b=p", "c=n"}}}
	two := []Case{{Kind: "valid", Language: "promql", Profile: "promql-prometheus-3.1.0", Coordinate: map[string]string{"a": "x", "b": "p", "c": "m"}}, {Kind: "valid", Language: "promql", Profile: "promql-prometheus-3.1.0", Coordinate: map[string]string{"a": "y", "b": "p", "c": "n"}}}
	if cov := Coverage(split, two); !strings.Contains(strings.Join(cov.Missing, ","), "promql:a=x|b=p|c=n") {
		t.Fatalf("a tuple spread over two cases was counted: %+v", cov)
	}
	// An exclusion applies in both orders and only in its own language.
	reversed := tinySpec()
	reversed.Excluded[0].Pair = []string{"b=q", "a=x"}
	if cov := Coverage(reversed, cases); cov.Required != 12 {
		t.Fatalf("a reversed exclusion was not applied: %+v", cov)
	}
	foreignExclusion := tinySpec()
	foreignExclusion.Excluded[0].Language = "logql"
	if cov := Coverage(foreignExclusion, cases); cov.Required != 13 {
		t.Fatalf("an exclusion of another language was applied: %+v", cov)
	}
	// Higher-order tuples of another language are not required of this one.
	foreignTuple := tinySpec()
	foreignTuple.HigherOrder[0].Language = "logql"
	if cov := Coverage(foreignTuple, cases); cov.Required != 11 {
		t.Fatalf("a tuple of another language was required: %+v", cov)
	}
}

func TestValidateCombinationRejectsWhatItMust(t *testing.T) {
	spec := tinySpec()
	ok := map[string]string{"a": "x", "b": "p", "c": "m"}
	if err := spec.ValidateCombination("promql", ok); err != nil {
		t.Fatalf("a valid combination was refused: %v", err)
	}
	bad := map[string]map[string]string{
		"an excluded pair":    {"a": "x", "b": "q", "c": "m"},
		"an undeclared value": {"a": "z", "b": "p", "c": "m"},
		"a missing axis":      {"a": "x", "b": "p"},
		"an extra axis":       {"a": "x", "b": "p", "c": "m", "d": "w"},
		"a misnamed axis":     {"a": "x", "b": "p", "d": "m"},
	}
	for name, c := range bad {
		if err := spec.ValidateCombination("promql", c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := spec.ValidateCombination("sql", ok); err == nil {
		t.Error("an unknown language was accepted")
	}
	reversed := tinySpec()
	reversed.Excluded[0].Pair = []string{"b=q", "a=x"}
	if err := reversed.ValidateCombination("promql", map[string]string{"a": "x", "b": "q", "c": "m"}); err == nil {
		t.Error("an exclusion written in the other order was not applied")
	}
}

func TestTuplesEnumerateTheCrossProductInAFixedOrder(t *testing.T) {
	l := tinySpec().Languages[0]
	all := tuples(l)
	if len(all) != 8 {
		t.Fatalf("%d tuples of a 2x2x2 space", len(all))
	}
	seen := map[string]bool{}
	for _, c := range all {
		seen[tupleKey(l, c)] = true
	}
	if len(seen) != 8 {
		t.Fatalf("tuple keys collide: %v", seen)
	}
	if got := tupleKey(l, all[0]); got != "a=x,b=p,c=m" {
		t.Fatalf("first key %q", got)
	}
	if got := tupleKey(l, all[7]); got != "a=y,b=q,c=n" {
		t.Fatalf("last key %q", got)
	}
	// Each tuple owns its map: changing one changes no other.
	all[0]["a"] = "mutated"
	if all[1]["a"] == "mutated" || all[2]["a"] == "mutated" {
		t.Fatal("tuples share a map")
	}
}
