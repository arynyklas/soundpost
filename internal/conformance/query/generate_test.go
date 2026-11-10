// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"soundpost/internal/query/profile"
	"soundpost/profiles"
)

func genFixture(t testing.TB) (GenerationSpec, Ledger, []GateDomain, profile.Registry, fs.FS) {
	t.Helper()
	spec, err := LoadGenerationSpec(queryRoot("generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ledger Ledger
	if err = ReadJSON(queryRoot("obligations.json"), &ledger); err != nil {
		t.Fatal(err)
	}
	var d struct {
		Domains []GateDomain `json:"domains"`
	}
	if err = ReadJSON(queryRoot("gate-domains.json"), &d); err != nil {
		t.Fatal(err)
	}
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := profile.Load(files)
	if err != nil {
		t.Fatal(err)
	}
	return spec, ledger, d.Domains, registry, files
}

func gen(t testing.TB, seed uint64, random int) ([]Case, GenerationSpec, []GateDomain, profile.Registry, fs.FS) {
	t.Helper()
	spec, ledger, domains, registry, files := genFixture(t)
	cases, err := Generate(context.Background(), registry, ledger, seed, GenerationBudget{Spec: spec, Domains: domains, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	return cases, spec, domains, registry, files
}

// featureSets lists every registered feature set (enabled gates) of a profile.
func featureSets(t testing.TB, files fs.FS, id string) []profile.FeatureSet {
	t.Helper()
	var m profile.Profile
	if err := ReadJSON(queryRoot("..", "..", "profiles", "query", id+".json"), &m); err != nil {
		t.Fatal(err)
	}
	return m.FeatureSets
}

func TestGeneratedMixedFeatureCoverage(t *testing.T) {
	cases, spec, _, registry, files := gen(t, 20261110, 12)
	again, _, _, _, _ := gen(t, 20261110, 12)
	if !reflect.DeepEqual(cases, again) {
		t.Fatal("the same seed produced a different suite")
	}
	other, _, _, _, _ := gen(t, 20261111, 12)
	if reflect.DeepEqual(cases, other) {
		t.Fatal("a different seed produced an identical suite: the seed is ignored")
	}
	// The exhaustive (non-extra) cases must also vary their surface form with
	// the seed, not only the seed-drawn supplements.
	surface := func(cs []Case) string {
		var b strings.Builder
		for _, c := range cs {
			if c.Kind == "valid" && !strings.Contains(c.ID, "#extra") {
				b.WriteString(c.Expression + "\n")
			}
		}
		return b.String()
	}
	if surface(cases) == surface(other) {
		t.Fatal("the seed does not vary the exhaustive cases")
	}
	// Pairwise (80 PromQL + 78 LogQL applicable pairs after the two declared
	// exclusions) plus 7 targeted higher-order tuples, counted by hand from the spec.
	cov := Coverage(spec, cases)
	if cov.Required != 165 || cov.Covered != 165 || len(cov.Missing) != 0 {
		t.Fatalf("interaction coverage %d/%d missing=%v", cov.Covered, cov.Required, cov.Missing)
	}
	// Removing every valid case that carries one pair must be seen.
	var trimmed []Case
	for _, c := range cases {
		if c.Kind == "valid" && c.Language == "promql" && c.Coordinate["sample_kind"] == "stale" && c.Coordinate["time_window"] == "subquery" {
			continue
		}
		trimmed = append(trimmed, c)
	}
	if c := Coverage(spec, trimmed); c.Covered >= c.Required || len(c.Missing) == 0 {
		t.Fatal("coverage did not notice a missing pairwise interaction")
	}
	// Valid cases are valid in EVERY registered feature set of their locked
	// configuration; negative cases are rejected with the declared category
	// before any execution; the two never mix.
	var validRun, negativeRun int
	resolved := map[string][]profile.Profile{}
	for _, c := range cases {
		if _, ok := resolved[c.Profile]; !ok {
			for _, set := range featureSets(t, files, c.Profile) {
				p, err := registry.Resolve(c.Profile, set.ID)
				if err != nil {
					t.Fatal(err)
				}
				resolved[c.Profile] = append(resolved[c.Profile], p)
			}
		}
		if c.Kind != "valid" && c.Kind != "negative" {
			continue
		}
		for _, p := range resolved[c.Profile] {
			set := p.ActiveFeatureSet
			out, err := CheckOwned(c.Language, c.Expression, p)
			if err != nil {
				t.Fatalf("%s in %s: %v", c.ID, set.ID, err)
			}
			if c.Kind == "valid" {
				validRun++
				if !out.Accepted {
					t.Fatalf("valid %s %q rejected in %s: %s", c.ID, c.Expression, set.ID, out.Category)
				}
			} else {
				negativeRun++
				if out.Accepted || out.Category != c.Reject {
					t.Fatalf("negative %s %q accepted=%v category=%q want %q", c.ID, c.Expression, out.Accepted, out.Category, c.Reject)
				}
			}
		}
	}
	if validRun == 0 || negativeRun == 0 {
		t.Fatal("nothing ran")
	}
	// Invalid combinations are rejected before execution and never generated.
	l, _ := spec.language("promql")
	bad := map[string]string{"sample_kind": "native_histogram", "time_window": "none", "metadata_mutation": "none", "order_duplicates": "tie_limit"}
	if err := spec.ValidateCombination("promql", bad); err == nil {
		t.Fatal("excluded combination accepted")
	}
	bad["order_duplicates"] = "undeclared"
	if err := spec.ValidateCombination("promql", bad); err == nil {
		t.Fatal("undeclared value accepted")
	}
	delete(bad, "order_duplicates")
	if err := spec.ValidateCombination("promql", bad); err == nil {
		t.Fatal("partial combination accepted")
	}
	for _, c := range cases {
		if c.Kind == "valid" && spec.ValidateCombination(c.Language, c.Coordinate) != nil {
			t.Fatalf("an invalid combination was generated: %s", c.ID)
		}
	}
	_ = l
	// A too-small budget is an error, not a silent truncation.
	spec2, ledger, domains, reg2, _ := genFixture(t)
	if _, err := Generate(context.Background(), reg2, ledger, 1, GenerationBudget{MaxCases: 10, Spec: spec2, Domains: domains}); err == nil {
		t.Fatal("budget overflow was truncated silently")
	}
	// Generated inputs carry the concrete shapes the brief names.
	var stale, hist, dup, newline bool
	for _, c := range cases {
		for _, in := range c.Input {
			stale = stale || in.Bits == StaleBits
			hist = hist || (in.Kind == "histogram" && in.Histogram != nil)
			newline = newline || strings.Contains(in.Labels["nl"], "\n")
		}
		if c.Coordinate["order_duplicates"] == "duplicate_timestamp" && len(c.Input) >= 2 && c.Input[len(c.Input)-1].Timestamp == c.Input[len(c.Input)-2].Timestamp {
			dup = true
		}
	}
	if !(stale && hist && dup && newline) {
		t.Fatalf("missing concrete inputs stale=%v histogram=%v duplicate=%v newline=%v", stale, hist, dup, newline)
	}
}

func TestGeneratedGateProbesRejectDisabledGatesOnly(t *testing.T) {
	cases, _, _, registry, _ := gen(t, 1, 0)
	var enabled, disabled int
	for _, c := range cases {
		if c.Kind != "gate" {
			continue
		}
		p, err := registry.Resolve(c.Profile, c.FeatureSet)
		if err != nil {
			t.Fatal(err)
		}
		out, err := CheckOwned(c.Language, c.Expression, p)
		if err != nil {
			t.Fatal(err)
		}
		if c.Enabled {
			enabled++
			if !out.Accepted {
				t.Fatalf("%s: gate %s enabled but %q rejected (%s)", c.ID, c.Gate, c.Expression, out.Category)
			}
		} else {
			disabled++
			if out.Accepted || out.Category != c.Reject {
				t.Fatalf("%s: gate %s disabled but %q accepted=%v category=%q", c.ID, c.Gate, c.Expression, out.Accepted, out.Category)
			}
		}
	}
	if enabled != 128 || disabled != 128 {
		t.Fatalf("expected both probes on all 128 feature sets of 3.13.5 (64 enabled + 64 disabled each), got %d enabled %d disabled", enabled, disabled)
	}
}

// Type-directed generation from the ledger's function signatures, run on the
// owned parser with the experimental gate on.
func TestGeneratedSignatureDirectedFunctionCases(t *testing.T) {
	cases, _, _, registry, files := gen(t, 3, 0)
	var valid, negative, arity, typed int
	for _, c := range cases {
		if c.Kind != "signature" && c.Kind != "signature-negative" {
			continue
		}
		if strings.HasPrefix(c.ID, "sig-arity/") {
			arity++
		}
		if strings.HasPrefix(c.ID, "sig-type/") {
			typed++
		}
		p, err := ResolveEnabled(files, registry, c.Profile, []string{"promql-experimental-functions"})
		if err != nil {
			t.Fatal(err)
		}
		out, err := CheckOwned("promql", c.Expression, p)
		if err != nil {
			t.Fatal(err)
		}
		if c.Kind == "signature" {
			valid++
			if !out.Accepted {
				t.Errorf("%s: %q rejected: %s", c.ID, c.Expression, out.Category)
			}
		} else {
			negative++
			if out.Accepted || out.Category != c.Reject {
				t.Errorf("%s: %q accepted=%v category=%q want %q", c.ID, c.Expression, out.Accepted, out.Category, c.Reject)
			}
		}
	}
	t.Logf("signature-directed: %d valid, %d negative (of 166 function-signature obligations; matrix/vector/scalar/string-typed only)", valid, negative)
	if valid != 166 || arity < 100 || typed < 100 {
		t.Fatalf("signature-directed cases: %d valid (want all 166 function-signature obligations), %d arity, %d type negatives", valid, arity, typed)
	}
}

func TestMinimizeKeepsTheMismatchAndShrinks(t *testing.T) {
	c := Case{Expression: `topk(1, label_replace(rate(m[5m]), "a", "$1", "job", "(.*)") BAD)`, Input: []InputRecord{{Kind: "float", Timestamp: "1"}, {Kind: "float", Timestamp: "2", Bits: StaleBits}, {Kind: "float", Timestamp: "3"}}}
	predicate := func(c Case) (bool, error) {
		stale := false
		for _, in := range c.Input {
			stale = stale || in.Bits == StaleBits
		}
		return stale && strings.Contains(c.Expression, "BAD"), nil
	}
	got, err := Minimize(context.Background(), CaseMismatch{Case: c}, predicate)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := predicate(got); !ok {
		t.Fatal("minimized case no longer reproduces")
	}
	if len(got.Input) != 1 || got.Input[0].Bits != StaleBits || len(got.Expression) >= len(c.Expression) {
		t.Fatalf("not minimal: %+v", got)
	}
	if _, err = Minimize(context.Background(), CaseMismatch{Case: c}, func(Case) (bool, error) { return false, nil }); err == nil {
		t.Fatal("a mismatch that does not reproduce was minimized")
	}
}
