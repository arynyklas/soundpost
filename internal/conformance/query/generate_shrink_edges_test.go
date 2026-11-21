// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"strings"
	"testing"
)

func shrunkExpressions(c Case) []string {
	var out []string
	for _, s := range shrinks(c) {
		out = append(out, s.Expression)
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// The shortest prefix of an expression is a candidate too: a mismatch that survives down to a
// single token is minimized to it.
func TestShrinksReachAOneRunePrefix(t *testing.T) {
	for _, expr := range []string{"m(", "(b", "ab"} {
		got := shrunkExpressions(Case{Expression: expr})
		if want := string([]rune(expr)[:1]); !containsString(got, want) {
			t.Errorf("shrinks of %q are %q, none is the one-rune prefix %q", expr, got, want)
		}
	}
}

// Dropping a space drops the whitespace the cut leaves beside it too: of two spaces between two
// tokens, dropping the run joins the tokens.
func TestShrinksDropAllTheWhitespaceBesideADroppedSpace(t *testing.T) {
	got := shrunkExpressions(Case{Expression: "a  b"})
	if !containsString(got, "ab") {
		t.Errorf("shrinks of %q are %q, none joins the two tokens", "a  b", got)
	}
}

// A combination whose count is right but whose keys are not the language's axes leaves an axis
// unassigned: that is the error, not a value that happens to be undeclared.
func TestValidateCombinationNamesAnUnassignedAxis(t *testing.T) {
	spec, _, _ := loadPlanInputs(t)
	l := spec.Languages[0]
	c := map[string]string{}
	for _, a := range l.Axes {
		c[a.ID] = a.Values[0]
	}
	if err := spec.ValidateCombination(l.Language, c); err != nil && !strings.Contains(err.Error(), "excluded combination") {
		t.Fatalf("the first value of every axis was refused: %v", err)
	}
	delete(c, l.Axes[0].ID)
	c["not-an-axis"] = "x"
	err := spec.ValidateCombination(l.Language, c)
	if err == nil || !strings.Contains(err.Error(), "axis "+l.Axes[0].ID+" unassigned") {
		t.Fatalf("a combination that leaves %s unassigned: %v", l.Axes[0].ID, err)
	}
}

// Generate validates the spec itself before it builds anything: a spec that is structurally unsound
// (here a language without profiles, which no builder notices) generates nothing.
func TestGenerateValidatesTheSpecBeforeBuildingAnything(t *testing.T) {
	_, ledger, domains, registry, _ := genFixture(t)
	s := cloneSpec(t, realSpec(t))
	s.Languages[0].Profiles = nil
	cases, err := Generate(context.Background(), registry, ledger, 1, GenerationBudget{Spec: s, Domains: domains})
	if err == nil || !strings.Contains(err.Error(), "language promql has no profiles") || len(cases) != 0 {
		t.Fatalf("Generate answered %d cases, %v; want no cases and the spec's own error", len(cases), err)
	}
}
