// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"strings"
	"testing"
)

func TestCoverageRejectsMissingOverload(t *testing.T) {
	l := Ledger{Complete: true, Obligations: []Obligation{{ID: "overload", Kind: "overload", Profile: "p", PositiveCases: []string{"yes"}, NegativeCases: []string{"no"}, InteractionCases: []string{"mixed"}}}}
	bindings := []Binding{{ObligationID: "overload", Implementation: "owned.example", Cases: []string{"yes", "no", "mixed"}, GoTests: []string{"TestOwnedOverload"}}}
	if err := ValidateCoverage(l, bindings); err != nil {
		t.Fatalf("complete unit fixture rejected: %v", err)
	}
	bindings = bindings[:0]
	if err := ValidateCoverage(l, bindings); err == nil {
		t.Fatal("missing overload must fail coverage")
	}
}
func TestGateCombinationClosure(t *testing.T) {
	if err := ValidateGateClosure([]string{"a", "b"}, []FeatureSet{{ID: "off"}}); err == nil {
		t.Fatal("missing combinations accepted")
	}
	sets := []FeatureSet{{ID: "off", DisabledCases: map[string][]string{"a": {"reject-a"}, "b": {"reject-b"}}}, {ID: "a", Enabled: []string{"a"}, DisabledCases: map[string][]string{"b": {"reject-b"}}}, {ID: "b", Enabled: []string{"b"}, DisabledCases: map[string][]string{"a": {"reject-a"}}}, {ID: "ab", Enabled: []string{"a", "b"}}}
	if err := ValidateGateClosure([]string{"a", "b"}, sets); err != nil {
		t.Fatal(err)
	}
	delete(sets[0].DisabledCases, "a")
	if err := ValidateGateClosure([]string{"a", "b"}, sets); err == nil {
		t.Fatal("disabled gate without negative case accepted")
	}
	sets[0].DisabledCases["a"] = []string{"reject-a"}
	sets[3].ID = "a"
	if err := ValidateGateClosure([]string{"a", "b"}, sets); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}
func TestComparatorPreservesSemantics(t *testing.T) {
	a := SemanticResult{Kind: "scalar", Values: []Value{{Bits: "0000000000000000"}}}
	b := a
	b.Values = []Value{{Bits: "8000000000000000"}}
	if len(Compare(a, b, OrderingFreedom{})) == 0 {
		t.Fatal("signed zero collapsed")
	}
	a.Values[0].Bits = "7ff8000000000001"
	b.Values[0].Bits = "7ff0000000000002"
	if len(Compare(a, b, OrderingFreedom{})) == 0 {
		t.Fatal("stale collapsed")
	}
	a = SemanticResult{Diagnostics: []Diagnostic{{Code: "a"}, {Code: "b"}}}
	b = SemanticResult{Diagnostics: []Diagnostic{{Code: "b"}, {Code: "a"}}}
	if len(Compare(a, b, OrderingFreedom{UnorderedVector: true})) == 0 {
		t.Fatal("diagnostic ordering erased")
	}
	a = SemanticResult{Kind: "vector", Values: []Value{{Bits: "0000000000000000"}, {Bits: "8000000000000000"}}}
	b = SemanticResult{Kind: "vector", Values: []Value{{Bits: "8000000000000000"}, {Bits: "0000000000000000"}}}
	if len(Compare(a, b, OrderingFreedom{})) == 0 {
		t.Fatal("ordered vector canonicalized without permission")
	}
	if len(Compare(a, b, OrderingFreedom{UnorderedVector: true})) != 0 {
		t.Fatal("explicit unordered vector not canonicalized")
	}
}
func TestOracleRejectsMissingArtifact(t *testing.T) {
	run := OracleRun{Profile: SourceProfile{ID: "promql-prometheus-3.1.0", Commit: exactPins["promql-prometheus-3.1.0"]}}
	if _, err := RunOracle(context.Background(), run); err == nil || !strings.Contains(err.Error(), "missing digest-locked isolated oracle artifact") {
		t.Fatalf("known profile must reach missing artifact guard, got %v", err)
	}
}
