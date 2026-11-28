// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"reflect"
	"testing"
)

func sampleResult() SemanticResult {
	return SemanticResult{
		Kind: "vector", Type: "vector",
		Values: []Value{
			{Timestamp: "1", Bits: "3ff0000000000000", Labels: map[string]string{"job": "a"}},
			{Timestamp: "1", Bits: "4000000000000000", Labels: map[string]string{"job": "b"}},
		},
		Diagnostics: []Diagnostic{{Code: "c1", Message: "m1"}, {Code: "c2", Message: "m2"}},
		Error:       &LanguageError{Code: "e", Start: 1, End: 2},
		Syntax:      []SyntaxObservation{{ID: "s", Accepted: true}},
		Evaluation:  &EvaluationBatch{Profile: "p"},
		LogQL:       &LogQLBatch{Profile: "p"},
	}
}

func fieldsOf(ms []Mismatch) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Field)
	}
	return out
}

// Every part of a semantic result is compared, and each difference is reported
// under the one field it belongs to. A comparator that skipped a field would let
// the release gate call two different answers equal.
func TestCompareReportsExactlyTheFieldThatDiffers(t *testing.T) {
	faults := []struct {
		name   string
		mutate func(r *SemanticResult)
		field  string
	}{
		{"kind", func(r *SemanticResult) { r.Kind = "matrix" }, "kind"},
		{"type", func(r *SemanticResult) { r.Type = "scalar" }, "type"},
		{"diagnostic code", func(r *SemanticResult) { r.Diagnostics[0].Code = "other" }, "diagnostics"},
		{"diagnostic message", func(r *SemanticResult) { r.Diagnostics[1].Message = "other" }, "diagnostics"},
		{"diagnostic order", func(r *SemanticResult) { r.Diagnostics[0], r.Diagnostics[1] = r.Diagnostics[1], r.Diagnostics[0] }, "diagnostics"},
		{"a diagnostic dropped", func(r *SemanticResult) { r.Diagnostics = r.Diagnostics[:1] }, "diagnostics"},
		{"error absent", func(r *SemanticResult) { r.Error = nil }, "error"},
		{"error code", func(r *SemanticResult) { r.Error.Code = "x" }, "error"},
		{"error start", func(r *SemanticResult) { r.Error.Start = 5 }, "error"},
		{"error end", func(r *SemanticResult) { r.Error.End = 5 }, "error"},
		{"syntax observation", func(r *SemanticResult) { r.Syntax[0].Accepted = false }, "syntax"},
		{"syntax observation dropped", func(r *SemanticResult) { r.Syntax = nil }, "syntax"},
		{"evaluation batch absent", func(r *SemanticResult) { r.Evaluation = nil }, "evaluation"},
		{"evaluation batch content", func(r *SemanticResult) { r.Evaluation.Profile = "q" }, "evaluation"},
		{"logql batch absent", func(r *SemanticResult) { r.LogQL = nil }, "logql"},
		{"logql batch content", func(r *SemanticResult) { r.LogQL.Profile = "q" }, "logql"},
		{"value bits", func(r *SemanticResult) { r.Values[0].Bits = "7ff8000000000001" }, "values"},
		{"value timestamp", func(r *SemanticResult) { r.Values[1].Timestamp = "2" }, "values"},
		{"value labels", func(r *SemanticResult) { r.Values[1].Labels["job"] = "c" }, "values"},
		{"value line", func(r *SemanticResult) { r.Values[0].Line = "x" }, "values"},
		{"value histogram", func(r *SemanticResult) { r.Values[0].Histogram = &Histogram{Kind: "integer"} }, "values"},
		{"a value dropped", func(r *SemanticResult) { r.Values = r.Values[:1] }, "values"},
		{"a value added", func(r *SemanticResult) { r.Values = append(r.Values, r.Values[0]) }, "values"},
		{"vector order", func(r *SemanticResult) { r.Values[0], r.Values[1] = r.Values[1], r.Values[0] }, "values"},
	}
	for _, f := range faults {
		want, got := sampleResult(), sampleResult()
		f.mutate(&got)
		if ms := fieldsOf(Compare(want, got, OrderingFreedom{})); !reflect.DeepEqual(ms, []string{f.field}) {
			t.Errorf("%s: mismatches %v, want exactly [%s]", f.name, ms, f.field)
		}
		// The comparison is symmetric in what it detects.
		if ms := fieldsOf(Compare(got, want, OrderingFreedom{})); !reflect.DeepEqual(ms, []string{f.field}) {
			t.Errorf("%s (swapped): mismatches %v", f.name, ms)
		}
	}
	if ms := Compare(sampleResult(), sampleResult(), OrderingFreedom{}); len(ms) != 0 {
		t.Fatalf("equal results differ: %v", ms)
	}
	// The identity of the oracle that produced a result is verified by the gate,
	// not compared as part of the semantics.
	got := sampleResult()
	got.Oracle = &OracleIdentity{Profile: "p", Revision: "r"}
	if ms := Compare(sampleResult(), got, OrderingFreedom{}); len(ms) != 0 {
		t.Fatalf("an oracle identity was compared: %v", ms)
	}
	// Mismatches carry both sides.
	g := sampleResult()
	g.Kind = "scalar"
	ms := Compare(sampleResult(), g, OrderingFreedom{})
	if len(ms) != 1 || ms[0].Want != "vector" || ms[0].Got != "scalar" {
		t.Fatalf("%+v", ms)
	}
	// Every field that differs is reported, in a fixed order.
	all := SemanticResult{Kind: "scalar", Type: "scalar", Values: []Value{{Timestamp: "9"}}, Diagnostics: []Diagnostic{{Code: "z"}}, Error: &LanguageError{Code: "z"}, Syntax: []SyntaxObservation{{ID: "z"}}, Evaluation: &EvaluationBatch{Profile: "z"}, LogQL: &LogQLBatch{Profile: "z"}}
	if got := fieldsOf(Compare(sampleResult(), all, OrderingFreedom{})); !reflect.DeepEqual(got, []string{"kind", "type", "diagnostics", "error", "syntax", "evaluation", "logql", "values"}) {
		t.Fatalf("%v", got)
	}
}

func TestCompareHonoursUnorderedVectorsOnlyForVectors(t *testing.T) {
	free := OrderingFreedom{UnorderedVector: true}
	permuted := func(kind string) (SemanticResult, SemanticResult) {
		a, b := sampleResult(), sampleResult()
		a.Kind, b.Kind = kind, kind
		b.Values[0], b.Values[1] = b.Values[1], b.Values[0]
		return a, b
	}
	a, b := permuted("vector")
	if ms := Compare(a, b, free); len(ms) != 0 {
		t.Fatalf("a permuted vector differs although the case grants unordered vectors: %v", ms)
	}
	if ms := Compare(a, b, OrderingFreedom{}); !reflect.DeepEqual(fieldsOf(ms), []string{"values"}) {
		t.Fatalf("a permuted vector matched without the freedom: %v", ms)
	}
	for _, kind := range []string{"matrix", "scalar", "streams", ""} {
		a, b = permuted(kind)
		if ms := Compare(a, b, free); !reflect.DeepEqual(fieldsOf(ms), []string{"values"}) {
			t.Errorf("a permuted %q result matched: the freedom is for vectors only (%v)", kind, ms)
		}
	}
	// Only when both sides are vectors.
	a, b = permuted("vector")
	b.Kind = "matrix"
	if got := fieldsOf(Compare(a, b, free)); !reflect.DeepEqual(got, []string{"kind", "values"}) {
		t.Errorf("a vector against a matrix was canonicalized: %v", got)
	}
	a, b = permuted("vector")
	a.Kind = "matrix"
	if got := fieldsOf(Compare(a, b, free)); !reflect.DeepEqual(got, []string{"kind", "values"}) {
		t.Errorf("a matrix against a vector was canonicalized: %v", got)
	}
	// Canonicalizing is a multiset comparison: duplicates and counts still matter.
	x, y := Value{Timestamp: "1", Bits: "3ff0000000000000"}, Value{Timestamp: "1", Bits: "4000000000000000"}
	for name, c := range map[string][2][]Value{
		"different multiplicity": {{x, x, y}, {x, y, y}},
		"a value dropped":        {{x, y}, {x}},
		"a value invented":       {{x}, {x, y}},
	} {
		w, g := SemanticResult{Kind: "vector", Values: c[0]}, SemanticResult{Kind: "vector", Values: c[1]}
		if ms := Compare(w, g, free); len(ms) == 0 {
			t.Errorf("%s was accepted as an unordered match", name)
		}
	}
	// The comparison never reorders what it was given.
	w, g := SemanticResult{Kind: "vector", Values: []Value{y, x}}, SemanticResult{Kind: "vector", Values: []Value{x, y}}
	Compare(w, g, free)
	if !reflect.DeepEqual(w.Values, []Value{y, x}) || !reflect.DeepEqual(g.Values, []Value{x, y}) {
		t.Fatalf("Compare sorted its arguments in place: %+v %+v", w.Values, g.Values)
	}
}
