// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"math"
	"strings"
	"testing"
)

func TestNonfiniteIsNotStaleAndModifierSpan(t *testing.T) {
	for _, text := range []string{"NaN", "Inf", "-Inf", "-0"} {
		e, err := Parse(text, testProfile())
		if err != nil {
			t.Fatal(err)
		}
		v, _, err := Check(e, testProfile())
		if err != nil {
			t.Fatal(err)
		}
		if v.FloatBits == 0x7ff0000000000002 {
			t.Fatal("literal became evaluator stale sentinel")
		}
		f := math.Float64frombits(v.FloatBits)
		switch text {
		case "NaN":
			if !math.IsNaN(f) {
				t.Fatal("lost ordinary NaN")
			}
		case "Inf":
			if !math.IsInf(f, 1) {
				t.Fatal("lost positive infinity")
			}
		case "-Inf":
			if !math.IsInf(f, -1) {
				t.Fatal("lost negative infinity")
			}
		case "-0":
			if f != 0 || !math.Signbit(f) {
				t.Fatal("lost negative zero")
			}
		}
	}
	text := `fixture_left or on(job) group_left(instance) fixture_right`
	e, err := Parse(text, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Check(e, testProfile())
	le, ok := err.(*syntax.LanguageError)
	if !ok {
		t.Fatalf("missing typed error: %v", err)
	}
	start := strings.Index(text, "group_left")
	end := start + len("group_left(instance)")
	modifierRange := e.(*Node).Matching.Range
	if modifierRange.StartByte != start || modifierRange.EndByte != end {
		t.Fatalf("modifier span %+v want %d..%d", modifierRange, start, end)
	}
	if le.Range != e.SourceRange() {
		t.Fatalf("set cardinality diagnostic must own binary expression: %+v", le.Range)
	}
}
