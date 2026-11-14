// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"math"
	"testing"
)

func TestActiveFeatureSelection(t *testing.T) {
	p := testProfile()
	p.FeatureSets = []profile.FeatureSet{{ID: "other", Enabled: []string{"promql-experimental-functions"}}}
	e, err := Parse(`sort_by_label(foo,"job")`, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = Check(e, p); err == nil {
		t.Fatal("inactive registered gate leaked")
	}
	p.ActiveFeatureSet.Enabled = []string{"promql-experimental-functions"}
	if _, _, err = Check(e, p); err != nil {
		t.Fatal(err)
	}
}
func TestLiteralBitsAndRuneRanges(t *testing.T) {
	e, err := Parse(`-0`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := Check(e, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if v.FloatBits != math.Float64bits(math.Copysign(0, -1)) {
		t.Fatal("signed zero lost")
	}
	e, err = Parse(`{"测量", "标签"="值"}`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	r := e.SourceRange()
	if r.EndByte <= r.EndRune {
		t.Fatal("byte/rune distinction lost")
	}
	_, err = Parse(`foo + on(job) group_left(job) bar`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	e, _ = Parse(`foo + on(job) group_left(job) bar`, testProfile())
	_, _, err = Check(e, testProfile())
	if err == nil {
		t.Fatal("matching/include collision accepted")
	}
	if _, ok := err.(*syntax.LanguageError); !ok {
		t.Fatal("untyped diagnostic")
	}
}
func TestPinnedGatedSyntax(t *testing.T) {
	for _, tc := range []struct{ text, gate string }{{`foo[5m] anchored`, "promql-extended-range-selectors"}, {`foo + fill(0) bar`, "promql-binop-fill-modifiers"}, {`foo[step() * 2]`, "promql-duration-expr"}} {
		p := testProfile()
		if e, err := Parse(tc.text, p); err == nil {
			if _, _, err = Check(e, p); err == nil {
				t.Errorf("disabled accepted %s", tc.text)
			}
		}
		p.ActiveFeatureSet.Enabled = []string{tc.gate}
		e, err := Parse(tc.text, p)
		if err != nil {
			t.Errorf("enabled parse %s: %v", tc.text, err)
			continue
		}
		if _, _, err = Check(e, p); err != nil {
			t.Errorf("enabled check %s: %v", tc.text, err)
		}
	}
}
