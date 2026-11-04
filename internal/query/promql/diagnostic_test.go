// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"soundpost/internal/query/syntax"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTypeErrorsOwnOffendingExpressionRanges(t *testing.T) {
	for _, tc := range []struct{ text, offending string }{{`abs("wrong")`, `"wrong"`}, {"histogram_fraction(0,\n # 测量\n \"错误\", fixture_metric)", `"错误"`}, {`sum("错误")`, `"错误"`}, {`topk("错误",fixture_metric)`, `"错误"`}, {`fixture_metric + "错误"`, `"错误"`}, {`"错误" + fixture_metric`, `"错误"`}} {
		e, err := Parse(tc.text, testProfile())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Check(e, testProfile())
		le, ok := err.(*syntax.LanguageError)
		if !ok {
			t.Fatalf("%s: %v", tc.text, err)
		}
		start := strings.Index(tc.text, tc.offending)
		want := syntax.SourceRange{StartByte: start, EndByte: start + len(tc.offending), StartRune: utf8.RuneCountInString(tc.text[:start]), EndRune: utf8.RuneCountInString(tc.text[:start+len(tc.offending)])}
		if le.Range != want {
			t.Errorf("%s: got %+v want %+v", tc.text, le.Range, want)
		}
	}
}
func TestReservedFunctionsHaveContextualGates(t *testing.T) {
	for _, text := range []string{`step()`, `range()`, `min_of(1,2)`, `max_of(1,2)`} {
		p := testProfile()
		p.ActiveFeatureSet.Enabled = []string{"promql-duration-expr"}
		e, err := Parse(text, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = Check(e, p); err == nil {
			t.Fatalf("standalone requires experimental-functions: %s", text)
		}
		p.ActiveFeatureSet.Enabled = []string{"promql-experimental-functions"}
		e, err = Parse(text, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = Check(e, p); err != nil {
			t.Fatalf("standalone %s: %v", text, err)
		}
	}
	p := testProfile()
	p.ActiveFeatureSet.Enabled = []string{"promql-duration-expr"}
	e, err := Parse(`fixture_metric[max_of(step()*2,range())]`, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = Check(e, p); err != nil {
		t.Fatal(err)
	}
}
func TestLanguageFailuresRetainSemanticOrigins(t *testing.T) {
	for _, tc := range []struct{ text, origin string }{
		{`{job=~".*"}`, `{job=~".*"}`},
		{`fixture_metric[0s]`, `0s`},
		{`fixture_metric{job=~"["}`, `job=~"["`},
		{`fixture_metric @ 1 @ 2`, `fixture_metric @ 1`},
		{`1 < 2`, `<`},
		{`fixture_left + on(job) group_right(job) fixture_right`, `+ on(job) group_right(job)`},
		{`fixture_left or on(job) group_left(instance) fixture_right`, `fixture_left or on(job) group_left(instance) fixture_right`},
	} {
		e, err := Parse(tc.text, testProfile())
		if err == nil {
			_, _, err = Check(e, testProfile())
		}
		le, ok := err.(*syntax.LanguageError)
		if !ok {
			t.Fatalf("%s: %v", tc.text, err)
		}
		start := strings.Index(tc.text, tc.origin)
		want := syntax.Range(tc.text, start, start+len(tc.origin))
		if le.Range != want {
			t.Errorf("%s: got %+v want semantic origin %+v", tc.text, le.Range, want)
		}
	}
}
func TestSignedFillLiteralRetainsBits(t *testing.T) {
	p := testProfile()
	p.ActiveFeatureSet.Enabled = []string{"promql-binop-fill-modifiers"}
	e, err := Parse(`fixture_left + fill_left(-0) fill_right(-1) fixture_right`, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = Check(e, p); err != nil {
		t.Fatal(err)
	}
	n := e.(*Node)
	if n.FillLeft == nil || *n.FillLeft != 0x8000000000000000 || n.FillRight == nil || *n.FillRight != 0xbff0000000000000 {
		t.Fatal("signed fill literal bits changed")
	}
	s := Format(e)
	r, err := Parse(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if Format(r) != s {
		t.Fatal("signed fill format is not idempotent")
	}
}
