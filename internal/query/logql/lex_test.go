// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"soundpost/internal/query/syntax"
	"strings"
	"testing"
)

func TestEveryLogQLLexicalAndDurationBoundary(t *testing.T) {
	p := testProfile(t)
	for _, s := range []string{`SUM BY(app)(RATE({app="api"}[1m]))`, `{app="api"}|JSON|n="2"`, `{app="api"}|Keep app`, "\ufeff{app=\"api\"}", "1 /* bounded comment */ + 2 // trailing comment\n + 3", `rate({app="api"}[1h2m3s4ms] offset 1ns)`, `{app="api"}|elapsed>1d`, `1 == 2`} {
		e, err := Parse(s, p)
		if err == nil {
			_, _, err = Check(e, p)
		}
		if err != nil {
			t.Fatalf("valid lexical boundary rejected: %q: %v", s, err)
		}
	}
	for _, s := range []string{"{app=\"api\"}\u2003|json", "{app=\"api\"}\f|json", `rate({app="api"}[1.5m])`, `rate({app="api"}[1s1m])`, `rate({app="api"}[1ns])`, `sort by(app)(vector(1))`, `{app="api"}|peer==ip("192.0.2.1")`, "{app=`" + string([]byte{255}) + "`}", "{app=`a\x00b`}", strings.Repeat(" ", 131072)} {
		e, err := Parse(s, p)
		if err == nil {
			_, _, err = Check(e, p)
		}
		if err == nil {
			t.Fatal("invalid lexical boundary accepted")
		}
	}
}
func TestEveryLogQLUnicodeEditionAndRanges(t *testing.T) {
	p := testProfile(t)
	tokens, err := lex("label𞓐", p)
	if err != nil || len(tokens) < 2 || tokens[0].kind != "ident" {
		t.Fatal("Unicode15 identifier classification rejected")
	}
	if _, err = lex("label𐵐", p); err == nil {
		t.Fatal("post-Unicode15 letter accepted by lexer")
	}
	tokens, err = lex(`{app="界"} | json`, p)
	if err != nil {
		t.Fatal(err)
	}
	last := tokens[len(tokens)-2]
	if last.span.EndByte-last.span.EndRune != 2 {
		t.Fatal("byte/rune ranges conflated")
	}
}
func TestEveryLogQLDiagnosticCodesAreSafe(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{`{app="private-marker"}|regexp "["`, `{app="private-marker"}|unknown_stage`, `{app="private-marker"`} {
		e, err := Parse(source, p)
		if err == nil {
			_, _, err = Check(e, p)
		}
		var diagnostic *syntax.LanguageError
		if err == nil || !errors.As(err, &diagnostic) || diagnostic.Code == "" {
			t.Fatalf("missing owned diagnostic family: %v", err)
		}
		if strings.Contains(err.Error(), "private-marker") {
			t.Fatal("query text leaked into diagnostic")
		}
	}
}
func TestEveryLogQLErrorFamilyIsAssignedAtOrigin(t *testing.T) {
	p := testProfile(t)
	for _, tc := range []struct{ source, code string }{
		{`{}`, "selector.empty-compatible"}, {`{app=~".*"}`, "selector.empty-compatible"},
		{`{app="api"}|regexp "["`, "regex.invalid"}, {`{app="api"}|regexp "(x)"`, "regexp.capture-required"},
		{`{app="api"}|pattern "<a><b>"`, "pattern.invalid"}, {`{app="api"}|line_format "{{ env }}"`, "template.invalid"},
		{`sort by(app)(vector(1))`, "grouping.unsupported"}, {`sum_over_time({app="api"}[1m])`, "range.unwrap-incompatible"},
		{`{app="api"}|unwrap n`, "syntax.unexpected-token"}, {`1 + on(app) group_left vector(2)`, "binary.matching-invalid"},
		{`vector(1) or 2`, "binary.set-invalid"},
		{`{app="api"}|label_format x=a,x=b`, "label-format.duplicate"}, {`{app="api"}|label_format __error__="x"`, "label-format.reserved"},
		{`{app="api"}|=ip("bad")`, "ip.pattern-invalid"}, {`{app="api"}|json x="a["`, "syntax.unexpected-token"},
		{`rate({app="api"}[1.5m])`, "syntax.duration"}, {`{app="\q"}`, "syntax.string-escape"},
	} {
		expr, err := Parse(tc.source, p)
		if err == nil {
			_, _, err = Check(expr, p)
		}
		var diagnostic *syntax.LanguageError
		if !errors.As(err, &diagnostic) || diagnostic.Code != tc.code {
			t.Fatalf("origin code want=%s error=%v diagnostic=%+v", tc.code, err, diagnostic)
		}
	}
}
func TestEveryLogQLPinnedScalarBoolAcceptance(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{"1 == 2", "1 == bool 2"} {
		expr, err := Parse(source, p)
		if err != nil {
			t.Fatal(err)
		}
		typed, _, err := Check(expr, p)
		if err != nil || typed.Type != TypeScalar {
			t.Fatalf("native-accepted scalar comparison rejected: %v", err)
		}
	}
}
func TestEveryLogQLVectorRequiresDirectNumberToken(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{"vector(0)", "vector(2)", "vector(1.25)", "vector(1e3)", `{app="api"}|n>1s`, `sum_over_time({app="api"}|unwrap duration(n)[1m] offset -1m)`} {
		expr, err := Parse(source, p)
		if err == nil {
			_, _, err = Check(expr, p)
		}
		if err != nil {
			t.Fatalf("valid direct number or unrelated duration rejected: %s %v", source, err)
		}
	}
	for _, source := range []string{"vector(-0)", "vector(+0)", "vector(-2.5)", "vector(1s)", "vector(1B)", "vector(1+2)", "vector((1))"} {
		_, err := Parse(source, p)
		var diagnostic *syntax.LanguageError
		if !errors.As(err, &diagnostic) || diagnostic.Code != "syntax.unexpected-token" {
			t.Fatalf("vector admitted non-NUMBER argument: %s %v", source, err)
		}
	}
}
