// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// foreignExpr satisfies the exported part of Expr but is not a *Node. The
// sealed unexported method means only this package can build one.
type foreignExpr struct{}

func (foreignExpr) SourceRange() syntax.SourceRange { return syntax.SourceRange{} }
func (foreignExpr) expression()                     {}

func TestWalkVisitsButNeverDescendsIntoForeignExpr(t *testing.T) {
	visited := 0
	Walk(foreignExpr{}, func(Expr) bool { visited++; return true })
	if visited != 1 {
		t.Fatalf("foreign expression must be visited once without a panic, visited %d", visited)
	}
	root := &Node{Kind: "binary", Children: []Expr{foreignExpr{}, &Node{Kind: "number"}}, RangeExpr: foreignExpr{}}
	visited = 0
	Walk(root, func(Expr) bool { visited++; return true })
	if visited != 4 {
		t.Fatalf("root, foreign child, number child and foreign range must each be visited, visited %d", visited)
	}
	Walk(nil, func(Expr) bool { t.Fatal("nil expression visited"); return true })
}

func TestGroupingTrailingCommaIsAcceptedOnceAndFormattedCanonically(t *testing.T) {
	for _, text := range []string{`sum by (a,) (foo)`, `sum without (a, b,) (foo)`, `foo / on(a,) group_left(b,) bar`} {
		e, err := Parse(text, testProfile())
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if _, _, err = Check(e, testProfile()); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		formatted := Format(e)
		if strings.Contains(formatted, ",)") || strings.Contains(formatted, ", )") {
			t.Fatalf("%s must format without the trailing comma, got %s", text, formatted)
		}
		again, err := Parse(formatted, testProfile())
		if err != nil || Format(again) != formatted {
			t.Fatalf("%s: canonical form %s must reparse identically: %v", text, formatted, err)
		}
	}
	for _, text := range []string{`sum by (a,,) (foo)`, `sum by (,) (foo)`, `sum by (,a) (foo)`} {
		if _, err := Parse(text, testProfile()); err == nil {
			t.Errorf("accepted %s", text)
		}
	}
}

func TestCheckDiagnosticsChannelIsAdvisoryAndErrorsStayTyped(t *testing.T) {
	e, err := Parse(`rate(foo[5m])`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	typed, diagnostics, err := Check(e, testProfile())
	if err != nil || typed.Type != Vector || len(diagnostics) != 0 {
		t.Fatalf("a valid expression has no static diagnostics: %v %v %v", typed.Type, diagnostics, err)
	}
	bad, err := Parse(`rate(1)`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	_, diagnostics, err = Check(bad, testProfile())
	var language *syntax.LanguageError
	if !asLanguage(err, &language) || language.Category != "type" || len(diagnostics) != 0 {
		t.Fatalf("failures are carried only by the typed error, never duplicated as diagnostics: %v %v", diagnostics, err)
	}
}

func asLanguage(err error, target **syntax.LanguageError) bool {
	l, ok := err.(*syntax.LanguageError)
	if ok {
		*target = l
	}
	return ok
}
