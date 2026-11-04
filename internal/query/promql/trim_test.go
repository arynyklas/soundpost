// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"os"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"testing"
)

func trimProfile(t *testing.T) profile.Profile {
	t.Helper()
	r, e := profile.Load(os.DirFS("../../../profiles/query"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := r.Resolve("promql-prometheus-3.13.5", "promql-prometheus-3.13.5/semantic-sha256-83c73719d785858aa72b493c92ac76a30bb3f3f2d73cda157fa23c43a7ebe393")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPinnedTrimGrammarAndRanges(t *testing.T) {
	p := trimProfile(t)
	for _, op := range []string{"</", ">/"} {
		q := "m " + op + " 2"
		e, err := Parse(q, p)
		if err != nil {
			t.Fatal(err)
		}
		n := e.(*Node)
		if n.Text != op || n.OperatorRange.StartByte != 2 || n.OperatorRange.EndByte != 4 {
			t.Fatalf("operator range %+v", n)
		}
		typed, _, err := Check(e, p)
		if err != nil || typed.Type != Vector {
			t.Fatalf("typed trim %+v %v", typed, err)
		}
		if _, err = Parse(q, executionProfile(t)); err == nil {
			t.Fatal("3.1 accepted a 3.13-only operator")
		}
		e, err = Parse("m "+op+" bool 2", p)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Check(e, p)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Category != "type" || language.Range.StartByte != 2 {
			t.Fatalf("bool error %v", err)
		}
		e, err = Parse("m "+op+" \"bad\"", p)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = Check(e, p); err == nil {
			t.Fatal("string trim operand accepted")
		}
	}
	e, err := Parse("m + 1 </ 2 == 3", p)
	if err != nil {
		t.Fatal(err)
	}
	root := e.(*Node)
	if root.Text != "==" || root.Children[0].(*Node).Text != "</" || root.Children[0].(*Node).Children[0].(*Node).Text != "+" {
		t.Fatalf("trim precedence tree %+v", root)
	}
}
func TestTrimRuntimeScalarErrorAndFloatRemoval(t *testing.T) {
	p := trimProfile(t)
	for _, q := range []string{"1 </ 2", "m </ 2", "m >/ 2"} {
		expr, e := Parse(q, p)
		if e != nil {
			t.Fatal(e)
		}
		typed, _, e := Check(expr, p)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
		if e != nil {
			t.Fatal(e)
		}
		src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 4)}}}
		r, ds, e := Evaluate(context.Background(), plan, src, value.NewBoundedAccount(1<<20))
		if q == "1 </ 2" {
			var language *syntax.LanguageError
			if !errors.As(e, &language) || language.Category != "execution" {
				t.Fatalf("scalar trim must fail at execution: %+v %v", r, e)
			}
			continue
		}
		if e != nil || len(r.Vector) != 0 || len(ds) == 0 {
			t.Fatalf("float trim must remove with annotation %+v %+v %v", r, ds, e)
		}
	}
}
