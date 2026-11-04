// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"reflect"
	"soundpost/internal/query/syntax"
	"testing"
)

func TestAllOwnedOperatorAndAggregationProductions(t *testing.T) {
	p := testProfile()
	p.ActiveFeatureSet.Enabled = []string{"promql-experimental-functions", "promql-duration-expr", "promql-binop-fill-modifiers", "promql-extended-range-selectors"}
	for _, op := range []string{"+", "-", "*", "/", "%", "^", "atan2", "==", "!=", ">", "<", ">=", "<=", "and", "or", "unless"} {
		text := "fixture_left " + op + " fixture_right"
		e, err := Parse(text, p)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if _, _, err = Check(e, p); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
	}
	for _, agg := range []string{"sum", "min", "max", "avg", "group", "stddev", "stdvar", "count", "count_values", "bottomk", "topk", "quantile", "limitk", "limit_ratio"} {
		args := "fixture_metric"
		switch agg {
		case "count_values":
			args = `"value", fixture_metric`
		case "bottomk", "topk", "quantile", "limitk", "limit_ratio":
			args = "0.5, fixture_metric"
		}
		for _, group := range []string{"", " by ()", " without ()", " by (job, instance)", ` without ("标签")`} {
			text := agg + group + "(" + args + ")"
			e, err := Parse(text, p)
			if err != nil {
				t.Fatalf("%s: %v", text, err)
			}
			if _, _, err = Check(e, p); err != nil {
				t.Fatalf("%s: %v", text, err)
			}
			s := Format(e)
			r, err := Parse(s, p)
			if err != nil || !reflect.DeepEqual(meaning(e), meaning(r)) {
				t.Fatalf("grouping meaning changed %s => %s: %v", text, s, err)
			}
		}
	}
}

type semanticNode struct {
	Kind, Text                          string
	Bits                                uint64
	Labels                              []string
	Matchers                            []Matcher
	Without                             bool
	Matching                            *VectorMatching
	Bool                                bool
	Window, Step, Offset, At, Extension string
	FillLeft, FillRight                 *uint64
	Children                            []semanticNode
}

func meaning(e Expr) semanticNode {
	n := e.(*Node)
	if n.Kind == "paren" {
		return meaning(n.Children[0])
	}
	s := semanticNode{Kind: n.Kind, Text: n.Text, Bits: n.FloatBits, Labels: n.Labels, Without: n.GroupWithout, Bool: n.Bool, Window: n.RangeText, Step: n.Step, Offset: n.Offset, At: n.At, Extension: n.Extension, FillLeft: n.FillLeft, FillRight: n.FillRight}
	if n.Kind == "number" {
		s.Text = ""
		s.Window = ""
	}
	for _, m := range n.Matchers {
		s.Matchers = append(s.Matchers, Matcher{Name: m.Name, Op: m.Op, Value: m.Value})
	}
	if n.Matching != nil {
		m := *n.Matching
		m.Range = syntax.SourceRange{}
		s.Matching = &m
	}
	for _, c := range n.Children {
		s.Children = append(s.Children, meaning(c))
	}
	return s
}
