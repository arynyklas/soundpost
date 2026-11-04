// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"fmt"
	"math"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"unicode/utf8"
)

func enabled(p profile.Profile, gate string) bool {
	if gate == "" {
		return true
	}
	for _, g := range p.ActiveFeatureSet.Enabled {
		if g == gate {
			return true
		}
	}
	return false
}
func Check(e Expr, p profile.Profile) (TypedExpr, []syntax.Diagnostic, error) {
	if err := validateProfile(p); err != nil {
		return TypedExpr{}, nil, err
	}
	v, err := check(e, p)
	return v, nil, err
}
func check(e Expr, p profile.Profile) (TypedExpr, error) {
	v := TypedExpr{Expr: e, ProfileID: p.ID, ProfileIdentity: p.Identity, FeatureSetID: p.ActiveFeatureSet.ID}
	fail := func(code, msg string) (TypedExpr, error) {
		return v, &syntax.LanguageError{Code: code, Category: "type", Range: e.SourceRange(), SafeMessage: msg}
	}
	if e == nil {
		return v, fmt.Errorf("nil expression")
	}
	n, ok := e.(*Node)
	if !ok {
		return fail("type.expression-invalid", "unknown expression")
	}
	if _, ok := signatures[p.ID]; !ok {
		return fail("profile.unknown", "unknown pinned PromQL profile")
	}
	for _, c := range n.Children {
		t, err := check(c, p)
		if err != nil {
			return v, err
		}
		v.Children = append(v.Children, t)
	}
	switch n.Kind {
	case "number":
		v.Type = Scalar
		v.FloatBits = n.FloatBits
	case "string":
		v.Type = String
	case "selector":
		v.Type = Vector
	case "paren":
		v.Type = v.Children[0].Type
		v.FloatBits = v.Children[0].FloatBits
	case "unary":
		v.Type = v.Children[0].Type
		if v.Type != Scalar && v.Type != Vector {
			return fail("unary.operand-type", "unary operator requires scalar or instant vector")
		}
		if f, ok := constantNumber(n); ok {
			v.FloatBits = math.Float64bits(f)
		}
	case "range":
		if v.Children[0].Type != Vector {
			return fail("range.input-type", "range requires instant vector")
		}
		v.Type = Matrix
	case "subquery":
		if v.Children[0].Type != Vector {
			return fail("subquery.input-type", "subquery requires instant vector")
		}
		v.Type = Matrix
	case "call", "duration_call":
		s, ok := signatures[p.ID][n.Text]
		if !ok {
			return v, &syntax.LanguageError{Code: "function.unknown", Category: "type", Range: checkFunctionNameRange(n), SafeMessage: "unknown function"}
		}
		gate := s.gate
		if n.Kind == "duration_call" {
			gate = "promql-duration-expr"
		}
		if !enabled(p, gate) {
			return v, &syntax.LanguageError{Code: "function.feature-disabled", Category: "type", Range: checkFunctionNameRange(n), SafeMessage: "function requires enabled feature " + gate}
		}
		min, max := len(s.args), len(s.args)
		if s.variadic != 0 {
			min--
			if s.variadic < 0 {
				max = -1
			} else {
				max = min + s.variadic
			}
		}
		if len(v.Children) < min || max >= 0 && len(v.Children) > max {
			return fail("function.arity", "invalid function argument count")
		}
		for i, a := range v.Children {
			j := i
			if j >= len(s.args) {
				j = len(s.args) - 1
			}
			if j < 0 || a.Type != s.args[j] {
				return v, typeErrorAt(n.Children[i], "function.argument-type", "invalid function argument type")
			}
		}
		if n.Text == "info" && len(n.Children) > 1 {
			sel := n.Children[1].(*Node)
			if sel.Kind != "selector" || sel.Text != "" {
				return v, typeErrorAt(sel, "function.argument-type", "info second argument requires label-only selector")
			}
		}
		v.Type = s.result
		v.OverloadID = p.ID + "/function/" + n.Text
		if n.Kind == "duration_call" {
			v.OverloadID = p.ID + "/duration/" + n.Text
		}
	case "aggregate":
		if (n.Text == "limitk" || n.Text == "limit_ratio") && !enabled(p, "promql-experimental-functions") {
			return fail("aggregation.feature-disabled", "aggregation requires experimental feature")
		}
		want := 1
		if n.Text == "topk" || n.Text == "bottomk" || n.Text == "quantile" || n.Text == "count_values" || n.Text == "limitk" || n.Text == "limit_ratio" {
			want = 2
		}
		if len(v.Children) != want {
			return fail("aggregation.arity", "invalid aggregation argument count")
		}
		if v.Children[want-1].Type != Vector {
			return v, typeErrorAt(n.Children[want-1], "aggregation.input-type", "aggregation requires instant vector")
		}
		if want == 2 {
			arg := Scalar
			if n.Text == "count_values" {
				arg = String
			}
			if v.Children[0].Type != arg {
				return v, typeErrorAt(n.Children[0], "aggregation.parameter-type", "invalid aggregation parameter")
			}
		}
		v.Type = Vector
		v.OverloadID = p.ID + "/aggregation/" + n.Text
	case "binary":
		a, b := v.Children[0].Type, v.Children[1].Type
		if a != Scalar && a != Vector {
			return v, typeErrorAt(n.Children[0], "binary.operand-type", "binary operands require scalar or instant vector")
		}
		if b != Scalar && b != Vector {
			return v, typeErrorAt(n.Children[1], "binary.operand-type", "binary operands require scalar or instant vector")
		}
		set := n.Text == "and" || n.Text == "or" || n.Text == "unless"
		cmp := n.Text == "==" || n.Text == "!=" || n.Text == ">" || n.Text == "<" || n.Text == ">=" || n.Text == "<="
		operatorFail := func(code, msg string) (TypedExpr, error) {
			return v, &syntax.LanguageError{Code: code, Category: "type", Range: n.OperatorRange, SafeMessage: msg}
		}
		if (n.Text == "</" || n.Text == ">/") && p.ID != "promql-prometheus-3.13.5" {
			return operatorFail("binary.operator-profile", "operator is not in the pinned profile")
		}
		if n.Bool && !cmp {
			return operatorFail("binary.bool-modifier", "bool only applies to comparison")
		}
		if a == Scalar && b == Scalar && cmp && !n.Bool {
			return operatorFail("binary.scalar-comparison-bool", "scalar comparison requires bool")
		}
		if set && (a != Vector || b != Vector) {
			return fail("binary.operand-type", "set operator requires instant vectors")
		}
		if n.FillLeft != nil || n.FillRight != nil {
			if a != Vector || b != Vector || set {
				return fail("binary.fill-operands", "fill requires arithmetic or comparison between instant vectors")
			}
		}
		if n.Matching != nil {
			m := n.Matching
			if a != Vector || b != Vector {
				return fail("binary.matching-operands", "vector matching requires two instant vectors")
			}
			if set && m.Cardinality != "" {
				return fail("binary.set-grouping", "set operators reject grouping")
			}
			if m.On {
				for _, x := range m.Labels {
					for _, y := range m.Include {
						if x == y {
							return operatorFail("binary.matching-label-overlap", "label appears in matching and grouping")
						}
					}
				}
			}
		}
		v.Type = Scalar
		if a == Vector || b == Vector {
			v.Type = Vector
		}
	default:
		return fail("type.expression-invalid", "invalid expression kind")
	}
	for _, d := range []Expr{n.RangeExpr, n.StepExpr, n.OffsetExpr} {
		if d != nil {
			dt, err := check(d, p)
			if err != nil {
				return v, err
			}
			if dt.Type != Scalar {
				return fail("duration.argument-type", "duration expression requires scalar")
			}
		}
	}
	if (n.FillLeft != nil || n.FillRight != nil) && (!enabled(p, "promql-binop-fill-modifiers") || p.ID != "promql-prometheus-3.13.5") {
		return fail("binary.fill-feature-disabled", "fill requires enabled feature")
	}
	if n.Extension != "" && (!enabled(p, "promql-extended-range-selectors") || p.ID != "promql-prometheus-3.13.5") {
		return fail("range.extension-feature-disabled", "range extension requires enabled feature")
	}
	if (n.Offset != "" || n.At != "") && n.Kind != "selector" && n.Kind != "range" && n.Kind != "subquery" {
		return fail("time.modifier-target", "time modifier requires selector or subquery")
	}
	return v, nil
}
func typeErrorAt(e Expr, code, msg string) error {
	return &syntax.LanguageError{Code: code, Category: "type", Range: e.SourceRange(), SafeMessage: msg}
}
func checkFunctionNameRange(n *Node) syntax.SourceRange {
	r := n.Range
	r.EndByte = min(r.EndByte, r.StartByte+len(n.Text))
	r.EndRune = min(r.EndRune, r.StartRune+utf8.RuneCountInString(n.Text))
	return r
}
