// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
)

type parser struct {
	s                        string
	ts                       []token
	i                        int
	p                        profile.Profile
	err                      error
	durationMode, allowEmpty bool
}

func Parse(s string, p profile.Profile) (Expr, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	ts, err := lex(s)
	if err != nil {
		return nil, err
	}
	q := parser{s: s, ts: ts, p: p}
	e := q.expr(0)
	if q.err == nil && q.peek().kind != "eof" {
		t := q.peek()
		q.err = &syntax.LanguageError{Code: "syntax.unexpected-token", Category: "syntax", Range: syntax.Range(q.s, t.start, t.end), SafeMessage: "unexpected token"}
	}
	return e, q.err
}
func (q *parser) peek() token { return q.ts[q.i] }
func (q *parser) pop() token {
	t := q.peek()
	if t.kind != "eof" {
		q.i++
	}
	return t
}
func (q *parser) eat(s string) bool {
	if q.peek().text == s {
		q.pop()
		return true
	}
	return false
}
func (q *parser) need(s string) {
	if !q.eat(s) {
		q.fail("expected " + s)
	}
}
func (q *parser) fail(s string) {
	if q.err == nil {
		t := q.peek()
		q.err = &syntax.LanguageError{Category: "syntax", Range: syntax.Range(q.s, t.start, t.end), SafeMessage: s}
	}
}
func (q *parser) failRange(r syntax.SourceRange, s string) {
	if q.err == nil {
		q.err = &syntax.LanguageError{Category: "syntax", Range: r, SafeMessage: s}
	}
}
func (q *parser) span(n *Node, start int) {
	end := start
	if q.i > 0 {
		end = q.ts[q.i-1].end
	}
	n.Range = syntax.Range(q.s, start, end)
}

var precedence = map[string]int{"or": 1, "and": 2, "unless": 2, "==": 3, "!=": 3, ">": 3, "<": 3, ">=": 3, "<=": 3, "</": 3, ">/": 3, "+": 4, "-": 4, "*": 5, "/": 5, "%": 5, "atan2": 5, "^": 6}
var aggregates = map[string]bool{"sum": true, "min": true, "max": true, "avg": true, "group": true, "stddev": true, "stdvar": true, "count": true, "count_values": true, "bottomk": true, "topk": true, "quantile": true, "limitk": true, "limit_ratio": true}

func (q *parser) names() []string {
	q.need("(")
	names := []string{}
	if q.eat(")") {
		return names
	}
	for q.err == nil {
		t := q.pop()
		if t.kind != "ident" && t.kind != "string" {
			q.failRange(syntax.Range(q.s, t.start, t.end), "expected label name")
			break
		}
		if t.value == "" || t.kind == "ident" && (!identifier(t.value) || strings.Contains(t.value, ":")) {
			q.fail("invalid label name")
		}
		names = append(names, t.value)
		if q.eat(")") {
			break
		}
		q.need(",")
		if q.eat(")") {
			break
		}
	}
	return names
}
func (q *parser) expr(min int) Expr {
	left := q.primary()
	for q.err == nil {
		op := q.peek()
		prec := precedence[op.text]
		if prec == 0 || prec < min {
			break
		}
		q.pop()
		if (op.text == "</" || op.text == ">/") && q.p.ID != "promql-prometheus-3.13.5" {
			q.failRange(syntax.Range(q.s, op.start+1, op.end), "operator is not in the pinned profile")
			break
		}
		if q.durationMode && op.text != "+" && op.text != "-" && op.text != "*" && op.text != "/" && op.text != "%" && op.text != "^" {
			q.fail("invalid duration operator")
		}
		n := &Node{Kind: "binary", Text: op.text, Children: []Expr{left}}
		n.Bool = q.eat("bool")
		if q.peek().text == "on" || q.peek().text == "ignoring" {
			t := q.pop()
			n.Matching = &VectorMatching{On: t.text == "on", Labels: q.names()}
			n.Matching.Range = syntax.Range(q.s, t.start, q.ts[q.i-1].end)
		}
		if q.peek().text == "group_left" || q.peek().text == "group_right" {
			t := q.pop()
			if n.Matching == nil {
				n.Matching = &VectorMatching{}
			}
			n.Matching.Cardinality = t.text
			if q.peek().text == "(" {
				n.Matching.Include = q.names()
			}
			n.Matching.Range = syntax.Range(q.s, t.start, q.ts[q.i-1].end)
		}
		for q.peek().text == "fill" || q.peek().text == "fill_left" || q.peek().text == "fill_right" {
			mode := q.pop().text
			q.gate("promql-binop-fill-modifiers")
			f := q.fillValue()
			bits := math.Float64bits(f)
			if mode == "fill" || mode == "fill_left" {
				if n.FillLeft != nil {
					q.fail("duplicate left fill")
				}
				b := bits
				n.FillLeft = &b
			}
			if mode == "fill" || mode == "fill_right" {
				if n.FillRight != nil {
					q.fail("duplicate right fill")
				}
				b := bits
				n.FillRight = &b
			}
		}
		n.OperatorRange = syntax.Range(q.s, op.start, q.ts[q.i-1].end)
		next := prec + 1
		if op.text == "^" {
			next = prec
		}
		n.Children = append(n.Children, q.expr(next))
		if q.durationMode {
			if n.Bool || n.Matching != nil || n.FillLeft != nil || n.FillRight != nil {
				q.fail("duration operators do not permit vector modifiers")
			}
			if op.text == "/" || op.text == "%" {
				if f, ok := constantNumber(n.Children[1].(*Node)); ok && f == 0 {
					q.fail("duration division by zero")
				}
			}
		}
		q.span(n, left.SourceRange().StartByte)
		left = n
	}
	return left
}
func (q *parser) primary() Expr {
	t := q.pop()
	n := &Node{Text: t.value, Range: syntax.Range(q.s, t.start, t.end)}
	switch {
	case t.text == "+" || t.text == "-":
		n.Kind = "unary"
		n.Text = t.text
		n.Children = []Expr{q.expr(6)}
	case t.text == "(":
		n.Kind = "paren"
		n.Children = []Expr{q.expr(0)}
		q.need(")")
	case t.kind == "number" || strings.EqualFold(t.text, "inf") || strings.EqualFold(t.text, "nan"):
		n = q.number(t)
	case t.kind == "string":
		n.Kind = "string"
	case t.text == "{":
		n.Kind = "selector"
		n.Text = ""
		q.selector(n, true)
	case t.kind == "ident":
		n.Kind = "selector"
		if aggregates[t.text] && (q.peek().text == "(" || q.peek().text == "by" || q.peek().text == "without") {
			n.Kind = "aggregate"
			if q.peek().text != "(" {
				n.GroupWithout = q.pop().text == "without"
				n.Labels = q.names()
			}
			q.args(n)
			if q.peek().text == "by" || q.peek().text == "without" {
				if n.Labels != nil {
					q.fail("duplicate aggregation grouping")
				}
				n.GroupWithout = q.pop().text == "without"
				n.Labels = q.names()
			}
		} else if q.peek().text == "(" && !(q.p.ID == "promql-prometheus-3.1.0" && (t.text == "start" || t.text == "end")) {
			n.Kind = "call"
			q.args(n)
		} else if q.eat("{") {
			q.selector(n, true)
		}
		if q.durationMode && n.Kind == "call" && (t.text == "step" || t.text == "range" || t.text == "min_of" || t.text == "max_of") {
			n.Kind = "duration_call"
			q.gate("promql-duration-expr")
		}
		if t.kind == "ident" && !identifier(t.text) {
			q.fail("UTF-8 metric names must be quoted")
		}
	default:
		n.Kind = "invalid"
		q.failRange(syntax.Range(q.s, t.start, t.end), "expected expression")
	}
	q.span(n, t.start)
	for q.err == nil {
		if q.durationMode {
			if n.Kind != "number" && n.Kind != "unary" && n.Kind != "paren" && n.Kind != "duration_call" {
				q.fail("invalid duration expression")
			}
			return n
		}
		switch q.peek().text {
		case "[":
			q.pop()
			r := &Node{Kind: "range", Children: []Expr{n}}
			r.RangeExpr = q.durationExpr(true)
			r.RangeText = durationText(r.RangeExpr)
			if q.eat(":") {
				r.Kind = "subquery"
				if q.peek().text != "]" {
					r.StepExpr = q.durationExpr(true)
					r.Step = durationText(r.StepExpr)
				}
			}
			q.need("]")
			if r.Kind == "range" && n.Kind != "selector" {
				q.fail("range requires vector selector")
			}
			if n.Offset != "" || n.At != "" {
				q.fail("range must precede time modifiers")
			}
			q.span(r, t.start)
			n = r
		case "offset":
			q.pop()
			if n.Offset != "" {
				q.fail("duplicate offset")
			}
			n.OffsetExpr = q.offsetValue()
			n.Offset = durationText(n.OffsetExpr)
			q.span(n, t.start)
		case "@":
			q.pop()
			if n.At != "" {
				q.failRange(n.Range, "duplicate @")
			}
			a := q.pop()
			n.At = a.text
			if a.text == "-" || a.text == "+" {
				a = q.pop()
				n.At += a.text
			}
			if a.text == "start" || a.text == "end" {
				q.need("(")
				q.need(")")
				n.At += "()"
			} else if a.kind != "number" {
				q.fail("expected timestamp")
			} else {
				f, err := strconv.ParseFloat(n.At, 64)
				if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f >= float64(math.MaxInt64) || f <= float64(math.MinInt64) {
					q.failRange(n.Range, "timestamp out of bounds")
				}
			}
			q.span(n, t.start)
		case "anchored", "smoothed":
			ext := q.pop().text
			q.gate("promql-extended-range-selectors")
			if n.Extension != "" && n.Extension != ext {
				q.fail("range extensions cannot be combined")
			}
			if n.Kind != "range" && n.Kind != "selector" && n.Kind != "subquery" {
				q.fail("extension requires selector or subquery")
			}
			n.Extension = ext
			q.span(n, t.start)
		default:
			return n
		}
	}
	return n
}
func (q *parser) args(n *Node) {
	q.need("(")
	if q.eat(")") {
		return
	}
	for q.err == nil {
		old := q.allowEmpty
		q.allowEmpty = n.Kind == "call" && n.Text == "info" && len(n.Children) == 1
		n.Children = append(n.Children, q.expr(0))
		q.allowEmpty = old
		if q.eat(")") {
			break
		}
		q.need(",")
	}
}
func (q *parser) selector(n *Node, opened bool) {
	nonempty := n.Text != "" || q.allowEmpty
	if q.eat("}") {
		if !nonempty {
			q.failRange(syntax.Range(q.s, n.Range.StartByte, q.ts[q.i-1].end), "selector must contain a nonempty matcher")
		}
		return
	}
	for q.err == nil {
		t := q.pop()
		if t.kind == "string" && q.peek().text != "=" && q.peek().text != "!=" && q.peek().text != "=~" && q.peek().text != "!~" {
			if n.Text != "" {
				q.fail("metric name specified twice")
			}
			n.Matchers = append(n.Matchers, Matcher{Name: "__name__", Op: "=", Value: t.value, Range: syntax.Range(q.s, t.start, t.end)})
			nonempty = nonempty || t.value != ""
		} else {
			if t.kind != "ident" && t.kind != "string" {
				q.failRange(syntax.Range(q.s, t.start, t.end), "expected label name")
				break
			}
			if t.value == "" || t.kind == "ident" && (!identifier(t.value) || strings.Contains(t.value, ":")) {
				q.fail("invalid label name")
			}
			op := q.pop()
			if op.text != "=" && op.text != "!=" && op.text != "=~" && op.text != "!~" {
				q.failRange(syntax.Range(q.s, op.start, op.end), "expected matcher operator")
			}
			v := q.pop()
			if v.kind != "string" {
				q.failRange(syntax.Range(q.s, v.start, v.end), "expected string")
			}
			m := Matcher{Name: t.value, Op: op.text, Value: v.value, Range: syntax.Range(q.s, t.start, v.end)}
			empty := v.value == ""
			if op.text == "=~" || op.text == "!~" {
				re, err := regexcompat.CompileLabel(q.p, v.value)
				if err != nil {
					q.failRange(m.Range, "invalid regular expression")
				} else {
					empty = re.MatchString("")
				}
			}
			if op.text == "!=" || op.text == "!~" {
				empty = !empty
			}
			nonempty = nonempty || !empty
			n.Matchers = append(n.Matchers, m)
			if t.value == "__name__" && n.Text != "" {
				q.fail("metric name specified twice")
			}
		}
		if q.eat("}") {
			break
		}
		q.need(",")
		if q.eat("}") {
			break
		}
	}
	if !nonempty {
		q.failRange(syntax.Range(q.s, n.Range.StartByte, q.ts[q.i-1].end), "selector must contain a nonempty matcher")
	}
}
