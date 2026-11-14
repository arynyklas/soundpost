// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"math"
	"strconv"
	"strings"
)

// maxParseDepth bounds the height of a parsed expression tree: parenthesised,
// call, unary, power and subquery nesting as well as the length of left
// associative operator chains. Everything after parsing recurses over the tree.
const maxParseDepth = 4096

type parser struct {
	s                        string
	ts                       []token
	i                        int
	p                        profile.Profile
	err                      error
	lexErr                   error
	signPos                  int // 1 + start of a unary sign owned by the duration keyword about to be parsed
	depth                    int
	durationMode, allowEmpty bool
}

func Parse(s string, p profile.Profile) (Expr, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	ts, lexErr := lex(s, p)
	q := parser{s: s, ts: ts, p: p}
	if lexErr != nil {
		q.lexErr = lexErr
	}
	e := q.expr(0)
	if q.err == nil && q.peek().kind != "eof" {
		t := q.peek()
		q.err = &syntax.LanguageError{Code: "syntax.unexpected-token", Category: "syntax", Range: syntax.Range(q.s, t.start, t.end), SafeMessage: "unexpected token"}
	}
	return e, q.err
}

// peek returns the next token. Reaching a lexical error token adopts the lexer's
// error exactly when the pinned parser would pull that item from its lexer.
func (q *parser) peek() token {
	t := q.ts[q.i]
	if t.kind == "lexerr" && q.err == nil {
		q.err = q.lexErr
	}
	return t
}
func (q *parser) pop() token {
	t := q.peek()
	if t.kind != "eof" && t.kind != "lexerr" {
		q.i++
	}
	return t
}
func (q *parser) failTok(t token, s string) {
	q.failRange(syntax.Range(q.s, t.start, t.end), s)
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
func (q *parser) failCode(r syntax.SourceRange, code, s string) {
	if q.err == nil {
		q.err = &syntax.LanguageError{Code: code, Category: "syntax", Range: r, SafeMessage: s}
	}
}

// tooDeep fails the parse when the expression tree would grow beyond
// maxParseDepth levels, given that levels of it are already open and extra
// more are being added by operator chains or subquery suffixes.
func (q *parser) tooDeep(extra int) bool {
	if q.depth+extra <= maxParseDepth {
		return false
	}
	t := q.peek()
	q.failCode(syntax.Range(q.s, t.start, t.end), "syntax.nesting-too-deep", "expression nesting is too deep")
	return true
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
		if t.value == "" {
			q.failTok(t, "invalid label name")
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
	q.depth++
	defer func() { q.depth-- }()
	if q.tooDeep(0) {
		return &Node{Kind: "invalid"}
	}
	left := q.primary()
	chain := 0
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
			q.failTok(op, "invalid duration operator")
			break
		}
		chain++
		if q.tooDeep(chain) {
			break
		}
		n := &Node{Kind: "binary", Text: op.text, Children: []Expr{left}}
		n.Bool = q.eat("bool")
		if q.peek().text == "on" || q.peek().text == "ignoring" {
			t := q.pop()
			n.Matching = &VectorMatching{On: t.text == "on", Labels: q.names()}
			n.Matching.Range = syntax.Range(q.s, t.start, q.ts[q.i-1].end)
		}
		// group_left/group_right are only valid after on(...) or ignoring(...).
		if n.Matching != nil && (q.peek().text == "group_left" || q.peek().text == "group_right") {
			t := q.pop()
			n.Matching.Cardinality = t.text
			if q.peek().text == "(" {
				n.Matching.Include = q.names()
			}
			n.Matching.Range = syntax.Range(q.s, t.start, q.ts[q.i-1].end)
		}
		// fill() | fill_left() | fill_right() | fill_left() fill_right() | fill_right() fill_left()
		fillGated := false
		if mode := q.fillKeyword(); mode != "" {
			fillGated = q.fillClause(n, mode)
			if mode != "fill" {
				other := "fill_left"
				if mode == "fill_left" {
					other = "fill_right"
				}
				if q.fillKeyword() == other {
					q.fillClause(n, other)
				}
			}
		}
		n.OperatorRange = syntax.Range(q.s, op.start, q.ts[q.i-1].end)
		next := prec + 1
		if op.text == "^" {
			next = prec
		}
		n.Children = append(n.Children, q.expr(next))
		if fillGated {
			q.failRange(syntax.Range(q.s, left.SourceRange().StartByte, q.ts[q.i-1].end), "syntax requires enabled feature promql-binop-fill-modifiers")
		}
		if q.durationMode && q.err == nil {
			q.durationGate(durationStart(left))
			if n.Bool || n.Matching != nil || n.FillLeft != nil || n.FillRight != nil {
				q.fail("duration operators do not permit vector modifiers")
			}
			if op.text == "/" || op.text == "%" {
				if f, ok := literalNumber(n.Children[1].(*Node)); ok && f == 0 {
					q.failTok(op, map[string]string{"/": "division by zero", "%": "modulo by zero"}[op.text])
				}
			}
		}
		q.span(n, left.SourceRange().StartByte)
		left = n
	}
	return left
}
func isNumberToken(t token) bool {
	return t.kind == "number" || t.kind == "duration" || t.kind == "ident" && (strings.EqualFold(t.text, "inf") || strings.EqualFold(t.text, "nan"))
}

// reservedOperand lists the keyword tokens that are not metric identifiers.
var reservedOperand = map[string]bool{"on": true, "ignoring": true, "group_left": true, "group_right": true, "bool": true, "atan2": true}

func (q *parser) primary() Expr {
	t := q.pop()
	signPos := q.signPos
	q.signPos = 0
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
		if q.durationMode && q.err == nil {
			q.durationGate(durationStart(n.Children[0]))
		}
	case isNumberToken(t):
		n = q.number(t)
	case t.kind == "string":
		n.Kind = "string"
	case t.text == "{":
		n.Kind = "selector"
		n.Text = ""
		q.selector(n, true)
	case t.kind == "ident":
		n.Kind = "selector"
		if reservedOperand[t.text] {
			q.failTok(t, "unexpected keyword")
			break
		}
		if aggregates[t.text] && (q.peek().text == "(" || q.peek().text == "by" || q.peek().text == "without") {
			n.Kind = "aggregate"
			n.Text = t.text
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
		} else if q.durationMode && q.p.ID == "promql-prometheus-3.13.5" && durationKeywords[t.text] && q.peek().text == "(" {
			n.Kind = "duration_call"
			n.Text = t.text
			q.durationCall(n, signPos)
		} else if q.peek().text == "(" && !(q.p.ID == "promql-prometheus-3.13.5" && (t.text == "fill" || t.text == "fill_left" || t.text == "fill_right")) && !(q.p.ID == "promql-prometheus-3.1.0" && (t.text == "start" || t.text == "end")) {
			n.Kind = "call"
			q.args(n)
			q.checkKnownFunction(n)
		} else if q.eat("{") {
			q.selector(n, true)
		}
		if t.kind == "ident" && !identifier(t.text) {
			q.fail("UTF-8 metric names must be quoted")
		}
	default:
		n.Kind = "invalid"
		q.failRange(syntax.Range(q.s, t.start, t.end), "expected expression")
	}
	q.span(n, t.start)
	wraps := 0
	for q.err == nil {
		if q.durationMode {
			if n.Kind != "number" && n.Kind != "unary" && n.Kind != "paren" && n.Kind != "duration_call" {
				q.fail("invalid duration expression")
			}
			return n
		}
		switch q.peek().text {
		case "[":
			lb := q.pop()
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
			if q.err == nil && r.Kind == "range" {
				bracket := syntax.Range(q.s, lb.start, q.ts[q.i-1].end)
				if n.Kind != "selector" {
					q.failRange(bracket, "ranges only allowed for vector selectors")
				} else if n.Offset != "" || n.At != "" {
					q.failRange(bracket, "no offset or @ modifiers allowed before range")
				}
			}
			q.span(r, t.start)
			n = r
			wraps++
			if q.tooDeep(wraps) {
				return n
			}
		case "offset":
			q.pop()
			e := q.offsetValue()
			if q.err == nil {
				switch {
				case n.Kind != "selector" && n.Kind != "range" && n.Kind != "subquery":
					q.failRange(n.Range, "offset modifier must be preceded by an instant vector selector or range vector selector or a subquery")
				case n.Offset != "":
					q.failRange(n.Range, "offset may not be set multiple times")
				}
			}
			n.OffsetExpr = e
			n.Offset = durationText(e)
			q.span(n, t.start)
		case "@":
			q.pop()
			sign := ""
			tk := q.peek()
			if tk.text == "+" || tk.text == "-" {
				sign = tk.text
				q.pop()
				tk = q.peek()
			}
			at := ""
			switch {
			case sign == "" && (tk.text == "start" || tk.text == "end"):
				q.pop()
				q.need("(")
				q.need(")")
				at = tk.text + "()"
			case isNumberToken(tk):
				q.pop()
				unsigned := math.Float64frombits(q.number(tk).FloatBits)
				f := unsigned
				if sign == "-" {
					f = -f
				}
				if q.err == nil {
					if math.IsInf(f, 0) || math.IsNaN(f) || f >= float64(math.MaxInt64) || f <= float64(math.MinInt64) {
						q.failRange(n.Range, "timestamp out of bounds for @ modifier")
					}
				}
				// Keep decimal source text; hex, underscore, octal and duration forms use their value.
				if pf, err := strconv.ParseFloat(tk.text, 64); tk.kind == "number" && err == nil && pf == unsigned {
					at = sign + tk.text
				} else {
					at = strconv.FormatFloat(f, 'g', -1, 64)
				}
			default:
				q.failTok(tk, "expected timestamp")
			}
			if q.err == nil {
				switch {
				case n.Kind != "selector" && n.Kind != "range" && n.Kind != "subquery":
					q.failRange(n.Range, "@ modifier must be preceded by an instant vector selector or range vector selector or a subquery")
				case n.At != "":
					q.failRange(n.Range, "@ <timestamp> may not be set multiple times")
				default:
					n.At = at
				}
			}
			q.span(n, t.start)
		case "anchored", "smoothed":
			if q.p.ID != "promql-prometheus-3.13.5" {
				return n
			}
			ext := q.pop().text
			switch {
			case !enabled(q.p, "promql-extended-range-selectors"):
				q.failRange(n.Range, ext+" modifier is experimental and not enabled")
			case n.Kind == "subquery":
				q.failCode(n.Range, "range.extension-subquery", ext+" modifier is not supported for subqueries")
			case n.Extension != "" && n.Extension != ext:
				q.failRange(n.Range, "anchored and smoothed modifiers cannot be used together")
			case n.Kind != "range" && n.Kind != "selector":
				q.failRange(n.Range, ext+" modifier not implemented")
			}
			// The keyword is not part of the selector's source range.
			n.Extension = ext
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
		if q.err == nil {
			// function_call_args COMMA reduces as a trailing comma unless an expression follows.
			if next := q.peek().text; next == ")" || next == "," {
				q.failTok(q.ts[q.i-1], "trailing commas not allowed in function call args")
			}
		}
	}
}

// checkKnownFunction raises the unknown-function error when a call is reduced,
// as the pinned grammar action does, so it precedes any grammar error in later
// tokens. It keeps its type category; the disabled-function check stays in Check.
func (q *parser) checkKnownFunction(n *Node) {
	if q.err != nil {
		return
	}
	if _, ok := signatures[q.p.ID][n.Text]; !ok {
		q.err = &syntax.LanguageError{Code: "function.unknown", Category: "type", Range: checkFunctionNameRange(n), SafeMessage: "unknown function"}
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
				q.failRange(syntax.Range(q.s, n.Range.StartByte, t.end), "metric name specified twice")
			}
			n.Matchers = append(n.Matchers, Matcher{Name: "__name__", Op: "=", Value: t.value, Range: syntax.Range(q.s, t.start, t.end)})
			nonempty = nonempty || t.value != ""
		} else {
			if t.kind != "ident" && t.kind != "string" {
				q.failRange(syntax.Range(q.s, t.start, t.end), "expected label name")
				break
			}
			if t.value == "" || t.kind == "ident" && (!identifier(t.value) || strings.Contains(t.value, ":")) {
				q.failTok(t, "invalid label name")
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
				q.failRange(syntax.Range(q.s, n.Range.StartByte, v.end), "metric name specified twice")
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
