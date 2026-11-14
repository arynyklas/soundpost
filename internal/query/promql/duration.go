// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var durationParts = regexp.MustCompile(`([0-9]+)(ms|[smhdwy])`)
var durationUnits = map[string]int64{"ms": 1, "s": 1000, "m": 60000, "h": 3600000, "d": 86400000, "w": 604800000, "y": 31536000000}

func durationSeconds(s string) (float64, bool) {
	parts := durationParts.FindAllStringSubmatch(s, -1)
	if len(parts) == 0 {
		return 0, false
	}
	var total int64
	last := int64(math.MaxInt64)
	var joined strings.Builder
	for _, p := range parts {
		joined.WriteString(p[0])
		unit := durationUnits[p[2]]
		if unit >= last {
			return 0, false
		}
		last = unit
		n, err := strconv.ParseInt(p[1], 10, 64)
		if err != nil || n > (math.MaxInt64-total)/unit {
			return 0, false
		}
		total += n * unit
	}
	if joined.String() != s || total > math.MaxInt64/1000000 {
		return 0, false
	}
	return float64(total) / 1000, true
}
func constantNumber(n *Node) (float64, bool) {
	switch n.Kind {
	case "number":
		return math.Float64frombits(n.FloatBits), true
	case "paren":
		return constantNumber(n.Children[0].(*Node))
	case "unary":
		f, ok := constantNumber(n.Children[0].(*Node))
		if n.Text == "-" {
			f = -f
		}
		return f, ok
	}
	return 0, false
}
func (q *parser) gate(name string) {
	if q.p.ID != "promql-prometheus-3.13.5" || !enabled(q.p, name) {
		q.fail("syntax requires enabled feature " + name)
	}
}

var durationKeywords = map[string]bool{"step": true, "range": true, "min_of": true, "max_of": true}

// durationGate reports a duration expression that is not enabled, positioned at
// the start of the construct the pinned parser blames (experimentalDurationExpr).
func (q *parser) durationGate(pos int) {
	if q.p.ID != "promql-prometheus-3.13.5" || !enabled(q.p, "promql-duration-expr") {
		q.failRange(syntax.Range(q.s, pos, pos), "experimental duration expression is not enabled")
	}
}

// durationStart is the position experimentalDurationExpr reports for e: the
// leftmost operand of a binary expression, otherwise the node's own start.
func durationStart(e Expr) int {
	n := e.(*Node)
	if n.Kind == "binary" && len(n.Children) > 0 {
		return durationStart(n.Children[0])
	}
	if n.Kind == "paren" && len(n.Children) > 0 {
		return durationStart(n.Children[0])
	}
	return n.Range.StartByte
}

// durationCall parses the argument list of step(), range(), min_of(a, b) or
// max_of(a, b); the min/max forms take exactly two duration expressions. A
// signed keyword (signPos > 0) is reported at its sign, as one grammar rule.
func (q *parser) durationCall(n *Node, signPos int) {
	gate := func(pos int) {
		if signPos > 0 {
			pos = signPos - 1
		}
		q.durationGate(pos)
	}
	q.need("(")
	if n.Text == "step" || n.Text == "range" {
		q.need(")")
		if q.err == nil {
			gate(n.Range.StartByte)
		}
		return
	}
	n.Children = append(n.Children, q.expr(0))
	q.need(",")
	n.Children = append(n.Children, q.expr(0))
	q.need(")")
	if q.err == nil {
		gate(durationStart(n.Children[0]))
	}
}

// literalNumber folds a numeric literal with unary signs (the pinned parser folds
// the sign into the NumberLiteral); parentheses are not folded.
func literalNumber(n *Node) (float64, bool) {
	switch n.Kind {
	case "number":
		return math.Float64frombits(n.FloatBits), true
	case "unary":
		f, ok := literalNumber(n.Children[0].(*Node))
		if n.Text == "-" {
			f = -f
		}
		return f, ok
	}
	return 0, false
}
func (q *parser) durationExpr(positive bool) Expr {
	if q.p.ID == "promql-prometheus-3.1.0" {
		// 3.1.0 ranges and resolutions are a single unsigned number or duration token.
		t := q.peek()
		if t.kind != "number" && t.kind != "duration" {
			q.failTok(t, "unexpected token, expected number or duration")
			return &Node{Kind: "invalid"}
		}
		q.pop()
		return q.number(t)
	}
	old := q.durationMode
	q.durationMode = true
	e := q.expr(0)
	q.durationMode = old
	if q.err != nil {
		return e
	}
	n := e.(*Node)
	if f, ok := constantNumber(n); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > float64(math.MaxInt64)/1e9 || positive && f <= 0 {
			q.failRange(n.Range, "duration out of range")
		}
	}
	return e
}
func durationText(e Expr) string {
	n := e.(*Node)
	if n.Kind == "number" && n.RangeText != "" {
		return n.RangeText
	}
	return Format(e)
}

var durationShape = regexp.MustCompile(`^(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$`)

// number converts a number or duration token the way the pinned parser does:
// base-inferred int64 first (so a leading zero is octal and underscores are
// accepted), then binary64; durations through ParseDuration, which 3.1.0
// additionally rejects when zero. Every failure is positioned at the token.
func (q *parser) number(t token) *Node {
	n := &Node{Kind: "number", Text: t.text, Range: syntax.Range(q.s, t.start, t.end)}
	if t.kind == "duration" {
		f, ok := durationSeconds(t.text)
		switch {
		case !ok && !durationShape.MatchString(t.text):
			q.failTok(t, "not a valid duration string")
		case !ok:
			q.failTok(t, "duration out of range")
		case f == 0 && q.p.ID == "promql-prometheus-3.1.0":
			q.failTok(t, "duration must be greater than 0")
		}
		n.FloatBits = math.Float64bits(f)
		n.RangeText = t.text
		return n
	}
	i, err := strconv.ParseInt(t.text, 0, 64)
	f := float64(i)
	if err != nil {
		f, err = strconv.ParseFloat(t.text, 64)
	}
	if err != nil {
		q.failTok(t, "error parsing number")
	}
	n.FloatBits = math.Float64bits(f)
	return n
}
