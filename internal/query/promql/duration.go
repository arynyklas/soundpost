// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"regexp"
	"soundpost/internal/query/syntax"
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
func (q *parser) durationExpr(positive bool) Expr {
	old := q.durationMode
	q.durationMode = true
	e := q.expr(0)
	q.durationMode = old
	if q.err != nil {
		return e
	}
	n := e.(*Node)
	if q.p.ID == "promql-prometheus-3.1.0" && n.Kind != "number" {
		q.fail("profile requires literal duration")
	}
	if f, ok := constantNumber(n); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > float64(math.MaxInt64)/1e9 || positive && f <= 0 {
			q.failRange(n.Range, "duration out of range")
		}
	} else {
		q.gate("promql-duration-expr")
	}
	if n.Kind != "number" && n.Kind != "unary" {
		q.gate("promql-duration-expr")
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
func (q *parser) number(t token) *Node {
	n := &Node{Kind: "number", Text: t.text}
	end := t.end
	// A duration literal is contiguous; whitespace must not turn two tokens into one literal.
	if q.peek().kind == "ident" && q.peek().start == end {
		candidate := q.s[t.start:q.peek().end]
		if f, ok := durationSeconds(candidate); ok {
			end = q.pop().end
			n.FloatBits = math.Float64bits(f)
			n.RangeText = q.s[t.start:end]
			n.Range = syntax.Range(q.s, t.start, end)
			return n
		}
	}
	f, err := strconv.ParseFloat(t.text, 64)
	if err != nil {
		if i, err2 := strconv.ParseInt(t.text, 0, 64); err2 == nil {
			f = float64(i)
		} else {
			q.fail("invalid number")
		}
	}
	n.FloatBits = math.Float64bits(f)
	n.Range = syntax.Range(q.s, t.start, end)
	return n
}
