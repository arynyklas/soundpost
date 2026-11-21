// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
)

// fillKeyword returns the fill modifier keyword at the cursor. The pinned
// lexer treats fill, fill_left and fill_right as keywords only when a left
// parenthesis follows; otherwise they are ordinary metric names.
func (q *parser) fillKeyword() string {
	t := q.peek()
	if q.p.ID != "promql-prometheus-3.13.5" || t.kind != "ident" || t.text != "fill" && t.text != "fill_left" && t.text != "fill_right" {
		return ""
	}
	if q.i+1 < len(q.ts) && q.ts[q.i+1].text == "(" {
		return t.text
	}
	return ""
}

// fillClause consumes one fill modifier on binary node n and reports whether
// the modifier is not enabled; the caller blames the whole binary expression
// once its right operand is parsed.
func (q *parser) fillClause(n *Node, mode string) (gated bool) {
	q.pop()
	gated = !enabled(q.p, "promql-binop-fill-modifiers")
	bits := math.Float64bits(q.fillValue())
	if mode == "fill" || mode == "fill_left" {
		b := bits
		n.FillLeft = &b
	}
	if mode == "fill" || mode == "fill_right" {
		b := bits
		n.FillRight = &b
	}
	return gated
}

func (q *parser) fillValue() float64 {
	q.need("(")
	negative := false
	if q.eat("-") {
		negative = true
	} else {
		q.eat("+")
	}
	t := q.peek()
	if !isNumberToken(t) {
		q.failTok(t, "fill requires numeric literal")
		return 0
	}
	q.pop()
	n := q.number(t)
	q.need(")")
	f := math.Float64frombits(n.FloatBits)
	if negative {
		f = -f
	}
	return f
}
