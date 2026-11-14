// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// startsOffsetOperand reports whether t can begin the value after "offset": a
// number or duration token and, in 3.13.5, a sign (a nested unary duration
// expression), a parenthesised duration expression or a duration keyword.
func (q *parser) startsOffsetOperand(t token) bool {
	if isNumberToken(t) {
		return true
	}
	if q.p.ID != "promql-prometheus-3.13.5" {
		return false
	}
	return t.text == "(" || t.text == "+" || t.text == "-" || t.kind == "ident" && durationKeywords[t.text]
}

// Offset's unparenthesized operand stops before exponentiation. Thus the outer
// binary expression, rather than the offset, owns the ^ in metric offset -2^2.
func (q *parser) offsetValue() Expr {
	old := q.durationMode
	q.durationMode = true
	defer func() { q.durationMode = old }()
	sign := q.peek()
	signed := sign.text == "-" || sign.text == "+"
	if signed {
		if q.p.ID == "promql-prometheus-3.1.0" && sign.text == "+" {
			q.failTok(sign, "unexpected + in offset")
			return &Node{Kind: "invalid"}
		}
		q.pop()
	}
	t := q.peek()
	if !q.startsOffsetOperand(t) {
		q.failTok(t, "unexpected token in offset")
		return &Node{Kind: "invalid"}
	}
	if signed && t.kind == "ident" && durationKeywords[t.text] {
		q.signPos = sign.start + 1 // "-step()" is a single grammar rule blamed at its sign
	}
	e := q.primary()
	if signed {
		n := &Node{Kind: "unary", Text: sign.text, Children: []Expr{e}, Range: syntax.Range(q.s, sign.start, e.SourceRange().EndByte)}
		e = n
	}
	n := e.(*Node)
	if q.err == nil && q.p.ID == "promql-prometheus-3.13.5" {
		// durationLiteralOutOfRange: the literal, in seconds, must fit a signed nanosecond Duration.
		if f, ok := literalNumber(n); ok && (f > float64(1<<63)/1e9 || f < -float64(1<<63)/1e9) {
			q.failRange(n.Range, "duration out of range")
		}
	}
	return e
}
