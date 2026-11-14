// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"math"
)

// Offset's unparenthesized operand stops before exponentiation. Thus the outer
// binary expression, rather than the offset, owns the ^ in metric offset -2^2.
func (q *parser) offsetValue() Expr {
	old := q.durationMode
	q.durationMode = true
	sign := q.peek()
	signed := sign.text == "-" || sign.text == "+"
	if signed {
		q.pop()
	}
	e := q.primary()
	if signed {
		n := &Node{Kind: "unary", Text: sign.text, Children: []Expr{e}, Range: syntax.Range(q.s, sign.start, e.SourceRange().EndByte)}
		e = n
	}
	q.durationMode = old
	n := e.(*Node)
	literal := n.Kind == "number" || n.Kind == "unary" && n.Children[0].(*Node).Kind == "number"
	if q.p.ID == "promql-prometheus-3.1.0" && (!literal || signed && sign.text == "+") {
		q.fail("profile requires literal offset")
	}
	if !literal {
		q.gate("promql-duration-expr")
	}
	if f, ok := constantNumber(n); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > float64(math.MaxInt64)/1e9 {
			q.fail("offset out of range")
		}
	}
	return e
}
