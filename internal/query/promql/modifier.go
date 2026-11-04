// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"strings"
)

func (q *parser) fillValue() float64 {
	q.need("(")
	negative := false
	if q.eat("-") {
		negative = true
	} else {
		q.eat("+")
	}
	t := q.pop()
	if t.kind != "number" && !strings.EqualFold(t.text, "inf") && !strings.EqualFold(t.text, "nan") {
		q.fail("fill requires numeric literal")
	}
	n := q.number(t)
	q.need(")")
	f := math.Float64frombits(n.FloatBits)
	if negative {
		f = -f
	}
	return f
}
