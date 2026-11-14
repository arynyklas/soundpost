// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"testing"
)

// The reference grammar reads the topk/bottomk parameter as one NUMBER token
// directly followed by a comma and converts it with an integer parser. Anything
// else is parsed as the single operand, so the comma is the unexpected token.
// Each row restates a recorded native observation (tk-* rows of the native
// metric replay); start is -1 where the reference reports no position.
func TestTopKParameterIsPlainIntegerToken(t *testing.T) {
	const tail = `,count_over_time({app="api"}[5s]))`
	for _, c := range []struct {
		param string
		code  string
		start int
	}{
		{`0`, "function.arguments", -1}, {`0.5`, "function.arguments", -1}, {`1.5`, "function.arguments", -1},
		{`1e0`, "function.arguments", -1}, {`0x2`, "function.arguments", -1}, {`1_0`, "function.arguments", -1},
		{`2.0`, "function.arguments", -1}, {`2.`, "function.arguments", -1},
		{`-1`, "syntax.unexpected-token", 7}, {`1/2`, "syntax.unexpected-token", 8}, {`2/1`, "syntax.unexpected-token", 8},
		{`(1)`, "syntax.unexpected-token", 8}, {`1+1`, "syntax.unexpected-token", 8},
		{`vector(1)`, "syntax.unexpected-token", 14}, {`scalar(vector(2))`, "syntax.unexpected-token", 5},
		{`"1"`, "syntax.unexpected-token", 5},
	} {
		for _, name := range []string{"topk", "bottomk"} {
			shift := 0
			if name == "bottomk" {
				shift = 3
			}
			q := name + "(" + c.param + tail
			p := testProfile(t)
			e, err := Parse(q, p)
			if err == nil {
				_, _, err = Check(e, p)
			}
			var language *syntax.LanguageError
			if !errors.As(err, &language) {
				t.Fatalf("%s: err=%v (want typed language error %s)", q, err, c.code)
			}
			if language.Code != c.code {
				t.Fatalf("%s: code=%s want %s", q, language.Code, c.code)
			}
			if c.start >= 0 && language.Range.StartByte != c.start+shift {
				t.Fatalf("%s: start=%d want %d", q, language.Range.StartByte, c.start+shift)
			}
		}
	}
	for _, q := range []string{`topk(1` + tail, `topk(100` + tail, `bottomk(2` + tail} {
		p := testProfile(t)
		e, err := Parse(q, p)
		if err == nil {
			_, _, err = Check(e, p)
		}
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}
