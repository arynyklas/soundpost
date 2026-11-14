// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestClassifyNativeParseMessage(t *testing.T) {
	intp := func(v int) *int { return &v }
	cases := []struct {
		name, text, semantic string
		start                *int
	}{
		{"named capture", `parse error : stage '|> "<a> done"' : named captures are not allowed: found '<a>'`, "pattern.invalid", nil},
		{"ip bad pattern", `parse error : stage '|= ip("192.0.2.900")' : ip: invalid pattern: "192.0.2.900"`, "ip.pattern-invalid", nil},
		{"ip reversed range", `parse error : stage '|= ip("192.0.2.9-192.0.2.1")' : ip: invalid pattern: "192.0.2.9-192.0.2.1"`, "ip.pattern-invalid", nil},
		{"ip operator", `parse error : stage '|~ ip("192.0.2.1")' : ip: invalid operation`, "ip.operator-invalid", nil},
		{"empty duration", `parse error at line 0, col 17: empty duration string`, "syntax.duration", intp(17)},
		{"unknown unit", `parse error at line 0, col 17: unknown unit "." in duration "1.5m"`, "syntax.duration", intp(17)},
		{"unknown unit multi digit col", `parse error at line 0, col 120: unknown unit "x" in duration "5x"`, "syntax.duration", intp(120)},
		{"missing closing bracket", `parse error at line 0, col 27: missing closing ']' in duration`, "syntax.duration", intp(27)},
		{"not a valid duration", `parse error at line 0, col 27: not a valid duration string: "x"`, "syntax.duration", intp(27)},
		{"not a valid duration on a real line is not the lexer error", `parse error at line 1, col 27: not a valid duration string: "x"`, "", nil},
		{"exponent without digits", `parse error at line 1, col 17: exponent has no digits`, "syntax.number", nil},
		{"p exponent needs hex mantissa", `parse error at line 1, col 17: 'P' exponent requires hexadecimal mantissa`, "syntax.number", nil},
		{"hex literal without digits", `parse error at line 1, col 17: hexadecimal literal has no digits`, "syntax.number", nil},
		{"invalid octal digit", `parse error at line 1, col 17: invalid digit '8' in octal literal`, "syntax.number", nil},
		{"separator rule", `parse error at line 1, col 17: '_' must separate successive digits`, "syntax.number", nil},
		{"number error on line 0 is not a source literal", `parse error at line 0, col 17: exponent has no digits`, "", nil},
		{"number wording inside another message", `parse error at line 1, col 17: syntax error: exponent has no digits`, "", nil},
		{"invalid char escape", `parse error at line 1, col 17: invalid char escape`, "syntax.string-escape", nil},
		{"topk parameter zero", `parse error : invalid parameter (must be greater than 0) topk(0`, "function.arguments", nil},
		{"bottomk parameter not an integer", `parse error : invalid parameter bottomk(0.5,`, "function.arguments", nil},
		{"parameter wording inside a positioned syntax error", `parse error at line 1, col 8: syntax error: invalid parameter topk(1`, "", nil},
		{"metric literal not a float", `parse error : unable to parse literal as a float: strconv.ParseFloat: parsing "0x10": invalid syntax`, "syntax.number", nil},
		{"vector literal out of range", `parse error : unable to parse vectorExpr as a float: strconv.ParseFloat: parsing "1e999": value out of range`, "syntax.number", nil},
		{"float wording inside another message", `parse error at line 1, col 3: unable to parse literal as a float: strconv.ParseFloat: parsing "x": invalid syntax`, "", nil},
		{"invalid char escape on line 0", `parse error at line 0, col 17: invalid char escape`, "", nil},
		{"missing closing bracket on a real line is not the lexer error", `parse error at line 1, col 27: missing closing ']' in duration`, "", nil},
		{"duration text on a real line is not the lexer error", `parse error at line 1, col 17: empty duration string`, "", nil},
		{"unrelated syntax error", `parse error at line 1, col 13: syntax error: unexpected unwrap`, "", nil},
		{"unterminated literal", `parse error at line 1, col 16: literal not terminated`, "syntax.string", nil},
		{"unterminated literal on line 0 is not a source literal", `parse error at line 0, col 16: literal not terminated`, "", nil},
		{"literal wording inside another message", `parse error at line 1, col 16: syntax error: literal not terminated`, "", nil},
		{"near-miss ip wording", `parse error : stage '|= ip("x")' : ip: something else`, "", nil},
		{"empty", ``, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			semantic, start := classifyNativeParseMessage(c.text)
			if semantic != c.semantic {
				t.Fatalf("semantic = %q, want %q", semantic, c.semantic)
			}
			if (start == nil) != (c.start == nil) || start != nil && *start != *c.start {
				t.Fatalf("start = %v, want %v", start, c.start)
			}
		})
	}
}
