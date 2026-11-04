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
		{"duration text on a real line is not the lexer error", `parse error at line 1, col 17: empty duration string`, "", nil},
		{"unrelated syntax error", `parse error at line 1, col 13: syntax error: unexpected unwrap`, "", nil},
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
