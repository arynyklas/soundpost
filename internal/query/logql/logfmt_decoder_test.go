// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"reflect"
	"testing"
)

func noStop() error { return nil }

// TestLogfmtDecoderStateMachine pins the token-level rules observed on the
// reference: where each syntax error fires, the reported position, what is kept
// before it, and how the lenient mode resumes.
func TestLogfmtDecoderStateMachine(t *testing.T) {
	type pairs = []logfmtField
	for _, tc := range []struct {
		name   string
		line   string
		strict bool
		want   pairs
		err    string
	}{
		{"value with equals", "a=b= c=1", false, pairs{{"c", "1", false}}, ""},
		{"strict stops at equals", "x=1 a=b= c=1", true, pairs{{"x", "1", false}}, "logfmt syntax error at pos 8 : unexpected '='"},
		{"empty key", "=v k=1", true, nil, "logfmt syntax error at pos 1 : unexpected '='"},
		{"space before equals", "a =1", true, pairs{{"a", "", false}}, "logfmt syntax error at pos 3 : unexpected '='"},
		{"quote starts key", `x=1 "k"=2`, true, pairs{{"x", "1", false}}, `logfmt syntax error at pos 5 : unexpected '"'`},
		{"quote inside bare value", `k=a"b" z=1`, true, nil, `logfmt syntax error at pos 4 : unexpected '"'`},
		{"unterminated counts bytes", "k=é b=\"é", true, pairs{{"k", "é", false}}, "logfmt syntax error at pos 11 : unterminated quoted value"},
		{"trailing backslash is unterminated", `k="a\`, true, nil, "logfmt syntax error at pos 6 : unterminated quoted value"},
		{"invalid escape points past the closing quote", `k="a\c" z=1`, true, nil, "logfmt syntax error at pos 8 : invalid quoted value"},
		{"escapes", `k="a\"b\\c\n" z=1`, true, pairs{{"k", "a\"b\\c\n", false}, {"z", "1", false}}, ""},
		{"no separator after closing quote", `a="x y"b=2`, true, pairs{{"a", "x y", false}, {"b", "2", false}}, ""},
		{"raw tab inside quotes", "a=\"x\ty\"", true, pairs{{"a", "x\ty", false}}, ""},
		{"lenient skips to whitespace after error", `a=1b=2 c=3 ="x y" d=4`, false, pairs{{"c", "3", false}, {"d", "4", false}}, ""},
		{"lenient resumes after bad quoted value", `a="\q" b=2`, false, pairs{{"b", "2", false}}, ""},
		{"lenient keeps valueless and empty", "a b= c=\"\"", false, pairs{{"a", "", false}, {"b", "", false}, {"c", "", false}}, ""},
		{"tab separates", "a=1\tb=2", false, pairs{{"a", "1", false}, {"b", "2", false}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeLogfmt(tc.line, tc.strict, noStop)
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if msg != tc.err {
				t.Fatalf("err=%q want %q", msg, tc.err)
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("pairs=%v want %v", got, tc.want)
			}
		})
	}
}

func TestSanitizeLabelIsPerRune(t *testing.T) {
	for in, want := range map[string]string{
		"a\u00a0b": "a_b",
		"é":        "_",
		"1é":       "_1_",
		"a.b-c":    "a_b_c",
		"日本":       "__",
	} {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q)=%q want %q", in, got, want)
		}
	}
}

func TestJSONPathWhitespaceAndQuotedKeys(t *testing.T) {
	for _, ok := range []string{`a[ "b" ]`, `a["b" ]`, `a[ 0 ]`, `  k  `, `a . b`, `["a"].b`} {
		if _, err := jsonPath(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{`a b`, `a[0]b`, `a.[0]`, `a.`, `.a`, `a[]`, `a['b']`, `["a\"b"]`, `a[-1]`, ``, `   `} {
		if _, err := jsonPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	steps, err := jsonPath(`  k  `)
	if err != nil || len(steps) != 1 || steps[0].key != "k" {
		t.Fatalf("surrounding spaces must not become part of the key: %v %v", steps, err)
	}
}
