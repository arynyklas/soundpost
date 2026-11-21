// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

func regexUTF8Profiles() []profile.Profile {
	return []profile.Profile{
		{ID: "promql-prometheus-3.1.0", Commit: "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"},
		{ID: "promql-prometheus-3.13.5", Commit: "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"},
	}
}

// Observed live against both pins: a selector regex of literal alternatives is
// accepted even when it is not UTF-8 (the PromQL escape \xff is one byte), and
// any metacharacter sends it through the compiler, which rejects it.
func TestSelectorRegexOfLiteralInvalidUTF8(t *testing.T) {
	accepted := []string{`m{v=~"\xff"}`, `m{v!~"\xff"}`, `m{v=~"a\xff"}`, `m{v=~"\xc3"}`, `m{v=~"\xed\xa0\x80"}`, `m{v=~"\xff|a"}`, `m{v!~"a|\xff"}`, `m{v=~"\xff|"}`, `m{v=~"\xff",w="x"}`, `{__name__=~"\xff"}`, `count_over_time(m{v=~"\xff"}[1m])`}
	rejected := []string{`m{v=~"\xff.*"}`, `m{v=~"\xff+"}`, `m{v=~"(\xff)"}`, `m{v=~"[\xff]"}`, `m{v=~"(?i)\xff"}`, `m{v=~".*\xff"}`, `m{v=~"\xff|a.*"}`, `m{v=~"a.|\xff"}`, `{__name__!~"\xff"}`}
	for _, p := range regexUTF8Profiles() {
		for _, expression := range accepted {
			e, err := Parse(expression, p)
			if err != nil {
				t.Fatalf("%s %q: %v", p.ID, expression, err)
			}
			// The formatted text must parse back to the same text.
			text := Format(e)
			again, err := Parse(text, p)
			if err != nil || Format(again) != text {
				t.Fatalf("%s %q formatted as %q does not round-trip: %v", p.ID, expression, text, err)
			}
		}
		for _, expression := range rejected {
			if _, err := Parse(expression, p); err == nil {
				t.Errorf("%s accepted %q", p.ID, expression)
			}
		}
	}
}

// A quoted string holding the character U+FFFD is refused by the pinned lexer
// (observed live on both pins) whether written raw, in a raw string or among
// other text; the escape spelling is accepted and formats back as an escape.
func TestQuotedStringRefusesRawReplacementCharacter(t *testing.T) {
	rejected := []string{"m{v=~\"\ufffd\"}", "m{v=\"\ufffd\"}", "m{v=~`\ufffd`}", "m{v=~'a\ufffd'}", "m{v=\"\u00e9\ufffd\"}"}
	accepted := []string{`m{v=~"\ufffd"}`, `m{v="\ufffd"}`, "m{v=\"\u00e9\u4e16\U0001f600\"}", "m{v=~`\u00e9`}"}
	for _, p := range regexUTF8Profiles() {
		for _, expression := range rejected {
			if _, err := Parse(expression, p); err == nil {
				t.Errorf("%s accepted %q", p.ID, expression)
			}
		}
		for _, expression := range accepted {
			e, err := Parse(expression, p)
			if err != nil {
				t.Fatalf("%s %q: %v", p.ID, expression, err)
			}
			text := Format(e)
			if _, err := Parse(text, p); err != nil {
				t.Errorf("%s %q formatted as %q does not reparse: %v", p.ID, expression, text, err)
			}
		}
	}
}
