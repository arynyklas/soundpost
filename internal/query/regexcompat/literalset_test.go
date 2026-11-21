// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

func promqlProfiles() []profile.Profile { return []profile.Profile{profiles()[0], profiles()[2]} }

// The PromQL references (3.1.0 and 3.13.5, observed live) match a label pattern
// whose |-separated alternatives hold no regexp metacharacter by byte equality,
// without compiling it, so such a pattern may be invalid UTF-8.
func TestLabelPatternOfLiteralAlternativesMayBeInvalidUTF8(t *testing.T) {
	cases := []struct {
		pattern string
		match   []string
		other   []string
	}{
		{"\xff", []string{"\xff"}, []string{"", "a", "\xff\xff", "\xffa", "\ufffd"}},
		{"a\xff", []string{"a\xff"}, []string{"a", "\xff", "a\xffb", "ba\xff"}},
		{"\xc3", []string{"\xc3"}, []string{"\u00e9", "\xc3\xa9"}},
		{"\xed\xa0\x80", []string{"\xed\xa0\x80"}, []string{"\ufffd"}},
		{"\xff|a", []string{"\xff", "a"}, []string{"", "\xffa", "b"}},
		{"a|\xff|x", []string{"a", "\xff", "x"}, []string{"ax", "\ufffd"}},
		{"\xff|", []string{"\xff", ""}, []string{"a"}},
	}
	for _, p := range promqlProfiles() {
		for _, tc := range cases {
			re, err := CompileLabel(p, tc.pattern)
			if err != nil {
				t.Fatalf("%s %q: %v", p.ID, tc.pattern, err)
			}
			for _, s := range tc.match {
				if !re.MatchString(s) {
					t.Errorf("%s %q did not match %q", p.ID, tc.pattern, s)
				}
			}
			for _, s := range tc.other {
				if re.MatchString(s) {
					t.Errorf("%s %q matched %q", p.ID, tc.pattern, s)
				}
			}
			if re.String() != tc.pattern {
				t.Errorf("pattern text lost: %q", re.String())
			}
		}
	}
}

// Any metacharacter in any alternative sends the pattern through the compiler,
// which rejects the invalid UTF-8; the other primitives never take the shortcut.
func TestInvalidUTF8PatternWithMetacharacterOrOutsideLabelModeStillFails(t *testing.T) {
	for _, p := range promqlProfiles() {
		for _, pattern := range []string{"\xff.*", "\xff+", "(\xff)", "[\xff]", "(?i)\xff", "(?i)A\xff", ".*\xff", "\xff|a.*", "a.|\xff", "\\\xff", "\xff{2}", "^\xff", "\xff$", "\xff?"} {
			if _, err := CompileLabel(p, pattern); err == nil {
				t.Errorf("%s accepted %q in label mode", p.ID, pattern)
			}
		}
		for _, pattern := range []string{"\xff", "\xff|a"} {
			if _, err := Compile(p, pattern); err == nil {
				t.Errorf("%s accepted %q in search mode", p.ID, pattern)
			}
		}
	}
	// The Loki profile has no such observed shortcut and keeps the compiler's verdict.
	if _, err := CompileLabel(profiles()[1], "\xff"); err == nil {
		t.Error("loki label pattern accepted invalid UTF-8")
	}
}

func TestLiteralLabelPatternThroughQueryScope(t *testing.T) {
	for _, p := range promqlProfiles() {
		p.Identity, p.ConfigurationHash = "id", "hash"
		scope, err := NewScope(p, Limits{CacheEntries: 4, CachePatternBytes: 64, ProgramUnits: 64, PatternBytes: 64, InputBytes: 64, Work: 100000, Matches: 8, OutputBytes: 64})
		if err != nil {
			t.Fatal(err)
		}
		re, err := scope.Compile(context.Background(), "\xff|a", Label)
		if err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		for input, want := range map[string]bool{"\xff": true, "a": true, "": false, "\xffa": false, "\ufffd": false} {
			got, err := scope.MatchString(context.Background(), re, input)
			if err != nil || got != want {
				t.Errorf("%s %q = %v, %v; want %v", p.ID, input, got, err, want)
			}
		}
		if loc, err := scope.FindStringSubmatchIndex(context.Background(), re, "\xff"); err != nil || len(loc) != 2 || loc[0] != 0 || loc[1] != 1 {
			t.Errorf("%s submatch of the literal = %v, %v", p.ID, loc, err)
		}
		if loc, err := scope.FindStringSubmatchIndex(context.Background(), re, "b"); err != nil || loc != nil {
			t.Errorf("%s submatch of a non-member = %v, %v", p.ID, loc, err)
		}
		if all, err := scope.FindAllStringSubmatchIndex(context.Background(), re, "a", -1); err != nil || len(all) != 1 {
			t.Errorf("%s find-all of a member = %v, %v", p.ID, all, err)
		}
		if all, err := scope.FindAllStringSubmatchIndex(context.Background(), re, "b", -1); err != nil || len(all) != 0 {
			t.Errorf("%s find-all of a non-member = %v, %v", p.ID, all, err)
		}
		if all := re.FindAllStringSubmatchIndex("a", -1); len(all) != 1 || re.FindAllStringSubmatchIndex("b", -1) != nil || re.FindStringSubmatchIndex("b") != nil {
			t.Errorf("%s direct submatch helpers disagree with the literal set", p.ID)
		}
		if again, err := scope.Compile(context.Background(), "\xff|a", Label); err != nil || again != re {
			t.Errorf("%s: literal pattern was not cached", p.ID)
		}
		if _, err := scope.Compile(context.Background(), "\xff.*", Label); err == nil {
			t.Errorf("%s: metacharacter pattern compiled", p.ID)
		}
		if _, err := scope.Compile(context.Background(), "^(?s:\xff)$", Search); err == nil {
			t.Errorf("%s: label_replace-style pattern compiled", p.ID)
		}
	}
}
