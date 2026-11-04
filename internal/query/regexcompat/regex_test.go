// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"soundpost/internal/query/profile"
)

func profiles() []profile.Profile {
	return []profile.Profile{
		{ID: "promql-prometheus-3.1.0", Commit: "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"},
		{ID: "logql-loki-3.5.2", Commit: "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"},
		{ID: "promql-prometheus-3.13.5", Commit: "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"},
	}
}

// These cases catch accidentally routing classes, syntax or folding through the host Unicode17 engine.
func TestPinnedUnicodeAndSyntax(t *testing.T) {
	for _, p := range profiles() {
		t.Run(p.ID, func(t *testing.T) {
			cases := []struct {
				pattern, input string
				want           bool
			}{
				{`\p{L}`, "\U00011f04", true},  // Kawi, introduced in Unicode15.
				{`\p{L}`, "\U00010d50", false}, // Garay, introduced in Unicode16.
				{`\p{L}`, "\U0001e6c0", false}, // Tai Yo, introduced in Unicode17.
				{`\P{L}`, "\U00010d50", true},
				{`(?i)\x{10d50}`, "\U00010d70", false}, // Must not acquire the new Garay fold.
				{`(?i)k`, "K", true}, {`(?i)s`, "ſ", true}, {`(?i)σ`, "ς", true},
				{`[[:alpha:]]`, "é", false}, {`\w`, "é", false},
				{`^.$`, string([]byte{0xff}), true}, {`^..$`, string([]byte{0xff, 0xfe}), true},
				{`é`, "e\u0301", false}, // No implicit Unicode normalization.
			}
			for _, tc := range cases {
				re, err := Compile(p, tc.pattern)
				if err != nil {
					t.Fatalf("%q: %v", tc.pattern, err)
				}
				if got := re.MatchString(tc.input); got != tc.want {
					t.Errorf("%q on %q = %v, want %v", tc.pattern, tc.input, got, tc.want)
				}
			}
			for _, pattern := range []string{`\p{Garay}`, `\p{Tai_Yo}`, `(?=x)`, `(x)\1`, `a{1001}`, `[z-a]`, string([]byte{0xff})} {
				if _, err := Compile(p, pattern); err == nil {
					t.Errorf("accepted invalid pinned pattern %q", pattern)
				}
			}
			for _, property := range []string{`\p{Cn}`, `\p{LC}`} {
				_, err := Compile(p, property)
				if (err == nil) != (p.ID == "promql-prometheus-3.13.5") {
					t.Errorf("%s acceptance: %v", property, err)
				}
			}
		})
	}
}

func TestSearchLabelAnchoringAndNewlines(t *testing.T) {
	for _, p := range profiles() {
		search, err := Compile(p, "a.b")
		if err != nil {
			t.Fatal(err)
		}
		label, err := CompileLabel(p, "a.b")
		if err != nil {
			t.Fatal(err)
		}
		if !search.MatchString("xaZby") || search.MatchString("a\nb") {
			t.Fatal("search flags changed")
		}
		if label.MatchString("xaZby") || !label.MatchString("a\nb") {
			t.Fatal("label anchoring/DotNL changed")
		}
		multiline, err := Compile(p, "(?m)^b$")
		if err != nil {
			t.Fatal(err)
		}
		if !multiline.MatchString("a\nb\nc") {
			t.Fatal("multiline anchors changed")
		}
		empty, err := CompileLabel(p, "a*")
		if err != nil || !empty.MatchString("") {
			t.Fatal("label empty match changed")
		}
	}
}

func TestCaptureReplacementAndEmptyProgression(t *testing.T) {
	for _, p := range profiles() {
		re, err := Compile(p, `(?P<word>a)(b)?`)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.FindStringSubmatchIndex("za"); !reflect.DeepEqual(got, []int{1, 2, 1, 2, -1, -1}) {
			t.Fatal(got)
		}
		if got := re.ReplaceAllString("a ab", `${word}:$2`); got != "a: a:b" {
			t.Fatal(got)
		}
		names := re.SubexpNames()
		names[1] = "poisoned"
		if re.SubexpNames()[1] != "word" {
			t.Fatal("mutable compiled metadata escaped")
		}
		empty, err := Compile(p, `a*`)
		if err != nil {
			t.Fatal(err)
		}
		if got := empty.FindAllStringSubmatchIndex("ba", -1); !reflect.DeepEqual(got, [][]int{{0, 0}, {1, 2}}) {
			t.Fatal(got)
		}
	}
}

func TestNoUnknownOrMismatchedProfileFallback(t *testing.T) {
	for _, p := range []profile.Profile{{}, {ID: "future"}, {ID: profiles()[0].ID, Commit: "wrong"}} {
		if _, err := Compile(p, "x"); !errors.Is(err, ErrProfile) {
			t.Fatalf("profile accepted: %+v %v", p, err)
		}
	}
}

func TestQueryScopeBoundsAndCancellation(t *testing.T) {
	p := profiles()[0]
	p.Identity = "query-profile-identity"
	p.ConfigurationHash = "configuration-identity"
	limits := Limits{CacheEntries: 1, CachePatternBytes: 16, ProgramUnits: 1024, PatternBytes: 16, InputBytes: 32, Work: 100000, Matches: 4, OutputBytes: 32}
	scope, err := NewScope(p, limits)
	if err != nil {
		t.Fatal(err)
	}
	re, err := scope.Compile(context.Background(), "a", Search)
	if err != nil {
		t.Fatal(err)
	}
	again, err := scope.Compile(context.Background(), "a", Search)
	if err != nil || again != re {
		t.Fatal("scope cache miss")
	}
	if _, err := scope.Compile(context.Background(), "b", Search); !errors.Is(err, ErrBudget) {
		t.Fatal("unbounded cache", err)
	}
	if _, err := scope.MatchString(context.Background(), re, strings.Repeat("x", 33)); !errors.Is(err, ErrBudget) {
		t.Fatal("unbounded input", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scope.MatchString(ctx, re, "a"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	other, err := NewScope(p, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.MatchString(context.Background(), re, "a"); !errors.Is(err, ErrScope) {
		t.Fatal("compiled program crossed query scopes", err)
	}
	if _, err := NewScope(profiles()[0], limits); !errors.Is(err, ErrProfile) {
		t.Fatal("unresolved query profile accepted", err)
	}
	tiny := limits
	tiny.Work = 1
	small, err := NewScope(p, tiny)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := small.Compile(context.Background(), "a", Search); !errors.Is(err, ErrBudget) {
		t.Fatal("compilation did not charge work", err)
	}
}

func TestPropertyNamesRetainCallerParserDistinction(t *testing.T) {
	for _, p := range profiles() {
		for _, pattern := range []string{`\p{Letter}`, `\p{greek}`, `\p{Assigned}`, `\p{ASCII}`} {
			if _, err := CompileLabel(p, pattern); err == nil {
				t.Errorf("%s label accepted %q", p.ID, pattern)
			}
			_, err := Compile(p, pattern)
			if (err == nil) != (p.ID == "promql-prometheus-3.13.5") {
				t.Errorf("%s search acceptance for %q: %v", p.ID, pattern, err)
			}
		}
	}
}

func TestPinnedCaseHelpersAndErrorClassification(t *testing.T) {
	for _, p := range profiles() {
		if got, err := ToLower(p, "\U00010d50KK"); err != nil || got != "\U00010d50kk" {
			t.Fatal(got, err)
		}
		if got, err := ToUpper(p, "\U00010d70sſ"); err != nil || got != "\U00010d70SS" {
			t.Fatal(got, err)
		}
		if got, err := SimpleFold(p, '\ua7cb'); err != nil || got != '\ua7cb' {
			t.Fatal(got, err)
		}
		for _, compile := range []func(profile.Profile, string) (*Regexp, error){Compile, CompileLabel} {
			_, err := compile(p, "x{1001}")
			code, ok := PatternErrorCode(err)
			if !ok || code != "invalid repeat count" {
				t.Fatal(code, ok, err)
			}
		}
	}
}

func newTestScope(t *testing.T, p profile.Profile) *Scope {
	t.Helper()
	p.Identity = "resolved-profile"
	p.ConfigurationHash = "resolved-configuration"
	s, err := NewScope(p, Limits{CacheEntries: 32, CachePatternBytes: 4096, ProgramUnits: 65536, PatternBytes: 4096, InputBytes: 8192, Work: 10000000, Matches: 16, OutputBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCancellableNFAKeepsAnchorsCapturesAndEmptyProgression(t *testing.T) {
	for _, p := range profiles() {
		s := newTestScope(t, p)
		for _, tc := range []struct {
			pattern, input string
			want           [][]int
		}{
			{`a*`, "ba", [][]int{{0, 0}, {1, 2}}},
			{`(?m)^b$`, "a\nb\nc", [][]int{{2, 3}}},
			{`\A|$`, "ab", [][]int{{0, 0}, {2, 2}}},
			{`(a|ab)(b)?`, "ab", [][]int{{0, 2, 0, 1, 1, 2}}},
			{`\b.`, "é a", [][]int{{3, 4}}},
			{`^.$`, string([]byte{0xff}), [][]int{{0, 1}}},
		} {
			re, err := s.Compile(context.Background(), tc.pattern, Search)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.FindAllStringSubmatchIndex(context.Background(), re, tc.input, -1)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s %q: %v %v", p.ID, tc.pattern, got, err)
			}
		}
		re, err := s.Compile(context.Background(), `(?P<x>a)(b)?`, Search)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.ReplaceAllString(context.Background(), re, "a ab", `${x}:$2`); err != nil || got != "a: a:b" {
			t.Fatal(got, err)
		}
		if got, err := s.FindStringSubmatchIndex(context.Background(), re, "za"); err != nil || !reflect.DeepEqual(got, []int{1, 2, 1, 2, -1, -1}) {
			t.Fatal(got, err)
		}
	}
}

// Use a real cancel context, triggered deterministically during the scan rather
// than a scheduling-sensitive sleep. This does not replace the regex engine.
type cancelOnPoll struct {
	context.Context
	cancel context.CancelFunc
	polls  int
}

func (c *cancelOnPoll) Err() error {
	c.polls++
	if c.polls == 10 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestCancellationDuringInputScan(t *testing.T) {
	s := newTestScope(t, profiles()[0])
	re, err := s.Compile(context.Background(), `a*z`, Search)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &cancelOnPoll{Context: ctx, cancel: cancel}
	if _, err := s.MatchString(observed, re, strings.Repeat("a", 8192)); !errors.Is(err, context.Canceled) {
		t.Fatal("input scan did not observe cancellation", err)
	}
}

func TestScopeLimitsAreNotSilentTruncation(t *testing.T) {
	s := newTestScope(t, profiles()[0])
	re, err := s.Compile(context.Background(), `a`, Search)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindAllStringSubmatchIndex(context.Background(), re, strings.Repeat("a", 17), -1); !errors.Is(err, ErrBudget) {
		t.Fatal("matches truncated as success", err)
	}
	if _, err := s.ReplaceAllString(context.Background(), re, "aa", strings.Repeat("$0", 4096)); !errors.Is(err, ErrBudget) {
		t.Fatal("unbounded expansion", err)
	}
	p := profiles()[0]
	p.Identity = "resolved"
	p.ConfigurationHash = "resolved"
	tiny, err := NewScope(p, Limits{CacheEntries: 1, CachePatternBytes: 32, ProgramUnits: 32, PatternBytes: 32, InputBytes: 32, Work: 100000, Matches: 1, OutputBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := tiny.Compile(context.Background(), `(a)`, Search)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tiny.FindStringSubmatchIndex(context.Background(), capture, "a"); !errors.Is(err, ErrBudget) {
		t.Fatal("unbounded captures", err)
	}
}
