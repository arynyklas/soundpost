// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"context"
	"testing"
)

// 3.1.0 optimized case-insensitive prefix/suffix matcher "compares a byte slice of
// len(pattern literal) using strings.EqualFold, then slices the residual using the
// same literal byte length. Fold-equivalent runes with different UTF8 encoded
// lengths can fail this optimized path even though the compiled regex would
// match." 3.13.5 "uses the ACTUAL consumed input byte length". The Kelvin sign
// U+212A (3 bytes) is fold-equivalent to k (1 byte).
func TestReleaseSemanticsFoldPrefixSuffixByteLength(t *testing.T) {
	const kelvin = "\u212a"
	type probe struct {
		pattern, input string
		legacy, modern bool // 3.1.0 optimized path, 3.13.5
	}
	probes := []probe{
		{"(?i)k.*", "kx", true, true},
		{"(?i)k.*", "KX", true, true},
		{"(?i)k.*", kelvin + "x", false, true},
		{"(?i)k.*", "xk", false, false},
		{"(?i).*k", "xk", true, true},
		{"(?i).*k", "xK", true, true},
		{"(?i).*k", "x" + kelvin, false, true},
		{"(?i).*k", "kx", false, false},
		{"(?i)k.+", "kx", true, true},
		{"(?i)k.+", "k", false, false},
		{"(?i)k.+", kelvin + "x", false, true},
		// A case-sensitive literal has no fold, and a pattern without the any-string
		// remainder is not the optimized shape: both agree with the compiled regex.
		{"k.*", kelvin + "x", false, false},
		{"(?i)k", kelvin, true, true},
		{"(?i)k[a-z]", kelvin + "x", true, true},
	}
	for _, tc := range []struct {
		profileIndex int
		modern       bool
	}{{0, false}, {2, true}} {
		p := profiles()[tc.profileIndex]
		scope := newTestScope(t, p)
		for _, pr := range probes {
			want := pr.legacy
			if tc.modern {
				want = pr.modern
			}
			re, err := CompileLabel(p, pr.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := re.MatchString(pr.input); got != want {
				t.Errorf("%s %q on %q: MatchString=%v, want %v", p.ID, pr.pattern, pr.input, got, want)
			}
			scoped, err := scope.Compile(context.Background(), pr.pattern, Label)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := scope.MatchString(context.Background(), scoped, pr.input); err != nil || got != want {
				t.Errorf("%s %q on %q: Scope.MatchString=%v err=%v, want %v", p.ID, pr.pattern, pr.input, got, err, want)
			}
		}
	}
}

func releaseLabelMatch(t *testing.T, pattern, input string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, p := range profiles() {
		if p.ID == "logql-loki-3.5.2" {
			continue
		}
		re, err := CompileLabel(p, pattern)
		if err != nil {
			t.Fatalf("%s %q: %v", p.ID, pattern, err)
		}
		out[p.ID] = re.MatchString(input)
	}
	return out
}

// "Optimized lookup must preserve the pinned final matcher behavior and not become
// Unicode normalization of label identity": a composed pattern never matches the
// decomposed spelling, a ligature never matches its compatibility letters, and
// full-width letters are not their ASCII forms.
func TestReleaseSemanticsMatchingDoesNotNormalizeLabelIdentity(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		want           bool
	}{
		{"(?i)caf\u00e9|tea", "cafe\u0301", false},
		{"(?i)caf\u00e9|tea", "CAF\u00c9", true},
		{"(?i)fi|bar", "\ufb01", false},
		{"(?i)fi|bar", "FI", true},
		{"(?i)\uff26\uff29|bar", "FI", false},
		{"(?i)\uff26\uff29|bar", "\uff46\uff49", true},
	} {
		for id, got := range releaseLabelMatch(t, tc.pattern, tc.input) {
			if got != tc.want {
				t.Errorf("%s %q on %q = %v, want %v", id, tc.pattern, tc.input, got, tc.want)
			}
		}
	}
}

// Perl classes and POSIX brackets are ASCII tables and \b uses ASCII word
// membership; with the i flag the ASCII letter classes gain the Kelvin sign and
// long s, but digits do not gain other decimal digits.
func TestReleaseSemanticsASCIIClassesFoldWithoutUnicodeDigits(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		want           bool
	}{
		{`\d+`, "123", true}, {`\d+`, "\u0663\u0663", false},
		{`(?i)\d+`, "\u0663", false},
		{`\w+`, "ab_1", true}, {`\w+`, "\u00e9", false},
		{`\s`, " ", true}, {`\s`, "\u00a0", false},
		{`[[:alpha:]]+`, "ab", true}, {`[[:alpha:]]+`, "\u00e9", false},
		{`(?i)[a-z]+`, "\u212a", true}, {`(?i)[a-z]+`, "\u017f", true}, {`(?i)[a-z]+`, "\u00e9", false},
		{`.*\bfoo\b.*`, "foo\u00e9", true}, {`.*\bfoo\b.*`, "foobar", false},
		{`.*\Bfoo.*`, "\u00e9foo", false}, {`.*\Bfoo.*`, "xfoo", true},
	} {
		for id, got := range releaseLabelMatch(t, tc.pattern, tc.input) {
			if got != tc.want {
				t.Errorf("%s %q on %q = %v, want %v", id, tc.pattern, tc.input, got, tc.want)
			}
		}
	}
}

// Case-insensitive matching uses the reference Unicode simple-fold orbits: Kelvin
// and long s fold with k and s, while the Unicode17-added pair U+A7CB/U+0264
// must not fold in either reference.
func TestReleaseSemanticsSimpleFoldOrbitsExcludeUnicode17Pairs(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		want           bool
	}{
		{"(?i)k|x", "\u212a", true}, {"(?i)K|x", "\u212a", true}, {"(?i)\u212a|x", "k", true},
		{"(?i)s|x", "\u017f", true}, {"(?i)\u017f|x", "S", true},
		{"(?i)\u0264|x", "\u0264", true}, {"(?i)\u0264|x", "\ua7cb", false},
		{"(?i)\ua7cb|x", "\u0264", false}, {"(?i)\ua7cb|x", "\ua7cb", true},
		{"(?i)[\u0264]", "\ua7cb", false},
	} {
		for id, got := range releaseLabelMatch(t, tc.pattern, tc.input) {
			if got != tc.want {
				t.Errorf("%s %q on %q = %v, want %v", id, tc.pattern, tc.input, got, tc.want)
			}
		}
	}
}
