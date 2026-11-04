// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"soundpost/internal/query/profile"
	"testing"
)

func TestLogQLClassificationUsesUnicode15(t *testing.T) {
	p := profile.Profile{ID: "logql-loki-3.5.2", Commit: "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"}
	for _, tc := range []struct {
		r                    rune
		letter, digit, space bool
	}{{'A', true, false, false}, {'界', true, false, false}, {'١', false, true, false}, {'\u2003', false, false, true}, {'\U00010d50', false, false, false}, {'\U0001e4d0', true, false, false}} {
		l, e := IsLetter(p, tc.r)
		if e != nil || l != tc.letter {
			t.Fatalf("letter %U=%v: %v", tc.r, l, e)
		}
		d, e := IsDigit(p, tc.r)
		if e != nil || d != tc.digit {
			t.Fatalf("digit %U=%v: %v", tc.r, d, e)
		}
		s, e := IsSpace(p, tc.r)
		if e != nil || s != tc.space {
			t.Fatalf("space %U=%v: %v", tc.r, s, e)
		}
	}
	if _, err := IsLetter(profile.Profile{}, 'a'); err == nil {
		t.Fatal("unresolved edition accepted")
	}
}
