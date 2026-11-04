// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"os"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"testing"
)

func resolvedProfile(t *testing.T, id, semantic string) profile.Profile {
	t.Helper()
	r, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Resolve(id, id+"/semantic-sha256-"+semantic)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyntaxErrorStartsAtOffendingTokenOrCharacter(t *testing.T) {
	p310 := resolvedProfile(t, "promql-prometheus-3.1.0", "1def724ec80987ebd117b52fbf8500c735f913efd1d1e16a7623f01699cc76a8")
	p3135 := trimProfile(t)
	for _, tc := range []struct {
		name  string
		query string
		p     profile.Profile
		start int
	}{
		{"3.1.0 </ reports the unexpected slash", "fixture_metric </ 2", p310, 16},
		{"3.1.0 >/ reports the unexpected slash", "fixture_metric >/ 2", p310, 16},
		{"3.1.0 CJK label name", "fixture_metric{区域=\"north\"}", p310, 15},
		{"3.13.5 CJK label name", "fixture_metric{区域=\"north\"}", p3135, 15},
		{"3.1.0 post-Unicode-15 letter", "𐵐_metric", p310, 0},
		{"3.13.5 post-Unicode-15 letter", "𐵐_metric", p3135, 0},
		// Neighbours: positions that were already correct.
		{"multi-byte rune after ASCII prefix", "fixture_metric + 区", p3135, 17},
		{"ASCII unexpected character", "fixture_metric $", p3135, 15},
		{"3.1.0 lone unexpected slash operator", "fixture_metric / / 2", p310, 17},
	} {
		_, err := Parse(tc.query, tc.p)
		var le *syntax.LanguageError
		if !errors.As(err, &le) {
			t.Fatalf("%s: want syntax error, got %v", tc.name, err)
		}
		if le.Range.StartByte != tc.start {
			t.Errorf("%s: start %d want %d (%+v)", tc.name, le.Range.StartByte, tc.start, le.Range)
		}
	}
}

func TestSlashAfterSpacedLessThanStaysAcceptedOn310(t *testing.T) {
	p := resolvedProfile(t, "promql-prometheus-3.1.0", "1def724ec80987ebd117b52fbf8500c735f913efd1d1e16a7623f01699cc76a8")
	if _, err := Parse("fixture_metric < 2 / 4", p); err != nil {
		t.Fatal(err)
	}
}
