// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// Host Unicode17 and Go1.26 alias syntax must not silently expand the pinned
// label matcher frontend. The safe error stays attached to the whole matcher.
func TestSelectorRegexUsesPinnedPrimitive(t *testing.T) {
	profiles := []profile.Profile{
		{ID: "promql-prometheus-3.1.0", Commit: "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"},
		{ID: "promql-prometheus-3.13.5", Commit: "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"},
	}
	for _, p := range profiles {
		for _, expression := range []string{`up{team=~"\\p{Garay}"}`, `up{team=~"\\p{Letter}"}`, `up{team=~"(?=a)"}`} {
			_, err := Parse(expression, p)
			var diagnostic *syntax.LanguageError
			if !errors.As(err, &diagnostic) || diagnostic.Category != "syntax" || diagnostic.SafeMessage != "invalid regular expression" {
				t.Fatalf("%s %q: %v", p.ID, expression, err)
			}
			if diagnostic.Range.StartByte != 3 || diagnostic.Range.EndByte != len(expression)-1 {
				t.Fatalf("matcher origin lost: %+v", diagnostic.Range)
			}
		}
		for _, expression := range []string{`up{team=~"\\p{Kawi}"}`, `{team!~".*"}`} {
			if _, err := Parse(expression, p); err != nil {
				t.Fatalf("%s %q: %v", p.ID, expression, err)
			}
		}
		if _, err := Parse(`{team=~".*"}`, p); err == nil {
			t.Fatal("empty-only selector accepted")
		}
		_, err := Parse(`up{team=~"\\p{Cn}"}`, p)
		if (err == nil) != (p.ID == "promql-prometheus-3.13.5") {
			t.Fatal(p.ID, err)
		}
	}
}
