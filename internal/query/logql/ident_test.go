// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/syntax"
)

func parseThenCheck(t *testing.T, source string) error {
	t.Helper()
	p := testProfile(t)
	e, err := Parse(source, p)
	if err == nil {
		_, _, err = Check(e, p)
	}
	return err
}

// Native identity and position for rejected queries: where the reference's
// grammar rejects, the identity is the generic grammar one and the position is
// the start of the first token the grammar cannot accept.
func TestRejectedQueriesCarryNativeIdentityAndPosition(t *testing.T) {
	for _, tc := range []struct {
		name, source, code string
		start              int
		checkStart         bool
	}{
		{"empty selector", `{}`, "selector.empty-compatible", 0, false},
		{"bad json path", `{app="api"}|json x="items["`, "syntax.unexpected-token", 0, false},
		{"unwrap outside range", `{app="api"}|unwrap n`, "syntax.unexpected-token", 12, true},
		{"stage after unwrap", `sum_over_time({app="api"}|unwrap n|json[1m])`, "syntax.unexpected-token", 35, true},
		{"line filter after unwrap", `sum_over_time({app="api"}|unwrap n|="x"[1m])`, "syntax.unexpected-token", 34, true},
		{"byte overflow", `{app="api"}|n>999999999999999999999TiB`, "syntax.unexpected-token", 38, true},
		{"empty range", `rate({app="api"}[])`, "syntax.duration", 17, true},
		{"fractional range", `rate({app="api"}[1.5m])`, "syntax.duration", 17, true},
	} {
		err := parseThenCheck(t, tc.source)
		var d *syntax.LanguageError
		if !errors.As(err, &d) {
			t.Fatalf("%s: want language error, got %v", tc.name, err)
		}
		if d.Code != tc.code || (tc.checkStart && d.Range.StartByte != tc.start) {
			t.Errorf("%s: got %s@%d want %s@%d", tc.name, d.Code, d.Range.StartByte, tc.code, tc.start)
		}
	}
}

func TestNeighbouringValidQueriesStayAccepted(t *testing.T) {
	for _, source := range []string{
		`sum_over_time({app="api"}|unwrap n[1m])`,
		`sum_over_time({app="api"}|unwrap n|n>3[1m])`,
		`{app="api"}|n>5MiB`,
		`{app="api"}|n>1024B`,
		`rate({app="api"}[5m])`,
		`{app="api"}|json x="items[0]"`,
	} {
		if err := parseThenCheck(t, source); err != nil {
			t.Errorf("valid query rejected: %s: %v", source, err)
		}
	}
}
