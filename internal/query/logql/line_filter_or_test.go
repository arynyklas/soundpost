// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import "testing"

// Native 3.5.2 reads `or` followed by a bare STRING or ip(STRING) only (the
// operator is inherited from the first filter); a second operator after `or`
// is a parse error there.
func TestLineFilterOrTakesNoSecondOperator(t *testing.T) {
	p := testProfile(t)
	for _, q := range []string{`{app="a"} != "x" or != "y"`, `{app="a"} |= "x" or |= "y"`, `{app="a"} |~ "x" or !~ "y"`, `{app="a"} |= "x" or "y" or |= "z"`} {
		if _, err := Parse(q, p); err == nil {
			t.Errorf("accepted %s", q)
		}
	}
	for _, q := range []string{`{app="a"} != "x" or "y"`, `{app="a"} |= "x" or ip("10.0.0.1") or "z"`, `{app="a"} |= "x" |= "y"`} {
		if _, err := Parse(q, p); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}
