// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import "testing"

// The typed decoder made a string of its own for every text of a log page (1,309 allocations for one page of
// 128 rows); the strings of a column are now views of one buffer (1,051). What is left is the two maps a row
// carries (fields and structured metadata) and the column slabs: maps are mutable values and stay one each.
func TestLogPageDecodeCopiesItsStringsIntoOneBuffer(t *testing.T) {
	b := decodeTestPages(t)["logs_canonical"]
	n := testing.AllocsPerRun(20, func() {
		if _, err := decodePageColumns(b, false, true); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("allocations of one 128-row log page decode: %.0f", n)
	if n > 1100 {
		t.Fatalf("a typed log page decode made %.0f allocations, want at most 1100", n)
	}
}
