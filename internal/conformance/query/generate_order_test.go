// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"sort"
	"testing"
)

// The generated cases come out in one order, by ID, however the builders push them: the case files
// written from them, the seeds' rows and every report listing are then byte-stable and diffable.
func TestGeneratedCasesAreOrderedByID(t *testing.T) {
	spec, ledger, domains := loadPlanInputs(t)
	cases, err := generateForRelease(spec, ledger, domains, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 1000 {
		t.Fatalf("only %d generated cases", len(cases))
	}
	if !sort.SliceIsSorted(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID }) {
		for i := 1; i < len(cases); i++ {
			if cases[i].ID < cases[i-1].ID {
				t.Fatalf("case %d %q follows %q: the generated cases are not ordered by ID", i, cases[i].ID, cases[i-1].ID)
			}
		}
	}
	for i := 1; i < len(cases); i++ {
		if cases[i].ID == cases[i-1].ID {
			t.Fatalf("case ID %q is generated twice", cases[i].ID)
		}
	}
}
