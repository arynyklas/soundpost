// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"fmt"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Every log row of a query is turned into a LogEntry whose fields are sorted by name: sort.Slice makes a
// closure and a reflect swapper per row (2 allocations beside the slice itself), and a log query of the gate
// mix does that for every row it reads.
func TestSortedFieldsAllocatesOnlyItsResult(t *testing.T) {
	scalar := func(raw string) model.Scalar { s, _ := model.ScalarFromCanonical(raw); return s }
	fields := map[string]model.Scalar{}
	for i := range 6 {
		fields[fmt.Sprintf("f%d", 5-i)] = scalar(fmt.Sprint(i))
	}
	got := sortedFields(fields)
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Name < got[j].Name }) || len(got) != 6 {
		t.Fatalf("fields not sorted by name: %v", got)
	}
	if got[0].Name != "f0" || got[5].Name != "f5" || got[0].Value != fields["f0"] {
		t.Fatalf("fields lost or mixed: %v", got)
	}
	if n := testing.AllocsPerRun(50, func() { _ = sortedFields(fields) }); n > 1 {
		t.Fatalf("%.0f allocations for 6 fields, want 1 (the result)", n)
	}
	if len(sortedFields(nil)) != 0 || sortedFields(nil) == nil {
		t.Fatal("no fields must give an empty, non-nil list as before")
	}
}
