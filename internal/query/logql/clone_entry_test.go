// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// cloneLogEntry copies a row's line, its three label sets and its fields: a line, a slice and a buffer per
// label set, and the fields: 8 allocations for the row below. Cloning each name and value on its own took 23.
func TestCloneLogEntryAllocatesPerSetNotPerLabel(t *testing.T) {
	e := LogEntry{
		Line:               "level=info msg=\"request served\" status=200 duration=12ms",
		StreamLabels:       model.Labels{{Name: "app", Value: "checkout"}, {Name: "cluster", Value: "eu-west-1"}, {Name: "env", Value: "production"}, {Name: "pod", Value: "checkout-7d9f8c6b5-x2x4z"}},
		StructuredMetadata: model.Labels{{Name: "trace_id", Value: "0af7651916cd43dd8448eb211c80319c"}, {Name: "user", Value: "u-1234"}},
		ParsedLabels:       model.Labels{{Name: "level", Value: "info"}, {Name: "status", Value: "200"}, {Name: "duration", Value: "12ms"}},
		Fields:             make([]TypedField, 2),
	}
	var c LogEntry
	n := testing.AllocsPerRun(200, func() { c = cloneLogEntry(e) })
	if n > 8 {
		t.Fatalf("cloneLogEntry of a row with 9 labels made %v allocations, want at most 8", n)
	}
	if !reflect.DeepEqual(c.StreamLabels, e.StreamLabels) || !reflect.DeepEqual(c.StructuredMetadata, e.StructuredMetadata) || !reflect.DeepEqual(c.ParsedLabels, e.ParsedLabels) || c.Line != e.Line || len(c.Fields) != 2 {
		t.Fatalf("clone differs: %+v", c)
	}
}
