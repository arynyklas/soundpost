// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

func scalarOf(t testing.TB, raw string) model.Scalar {
	t.Helper()
	var s model.Scalar
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("scalar %s: %v", raw, err)
	}
	return s
}

// A log row of a metric query goes through RunLogRow and RunPipeline: both marshalled every field and every
// metadata value into a copy only to read its length, decoded each metadata string with encoding/json and
// sorted the metadata with a closure. The row below cost 36 allocations before the change.
func TestRunLogRowAllocatesLittleForAPlainRow(t *testing.T) {
	row := scan.LogRow{ID: model.NewID(), Source: model.NewID(), Timestamp: 1, Multiplicity: 1, Record: model.LogRecord{
		Line:         "level=info msg=served",
		StreamLabels: model.Labels{{Name: "app", Value: "api"}, {Name: "env", Value: "prod"}},
		Fields:       map[string]model.Scalar{"status": scalarOf(t, "200"), "path": scalarOf(t, `"/v1/orders"`), "cached": scalarOf(t, "true")},
		Metadata:     map[string]model.Scalar{"trace": scalarOf(t, `"0af7651916cd43dd8448eb211c80319c"`), "user": scalarOf(t, `"u-1234"`), "region": scalarOf(t, `"eu"`)},
	}}
	plan := testPlan(t, `{app="api"}`)
	account := value.NewBoundedAccount(1 << 20)
	ctx := context.Background()
	n := testing.AllocsPerRun(100, func() {
		r, err := RunLogRow(ctx, plan, row, account)
		if err != nil || !r.Retained {
			t.Fatalf("RunLogRow: %v", err)
		}
		account.Release(r.Bytes)
	})
	t.Logf("allocations of RunLogRow for a row of 2 stream labels, 3 fields, 3 metadata entries: %.0f", n)
	if n > 24 {
		t.Fatalf("RunLogRow made %.0f allocations for a plain row, want at most 24", n)
	}
	if account.Used() != 0 {
		t.Fatalf("accounting leaked %d", account.Used())
	}
}

// The metadata text of every shape of scalar is what the decode through encoding/json gave: plain strings are
// views, escaped or odd ones still take the decode, numbers, booleans and null keep their JSON text.
func TestRunLogRowMetadataTextIsUnchanged(t *testing.T) {
	raws := []string{`"plain"`, `""`, `"with space"`, `"tab\there"`, `"quote\"inside"`, `"back\\slash"`, `"<&>"`, `"caf\u00e9"`, `"日本語"`, `"\u0000ctl"`, `7`, `-3`, `true`, `false`, `null`}
	meta := map[string]model.Scalar{}
	want := map[string]string{}
	for i, raw := range raws {
		name := string(rune('a' + i))
		s := scalarOf(t, raw)
		meta[name] = s
		var text string
		if len(raw) > 0 && raw[0] == '"' {
			if err := json.Unmarshal([]byte(raw), &text); err != nil {
				t.Fatal(err)
			}
		} else {
			text = raw
		}
		want[name] = text
	}
	row := scan.LogRow{ID: model.NewID(), Timestamp: 1, Multiplicity: 1, Record: model.LogRecord{Line: "x", StreamLabels: model.Labels{{Name: "app", Value: "api"}}, Metadata: meta}}
	account := value.NewBoundedAccount(1 << 20)
	r, err := RunLogRow(context.Background(), testPlan(t, `{app="api"}`), row, account)
	if err != nil || !r.Retained {
		t.Fatalf("RunLogRow: %v", err)
	}
	if len(r.Entry.StructuredMetadata) != len(raws) {
		t.Fatalf("%d metadata entries, want %d", len(r.Entry.StructuredMetadata), len(raws))
	}
	prev := ""
	for _, l := range r.Entry.StructuredMetadata {
		if l.Name < prev {
			t.Fatalf("metadata is not sorted by name: %v", r.Entry.StructuredMetadata)
		}
		prev = l.Name
		if l.Value != want[l.Name] {
			t.Fatalf("metadata %s = %q, want %q", l.Name, l.Value, want[l.Name])
		}
	}
	account.Release(r.Bytes)
	if account.Used() != 0 {
		t.Fatal("accounting leaked")
	}
}
