// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestPipelineDifferentialCorpus replays every row of the pipeline differential
// corpus, whose expected values are observations of the pinned reference, and
// demands exact equality: same retention, same line, the complete label set
// (no extra and no missing labels) and the same unwrapped float bits.
func TestPipelineDifferentialCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/query/cases/logql-pipeline-differential.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []authoredCase }
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// A floor, not an exact count: the corpus may gain native-observed vectors but a
	// truncated file must never pass silently.
	if len(f.Cases) < 712 {
		t.Fatalf("differential corpus shrank to %d rows", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			in := c.Input.Entry
			e := LogEntry{Timestamp: in.Timestamp, ID: in.ID, Multiplicity: in.Multiplicity, Line: in.Line, StreamLabels: in.StreamLabels, StructuredMetadata: in.StructuredMetadata, Fields: in.Fields}
			account := value.NewBoundedAccount(16 << 20)
			r, err := RunPipeline(context.Background(), testPlan(t, c.Input.Expression), e, account)
			if err != nil {
				t.Fatal(err)
			}
			if r.Retained != c.Expected.Retained {
				t.Fatalf("retained=%v want=%v", r.Retained, c.Expected.Retained)
			}
			if !r.Retained {
				if account.Used() != 0 {
					t.Fatal("pipeline account leaked")
				}
				return
			}
			if r.Entry.Line != c.Expected.Line {
				t.Fatalf("line=%q want=%q", r.Entry.Line, c.Expected.Line)
			}
			got := make([]string, 0, len(r.Labels))
			for _, l := range r.Labels {
				got = append(got, l.Name+"="+l.Value)
			}
			want := make([]string, 0, len(c.Expected.LabelsSubset))
			for _, l := range c.Expected.LabelsSubset {
				want = append(want, l.Name+"="+l.Value)
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("labels=%q want=%q", got, want)
			}
			switch {
			case c.Expected.UnwrappedBits == nil && r.Unwrapped != nil:
				t.Fatalf("unexpected unwrapped value %x", math.Float64bits(*r.Unwrapped))
			case c.Expected.UnwrappedBits != nil && r.Unwrapped == nil:
				t.Fatalf("missing unwrapped value, want %x", uint64(*c.Expected.UnwrappedBits))
			case c.Expected.UnwrappedBits != nil && math.Float64bits(*r.Unwrapped) != uint64(*c.Expected.UnwrappedBits):
				t.Fatalf("unwrapped=%x want=%x", math.Float64bits(*r.Unwrapped), uint64(*c.Expected.UnwrappedBits))
			}
			account.Release(r.Bytes)
			if account.Used() != 0 {
				t.Fatal("pipeline account leaked")
			}
		})
	}
}
