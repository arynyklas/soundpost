// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"testing"
)

func TestLogLimitUsesOriginalStreamHashInBothDirections(t *testing.T) {
	originalA := model.Labels{{Name: "app", Value: "a"}}
	originalB := model.Labels{{Name: "app", Value: "b"}}
	// Explicit pinned bytes, rather than the sketch's FE-prefixed byte encoding.
	hashA := metricXXH64([]byte{'a', 'p', 'p', 255, 'a', 255})
	hashB := metricXXH64([]byte{'a', 'p', 'p', 255, 'b', 255})
	if hashA == 0 || hashB == 0 || hashA == hashB {
		t.Fatal("fixture does not distinguish stream hashes")
	}
	want := byte(1)
	if hashB < hashA {
		want = 2
	}
	for _, order := range []LogOrder{Forward, Backward} {
		a := value.NewBoundedAccount(32 << 20)
		queryLabels := model.Labels{{Name: "app", Value: "changed"}}
		first := PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{1}, Timestamp: 1000000001, Multiplicity: 1, Line: "same"}, Labels: queryLabels, OriginalStreamLabels: originalA}
		second := PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{2}, Timestamp: 1000000001, Multiplicity: 1, Line: "same"}, Labels: queryLabels, OriginalStreamLabels: originalB}
		merged, err := MergeLogs(context.Background(), []EntryIterator{&entryRows{rows: []PipelineResult{first, second}}}, order, 1, a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := merged.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.Entry.ID[0] != want {
			t.Fatalf("direction=%s got=%d want original-hash stream=%d", order, got.Entry.ID[0], want)
		}
		a.Release(got.Bytes)
		if err = merged.Close(); err != nil {
			t.Fatal(err)
		}
		if a.Used() != 0 {
			t.Fatalf("stream hash merge leaked=%d", a.Used())
		}
	}
}
