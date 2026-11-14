// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"io"
	"testing"
)

func TestSourceWriteCredentialCannotReadOrTouchIndex(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, _ := normalized(t, store, a, c, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	before := e.Stats()
	if _, err = e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2}); err == nil {
		t.Fatal("write credential became read authority")
	}
	if e.Stats().IndexLookups != before.IndexLookups {
		t.Fatal("write-only scope touched index")
	}
}
func TestTypedIndexChecksumIsNotEOF(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("scan_time"))
		key, value := bucket.Cursor().First()
		copyValue := append([]byte(nil), value...)
		copyValue[0] ^= 1
		return bucket.Put(key, copyValue)
	})
	if err != nil {
		t.Fatal(err)
	}
	it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	if _, err = it.Next(context.Background()); err == nil || err == io.EOF {
		t.Fatal("corrupt index became EOF")
	}
}
func TestNativeIDPostingsAndExactFieldLiterals(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	rows := typedRows(base.Records[0].Resource)
	for _, row := range rows {
		appendTyped(t, e, store, a, c, d, row)
	}
	cases := []struct {
		kind    model.Kind
		matcher Matcher
		want    int
	}{
		{model.SpanKind, Matcher{Target: MatchField, Name: "trace_id", Op: MatchEqual, Literal: Literal{Kind: LiteralString, String: rows[6].Payload.Span.Trace.String()}}, 1},
		{model.JobAttempt, Matcher{Target: MatchField, Name: "sequence", Op: MatchEqual, Literal: Literal{Kind: LiteralUnsigned, Unsigned: 9007199254740993}}, 1},
		{model.Metric, Matcher{Target: MatchField, Name: "histogram_count", Op: MatchEqual, Literal: Literal{Kind: LiteralInteger, Integer: 9007199254740993}}, 1},
		{model.Metric, Matcher{Target: MatchField, Name: "float_bits", Op: MatchEqual, Literal: Literal{Kind: LiteralFloatBits, Bits: 0x7ff0000000000002}}, 1},
		{model.Metric, Matcher{Target: MatchLabel, Name: "missing", Op: MatchEqual, Literal: Literal{Kind: LiteralString, String: ""}}, 4},
		{model.Log, Matcher{Target: MatchField, Name: "count", Op: MatchEqual, Literal: Literal{Kind: LiteralString, String: "9007199254740993"}}, 0},
		{model.Log, Matcher{Target: MatchField, Name: "count", Op: MatchEqual, Literal: Literal{Kind: LiteralInteger, Integer: 9007199254740993}}, 2},
	}
	for _, phase := range []string{"hot", "cold", "compact"} {
		if phase == "cold" {
			if err = e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "compact" {
			if err = e.Compact(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range cases {
			got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: tc.kind, End: 2, Selectors: []Matcher{tc.matcher}})
			if len(got) != tc.want {
				t.Fatalf("%s %s %s: rows %d want %d", phase, tc.kind, tc.matcher.Name, len(got), tc.want)
			}
		}
	}
}
func TestActiveIteratorBudgetAndRelease(t *testing.T) {
	store, a, _, d := fixture(t)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var opened []RowIterator
	for range 32 {
		it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2})
		if err != nil {
			t.Fatal(err)
		}
		opened = append(opened, it)
	}
	if _, err = e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2}); err == nil {
		t.Fatal("iterator budget unbounded")
	}
	for _, it := range opened {
		it.Close()
	}
	if e.Stats().ActiveIterators != 0 || e.Stats().BorrowedPages != 0 {
		t.Fatal("resources not released")
	}
}
