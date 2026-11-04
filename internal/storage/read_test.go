// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"io"
	"soundpost/internal/model"
	"testing"
)

func TestReadFencePrecedesIndexLookup(t *testing.T) {
	store, a, _, d := fixture(t)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	before := e.Stats()
	_, err = e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2, Fence: ReadFence{Min: []model.Cursor{{Group: model.NewID(), Index: 1}}}})
	if err == nil {
		t.Fatal("missing fence accepted")
	}
	if e.Stats().IndexLookups != before.IndexLookups {
		t.Fatal("unmet fence touched index")
	}
}
func TestSnapshotSurvivesFlushAndCompactionWithoutTailDuplicates(t *testing.T) {
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
	it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	row := b.Records[0]
	row.ID = model.NewID()
	row.ObservedAt = 2
	appendTyped(t, e, store, a, c, d, row)
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = e.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count += page.Len()
		if page.IDs[0] != b.Records[0].ID {
			t.Fatal("post-admission tail leaked")
		}
	}
	if count != 1 {
		t.Fatal("snapshot multiplicity", count)
	}
}
func TestProjectedPageAndSignalSpecificTime(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	timestamp := model.UnixNano(42)
	row := model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: 1, Resource: b.Records[0].Resource, Payload: model.Payload{Log: &model.LogRecord{Timestamp: &timestamp, Severity: "error", TemplateID: "safe", TemplateRevision: 1, Line: "safe", SourceClass: "structured", StreamLabels: model.Labels{}}}}
	appendTyped(t, e, store, a, c, d, row)
	it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Log, Start: 42, End: 43, Projection: []Field{FieldID, FieldTime, FieldObservedTime}})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	page, err := it.Next(context.Background())
	if err != nil || page.Len() != 1 || page.Times[0] != 42 || page.ObservedTimes[0] != 1 {
		t.Fatal("signal time changed", err)
	}
	if page.Values[0].Log != nil || page.Resources[0].Service != (model.ID{}) {
		t.Fatal("unrequested columns returned")
	}
}
func TestCancelledScanIsNeverEOF(t *testing.T) {
	store, a, _, d := fixture(t)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	it, err := e.Scan(ctx, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 1})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = it.Next(ctx)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatal("cancel became EOF")
	}
}
