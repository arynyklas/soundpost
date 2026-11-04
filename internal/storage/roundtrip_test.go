// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

func scanScope(t *testing.T, s *control.Store, a *auth.Service, d model.SourceDescriptor) auth.Scope {
	return scanPermission(t, s, a, d, auth.Read)
}
func scanPermission(t *testing.T, _ *control.Store, a *auth.Service, d model.SourceDescriptor, permission auth.Permission) auth.Scope {
	t.Helper()
	session, err := a.Login(context.Background(), "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatalf("reader login: %v", err)
	}
	cred, err := a.Authenticate(context.Background(), session.Token)
	if err != nil {
		t.Fatalf("reader authenticate: %v", err)
	}
	scope, err := a.Authorize(context.Background(), cred, d.Org, []model.ID{d.Project}, permission)
	if err != nil {
		t.Fatalf("reader authorize %s: %v", permission, err)
	}
	return scope
}
func collectPages(t *testing.T, e *Engine, s auth.Scope, q ScanRequest) []model.Record {
	t.Helper()
	it, err := e.Scan(context.Background(), s, q)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var out []model.Record
	for {
		p, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.IDs {
			r := model.Record{ID: p.IDs[i], Kind: q.Signal, ObservedAt: p.ObservedTimes[i], Resource: p.Resources[i], Payload: p.Values[i]}
			b := mustJSON(t, r)
			var owned model.Record
			if err = model.StrictJSON(b, &owned); err != nil {
				t.Fatal(err)
			}
			out = append(out, owned)
		}
	}
	return out
}
func TestHotColdCompactedTypedEquality(t *testing.T) {
	t.Run("all closed C04 variants", TestAllClosedPayloadsHotColdCompactedTypedEquality)
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := e.Append(context.Background(), write, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	q := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, Start: 0, End: 100, Fence: ReadFence{Min: []model.Cursor{receipt.Cursor}}}
	want := collectPages(t, e, read, q)
	if len(want) != 1 {
		t.Fatalf("rows %d", len(want))
	}
	for _, step := range []func(context.Context) error{e.Flush, e.Compact} {
		if err = step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := collectPages(t, e, read, q); !reflect.DeepEqual(want, got) {
			t.Fatal("typed roundtrip changed")
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := collectPages(t, e, read, q); !reflect.DeepEqual(want, got) {
		t.Fatal("restart changed typed values")
	}
}
func TestForeignProjectNeverTouchesIndex(t *testing.T) {
	store, a, _, d := fixture(t)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	before := e.Stats()
	_, err = e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{model.NewID()}, Signal: model.Metric, End: 10})
	if err == nil {
		t.Fatal("foreign accepted")
	}
	if e.Stats().IndexLookups != before.IndexLookups {
		t.Fatal("foreign touched index")
	}
}
func TestCancelledScanReleasesPages(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	it, err := e.Scan(ctx, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = it.Next(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = it.Next(ctx); err == nil {
		t.Fatal("cancel ignored")
	}
	if e.Stats().BorrowedPages != 0 || e.Stats().ActiveIterators != 0 {
		t.Fatal("pages retained")
	}
}
func TestUnknownSegmentVersionIsNotEOF(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.catalog.Manifest.Segments) == 0 {
		t.Fatal("missing segments")
	}
	filePath, err := segmentPath(e.dir, e.catalog.Manifest.Segments[0].File)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte{0, 2}, 4)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	read := scanScope(t, store, a, d)
	it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 10})
	if err == nil {
		defer it.Close()
		_, err = it.Next(context.Background())
	}
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatal("unknown version became EOF")
	}
}
