// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"testing"
)

type logFixtureScanner struct {
	rows    *logFixtureRows
	request storage.ScanRequest
}

func (s *logFixtureScanner) Scan(_ context.Context, _ auth.Scope, r storage.ScanRequest) (storage.RowIterator, error) {
	s.request = r
	return s.rows, nil
}

type logFixtureRows struct {
	pages               []storage.Page
	pos, closes         int
	failure, errorClose error
	marks               []model.Cursor
	poison              bool
}

func (r *logFixtureRows) Next(context.Context) (storage.Page, error) {
	if r.pos >= len(r.pages) {
		if r.poison && len(r.pages) > 0 {
			for _, p := range r.pages {
				for j := range p.Values {
					if p.Values[j].Log != nil {
						p.Values[j].Log.Line = "changed"
						p.Values[j].Log.StreamLabels[0].Value = "poison"
					}
				}
			}
		}
		if r.failure != nil {
			return storage.Page{}, r.failure
		}
		return storage.Page{}, io.EOF
	}
	p := r.pages[r.pos]
	r.pos++
	return p, nil
}
func (r *logFixtureRows) Watermarks() []model.Cursor { return r.marks }
func (r *logFixtureRows) Close() error               { r.closes++; return r.errorClose }
func logPage(project model.ID) storage.Page {
	return storage.Page{IDs: []model.ID{{1}, {2}, {3}}, Projects: []model.ID{project, project, project}, Sources: []model.ID{{4}, {4}, {4}}, Times: []model.UnixNano{10, 10, 20}, Values: []model.Payload{{Log: &model.LogRecord{Line: "admitted safe", TemplateID: "old", StreamLabels: model.Labels{{Name: "app", Value: "api"}}}}, {Log: &model.LogRecord{Line: "admitted safe", TemplateID: "old", StreamLabels: model.Labels{{Name: "app", Value: "api"}}}}, {Log: &model.LogRecord{Line: "outside", StreamLabels: model.Labels{{Name: "app", Value: "api"}}}}}}
}
func TestLogScanImmutableLineIdentityAndHalfOpenBounds(t *testing.T) {
	project := model.ID{9}
	rows := &logFixtureRows{pages: []storage.Page{logPage(project)}, poison: true, marks: []model.Cursor{{Group: model.ID{8}, Index: 9007199254740993}}}
	scanner := &logFixtureScanner{rows: rows}
	account := value.NewBoundedAccount(1 << 20)
	source := NewLogSource(scanner, auth.Scope{}, project, storage.ReadFence{})
	it, err := source.Select(context.Background(), LogSelection{Start: 10, End: 20, Matchers: []LabelMatcher{{Name: "app", Op: "=", Value: "api"}}, Account: account})
	if err != nil {
		t.Fatal(err)
	}
	first, err := it.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := it.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Timestamp != 10 || second.Timestamp != 10 || first.ID == second.ID || first.Multiplicity != 1 || first.Record.Line != "admitted safe" {
		t.Fatal("identity or stored immutable line lost")
	}
	if _, err = it.Next(context.Background()); err != io.EOF {
		t.Fatalf("half-open exhaustion %v", err)
	}
	if first.Record.Line != "admitted safe" || first.Record.StreamLabels[0].Value != "api" {
		t.Fatal("borrowed C05 page escaped into retained row")
	}
	if account.Used() != 0 || rows.closes != 1 {
		t.Fatal("iterator or accounting leaked")
	}
	if scanner.request.Signal != model.Log || len(scanner.request.Selectors) != 0 || scanner.request.Projects[0] != project {
		t.Fatal("unsafe pushdown or missing scope")
	}
	if len(it.Watermarks()) != 1 || it.Watermarks()[0].Index != 9007199254740993 {
		t.Fatal("watermark precision lost")
	}
}
func TestLogScanFailuresAreNeverEOF(t *testing.T) {
	for _, failure := range []error{model.Fail(model.Unavailable), model.Fail(model.Forbidden), model.Fail(model.Corrupt), context.Canceled} {
		rows := &logFixtureRows{failure: failure}
		src := NewLogSource(&logFixtureScanner{rows: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{})
		it, err := src.Select(context.Background(), LogSelection{Start: 0, End: 30, Account: value.NewBoundedAccount(1 << 20)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = it.Next(context.Background()); err == nil || errors.Is(err, io.EOF) || !errors.Is(err, failure) {
			t.Fatalf("failure became exhaustion %v", err)
		}
		if rows.closes != 1 {
			t.Fatal("failure did not close iterator")
		}
	}
}
func TestLogScanPartialEmptyPageRemainsPartial(t *testing.T) {
	for _, allow := range []bool{false, true} {
		rows := &logFixtureRows{pages: []storage.Page{{Partial: true}}, marks: []model.Cursor{{Group: model.ID{2}, Index: 7}}}
		it, err := NewLogSource(&logFixtureScanner{rows: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{AllowPartial: allow}).Select(context.Background(), LogSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = it.Next(context.Background())
		if !allow {
			if err == nil || errors.Is(err, io.EOF) {
				t.Fatal("partial input became complete")
			}
		} else if err != io.EOF || !it.Partial() || len(it.Watermarks()) != 1 {
			t.Fatal("empty page metadata lost")
		}
	}
}
func TestLogScanCloseFailureAndCancellation(t *testing.T) {
	rows := &logFixtureRows{errorClose: io.ErrUnexpectedEOF}
	it, err := NewLogSource(&logFixtureScanner{rows: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{}).Select(context.Background(), LogSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = it.Next(context.Background()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("close failure erased")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = it.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled exhausted iterator reported EOF")
	}
}
