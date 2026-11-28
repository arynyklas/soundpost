// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

func clonePage(project model.ID, n int) storage.Page {
	p := storage.Page{}
	for i := range n {
		p.IDs = append(p.IDs, model.ID{byte(i + 1)})
		p.Projects = append(p.Projects, project)
		p.Sources = append(p.Sources, model.ID{4})
		p.Times = append(p.Times, model.UnixNano(10+i))
		p.Values = append(p.Values, model.Payload{Log: &model.LogRecord{Severity: "info", TemplateID: "tmpl", Line: "GET /api/v1/items 200 12ms", StreamLabels: model.Labels{{Name: "app", Value: "api"}, {Name: "env", Value: "prod"}, {Name: "route", Value: "items"}}}})
	}
	return p
}

func cloneRun(t testing.TB, rows *logFixtureRows, account *value.BoundedAccount, project model.ID) (n int) {
	rows.pos = 0
	it, err := NewLogSource(&logFixtureScanner{rows: rows}, auth.Scope{}, project, storage.ReadFence{}).Select(context.Background(), LogSelection{Start: 0, End: 1000, Account: account})
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
}

// The row an iterator hands out owns its bytes (the page it came from is shared and cached), and it did so
// with one allocation per string, per label and per map: a dozen per row, 25 CPU seconds of the 24 h log
// class in the gate mix. The owned copy is one buffer for the strings, one slice for the labels, and the
// maps of a row that has none are shared and never written.
func TestLogRowIsOwnedWithAFewAllocations(t *testing.T) {
	const n = 100
	project := model.ID{9}
	rows := &logFixtureRows{pages: []storage.Page{clonePage(project, n)}, marks: []model.Cursor{{Group: model.ID{8}, Index: 1}}}
	account := value.NewBoundedAccount(1 << 20)
	allocs := testing.AllocsPerRun(20, func() { cloneRun(t, rows, account, project) })
	t.Logf("allocations per log row: %.2f", allocs/n)
	if per := allocs / n; per > 3 {
		t.Fatalf("%.2f allocations per row, want at most 3", per)
	}
}

// The owned copy equals the stored record, and does not alias it.
func TestOwnedLogRowEqualsTheStoredRecordAndDoesNotAliasIt(t *testing.T) {
	ts, span, trace, run := model.UnixNano(5), model.SpanID{1, 2}, model.ID{3}, model.ID{4}
	scalar := func(raw string) model.Scalar { s, _ := model.ScalarFromCanonical(raw); return s }
	for _, rec := range []model.LogRecord{
		{Line: "a", StreamLabels: model.Labels{{Name: "x", Value: "y"}}},
		{Severity: "warn", TemplateID: "t", TemplateRevision: 3, Line: "", StreamLabels: model.Labels{}, Fields: map[string]model.Scalar{}, Metadata: map[string]model.Scalar{}, SourceClass: "raw"},
		{Severity: "warn", Line: "l", StreamLabels: model.Labels{{Name: "a", Value: "1"}, {Name: "b", Value: ""}}, Fields: map[string]model.Scalar{"k": scalar("1"), "z": scalar(`"v"`)}, Metadata: map[string]model.Scalar{"m": scalar("true")}, Timestamp: &ts, Trace: &trace, Span: &span, Run: &run},
	} {
		rec := rec
		got := ownLogRecord(&rec)
		if !reflect.DeepEqual(got, rec) {
			t.Fatalf("owned copy differs:\n got %#v\nwant %#v", got, rec)
		}
		if len(rec.StreamLabels) > 0 && &got.StreamLabels[0] == &rec.StreamLabels[0] {
			t.Fatal("labels alias the stored record")
		}
		if rec.Timestamp != nil && got.Timestamp == rec.Timestamp || rec.Trace != nil && got.Trace == rec.Trace {
			t.Fatal("pointers alias the stored record")
		}
	}
}

// The memory a row costs is computed from the length of its scalars, not from a marshalled copy of each:
// the row with five fields made five more allocations before it was handed out.
func TestLogRowWithFieldsIsChargedWithoutMarshalCopies(t *testing.T) {
	const n = 100
	project := model.ID{9}
	page := clonePage(project, n)
	scalar := func(raw string) model.Scalar { s, _ := model.ScalarFromCanonical(raw); return s }
	fields := map[string]model.Scalar{"count": scalar("12"), "ok": scalar("true"), "name": scalar(`"abc"`), "none": scalar("null"), "neg": scalar("-3")}
	for i := range page.Values {
		page.Values[i].Log.Fields = fields
	}
	rows := &logFixtureRows{pages: []storage.Page{page}, marks: []model.Cursor{{Group: model.ID{8}, Index: 1}}}
	account := value.NewBoundedAccount(1 << 20)
	allocs := testing.AllocsPerRun(20, func() { cloneRun(t, rows, account, project) })
	t.Logf("allocations per log row with five fields: %.2f", allocs/n)
	if per := allocs / n; per > 3 {
		t.Fatalf("%.2f allocations per row with five fields, want at most 3", per)
	}
	if account.Used() != 0 {
		t.Fatalf("%d bytes still charged", account.Used())
	}
}
