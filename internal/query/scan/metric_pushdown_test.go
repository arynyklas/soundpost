// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

// nameScanner serves the rows it holds in one page. With honour set it answers the metric-name selector the
// way the storage index does (the postings of "name=" list the rows of that name), and counts the rows it
// served: that is what a query of one metric name out of many reads, decodes and hands to the evaluator.
type nameScanner struct {
	rows     storage.Page
	honour   bool
	served   int
	requests []storage.ScanRequest
}

type servedRows struct {
	page storage.Page
	done bool
}

func (r *servedRows) Next(context.Context) (storage.Page, error) {
	if r.done {
		return storage.Page{}, io.EOF
	}
	r.done = true
	return r.page, nil
}
func (r *servedRows) Watermarks() []model.Cursor {
	return []model.Cursor{{Group: model.ID{7}, Index: 3}}
}
func (r *servedRows) Close() error { return nil }

func (s *nameScanner) Scan(_ context.Context, _ auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	s.requests = append(s.requests, req)
	var out storage.Page
	for j := range s.rows.Times {
		if s.honour {
			keep := true
			for _, m := range req.Selectors {
				if m.Target != storage.MatchField || m.Name != "name" || m.Op != storage.MatchEqual {
					return nil, errors.New("a selector the index does not answer exactly was pushed down")
				}
				keep = keep && s.rows.Values[j].Metric.Name == m.Literal.String
			}
			if !keep {
				continue
			}
		}
		out.IDs = append(out.IDs, s.rows.IDs[j])
		out.Projects = append(out.Projects, s.rows.Projects[j])
		out.Times = append(out.Times, s.rows.Times[j])
		out.ObservedTimes = append(out.ObservedTimes, s.rows.ObservedTimes[j])
		out.Values = append(out.Values, s.rows.Values[j])
	}
	s.served += out.Len()
	return &servedRows{page: out}, nil
}

func fiveNames(project model.ID) storage.Page {
	var page storage.Page
	bits := func(f float64) *model.FloatBits { b := model.FloatBits(math.Float64bits(f)); return &b }
	for i := range 200 {
		name := string(rune('a' + i%5))
		page.IDs = append(page.IDs, model.ID{byte(i + 1)})
		page.Projects = append(page.Projects, project)
		page.Times = append(page.Times, model.UnixNano(10+i))
		page.ObservedTimes = append(page.ObservedTimes, model.UnixNano(10+i))
		page.Values = append(page.Values, model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{{Name: "route", Value: string(rune('x' + i%3))}}, Value: bits(float64(i))}})
	}
	return page
}

func collect(t *testing.T, scanner *nameScanner, project model.ID, ms []LabelMatcher) []value.Series {
	t.Helper()
	src := NewMetricSource(scanner, auth.Scope{}, project, storage.ReadFence{})
	it, err := src.Select(context.Background(), MetricSelection{Start: 0, End: 1000, Matchers: ms, Account: value.NewBoundedAccount(1 << 24)})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var out []value.Series
	for {
		s, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
}

// A selection of one metric name out of five reads the rows of that name only: the evaluator would drop the
// other four fifths after the storage had walked, read and decoded them (the org 24 h query of the Queries
// gate: 1,430 pages of rows of five names for the samples of one). The series the evaluator gets are the same
// as when every row is served, and nothing is pushed down that the index does not answer exactly.
func TestMetricSelectReadsOnlyTheRowsOfTheNameItIsAskedFor(t *testing.T) {
	project := model.ID{9}
	ask := []LabelMatcher{{Name: "__name__", Op: "=", Value: "b"}, {Name: "route", Op: "!=", Value: "z"}}

	all := &nameScanner{rows: fiveNames(project)}
	want := collect(t, all, project, ask)
	if len(want) == 0 || all.served != 200 {
		t.Fatalf("reference: %d series, %d rows served", len(want), all.served)
	}

	pushed := &nameScanner{rows: fiveNames(project), honour: true}
	got := collect(t, pushed, project, ask)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the series differ when the name is answered by the index:\n got %v\nwant %v", got, want)
	}
	if pushed.served != 40 {
		t.Fatalf("%d rows served for one name of five (200 rows), want the 40 of that name", pushed.served)
	}
	sel := pushed.requests[0].Selectors
	if len(sel) != 1 || sel[0].Target != storage.MatchField || sel[0].Name != "name" || sel[0].Op != storage.MatchEqual || sel[0].Literal.Kind != storage.LiteralString || sel[0].Literal.String != "b" {
		t.Fatalf("selectors %+v, want the metric name equal to b", sel)
	}
	if pushed.requests[0].MaxPageRows != storage.MaxScanPageRows {
		t.Fatalf("MaxPageRows %d: a selection reads every row of its range and asks for larger pages", pushed.requests[0].MaxPageRows)
	}

	// Matchers the index cannot answer exactly are never pushed.
	for _, ms := range [][]LabelMatcher{
		{{Name: "__name__", Op: "!=", Value: "b"}},
		{{Name: "__name__", Op: "!=", Value: ""}},
		{{Name: "__name__", Op: "=", Value: ""}},
		{{Name: "route", Op: "=", Value: "x"}},
		nil,
	} {
		s := &nameScanner{rows: fiveNames(project), honour: true}
		collect(t, s, project, ms)
		if len(s.requests[0].Selectors) != 0 || s.served != 200 {
			t.Fatalf("matchers %v: selectors %+v, %d rows served; nothing may be pushed down", ms, s.requests[0].Selectors, s.served)
		}
	}
}
