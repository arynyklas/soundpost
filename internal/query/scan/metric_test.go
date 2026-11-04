// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"math"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
	"testing"
)

// borrowedMemoryScanner implements the C05 page lifetime exactly: advancing
// poisons the old page, exposing adapters that retain borrowed histogram slices.
type borrowedMemoryScanner struct {
	it      *borrowedRows
	request storage.ScanRequest
}

func (s *borrowedMemoryScanner) Scan(ctx context.Context, scope auth.Scope, r storage.ScanRequest) (storage.RowIterator, error) {
	s.request = r
	return s.it, nil
}

type borrowedRows struct {
	page     storage.Page
	advanced bool
	closes   int
	failure  error
	cancel   context.CancelFunc
	cursors  []model.Cursor
}

func (r *borrowedRows) Next(ctx context.Context) (storage.Page, error) {
	if r.advanced {
		for i := range r.page.Times {
			r.page.Times[i] = -99
			r.page.Values[i].Metric.Name = "poison"
			if start := r.page.Values[i].Metric.StartTimestamp; start != nil {
				*start = 999
			}
			if h := r.page.Values[i].Metric.Histogram; h != nil {
				h.Integer.PositiveBuckets[0] = 99
			}
		}
		if r.cancel != nil {
			r.cancel()
		}
		if r.failure != nil {
			return storage.Page{}, r.failure
		}
		return storage.Page{}, io.EOF
	}
	r.advanced = true
	return r.page, nil
}
func (r *borrowedRows) Watermarks() []model.Cursor { return r.cursors }
func (r *borrowedRows) Close() error               { r.closes++; return nil }
func TestMetricScanBorrowedPageAndCancellation(t *testing.T) {
	var project model.ID
	project[0] = 1
	bits := model.FloatBits(math.Float64bits(4))
	h := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", ResetHint: "unknown", Count: 9007199254740993, PositiveSpans: []model.HistogramSpan{{Length: 1}}, PositiveBuckets: []model.DeltaBucket{7}}}
	rows := &borrowedRows{page: storage.Page{IDs: []model.ID{{1}, {2}}, Projects: []model.ID{project, project}, Times: []model.UnixNano{10, 20}, ObservedTimes: []model.UnixNano{100, 200}, Values: []model.Payload{{Metric: &model.MetricPoint{Name: "a", Value: &bits}}, {Metric: &model.MetricPoint{Name: "h", Histogram: h}}}}}
	scanner := &borrowedMemoryScanner{it: rows}
	account := value.NewBoundedAccount(1 << 20)
	src := NewMetricSource(scanner, auth.Scope{}, project, storage.ReadFence{})
	it, e := src.Select(context.Background(), MetricSelection{Start: 0, End: 30, Account: account})
	if e != nil {
		t.Fatal(e)
	}
	defer it.Close()
	a, e := it.Next(context.Background())
	if e != nil || a.Samples[0].Time != 10 || value.Label(a.Labels, "__name__") != "a" {
		t.Fatalf("borrowed float: %+v %v", a, e)
	}
	b, e := it.Next(context.Background())
	if e != nil || b.Samples[0].Histogram.Integer.Count != 9007199254740993 || b.Samples[0].Histogram.Integer.PositiveBuckets[0] != 7 {
		t.Fatalf("borrowed histogram: %+v %v", b, e)
	}
	if rows.closes != 1 {
		t.Fatalf("row closes %d", rows.closes)
	}
	if scanner.request.Signal != model.Metric || len(scanner.request.Projects) != 1 || scanner.request.Projects[0] != project {
		t.Fatal("unscoped scan")
	}
	_ = it.Close()
	if account.Used() != 0 {
		t.Fatal("scan accounting leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	rows = &borrowedRows{page: storage.Page{}, cancel: cancel}
	scanner.it = rows
	if _, e = src.Select(ctx, MetricSelection{Start: 0, End: 30, Account: account}); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel error %v", e)
	}
	if rows.closes != 1 {
		t.Fatalf("cancel closes %d", rows.closes)
	}
}
func TestMetricScanErrorsNeverEOF(t *testing.T) {
	for _, failure := range []error{model.Fail(model.Unavailable), model.Fail(model.Corrupt)} {
		rows := &borrowedRows{failure: failure}
		src := NewMetricSource(&borrowedMemoryScanner{it: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{})
		_, e := src.Select(context.Background(), MetricSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
		if e == nil || errors.Is(e, io.EOF) {
			t.Fatalf("lost scan failure %v", e)
		}
		if rows.closes != 1 {
			t.Fatal("error iterator not closed")
		}
	}
	rows := &borrowedRows{page: storage.Page{IDs: []model.ID{{1}}}}
	_, e := NewMetricSource(&borrowedMemoryScanner{it: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{}).Select(context.Background(), MetricSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
	if e == nil {
		t.Fatal("corrupt column lengths accepted")
	}
}
func TestMetricScanPartialEmptyPageMetadata(t *testing.T) {
	for _, allow := range []bool{false, true} {
		rows := &borrowedRows{page: storage.Page{Partial: true}, cursors: []model.Cursor{{Group: model.ID{3}, Index: 17}}}
		src := NewMetricSource(&borrowedMemoryScanner{it: rows}, auth.Scope{}, model.ID{1}, storage.ReadFence{AllowPartial: allow})
		it, e := src.Select(context.Background(), MetricSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
		if !allow {
			if e == nil || errors.Is(e, io.EOF) {
				t.Fatalf("partial input became complete success: %v", e)
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if !it.Partial() {
			t.Fatal("empty partial page lost completeness")
		}
		cuts := it.Watermarks()
		if len(cuts) != 1 || cuts[0].Group != (model.ID{3}) || cuts[0].Index != 17 {
			t.Fatalf("lost cuts %v", cuts)
		}
		cuts[0].Index = 99
		if it.Watermarks()[0].Index != 17 {
			t.Fatal("mutable read cuts escaped")
		}
		if _, e = it.Next(context.Background()); e != io.EOF {
			t.Fatalf("actual empty exhaustion %v", e)
		}
		_ = it.Close()
		if rows.closes != 1 {
			t.Fatalf("closed %d times", rows.closes)
		}
	}
}
func TestMetricScanBorrowedOptionalStartTimestamp(t *testing.T) {
	start := model.UnixNano(-42)
	bits := model.FloatBits(0x3ff0000000000000)
	project := model.ID{1}
	rows := &borrowedRows{page: storage.Page{IDs: []model.ID{{1}}, Projects: []model.ID{project}, Times: []model.UnixNano{10}, ObservedTimes: []model.UnixNano{100}, Values: []model.Payload{{Metric: &model.MetricPoint{Name: "m", Value: &bits, StartTimestamp: &start}}}}}
	src := NewMetricSource(&borrowedMemoryScanner{it: rows}, auth.Scope{}, project, storage.ReadFence{})
	it, e := src.Select(context.Background(), MetricSelection{Start: 0, End: 20, Account: value.NewBoundedAccount(1 << 20)})
	if e != nil {
		t.Fatal(e)
	}
	defer it.Close()
	s, e := it.Next(context.Background())
	if e != nil || len(s.Samples) != 1 || s.Samples[0].StartTimestamp == nil || *s.Samples[0].StartTimestamp != -42 {
		t.Fatalf("borrowed start timestamp %+v %v", s, e)
	}
	if s.Samples[0].Time != 10 || start != 999 {
		t.Fatal("event/start/observed clocks were conflated or page poisoning did not execute")
	}
}
func TestMetricScanUsesLexicalSeriesOrder(t *testing.T) {
	one := model.FloatBits(0x3ff0000000000000)
	project := model.ID{1}
	rows := &borrowedRows{page: storage.Page{IDs: []model.ID{{1}, {2}}, Projects: []model.ID{project, project}, Times: []model.UnixNano{0, 0}, Values: []model.Payload{{Metric: &model.MetricPoint{Name: "z", Value: &one}}, {Metric: &model.MetricPoint{Name: "aa", Value: &one}}}}}
	it, e := NewMetricSource(&borrowedMemoryScanner{it: rows}, auth.Scope{}, project, storage.ReadFence{}).Select(context.Background(), MetricSelection{Start: 0, End: 1, Account: value.NewBoundedAccount(1 << 20)})
	if e != nil {
		t.Fatal(e)
	}
	defer it.Close()
	first, e := it.Next(context.Background())
	if e != nil || value.Label(first.Labels, "__name__") != "aa" {
		t.Fatalf("lexical first %+v %v", first, e)
	}
	second, e := it.Next(context.Background())
	if e != nil || value.Label(second.Labels, "__name__") != "z" {
		t.Fatalf("lexical second %+v %v", second, e)
	}
}
