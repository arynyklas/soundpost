// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

func TestLogZeroLimitRetainsPartialCuts(t *testing.T) {
	src := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "one")}, partial: true}
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogs(context.Background(), metricPlan(t, `{app="api"}`, value.Evaluation{Start: 0, End: 2e9}), src, Forward, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Logs) != 0 || !r.Partial || len(r.Watermarks) != 1 {
		t.Fatalf("zero limit fabricated complete empty: %+v", r)
	}
	a.Release(value.ResultBytes(r))
	if a.Used() != 0 {
		t.Fatalf("zero limit leaked=%d", a.Used())
	}
}
func TestLogOriginalCategoriesSurviveFormatting(t *testing.T) {
	row := metricRow(1, 1e9, "safe original")
	src := &metricSource{rows: []scan.LogRow{row}}
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogs(context.Background(), metricPlan(t, `{app="api"}|label_format app="changed"|line_format "rendered"`, value.Evaluation{Start: 0, End: 2e9}), src, Forward, 1, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Logs) != 1 || r.Logs[0].Line != "rendered" || value.Label(r.Logs[0].Labels, "app") != "changed" || value.Label(r.Logs[0].StreamLabels, "app") != "api" || r.Logs[0].ID != row.ID || r.Logs[0].Source != row.Source {
		t.Fatalf("query view overwrote original identity: %+v", r.Logs)
	}
}

// peakAccount records the highest charge held at any instant.
type peakAccount struct {
	*value.BoundedAccount
	mu   sync.Mutex
	peak int64
}

func newPeakAccount(limit int64) *peakAccount {
	return &peakAccount{BoundedAccount: value.NewBoundedAccount(limit)}
}
func (a *peakAccount) Reserve(n int64) error {
	if err := a.BoundedAccount.Reserve(n); err != nil {
		return err
	}
	used := a.BoundedAccount.Used()
	a.mu.Lock()
	if used > a.peak {
		a.peak = used
	}
	a.mu.Unlock()
	return nil
}
func (a *peakAccount) Peak() int64 { a.mu.Lock(); defer a.mu.Unlock(); return a.peak }

// genIter yields row(i) for i in [0,n) in generation order, without holding the
// rows: a shard of a very large match set.
type genIter struct {
	n, at   int
	row     func(i int) PipelineResult
	partial bool
	marks   []model.Cursor
}

func (g *genIter) Next(ctx context.Context) (PipelineResult, error) {
	if err := ctx.Err(); err != nil {
		return PipelineResult{}, err
	}
	if g.at >= g.n {
		return PipelineResult{}, io.EOF
	}
	r := g.row(g.at)
	g.at++
	return r, nil
}
func (g *genIter) Watermarks() []model.Cursor { return g.marks }
func (g *genIter) Partial() bool              { return g.partial }
func (g *genIter) Close() error               { return nil }

// seen is the observable identity of one merged entry, multiplicity included.
type seen struct {
	ID     model.ID
	Source model.ID
	Time   model.UnixNano
	Mult   model.Uint64
	Line   string
	Labels string
}

func drainSeen(t *testing.T, it LogIterator, a value.Account) []seen {
	t.Helper()
	var out []seen
	for {
		r, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, seen{r.Entry.ID, r.Entry.Source, r.Entry.Timestamp, r.Entry.Multiplicity, r.Entry.Line, labelString(r.Labels)})
		a.Release(r.Bytes)
	}
	return out
}

// cutUnits is the unbounded answer truncated to limit units of multiplicity.
func cutUnits(all []seen, limit uint64) []seen {
	var out []seen
	for _, s := range all {
		if limit == 0 {
			break
		}
		if uint64(s.Mult) > limit {
			s.Mult = model.Uint64(limit)
		}
		limit -= uint64(s.Mult)
		out = append(out, s)
	}
	return out
}

var limitStreams = func() [5]model.Labels {
	var s [5]model.Labels
	for i := range s {
		s[i] = model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: "h" + strconv.Itoa(i)}}
	}
	return s
}()

// limitRow is row k of a large synthetic match set: about four rows per
// timestamp, five streams, multiplicity 1..3, rows of equal time and stream
// distinguished only by identity.
func limitRow(k int) PipelineResult {
	var id model.ID
	binary.BigEndian.PutUint32(id[:4], uint32(k))
	labels := limitStreams[k%5]
	return PipelineResult{Retained: true, Entry: LogEntry{ID: id, Source: model.ID{2}, Timestamp: model.UnixNano(1_000_000_000 + int64(k*7919%50000)), Multiplicity: model.Uint64(1 + k%3), Line: "line"}, Labels: labels, OriginalStreamLabels: labels}
}

// limit=10 over 200k rows in several shards: the merge holds O(limit) rows, and
// its output is exactly what the full order, cut at ten units, gives.
func TestMergeLogsLimitIsBoundedByLimitNotMatches(t *testing.T) {
	const rows, shards, limit = 200_000, 4, 10
	build := func() []EntryIterator {
		its := make([]EntryIterator, shards)
		for s := range its {
			s := s
			its[s] = &genIter{n: rows / shards, row: func(i int) PipelineResult { return limitRow(i*shards + s) }}
		}
		return its
	}
	for _, order := range []LogOrder{Forward, Backward} {
		bounded := newPeakAccount(1 << 40)
		it, err := MergeLogs(context.Background(), build(), order, limit, bounded)
		if err != nil {
			t.Fatal(err)
		}
		got := drainSeen(t, it, bounded)
		it.Close()
		if bounded.Used() != 0 {
			t.Fatalf("%s: bounded merge leaked %d", order, bounded.Used())
		}
		full := newPeakAccount(1 << 40)
		fit, err := MergeLogs(context.Background(), build(), order, math.MaxUint64, full)
		if err != nil {
			t.Fatal(err)
		}
		want := cutUnits(drainSeen(t, fit, full), limit)
		fit.Close()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: bounded output differs from the full order cut at the limit\n got %+v\nwant %+v", order, got, want)
		}
		// One held row costs well under 4 KiB here; the unbounded merge holds all
		// 200k of them.
		if full.Peak() < rows*1024 {
			t.Fatalf("%s: the reference merge peaked at only %d: the peak measure cannot see Theta(matches)", order, full.Peak())
		}
		if bounded.Peak() > (limit+2)*4096 {
			t.Fatalf("%s: limit %d over %d rows peaked at %d bytes: memory follows matches, not the limit", order, limit, rows, bounded.Peak())
		}
	}
}

// The bounded merge is the full order truncated, entry for entry: ties between
// streams (hash and label order), identity ties inside a stream, rows that are
// fully identical but for their multiplicity, a limit that cuts inside a tied
// multiplicity run, and limits of zero, one, a run, everything and beyond.
func TestMergeLogsBoundedEqualsFullOrderThenTruncation(t *testing.T) {
	for _, hashed := range []bool{true, false} {
		rng := rand.New(rand.NewPCG(11, 13))
		type spec struct {
			id     byte
			stream int
			time   int64
			mult   model.Uint64
		}
		specs := make([]spec, 300)
		var total uint64
		for i := range specs {
			specs[i] = spec{id: byte(rng.IntN(25)), stream: rng.IntN(4), time: int64(rng.IntN(9)), mult: model.Uint64(1 + rng.IntN(4))}
			total += uint64(specs[i].mult)
		}
		toRow := func(s spec) PipelineResult {
			r := PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{s.id}, Source: model.ID{2}, Timestamp: model.UnixNano(1_000_000_000 + s.time), Multiplicity: s.mult, Line: "same"}, Labels: limitStreams[s.stream]}
			if hashed {
				r.OriginalStreamLabels = limitStreams[s.stream]
			}
			return r
		}
		build := func() []EntryIterator {
			its := make([]EntryIterator, 3)
			for s := range its {
				var part []spec
				for i := s; i < len(specs); i += 3 {
					part = append(part, specs[i])
				}
				mine := part
				its[s] = &genIter{n: len(mine), row: func(i int) PipelineResult { return toRow(mine[i]) }, partial: s == 1, marks: []model.Cursor{{Group: model.ID{byte(s + 1)}, Index: 5}}}
			}
			return its
		}
		merge := func(order LogOrder, limit uint64) (rows []seen, partial bool, marks []model.Cursor, used int64) {
			a := value.NewBoundedAccount(1 << 40)
			it, err := mergeLogs(context.Background(), build(), order, limit, a, hashed)
			if err != nil {
				t.Fatal(err)
			}
			rows = drainSeen(t, it, a)
			partial, marks = it.Partial(), it.Watermarks()
			it.Close()
			return rows, partial, marks, a.Used()
		}
		for _, order := range []LogOrder{Forward, Backward} {
			all, allPartial, allMarks, _ := merge(order, math.MaxUint64)
			var sum uint64
			for _, s := range all {
				sum += uint64(s.Mult)
			}
			if sum != total {
				t.Fatalf("hashed=%v %s: unbounded merge lost multiplicity %d != %d", hashed, order, sum, total)
			}
			if !allPartial || len(allMarks) != 3 {
				t.Fatalf("hashed=%v %s: reference lost metadata: %v %v", hashed, order, allPartial, allMarks)
			}
			for _, limit := range []uint64{0, 1, 2, 3, 5, 10, 17, 64, total - 1, total, total + 7, math.MaxUint64 - 1, math.MaxUint64} {
				got, partial, marks, used := merge(order, limit)
				if want := cutUnits(all, limit); !reflect.DeepEqual(got, want) {
					t.Fatalf("hashed=%v %s limit=%d: bounded merge differs from the full order cut\n got %+v\nwant %+v", hashed, order, limit, got, want)
				}
				if partial != allPartial || !reflect.DeepEqual(marks, allMarks) {
					t.Fatalf("hashed=%v %s limit=%d: partial/watermark metadata lost: %v %v", hashed, order, limit, partial, marks)
				}
				if used != 0 {
					t.Fatalf("hashed=%v %s limit=%d: leaked %d", hashed, order, limit, used)
				}
			}
		}
	}
}

// The bound is counted in multiplicity units: entries of multiplicity 5 reach a
// limit of 10 with two rows, so the merge never holds more than a few of them.
func TestMergeLogsBoundCountsMultiplicityUnits(t *testing.T) {
	heavy := func(k int) PipelineResult {
		r := limitRow(k)
		r.Entry.Multiplicity = 5
		return r
	}
	probe := newPeakAccount(1 << 40)
	it, err := MergeLogs(context.Background(), []EntryIterator{&genIter{n: 1, row: heavy}}, Forward, math.MaxUint64, probe)
	if err != nil {
		t.Fatal(err)
	}
	it.Close()
	oneRow := probe.Peak()
	a := newPeakAccount(1 << 40)
	it, err = MergeLogs(context.Background(), []EntryIterator{&genIter{n: 500, row: heavy}}, Forward, 10, a)
	if err != nil {
		t.Fatal(err)
	}
	got := drainSeen(t, it, a)
	it.Close()
	if len(got) != 2 || got[0].Mult != 5 || got[1].Mult != 5 || a.Used() != 0 {
		t.Fatalf("limit 10 over multiplicity-5 rows: %+v used=%d", got, a.Used())
	}
	if a.Peak() > 4*oneRow {
		t.Fatalf("peak %d is %d rows' worth: the bound counted rows, not multiplicity", a.Peak(), a.Peak()/oneRow)
	}
}

// A budget that cannot hold the entries the limit needs is still the typed
// Quota; one that holds them is no longer exceeded by matches beyond the limit.
func TestMergeLogsBoundedKeepsTypedQuotaForTrueBudgetAborts(t *testing.T) {
	build := func() []EntryIterator {
		return []EntryIterator{&genIter{n: 400, row: limitRow}}
	}
	probe := newPeakAccount(1 << 40)
	it, err := MergeLogs(context.Background(), build(), Forward, 3, probe)
	if err != nil {
		t.Fatal(err)
	}
	it.Close()
	// Room for the rows the limit keeps (plus one in flight) but nowhere near
	// the 400 matches.
	a := newPeakAccount(probe.Peak() + probe.Peak()/2)
	it, err = MergeLogs(context.Background(), build(), Forward, 3, a)
	if err != nil {
		t.Fatalf("matches beyond the limit exhausted the budget: %v", err)
	}
	if got := drainSeen(t, it, a); len(got) == 0 || a.Used() != 0 {
		t.Fatalf("got=%d used=%d", len(got), a.Used())
	}
	// The same budget cannot hold a limit that needs every row.
	a = newPeakAccount(probe.Peak() + probe.Peak()/2)
	_, err = MergeLogs(context.Background(), build(), Forward, 5000, a)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Quota {
		t.Fatalf("a true budget abort must stay the typed Quota, got %#v", err)
	}
	if a.Used() != 0 {
		t.Fatalf("quota abort leaked %d", a.Used())
	}
}

// genSource serves one generated match set; every Select starts it over.
type genSource struct {
	n          int
	row        func(i int) scan.LogRow
	selections int
}

func (s *genSource) ProjectID() model.ID { return model.ID{1} }
func (s *genSource) Select(context.Context, scan.LogSelection) (scan.LogIterator, error) {
	s.selections++
	return &genLogRows{n: s.n, row: s.row}, nil
}

type genLogRows struct {
	n, at int
	row   func(i int) scan.LogRow
}

func (g *genLogRows) Next(context.Context) (scan.LogRow, error) {
	if g.at >= g.n {
		return scan.LogRow{}, io.EOF
	}
	r := g.row(g.at)
	g.at++
	return r, nil
}
func (g *genLogRows) Watermarks() []model.Cursor { return nil }
func (g *genLogRows) Partial() bool              { return false }
func (g *genLogRows) Close() error               { return nil }

// The interval path honors the limit too: thinned to one entry per interval, a
// limit of ten over 100k rows keeps a prefix of the order (grown while thinning
// has not yet produced ten), not every match, and answers exactly what the
// unbounded evaluation truncated to ten answers.
func TestEvaluateLogsIntervalHonorsLimitBoundedByPrefix(t *testing.T) {
	const rows, limit, interval = 100_000, 10, 100
	// A permutation of 1..rows: timestamps unique, arrival unordered.
	src := &genSource{n: rows, row: func(i int) scan.LogRow {
		r := metricRow(byte(i), int64(i*40503%rows)+1, "x")
		binary.BigEndian.PutUint32(r.ID[:4], uint32(i+1))
		return r
	}}
	plan := metricPlan(t, `{app="api"}`, value.Evaluation{Start: 0, End: rows + 10})
	for _, order := range []LogOrder{Forward, Backward} {
		src.selections = 0
		bounded := newPeakAccount(1 << 40)
		got, err := EvaluateLogsInterval(context.Background(), plan, src, order, limit, interval, bounded)
		if err != nil {
			t.Fatal(err)
		}
		passes := src.selections
		bounded.Release(value.ResultBytes(got))
		if bounded.Used() != 0 {
			t.Fatalf("%s: leaked %d", order, bounded.Used())
		}
		full := newPeakAccount(1 << 40)
		all, err := EvaluateLogsInterval(context.Background(), plan, src, order, math.MaxUint64, interval, full)
		if err != nil {
			t.Fatal(err)
		}
		want := all.Logs[:limit]
		if len(got.Logs) != limit || !reflect.DeepEqual(got.Logs, want) {
			t.Fatalf("%s: interval limit differs from the unbounded evaluation cut at %d\n got %+v\nwant %+v", order, limit, got.Logs, want)
		}
		if len(all.Logs) < 900 {
			t.Fatalf("%s: reference thinned to only %d entries", order, len(all.Logs))
		}
		// Thinning spends about 100 rows per entry: ten entries need a prefix of
		// about a thousand rows, never the 100k matches.
		if passes < 2 {
			t.Fatalf("%s: the first prefix already sufficed (%d passes); the growth path was not exercised", order, passes)
		}
		if full.Peak() < rows*512 || bounded.Peak() > full.Peak()/8 {
			t.Fatalf("%s: interval path peaked at %d against %d unbounded: memory follows matches, not the limit", order, bounded.Peak(), full.Peak())
		}
	}
}

// A prefix that was never cut is the whole match set: no rescan, and a limit
// the thinned entries cannot reach still returns every thinned entry.
func TestEvaluateLogsIntervalShortResultNeedsNoRescan(t *testing.T) {
	src := &genSource{n: 50, row: func(i int) scan.LogRow {
		r := metricRow(byte(i+1), int64(i)+1, "x")
		return r
	}}
	plan := metricPlan(t, `{app="api"}`, value.Evaluation{Start: 0, End: 100})
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogsInterval(context.Background(), plan, src, Forward, 40, 10, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Logs) != 5 || r.Logs[0].Timestamp != 1 || r.Logs[4].Timestamp != 41 {
		t.Fatalf("thinned entries: %+v", r.Logs)
	}
	if src.selections > 3 {
		t.Fatalf("selections=%d: rescans past the point the prefix covered every match", src.selections)
	}
}
