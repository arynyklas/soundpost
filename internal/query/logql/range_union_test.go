// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// countingSource counts what the engine asks the storage layer for: the
// number of Select calls and the rows those selections hand out.
type countingSource struct {
	*metricSource
	selects   int
	delivered int
}

func (s *countingSource) Select(ctx context.Context, r scan.LogSelection) (scan.LogIterator, error) {
	s.selects++
	it, err := s.metricSource.Select(ctx, r)
	if err != nil {
		return nil, err
	}
	return &countingRows{LogIterator: it, owner: s}, nil
}

type countingRows struct {
	scan.LogIterator
	owner *countingSource
}

func (i *countingRows) Next(ctx context.Context) (scan.LogRow, error) {
	r, err := i.LogIterator.Next(ctx)
	if err == nil {
		i.owner.delivered++
	}
	return r, err
}

const second = int64(1e9)

// minuteLogs is one row a minute over the whole span, cycling through a few
// routes, so a 24 h range query at a 10 m step has a 1 h window that overlaps
// its neighbours six times over.
func minuteLogs(hours int64) []scan.LogRow {
	var rows []scan.LogRow
	for i := int64(0); i < hours*60; i++ {
		line := fmt.Sprintf("n=%d msg=ok", i%7)
		if i%5 == 0 {
			line = fmt.Sprintf("n=%d msg=retried", i%7)
		}
		r := metricRow(byte(i%250+1), i*60*second, line)
		r.ID = model.ID{byte(i), byte(i >> 8), byte(i >> 16), 7}
		r.Record.StreamLabels = model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", i%3)}}
		rows = append(rows, r)
	}
	return rows
}

// TestRangeQueryReadsEachSelectorOnce is the engine-level cost contract: the
// storage layer is asked once per log selector of the query, and no row is
// delivered twice, however many grid steps the range has.
func TestRangeQueryReadsEachSelectorOnce(t *testing.T) {
	rows := minuteLogs(25)
	ev := value.Evaluation{Start: model.UnixNano(60 * 60 * second), End: model.UnixNano(25 * 60 * 60 * second), Step: 10 * 60 * second}
	cases := []struct {
		q         string
		ev        value.Evaluation
		selectors int
	}{
		{`sum by (route) (count_over_time({route=~"r.+"}[1h]))`, ev, 1},
		{`sum(rate({route="r0"}[5m]))`, value.Evaluation{Start: ev.Start, End: ev.Start + model.UnixNano(60*60*second), Step: 60 * second}, 1},
		{`sum(count_over_time({route="r0"}[10m])) / sum(count_over_time({route="r1"}[10m]))`, ev, 2},
	}
	for _, tc := range cases {
		t.Run(tc.q, func(t *testing.T) {
			plan := metricPlan(t, tc.q, tc.ev)
			run := func(opts evalOptions) (*countingSource, value.Result) {
				src := &countingSource{metricSource: &metricSource{rows: rows}}
				a := value.NewBoundedAccount(256 << 20)
				r, _, err := evaluate(context.Background(), plan, src, a, opts)
				if err != nil {
					t.Fatal(err)
				}
				a.Release(value.ResultBytes(r))
				if a.Used() != 0 {
					t.Fatalf("leaked %d", a.Used())
				}
				return src, r
			}
			old, want := run(evalOptions{perStep: true})
			got, result := run(evalOptions{})
			t.Logf("per-step: selects=%d rows=%d; union: selects=%d rows=%d", old.selects, old.delivered, got.selects, got.delivered)
			if old.selects <= 2*tc.selectors {
				t.Fatalf("test source not sensitive: per-step path made %d selects", old.selects)
			}
			if got.selects != tc.selectors {
				t.Fatalf("selects=%d, want one per selector (%d)", got.selects, tc.selectors)
			}
			if got.delivered > tc.selectors*len(rows) {
				t.Fatalf("delivered %d rows for %d selectors over %d rows", got.delivered, tc.selectors, len(rows))
			}
			if !reflect.DeepEqual(result, want) {
				t.Fatalf("union result differs from per-step result:\n got=%+v\nwant=%+v", result, want)
			}
		})
	}
}

// TestLogStreamRangeQueryReadsOnce pins that a raw-log query is one scan: it
// never had a per-step read to remove.
func TestLogStreamRangeQueryReadsOnce(t *testing.T) {
	rows := minuteLogs(25)
	src := &countingSource{metricSource: &metricSource{rows: rows}}
	a := value.NewBoundedAccount(256 << 20)
	plan := metricPlan(t, `{route="r1"} |= "retried"`, value.Evaluation{Start: 0, End: model.UnixNano(25 * 60 * 60 * second), Step: 60 * second})
	r, err := EvaluateLogs(context.Background(), plan, src, Backward, 10, a)
	if err != nil {
		t.Fatal(err)
	}
	a.Release(value.ResultBytes(r))
	if len(r.Logs) != 10 || src.selects != 1 || src.delivered > len(rows) {
		t.Fatalf("logs=%d selects=%d delivered=%d", len(r.Logs), src.selects, src.delivered)
	}
}

// unionOutcome is everything a caller can observe of one evaluation.
type unionOutcome struct {
	result value.Result
	diags  []syntax.Diagnostic
	err    string
	used   int64
}

func errorKey(err error) string {
	if err == nil {
		return ""
	}
	var pipeline *MetricPipelineError
	if errors.As(err, &pipeline) {
		return fmt.Sprintf("pipeline:%s:%v", pipeline.Category, pipeline.EngineSet)
	}
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fmt.Sprintf("fault:%s:%s", fault.Code, fault.SafeDetail)
	}
	return err.Error()
}

// corpusPlan is metricPlan with the failing query named.
func corpusPlan(t *testing.T, q string, ev value.Evaluation) Plan {
	t.Helper()
	p := testProfile(t)
	x, err := Parse(q, p)
	if err != nil {
		t.Fatalf("corpus query %s: %v", q, err)
	}
	typed, _, err := Check(x, p)
	if err != nil {
		t.Fatalf("corpus query %s: %v", q, err)
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		t.Fatalf("corpus query %s: %v", q, err)
	}
	return plan
}

func runOutcome(t *testing.T, plan Plan, src scan.LogSource, limit int64, opts evalOptions) unionOutcome {
	t.Helper()
	a := value.NewBoundedAccount(limit)
	r, ds, err := evaluate(context.Background(), plan, src, a, opts)
	out := unionOutcome{result: r, diags: ds, err: errorKey(err)}
	if err == nil {
		a.Release(value.ResultBytes(r))
	}
	out.used = a.Used()
	return out
}

// randomLogs makes rows with gaps, equal timestamps across streams, rows on
// and one nanosecond off every window boundary the corpus grids produce,
// multiplicities above one, unparsable payloads and an arbitrary slice order.
func randomLogs(seed int64, shuffle bool) []scan.LogRow {
	rng := rand.New(rand.NewPCG(uint64(seed), 0x9e3779b97f4a7c15))
	var rows []scan.LogRow
	add := func(at int64) {
		i := len(rows)
		line := fmt.Sprintf("n=%d level=%s msg=%q", rng.IntN(20), []string{"info", "warn", "error"}[rng.IntN(3)], []string{"ok", "retried", "timeout x"}[rng.IntN(3)])
		switch rng.IntN(20) {
		case 0:
			line = "n=bad level=info"
		case 1:
			line = "%%% not logfmt"
		case 2:
			line = fmt.Sprintf(`{"n":%d,"level":"warn"}`, rng.IntN(9))
		}
		r := metricRow(1, at, line)
		r.ID = model.ID{byte(i), byte(i >> 8), 3, 1}
		r.Record.StreamLabels = model.Labels{{Name: "app", Value: []string{"api", "web"}[rng.IntN(2)]}, {Name: "host", Value: []string{"a", "b"}[rng.IntN(2)]}, {Name: "route", Value: fmt.Sprintf("r%d", rng.IntN(3))}}
		if rng.IntN(10) == 0 {
			r.Multiplicity = model.Uint64(1 + rng.IntN(3))
		}
		rows = append(rows, r)
	}
	// Two clusters with a gap between them, then boundary rows.
	for range 70 {
		add(int64(10+rng.IntN(25)) * second)
	}
	for range 50 {
		add(int64(45+rng.IntN(20))*second + int64(rng.IntN(3))*int64(5e8))
	}
	for _, edge := range []int64{15, 20, 25, 30, 35, 40, 45, 50, 55, 60} {
		for _, d := range []int64{-1, 0, 1} {
			add(edge*second + d)
		}
	}
	if shuffle {
		rng.Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	} else {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Timestamp < rows[j].Timestamp })
	}
	return rows
}

var unionCorpus = []string{
	`count_over_time({app="api"}[10s])`,
	`rate({app="api"}[10s])`,
	`bytes_over_time({app="api"}[10s])`,
	`bytes_rate({app="web"}[5s])`,
	`absent_over_time({app="api"}[10s])`,
	`absent_over_time({app="nope"}[10s])`,
	`count_over_time({app="api"} |= "retried" [10s])`,
	`count_over_time({app="api"} != "ok" |~ "re.+" [10s])`,
	`count_over_time({app=~"a.+", host!="b"} [7s])`,
	`count_over_time({app="api"} | logfmt | level="warn" [10s])`,
	`count_over_time({app="api"} | json [10s])`,
	`count_over_time({app="api"} | logfmt | line_format "{{.msg}}" |= "retried" [10s])`,
	`count_over_time({app="api"} | logfmt | label_format r2=route, k=level [10s])`,
	`sum by (k) (count_over_time({app="api"} | logfmt | label_format k=level [10s]))`,
	`count_over_time({app="api"} | regexp "n=(?P<num>\\d+)" | num != "3" [10s])`,
	`count_over_time({app="api"} | drop host [10s])`,
	`count_over_time({app="api"} | keep app, route [10s])`,
	`count_over_time({app="api"} | decolorize [10s])`,
	`sum_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`avg_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`min_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`max_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`stddev_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`stdvar_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`quantile_over_time(0.9, {app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`first_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`last_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`rate({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`rate_counter({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
	`sum_over_time({app="api"} | logfmt | unwrap n [10s])`,
	`sum_over_time({app="api"} | logfmt | __error__="" | unwrap n [10s])`,
	`avg_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s]) by (route)`,
	`avg_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s]) without (host)`,
	`count_over_time({app="api"} [10s] offset 5s)`,
	`rate({app="api"} [10s] offset 20s)`,
	`sum by (route) (count_over_time({app=~".+"} [10s]))`,
	`sum without (host) (count_over_time({app=~".+"} [10s]))`,
	`avg(count_over_time({app=~".+"} [10s]))`,
	`min(count_over_time({app=~".+"} [10s]))`,
	`max by (app) (count_over_time({app=~".+"} [10s]))`,
	`count(count_over_time({app=~".+"} [10s]))`,
	`stddev(count_over_time({app=~".+"} [10s]))`,
	`stdvar(count_over_time({app=~".+"} [10s]))`,
	`topk(2, count_over_time({app=~".+"} [10s]))`,
	`bottomk(1, count_over_time({app=~".+"} [10s]))`,
	`sort(count_over_time({app=~".+"} [10s]))`,
	`sort_desc(sum by (route) (count_over_time({app=~".+"} [10s])))`,
	`label_replace(count_over_time({app=~".+"} [10s]), "dst", "$1", "route", "r(.)")`,
	`count_over_time({app="api"} [10s]) + count_over_time({app="api"} [5s])`,
	`count_over_time({app="api"} [10s]) / ignoring(host) count_over_time({app="api"} [10s] offset 5s)`,
	`sum by (route) (rate({app="api"} [10s])) / on(route) group_left sum by (route) (rate({app=~".+"} [10s]))`,
	`count_over_time({app="api"} [10s]) > bool 2`,
	`count_over_time({app="api"} [10s]) > 2`,
	`count_over_time({app="api"} [10s]) and count_over_time({app="api"} |= "retried" [10s])`,
	`count_over_time({app="api"} [10s]) or count_over_time({app="web"} [10s])`,
	`count_over_time({app="api"} [10s]) unless count_over_time({app="web"} [10s])`,
	`sum(count_over_time({app="api"} [10s])) + vector(1)`,
	`vector(3)`,
	`sum(rate({app="api"} [10s])) * 60`,
	`count_over_time({app="api"} [10s]) + count_over_time({app="api"} [10s] offset 10s)`,
	`quantile_over_time(0.5, {app="api"} | logfmt | unwrap n | __error__="" [10s]) / on() sum(count_over_time({app="api"} [10s]))`,
}

var unionGrids = []value.Evaluation{
	{Start: model.UnixNano(20 * second), End: model.UnixNano(60 * second), Step: 5 * second},
	{Start: model.UnixNano(20 * second), End: model.UnixNano(60 * second), Step: 10 * second},
	{Start: model.UnixNano(20 * second), End: model.UnixNano(60 * second), Step: 20 * second},
	{Start: model.UnixNano(22 * second), End: model.UnixNano(61 * second), Step: 7 * second},
	{Start: model.UnixNano(15 * second), End: model.UnixNano(60 * second), Step: 1 * second},
	{Start: model.UnixNano(40 * second), End: model.UnixNano(40 * second), Step: 1 * second},
	{Instant: true, Time: model.UnixNano(40 * second)},
}

// TestUnionScanMatchesPerStepEvaluation runs a broad query corpus through the
// per-step path and the union path over randomized data and demands the same
// results, diagnostics, errors and account balance.
func TestUnionScanMatchesPerStepEvaluation(t *testing.T) {
	datasets := map[string][]scan.LogRow{"sorted": randomLogs(1, false), "shuffled": randomLogs(2, true)}
	total, nonEmpty := 0, 0
	failures := map[string]int{}
	for name, rows := range datasets {
		for _, q := range unionCorpus {
			for gi, ev := range unionGrids {
				plan := corpusPlan(t, q, ev)
				for _, partial := range []bool{false, true} {
					want := runOutcome(t, plan, &metricSource{rows: rows, partial: partial}, 64<<20, evalOptions{perStep: true})
					got := runOutcome(t, plan, &metricSource{rows: rows, partial: partial}, 64<<20, evalOptions{})
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%s grid=%d partial=%v %s:\n got=%+v\nwant=%+v", name, gi, partial, q, got, want)
					}
					total++
					if want.err != "" {
						failures[want.err]++
					} else if len(want.result.Vector)+len(want.result.Matrix) > 0 {
						nonEmpty++
					}
				}
			}
		}
	}
	// A corpus that mostly fails or mostly returns nothing compares nothing.
	t.Logf("%d evaluations, %d with samples, failures %v", total, nonEmpty, failures)
	if nonEmpty*2 < total {
		t.Fatalf("only %d of %d evaluations returned samples", nonEmpty, total)
	}
}

// TestUnionScanKeepsErrorPrecedence places failing rows so that the step which
// first meets them decides the error, and a source that fails after its rows.
func TestUnionScanKeepsErrorPrecedence(t *testing.T) {
	base := randomLogs(3, false)
	bad := func(rows []scan.LogRow, at int64, mutate func(*scan.LogRow)) []scan.LogRow {
		r := metricRow(1, at, "n=1")
		r.ID = model.ID{0xee, byte(at / second), 1}
		r.Record.StreamLabels = model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: "a"}, {Name: "route", Value: "r0"}}
		mutate(&r)
		return append(append([]scan.LogRow(nil), rows...), r)
	}
	zeroMultiplicity := func(r *scan.LogRow) { r.Multiplicity = 0 }
	unparsable := func(r *scan.LogRow) { r.Record.Line = "n=bad" }
	sources := map[string]*metricSource{
		"invalid-late":           {rows: bad(base, 58*second, zeroMultiplicity)},
		"invalid-early":          {rows: bad(base, 21*second, zeroMultiplicity)},
		"invalid-then-error-row": {rows: bad(bad(base, 30*second, zeroMultiplicity), 50*second, unparsable)},
		"error-row-then-invalid": {rows: bad(bad(base, 30*second, unparsable), 50*second, zeroMultiplicity)},
		"source-failure":         {rows: base, failure: model.Fail(model.Unavailable)},
		"source-failure-error":   {rows: bad(base, 30*second, unparsable), failure: model.Fail(model.Unavailable)},
	}
	queries := []string{
		`count_over_time({app="api"} [10s])`,
		`sum_over_time({app="api"} | logfmt | unwrap n [10s])`,
		`absent_over_time({app="api"} [10s])`,
		`sum(count_over_time({app="api"} [10s])) + sum(sum_over_time({app="api"} | logfmt | unwrap n [10s]))`,
	}
	for name, src := range sources {
		for _, q := range queries {
			for gi, ev := range unionGrids {
				plan := corpusPlan(t, q, ev)
				want := runOutcome(t, plan, src, 64<<20, evalOptions{perStep: true})
				got := runOutcome(t, plan, src, 64<<20, evalOptions{})
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s grid=%d %s:\n got=%+v\nwant=%+v", name, gi, q, got, want)
				}
			}
		}
	}
}

// TestUnionScanHonoursTheMemoryAccount sweeps the account limit: whatever the
// limit, the union path must succeed or fail exactly like the per-step path,
// falling back to it when the retained union does not fit.
func TestUnionScanHonoursTheMemoryAccount(t *testing.T) {
	rows := randomLogs(4, false)
	queries := []string{
		`sum by (route) (count_over_time({app=~".+"} [10s]))`,
		`sum_over_time({app="api"} | logfmt | unwrap n | __error__="" [10s])`,
		`quantile_over_time(0.5, {app="api"} | logfmt | unwrap n | __error__="" [10s])`,
		`count_over_time({app="api"} [10s]) + count_over_time({app="web"} [10s])`,
	}
	ev := value.Evaluation{Start: model.UnixNano(20 * second), End: model.UnixNano(60 * second), Step: 5 * second}
	for _, q := range queries {
		plan := corpusPlan(t, q, ev)
		unioned, fellBack := 0, 0
		for limit := int64(256); limit <= 8<<20; limit = limit + limit/3 + 1 {
			base, scanning := &countingSource{metricSource: &metricSource{rows: rows}}, &countingSource{metricSource: &metricSource{rows: rows}}
			want := runOutcome(t, plan, base, limit, evalOptions{perStep: true})
			got := runOutcome(t, plan, scanning, limit, evalOptions{})
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("limit=%d %s:\n got=%+v\nwant=%+v", limit, q, got, want)
			}
			if want.err != "" {
				continue
			}
			// A successful run that read fewer times than per step used the
			// union; one that read more started a union and gave it up.
			switch {
			case scanning.selects < base.selects:
				unioned++
			case scanning.selects > base.selects:
				fellBack++
			}
		}
		if unioned == 0 || fellBack == 0 {
			t.Fatalf("%s: sweep saw %d union runs and %d fallbacks; it must see both", q, unioned, fellBack)
		}
	}
}
