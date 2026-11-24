// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// scanSource is an in-memory metric source that behaves like the production scan:
// it delivers only the series that match the request and only the samples inside
// the half-open [Start, End) window, sorted by label set, and it counts what it
// delivered. failWindow, when set, makes every Select whose window contains the
// timestamp fail, which is how a corrupt region of the stored data looks to a
// query: the first evaluation step that reaches it fails, however the reads are
// planned.
type scanSource struct {
	series     []value.Series
	unfiltered bool // deliver whole series, as sources that ignore the window do
	partial    bool
	cursors    []model.Cursor
	failAt     int64
	failErr    error

	calls int
	rows  int64
	bytes int64
}

func (s *scanSource) ProjectID() model.ID { return model.ID{1} }

func (s *scanSource) Select(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
	s.calls++
	if s.failErr != nil && int64(r.Start) <= s.failAt && s.failAt < int64(r.End) {
		return nil, s.failErr
	}
	matchers, err := scan.CompileMatchers(ctx, r)
	if err != nil {
		return nil, err
	}
	var out []value.Series
	for _, series := range s.series {
		ok, err := matchers.Match(ctx, series.Labels)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		samples := series.Samples
		if !s.unfiltered {
			lo := sort.Search(len(samples), func(i int) bool { return samples[i].Time >= r.Start })
			hi := sort.Search(len(samples), func(i int) bool { return samples[i].Time >= r.End })
			samples = samples[lo:hi]
			if len(samples) == 0 {
				continue
			}
		}
		series.Samples = samples
		series.Project = model.ID{1}
		out = append(out, series)
		s.rows += int64(len(samples))
		for _, p := range samples {
			s.bytes += value.SampleBytes(p)
		}
	}
	return &scanIter{series: out, partial: s.partial, cursors: s.cursors}, nil
}

type scanIter struct {
	series  []value.Series
	i       int
	partial bool
	cursors []model.Cursor
}

func (i *scanIter) Next(ctx context.Context) (value.Series, error) {
	if e := ctx.Err(); e != nil {
		return value.Series{}, e
	}
	if i.i == len(i.series) {
		return value.Series{}, io.EOF
	}
	i.i++
	return i.series[i.i-1], nil
}
func (i *scanIter) Close() error               { return nil }
func (i *scanIter) Watermarks() []model.Cursor { return i.cursors }
func (i *scanIter) Partial() bool              { return i.partial }

// denseFixture is the shape of the gate scenario in miniature: parallel series
// scraped every second.
func denseFixture(series, seconds int) []value.Series {
	out := make([]value.Series, 0, series)
	for k := range series {
		samples := make([]value.Sample, 0, seconds)
		for t := range seconds {
			samples = append(samples, msSample(int64(t)*1000, float64(t*(k+1))))
		}
		out = append(out, metricSeries("app_m0", model.Labels{{Name: "i", Value: fmt.Sprintf("%03d", k)}}, samples...))
	}
	return out
}

func planFor(t testing.TB, p profile.Profile, query string, ev value.Evaluation) Plan {
	t.Helper()
	e, err := Parse(query, p)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return plan
}

// A range evaluation reads each selector once, not once per grid step: the
// number of Select calls and delivered rows is a function of the selectors and
// the time span, never of the step count.
func TestRangeEvaluationReadsEachSelectorOnce(t *testing.T) {
	const seconds = 7200
	fixture := denseFixture(12, seconds)
	// 1 h range ending at 2 h, step 30 s: 121 steps.
	ev := rangeOf(3_600_000, 7_200_000-1000, 30_000)
	steps := int64(len(mustGrid(t, ev)))
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, c := range []struct {
			query     string
			selectors int
			window    int64 // seconds a selector reads beyond the range start
		}{
			{"sum(rate(app_m0[10m]))", 1, 600},
			{"app_m0", 1, 300},
			{"sum(app_m0) / sum(app_m0 offset 5m)", 2, 300 + 300},
			{"topk(3, rate(app_m0[5m]))", 1, 300},
			{"max_over_time(app_m0[2m])", 1, 120},
			{"sum by (i) (increase(app_m0[10m] offset 10m))", 1, 600},
			{"avg_over_time(rate(app_m0[1m])[10m:30s])", 1, 660},
			{"max_over_time(avg_over_time(rate(app_m0[1m])[5m:30s])[10m:1m])", 1, 960},
		} {
			plan := planFor(t, p, c.query, ev)
			old, shared := &scanSource{series: fixture}, &scanSource{series: fixture}
			want, wantNotes, err := evaluate(context.Background(), plan, old, value.NewBoundedAccount(1<<28), false)
			if err != nil {
				t.Fatalf("%s %s: per-step path: %v", id, c.query, err)
			}
			got, gotNotes, err := evaluate(context.Background(), plan, shared, value.NewBoundedAccount(1<<28), true)
			if err != nil {
				t.Fatalf("%s %s: shared path: %v", id, c.query, err)
			}
			if !reflect.DeepEqual(want, got) || !reflect.DeepEqual(wantNotes, gotNotes) {
				t.Fatalf("%s %s: shared scans changed the result", id, c.query)
			}
			t.Logf("%s %-52s steps=%d per-step: selects=%d rows=%d bytes=%d | shared: selects=%d rows=%d bytes=%d",
				id, c.query, steps, old.calls, old.rows, old.bytes, shared.calls, shared.rows, shared.bytes)
			if int64(old.calls) < steps {
				t.Fatalf("%s %s: the per-step reference made %d selects for %d steps", id, c.query, old.calls, steps)
			}
			if shared.calls != c.selectors {
				t.Fatalf("%s %s: %d selects, want %d (one per selector, %d steps)", id, c.query, shared.calls, c.selectors, steps)
			}
			// Rows: at most the selector's span (range + its widest read) per series, per selector.
			limit := int64(c.selectors) * int64(len(fixture)) * (3600 + c.window + 2)
			if shared.rows > limit {
				t.Fatalf("%s %s: %d rows delivered, more than the %d the time span of its selectors holds", id, c.query, shared.rows, limit)
			}
			if shared.rows*3 > old.rows {
				t.Fatalf("%s %s: rows %d did not drop against %d of the per-step path", id, c.query, shared.rows, old.rows)
			}
		}
	}
}

func mustGrid(t testing.TB, ev value.Evaluation) []model.UnixNano {
	t.Helper()
	g, err := EvaluationGrid(ev)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// rangeFixture is randomized data with every shape the evaluation has to cope
// with: irregular scrape times, gaps, staleness markers, NaN, counter resets,
// series that start late or end early, timestamps exactly on step and window
// boundaries, classic histogram buckets and native histograms.
func rangeFixture(seed int64) []value.Series {
	rng := rand.New(rand.NewPCG(uint64(seed), 0x9e3779b97f4a7c15))
	var out []value.Series
	scrape := func(name string, labels model.Labels, intervalMS, jitterMS, startMS, endMS int64, next func(i int) (value.Sample, bool)) {
		var samples []value.Sample
		at := startMS + rng.Int64N(intervalMS)
		for i := 0; at < endMS; i++ {
			if s, ok := next(i); ok {
				s.Time = model.UnixNano(at * 1_000_000)
				samples = append(samples, s)
			}
			at += intervalMS
			if jitterMS > 0 {
				at += rng.Int64N(2*jitterMS+1) - jitterMS
			}
			if rng.IntN(40) == 0 {
				at += intervalMS * int64(1+rng.IntN(8)) // gap
			}
		}
		if len(samples) > 0 {
			out = append(out, metricSeries(name, labels, samples...))
		}
	}
	gauge := func() func(int) (value.Sample, bool) {
		v := float64(rng.IntN(100))
		return func(int) (value.Sample, bool) {
			switch rng.IntN(60) {
			case 0:
				return value.Sample{Float: value.StaleBits}, true
			case 1:
				return value.Sample{Float: model.FloatBits(math.Float64bits(math.NaN()))}, true
			case 2:
				return value.Sample{}, false
			}
			v += float64(rng.IntN(11) - 5)
			return value.Sample{Float: relBits(v)}, true
		}
	}
	counter := func() func(int) (value.Sample, bool) {
		v := float64(rng.IntN(10))
		return func(int) (value.Sample, bool) {
			if rng.IntN(70) == 0 {
				v = float64(rng.IntN(3)) // reset
			} else {
				v += float64(rng.IntN(20))
			}
			if rng.IntN(80) == 0 {
				return value.Sample{Float: value.StaleBits}, true
			}
			return value.Sample{Float: relBits(v)}, true
		}
	}
	const hour = 3_600_000
	for _, job := range []string{"a", "b", "c"} {
		for _, instance := range []string{"i1", "i2"} {
			start, end := int64(0), int64(hour)
			if job == "c" && instance == "i2" {
				start, end = 900_000, 2_400_000 // appears late, disappears early
			}
			scrape("m", model.Labels{{Name: "instance", Value: instance}, {Name: "job", Value: job}}, 10_000, 1_000, start, end, gauge())
		}
	}
	for _, job := range []string{"a", "b"} {
		// Exactly aligned to 30 s: samples sit on step and window boundaries.
		scrape("g", model.Labels{{Name: "instance", Value: "i1"}, {Name: "job", Value: job}}, 30_000, 0, 0, hour, func(i int) (value.Sample, bool) {
			return value.Sample{Float: relBits(float64((i*7 + len(job)) % 5))}, true
		})
	}
	for _, job := range []string{"a", "b", "c"} {
		scrape("c_total", model.Labels{{Name: "job", Value: job}}, 15_000, 500, 0, hour, counter())
	}
	for _, job := range []string{"a", "b"} {
		bounds := []string{"0.1", "1", "10", "+Inf"}
		counts := make([]float64, len(bounds))
		series := make([][]value.Sample, len(bounds))
		at := int64(0)
		for at < hour {
			for k := range counts {
				counts[k] += float64(rng.IntN(4))
			}
			// buckets are cumulative in le
			run := 0.0
			for k := range counts {
				run += counts[k]
				series[k] = append(series[k], msSample(at, run))
			}
			at += 15_000
		}
		for k, le := range bounds {
			out = append(out, metricSeries("bkt", model.Labels{{Name: "job", Value: job}, {Name: "le", Value: le}}, series[k]...))
		}
	}
	for _, job := range []string{"a", "b"} {
		var samples []value.Sample
		counts := []uint64{1, 1, 1}
		for at := int64(0); at < hour; at += 30_000 {
			for k := range counts {
				counts[k] += uint64(rng.IntN(5))
			}
			sum := float64(counts[0] + 2*counts[1] + 4*counts[2])
			samples = append(samples, relHistSample(at/1000, relExp(sum, 0, counts[0], counts[1], counts[2])))
		}
		out = append(out, metricSeries("h", model.Labels{{Name: "job", Value: job}}, samples...))
	}
	out = append(out, metricSeries("target_info", model.Labels{{Name: "job", Value: "a"}, {Name: "version", Value: "1.2"}}, msSample(0, 1), msSample(1_800_000, 1), msSample(3_500_000, 1)))
	sort.SliceStable(out, func(i, j int) bool { return value.CompareLabels(out[i].Labels, out[j].Labels) < 0 })
	return out
}

var rangeCorpus = []string{
	// selectors, offset, @, lookback, staleness
	`m`, `m offset 2m`, `m offset -1m`, `m @ 1200`, `m @ start()`, `m @ end()`, `m @ 900 offset 1m`, `m offset 5m @ 1500`,
	`m{job=~"a|b"}`, `m{job!~"a.*"}`, `{__name__=~"m|g"}`, `m{job="a", instance!="i1"}`, `{job="c"}`, `nosuch`,
	`g`, `g offset 30s`, `c_total`, `h`,
	// range functions over a matrix selector
	`rate(c_total[5m])`, `increase(c_total[5m])`, `irate(c_total[2m])`, `rate(c_total[10s])`, `rate(c_total[1h])`, `rate(c_total[5m] offset 3m)`, `rate(c_total[5m] @ 1500)`,
	`delta(m[5m])`, `idelta(m[2m])`, `deriv(m[5m])`, `predict_linear(m[5m], 60)`, `resets(c_total[10m])`, `changes(m[5m])`,
	`avg_over_time(m[5m])`, `min_over_time(m[5m])`, `max_over_time(m[5m])`, `sum_over_time(m[5m])`, `count_over_time(m[5m])`,
	`stddev_over_time(m[5m])`, `stdvar_over_time(m[5m])`, `quantile_over_time(0.9, m[5m])`, `last_over_time(m[5m])`, `present_over_time(m[5m])`,
	`absent_over_time(nosuch[5m])`, `absent_over_time(m[5m])`, `absent(nosuch)`, `absent(m)`, `absent(m{job="zz"})`,
	`mad_over_time(m[5m])`, `ts_of_last_over_time(m[5m])`, `ts_of_min_over_time(m[5m])`, `ts_of_max_over_time(m[5m])`, `first_over_time(m[5m])`,
	`avg_over_time(m[2m] offset 4m)`, `avg_over_time(m[1h])`, `max_over_time(g[30s])`, `count_over_time(g[1m])`,
	// aggregation
	`sum(rate(c_total[5m]))`, `sum by (job) (rate(c_total[5m]))`, `avg without (instance) (m)`, `count(m)`, `min(m)`, `max(m)`, `group(m)`,
	`stddev(m)`, `stdvar(m)`, `quantile(0.5, m)`, `topk(2, m)`, `bottomk(2, g)`, `topk(1, rate(c_total[5m]))`, `topk(scalar(min(g)) + 1, m)`,
	`count_values("v", g)`, `count_values by (job) ("v", g)`, `limitk(2, m)`, `limit_ratio(0.5, m)`,
	// operators
	`m + g`, `m * on(job) group_left g`, `m > bool g`, `m and g`, `m or g`, `m unless g`, `m / ignoring(instance) group_right g`,
	`m - m offset 5m`, `sum(m) / sum(m offset 5m)`, `rate(c_total[5m]) / rate(c_total[5m] offset 5m)`, `m > 50`, `m == on(job) group_left g`,
	`-m`, `m + on(job) group_left() sum by (job) (m)`, `m fill(0) + g`, `m + fill_left(0) g`,
	// instant functions
	`abs(m)`, `ceil(m)`, `floor(m)`, `round(m, 5)`, `clamp(m, 20, 60)`, `clamp_min(m, 20)`, `clamp_max(m, 60)`, `sqrt(abs(m))`, `exp(g)`, `ln(abs(m))`, `log2(abs(m))`, `log10(abs(m))`, `sgn(m)`,
	`timestamp(m)`, `timestamp(m offset 1m)`, `timestamp(g @ 900)`, `time()`, `vector(1)`, `scalar(sum(m))`, `scalar(g)`, `pi()`,
	`label_replace(m, "x", "$1", "job", "(.*)")`, `label_join(m, "x", "-", "job", "instance")`, `sort(m)`, `sort_desc(g)`, `sort_by_label(m, "job")`,
	`minute(timestamp(m))`, `hour(vector(time()))`, `day_of_week()`, `info(m)`, `info(m, {version=~".+"})`,
	// histograms
	`histogram_quantile(0.9, sum by (le) (rate(bkt[5m])))`, `histogram_quantile(0.5, bkt)`, `histogram_quantile(0.5, rate(h[5m]))`,
	`histogram_count(h)`, `histogram_sum(rate(h[5m]))`, `histogram_avg(h)`, `histogram_fraction(0, 1, h)`, `histogram_fraction(0, 1, rate(h[5m]))`, `rate(h[5m])`, `increase(h[5m])`, `sum(h)`,
	`histogram_quantile(0.9, sum by (le, job) (increase(bkt[5m] offset 1m)))`,
	// subqueries
	`max_over_time(m[10m:1m])`, `avg_over_time(rate(c_total[2m])[10m:30s])`, `sum_over_time(m[5m:1m] offset 1m)`, `max_over_time(m[10m:] @ 1200)`,
	`max_over_time(avg_over_time(rate(c_total[1m])[5m:30s])[10m:1m])`, `sum_over_time(m[1m:7s])`, `max_over_time(m[2m:30s] offset 1m)`, `min_over_time(m[20m:3m] @ end())`, `avg_over_time(m[40s:10s])`,
	`max_over_time(sum(rate(c_total[1m]))[5m:1m]) + sum(m)`, `max_over_time(m[5m:1m] offset -2m)`,
	`deriv(rate(c_total[2m])[10m:1m])`, `min_over_time((m + g)[5m:1m])`, `max_over_time(m[10m:7s])`, `last_over_time(m[1m:15s] @ end())`,
	`rate(c_total[5m])[10m:1m]`, `max_over_time(sum by (job) (m)[10m:1m])`, `avg_over_time(max_over_time(m[2m])[10m:1m])`,
	// extended range selectors
	`rate(c_total[5m] smoothed)`, `rate(c_total[5m] anchored)`, `increase(c_total[5m] anchored)`, `m smoothed`, `m anchored`, `sum_over_time(m[5m] anchored)`,
	`delta(m[5m] smoothed)`, `count_over_time(m[2m] anchored) + 1`,
}

type rangeProfile struct {
	name string
	p    profile.Profile
}

func rangeProfiles(t testing.TB) []rangeProfile {
	all313 := []string{"promql-binop-fill-modifiers", "promql-delayed-name-removal", "promql-duration-expr", "promql-experimental-functions", "promql-extended-range-selectors", "type-and-unit-labels", "use-start-timestamps"}
	return []rangeProfile{
		{"3.1.0", featureProfile(t, relP31)},
		{"3.1.0+delayed+experimental", featureProfile(t, relP31, "promql-delayed-name-removal", "promql-experimental-functions")},
		{"3.13.5", featureProfile(t, relP313)},
		{"3.13.5+all", featureProfile(t, relP313, all313...)},
	}
}

var rangeShapes = []struct {
	name string
	ev   value.Evaluation
}{
	{"aligned-30s", rangeOf(600_000, 1_800_000, 30_000)},
	{"unaligned-7s", rangeOf(301_000, 1_201_000, 7_000)},
	{"sparse-10m", rangeOf(0, 3_600_000, 600_000)},
	{"one-step", rangeOf(900_000, 900_000, 30_000)},
	{"dense-1s-late", rangeOf(3_540_000, 3_600_000, 1_000)},
}

type runOutcome struct {
	result value.Result
	notes  []syntax.Diagnostic
	err    error
	used   int64
	stats  QueryStatistics
}

func runPlan(plan Plan, src scan.MetricSource, limit int64, shared bool) runOutcome {
	var o runOutcome
	plan.Stats = &o.stats
	plan.perStepStats = true
	account := value.NewBoundedAccount(limit)
	o.result, o.notes, o.err = evaluate(context.Background(), plan, src, account, shared)
	o.used = account.Used()
	return o
}

func sameOutcome(t *testing.T, label string, want, got runOutcome) {
	t.Helper()
	if (want.err == nil) != (got.err == nil) || want.err != nil && want.err.Error() != got.err.Error() {
		t.Fatalf("%s: error differs: per-step %v, shared %v", label, want.err, got.err)
	}
	var wf, gf *model.Fault
	if errors.As(want.err, &wf) != errors.As(got.err, &gf) || wf != nil && wf.Code != gf.Code {
		t.Fatalf("%s: error class differs: %v vs %v", label, want.err, got.err)
	}
	if !reflect.DeepEqual(want.result, got.result) {
		t.Fatalf("%s: result differs\nper-step: %+v\nshared:   %+v", label, want.result, got.result)
	}
	if !reflect.DeepEqual(want.notes, got.notes) {
		t.Fatalf("%s: diagnostics differ\nper-step: %+v\nshared:   %+v", label, want.notes, got.notes)
	}
	if !reflect.DeepEqual(want.stats, got.stats) {
		t.Fatalf("%s: statistics differ\nper-step: %+v\nshared:   %+v", label, want.stats, got.stats)
	}
	if want.used != 0 || got.used != 0 {
		t.Fatalf("%s: leaked reservations: per-step %d, shared %d", label, want.used, got.used)
	}
}

// The shared-scan evaluation must be indistinguishable from the per-step one:
// results, annotations, errors, statistics, over every language family, on
// randomized data, for windows shorter than, equal to and longer than the step.
func TestRangeSharedScansMatchPerStepEvaluation(t *testing.T) {
	profiles := rangeProfiles(t)
	evaluated, sharedFewer, skipped := 0, 0, map[string]int{}
	for _, seed := range []int64{1, 2} {
		fixture := rangeFixture(seed)
		for _, rp := range profiles {
			for _, query := range rangeCorpus {
				for _, shape := range rangeShapes {
					e, err := Parse(query, rp.p)
					if err != nil {
						skipped[rp.name]++
						break
					}
					typed, _, err := Check(e, rp.p)
					if err != nil {
						skipped[rp.name]++
						break
					}
					plan, err := BuildPlan(typed, shape.ev, rp.p)
					if err != nil {
						skipped[rp.name]++
						continue
					}
					for _, unfiltered := range []bool{false, true} {
						if unfiltered && seed != 1 {
							continue
						}
						perStep := &scanSource{series: fixture, unfiltered: unfiltered, partial: seed == 2, cursors: []model.Cursor{{Group: model.ID{2}, Index: 9}}}
						shared := &scanSource{series: fixture, unfiltered: unfiltered, partial: seed == 2, cursors: []model.Cursor{{Group: model.ID{2}, Index: 9}}}
						ref := runPlan(plan, perStep, 1<<28, false)
						got := runPlan(plan, shared, 1<<28, true)
						sameOutcome(t, fmt.Sprintf("seed %d %s %s %s unfiltered=%v", seed, rp.name, shape.name, query, unfiltered), ref, got)
						evaluated++
						if shared.calls < perStep.calls {
							sharedFewer++
						}
					}
				}
			}
		}
	}
	t.Logf("evaluated %d (query, profile, grid, source) combinations, %d of them with fewer selects than per step; skipped (unsupported by profile): %v", evaluated, sharedFewer, skipped)
	if evaluated < 2000 || sharedFewer < evaluated/3 {
		t.Fatalf("%d combinations evaluated, %d shared fewer selects: the corpus no longer exercises the shared path", evaluated, sharedFewer)
	}
}

// Failures raised by storage or by invalid stored data surface at the same step
// with the same error and the same annotations as before, wherever the bad data
// sits in the range.
func TestRangeSharedScansReproduceStorageFailures(t *testing.T) {
	fixture := rangeFixture(7)
	p := featureProfile(t, relP313)
	for _, query := range []string{`m`, `sum(rate(c_total[5m])) + sum(m)`, `quantile(2, m) + on(job) group_left sum by (job) (m)`, `max_over_time(m[10m:1m])`, `rate(c_total[5m] anchored)`} {
		pp := p
		if strings.Contains(query, "anchored") {
			pp = featureProfile(t, relP313, "promql-extended-range-selectors")
		}
		for _, at := range []int64{300_000, 905_000, 1_234_000, 1_800_000} {
			plan := planFor(t, pp, query, rangeOf(600_000, 1_800_000, 30_000))
			mk := func() *scanSource {
				return &scanSource{series: fixture, failAt: at * 1_000_000, failErr: model.Fail(model.Unavailable)}
			}
			sameOutcome(t, fmt.Sprintf("%s fail at %d", query, at), runPlan(plan, mk(), 1<<28, false), runPlan(plan, mk(), 1<<28, true))
		}
	}
	// Invalid stored data: samples out of order, or a series of another project.
	for _, bad := range []string{"unordered", "foreign"} {
		for _, query := range []string{`m`, `rate(c_total[5m])`, `sum(m) + sum(g)`} {
			plan := planFor(t, p, query, rangeOf(600_000, 1_800_000, 30_000))
			data := append([]value.Series(nil), fixture...)
			corrupted := map[string]bool{}
			for i := range data {
				name := value.Label(data[i].Labels, "__name__")
				if corrupted[name] || name != "c_total" && name != "m" && name != "g" {
					continue
				}
				corrupted[name] = true
				samples := append([]value.Sample(nil), data[i].Samples...)
				if n := len(samples) * 2 / 3; bad == "unordered" && n > 1 {
					samples[n], samples[n-1] = samples[n-1], samples[n]
				}
				data[i].Samples = samples
				if bad == "foreign" {
					data[i].Project = model.ID{9}
				}
			}
			src := func() scan.MetricSource {
				if bad == "foreign" {
					return foreignProjectSource{&scanSource{series: data}, data}
				}
				return &scanSource{series: data, unfiltered: true}
			}
			sameOutcome(t, query+" "+bad, runPlan(plan, src(), 1<<28, false), runPlan(plan, src(), 1<<28, true))
		}
	}
}

// foreignProjectSource keeps the project of the series it was given instead of stamping its own.
type foreignProjectSource struct {
	*scanSource
	data []value.Series
}

func (s foreignProjectSource) Select(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
	s.scanSource.calls++
	return &scanIter{series: s.data}, nil
}

// Budgets: the sample budget is charged for the retained samples only, so it is
// exceeded for exactly the same queries; a query that fits the memory account
// per step still fits it, whatever the account's size, and returns the same result.
func TestRangeSharedScansKeepBudgets(t *testing.T) {
	fixture := rangeFixture(11)
	fellBack := 0
	defer func() {
		if fellBack == 0 {
			t.Error("no memory limit made the shared reads fall back: the sweep does not exercise the give-back path")
		}
	}()
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, query := range []string{`m`, `sum(rate(c_total[5m]))`, `m + g`, `max_over_time(m[10m:1m])`, `topk(2, rate(c_total[5m]))`, `histogram_quantile(0.9, sum by (le) (rate(bkt[5m])))`, `timestamp(m)`} {
			plan := planFor(t, p, query, rangeOf(600_000, 1_800_000, 30_000))
			for _, max := range []int64{1, 50, 400, 3000, 20_000, 200_000} {
				budgeted := plan
				budgeted.budgeted, budgeted.MaxSamples = true, max
				sameOutcome(t, fmt.Sprintf("%s %s max-samples %d", id, query, max),
					runPlan(budgeted, &scanSource{series: fixture}, 1<<28, false), runPlan(budgeted, &scanSource{series: fixture}, 1<<28, true))
			}
			unlimited := runPlan(plan, &scanSource{series: fixture}, 1<<28, false)
			if unlimited.err != nil {
				t.Fatalf("%s %s: %v", id, query, unlimited.err)
			}
			full := &scanSource{series: fixture}
			runPlan(plan, full, 1<<28, true)
			for limit := int64(1 << 8); limit <= 1<<24; limit += limit/8 + 1 {
				perStep, shared := &scanSource{series: fixture}, &scanSource{series: fixture}
				ref := runPlan(plan, perStep, limit, false)
				got := runPlan(plan, shared, limit, true)
				if ref.err == nil {
					// Fitting before means fitting now, with the same answer.
					sameOutcome(t, fmt.Sprintf("%s %s memory %d", id, query, limit), ref, got)
					if shared.calls > full.calls {
						fellBack++ // the shared reads did not fit next to the rest and were given back
					}
					continue
				}
				if got.used != 0 || ref.used != 0 {
					t.Fatalf("%s %s memory %d: leaked reservations: %d / %d", id, query, limit, ref.used, got.used)
				}
				if got.err != nil {
					var fault *model.Fault
					if !errors.As(got.err, &fault) || fault.Code != model.Quota {
						t.Fatalf("%s %s memory %d: shared path failed with %v, per-step with %v", id, query, limit, got.err, ref.err)
					}
				} else if !reflect.DeepEqual(unlimited.result, got.result) {
					t.Fatalf("%s %s memory %d: shared path succeeded with a different result", id, query, limit)
				}
			}
		}
	}
}
