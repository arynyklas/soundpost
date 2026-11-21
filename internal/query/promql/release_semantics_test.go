// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The reference engine reports cancellation, deadline expiry, sample-budget
// exhaustion and storage failure as distinct error classes and never as an empty
// successful result. The pinned oracle wrapper cannot be reconfigured for these
// (fixed context, fixed budget, in-memory storage), so the failure classes are
// observed here against the owned engine, with expectations derived from the
// rule text only.

type releaseFuncSource struct {
	selectFn func(context.Context, scan.MetricSelection) (scan.SeriesIterator, error)
}

func (releaseFuncSource) ProjectID() model.ID { return model.ID{1} }
func (s releaseFuncSource) Select(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
	return s.selectFn(ctx, r)
}

// releaseFailingIter yields its series, then fails with failure instead of io.EOF.
type releaseFailingIter struct {
	series  []value.Series
	i       int
	failure error
}

func (f *releaseFailingIter) Next(ctx context.Context) (value.Series, error) {
	if f.i == len(f.series) {
		return value.Series{}, f.failure
	}
	s := f.series[f.i]
	f.i++
	if s.Project == (model.ID{}) {
		s.Project = model.ID{1}
	}
	return s, nil
}
func (*releaseFailingIter) Watermarks() []model.Cursor { return nil }
func (*releaseFailingIter) Partial() bool              { return false }
func (*releaseFailingIter) Close() error               { return nil }

func releaseSemanticsFixture() []value.Series {
	return []value.Series{
		metricSeries("m", model.Labels{{Name: "job", Value: "api"}}, msSample(5_000, 1), msSample(10_000, 2), msSample(15_000, 3), msSample(20_000, 4)),
		metricSeries("m", model.Labels{{Name: "job", Value: "web"}}, msSample(5_000, 10), msSample(10_000, 20), msSample(15_000, 30), msSample(20_000, 40)),
	}
}

func releaseSemanticsPlan(t *testing.T, id, query string, ev value.Evaluation) Plan {
	t.Helper()
	p := featureProfile(t, id)
	e, err := Parse(query, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func releaseFault(t *testing.T, err error) model.Code {
	t.Helper()
	var fault *model.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("error %v is not a typed *model.Fault", err)
	}
	return fault.Code
}

// "Explicit context cancellation produces ErrQueryCanceled; does not become
// empty success." The cancelled context is observed before evaluation starts and
// from inside a nested expression (the second operand's selection cancels).
func TestReleaseSemanticsCancelIsNeverEmptySuccess(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		plan := releaseSemanticsPlan(t, id, "sum(m)", instantAt(20_000))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, _, err := Evaluate(ctx, plan, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
		if err == nil || releaseFault(t, err) != model.Cancelled {
			t.Fatalf("%s: pre-cancelled evaluation returned err=%v result=%+v, want class %q", id, err, result, model.Cancelled)
		}
		if len(result.Vector) != 0 || len(result.Matrix) != 0 {
			t.Fatalf("%s: cancellation leaked a result: %+v", id, result)
		}

		nested := releaseSemanticsPlan(t, id, "sum(m) + sum(m)", instantAt(20_000))
		ctx, cancel = context.WithCancel(context.Background())
		calls := 0
		src := releaseFuncSource{func(c context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
			calls++
			if calls == 2 {
				cancel() // cancelled while the right-hand operand is being selected
			}
			return seriesSource(releaseSemanticsFixture()).Select(c, r)
		}}
		result, _, err = Evaluate(ctx, nested, src, value.NewBoundedAccount(1<<24))
		cancel()
		if err == nil || releaseFault(t, err) != model.Cancelled {
			t.Fatalf("%s: nested cancellation returned err=%v result=%+v, want class %q", id, err, result, model.Cancelled)
		}
		if len(result.Vector) != 0 {
			t.Fatalf("%s: nested cancellation became a partial result: %+v", id, result)
		}

		// The same query under a live context completes with a non-empty result.
		ok, _, err := Evaluate(context.Background(), nested, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
		if err != nil || len(ok.Vector) != 1 {
			t.Fatalf("%s: neighbouring live evaluation: err=%v result=%+v", id, err, ok)
		}
	}
}

// "Deadline expiration produces ErrQueryTimeout; does not become empty success."
func TestReleaseSemanticsTimeoutIsNeverEmptySuccess(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		plan := releaseSemanticsPlan(t, id, "sum(m)", instantAt(20_000))
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		result, _, err := Evaluate(ctx, plan, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
		if err == nil || releaseFault(t, err) != model.Timeout {
			t.Fatalf("%s: expired deadline returned err=%v result=%+v, want class %q", id, err, result, model.Timeout)
		}
		if len(result.Vector) != 0 {
			t.Fatalf("%s: timeout leaked a result: %+v", id, result)
		}

		// Expiry in the middle of a range evaluation, inside a nested expression: the
		// second selection blocks until the deadline passes.
		rangePlan := releaseSemanticsPlan(t, id, "sum(m) + sum(m)", rangeOf(5_000, 20_000, 5_000))
		live, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer stop()
		calls := 0
		src := releaseFuncSource{func(c context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
			calls++
			if calls == 2 {
				<-c.Done()
			}
			return seriesSource(releaseSemanticsFixture()).Select(c, r)
		}}
		result, _, err = Evaluate(live, rangePlan, src, value.NewBoundedAccount(1<<24))
		if err == nil || releaseFault(t, err) != model.Timeout || len(result.Matrix) != 0 {
			t.Fatalf("%s: range timeout returned err=%v result=%+v", id, err, result)
		}
	}
}

// "Iterator/select expansion failures remain ErrStorage/wrapped storage error,
// including associated annotations; no fabricated empty data."
func TestReleaseSemanticsStorageFailureIsNeverEmptyData(t *testing.T) {
	storageFailure := model.Fail(model.Unavailable)
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		// Failure while expanding the iterator after one series was produced.
		plan := releaseSemanticsPlan(t, id, "sum(m)", instantAt(20_000))
		midExpansion := releaseFuncSource{func(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
			return &releaseFailingIter{series: releaseSemanticsFixture()[:1], failure: storageFailure}, nil
		}}
		result, _, err := Evaluate(context.Background(), plan, midExpansion, value.NewBoundedAccount(1<<24))
		if err == nil || !errors.Is(err, storageFailure) {
			t.Fatalf("%s: iterator failure was lost: err=%v result=%+v", id, err, result)
		}
		if releaseFault(t, err) != model.Unavailable || len(result.Vector) != 0 {
			t.Fatalf("%s: storage failure changed class or fabricated data: err=%v result=%+v", id, err, result)
		}

		// Failure raised by the select itself.
		selectFails := releaseFuncSource{func(context.Context, scan.MetricSelection) (scan.SeriesIterator, error) {
			return nil, storageFailure
		}}
		result, _, err = Evaluate(context.Background(), plan, selectFails, value.NewBoundedAccount(1<<24))
		if err == nil || !errors.Is(err, storageFailure) || len(result.Vector) != 0 {
			t.Fatalf("%s: select failure: err=%v result=%+v", id, err, result)
		}

		// A warning raised by the first operand is returned together with the failure of the second.
		withNote := releaseSemanticsPlan(t, id, "quantile(2, m) + on(job) group_left sum by (job) (m)", instantAt(20_000))
		calls := 0
		src := releaseFuncSource{func(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
			calls++
			if calls == 2 {
				return nil, storageFailure
			}
			return seriesSource(releaseSemanticsFixture()).Select(ctx, r)
		}}
		result, notes, err := Evaluate(context.Background(), withNote, src, value.NewBoundedAccount(1<<24))
		if err == nil || !errors.Is(err, storageFailure) || len(result.Vector) != 0 {
			t.Fatalf("%s: nested select failure: err=%v result=%+v", id, err, result)
		}
		if len(notes) == 0 {
			t.Fatalf("%s: the quantile warning raised before the storage failure was dropped", id)
		}

		// Clean EOF stays a success: the failure above is not an artifact of the helper.
		ok, _, err := Evaluate(context.Background(), plan, releaseFuncSource{func(context.Context, scan.MetricSelection) (scan.SeriesIterator, error) {
			return &releaseFailingIter{series: releaseSemanticsFixture(), failure: io.EOF}, nil
		}}, value.NewBoundedAccount(1<<24))
		if err != nil || len(ok.Vector) != 1 {
			t.Fatalf("%s: neighbouring clean iterator: err=%v result=%+v", id, err, ok)
		}
	}
}

// "Exceeding query.max-samples returns ErrTooManySamples; no complete truncated
// vector." Whatever the budget, an evaluation either completes with exactly the
// full result or fails with the quota class and an empty result; it never returns
// a truncated successful vector, and every reservation is released.
func TestReleaseSemanticsSampleBudgetNeverTruncates(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, query := range []string{"m", "sum by (job) (m)", "m + m", "sum_over_time(m[20s])"} {
			plan := releaseSemanticsPlan(t, id, query, instantAt(20_000))
			full, _, err := Evaluate(context.Background(), plan, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
			if err != nil || len(full.Vector) != 2 {
				t.Fatalf("%s %q: unconstrained evaluation: err=%v result=%+v", id, query, err, full)
			}
			sawFailure, sawSuccess := false, false
			for limit := int64(0); limit <= 1<<14; limit = limit*2 + 1 {
				account := value.NewBoundedAccount(limit)
				result, _, err := Evaluate(context.Background(), plan, seriesSource(releaseSemanticsFixture()), account)
				if account.Used() != 0 && err != nil {
					t.Fatalf("%s %q limit %d: failed evaluation leaked %d reserved units", id, query, limit, account.Used())
				}
				if err == nil {
					sawSuccess = true
					if len(result.Vector) != len(full.Vector) {
						t.Fatalf("%s %q limit %d: truncated successful vector %d series, want %d", id, query, limit, len(result.Vector), len(full.Vector))
					}
					continue
				}
				sawFailure = true
				if releaseFault(t, err) != model.Quota {
					t.Fatalf("%s %q limit %d: error class %v, want %q", id, query, limit, err, model.Quota)
				}
				if len(result.Vector) != 0 {
					t.Fatalf("%s %q limit %d: failed evaluation returned a partial vector: %+v", id, query, limit, result)
				}
			}
			if !sawFailure || !sawSuccess {
				t.Fatalf("%s %q: sweep did not cross the budget boundary (failure=%v success=%v)", id, query, sawFailure, sawSuccess)
			}
		}
	}
}

func releaseLanguageCode(t *testing.T, err error) string {
	t.Helper()
	var language *syntax.LanguageError
	if !errors.As(err, &language) {
		t.Fatalf("error %v is not a language error", err)
	}
	return language.Code
}

// "Repeated match without group_left/right or copied grouping labels that fail
// output uniqueness errors." Two many-side samples whose copied grouping label
// makes them identical inside one match group are a repeated match.
func TestReleaseSemanticsCopiedGroupingLabelCollisionIsMultipleMatch(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "job", Value: "x"}, {Name: "zone", Value: "p"}}, msSample(15_000, 2)),
		metricSeries("a", model.Labels{{Name: "job", Value: "x"}, {Name: "zone", Value: "q"}}, msSample(15_000, 3)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}, {Name: "zone", Value: "r"}}, msSample(15_000, 10)),
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		_, _, err := evalWith(t, p, "a * on(job) group_left(zone) b", instantAt(20_000), series...)
		if err == nil || releaseLanguageCode(t, err) != "binary.matching-cardinality" {
			t.Fatalf("%s: colliding copied grouping labels: err=%v, want binary.matching-cardinality", id, err)
		}
		// Copying a label that keeps the outputs distinct is valid.
		r, _, err := evalWith(t, p, "a * on(job) group_left() b", instantAt(20_000), series...)
		if err != nil || len(r.Vector) != 2 {
			t.Fatalf("%s: distinct outputs: err=%v result=%+v", id, err, r)
		}
	}
}

// Without grouping modifiers a repeated match needs two RESULT samples in one match
// group. A comparison that filters every pair out produces no result sample, so no
// match is repeated; the same pair kept by the comparison is a repeated match.
func TestReleaseSemanticsFilteredComparisonIsNotARepeatedMatch(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "instance", Value: "1"}, {Name: "job", Value: "x"}}, msSample(15_000, 2)),
		metricSeries("a", model.Labels{{Name: "instance", Value: "2"}, {Name: "job", Value: "x"}}, msSample(15_000, 3)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 10)),
	}
	p := featureProfile(t, "promql-prometheus-3.1.0")
	r, _, err := evalWith(t, p, "a > on(job) b", instantAt(20_000), series...)
	if err != nil || len(r.Vector) != 0 {
		t.Fatalf("comparison keeping nothing: err=%v result=%+v, want empty vector", err, r)
	}
	_, _, err = evalWith(t, p, "a < on(job) b", instantAt(20_000), series...)
	if err == nil || releaseLanguageCode(t, err) != "binary.matching-cardinality" {
		t.Fatalf("comparison keeping both: err=%v, want binary.matching-cardinality", err)
	}
	_, _, err = evalWith(t, p, "a + on(job) b", instantAt(20_000), series...)
	if err == nil || releaseLanguageCode(t, err) != "binary.matching-cardinality" {
		t.Fatalf("arithmetic repeated match: err=%v, want binary.matching-cardinality", err)
	}
}

// "Standalone matrix selector with anchored/smoothed ... rejects histogram-bearing
// matrices in this root matrix-selector path. Supported rate/increase/delta call
// paths separately implement extended histogram interpolation."
func TestReleaseSemanticsExtendedRootRejectsHistogramMatrices(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", "promql-extended-range-selectors")
	hist := metricSeries("h", model.Labels{{Name: "job", Value: "api"}},
		value.Sample{Time: 5_000_000_000, Histogram: nativeTestHistogram(2)},
		value.Sample{Time: 10_000_000_000, Histogram: nativeTestHistogram(4)},
		value.Sample{Time: 15_000_000_000, Histogram: nativeTestHistogram(8)})
	float := metricSeries("c", model.Labels{{Name: "job", Value: "api"}}, msSample(5_000, 1), msSample(10_000, 3), msSample(15_000, 6))
	for _, extension := range []string{"anchored", "smoothed"} {
		_, _, err := evalWith(t, p, "h[10s] "+extension, instantAt(16_000), hist, float)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Category != "execution" {
			t.Fatalf("%s root matrix over histograms: err=%v, want an execution error", extension, err)
		}
		r, _, err := evalWith(t, p, "c[10s] "+extension, instantAt(16_000), hist, float)
		if err != nil || r.Type != "matrix" || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) == 0 {
			t.Fatalf("%s root matrix over floats: err=%v result=%+v", extension, err, r)
		}
	}
	// The supported call path handles the same histogram series.
	r, _, err := evalWith(t, p, "rate(h[10s] smoothed)", instantAt(16_000), hist, float)
	if err != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Histogram == nil {
		t.Fatalf("rate over smoothed histogram window: err=%v result=%+v", err, r)
	}
}

func releaseOptionProfile(t *testing.T, id string, options map[string]string) profile.Profile {
	t.Helper()
	p := featureProfile(t, id)
	configuration := map[string]json.RawMessage{}
	for k, v := range p.Configuration {
		configuration[k] = v
	}
	for key, state := range options {
		configuration[key] = json.RawMessage(`{"name":"` + key + `","default":"` + state + `"}`)
	}
	p.Configuration = configuration
	return p
}

func releasePlanFor(t *testing.T, p profile.Profile, query string, ev value.Evaluation) error {
	t.Helper()
	e, err := Parse(query, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildPlan(typed, ev, p)
	return err
}

// "Engine validation rejects @ and negative offsets when corresponding engine
// options are disabled, separately from parser gates." Both references ship with
// both options enabled; the pinned oracle wrapper cannot switch them off.
func TestReleaseSemanticsEngineOptionsRejectAtAndNegativeOffset(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		enabled := releaseOptionProfile(t, id, nil)
		noAt := releaseOptionProfile(t, id, map[string]string{"engine.enable-at-modifier": "false"})
		noNegative := releaseOptionProfile(t, id, map[string]string{"engine.enable-negative-offset": "false"})
		for _, tc := range []struct {
			query                string
			usesAt, usesNegative bool
		}{
			{"m @ 10", true, false},
			{"m @ start()", true, false},
			{"sum(m @ end() offset 5s)", true, false},
			{"m[10s] @ 5", true, false},
			{"m[10s:5s] @ 5", true, false},
			{"m offset -5s", false, true},
			{"sum(rate(m[10s] offset -1m))", false, true},
			{"m[10s:5s] offset -5s", false, true},
			{"m @ 10 offset -5s", true, true},
			{"m offset 5s", false, false},
			{"sum(rate(m[10s])) + 1", false, false},
			{"m offset 1ms", false, false},
		} {
			ev := instantAt(20_000)
			if err := releasePlanFor(t, enabled, tc.query, ev); err != nil {
				t.Fatalf("%s %q with both options enabled: %v", id, tc.query, err)
			}
			err := releasePlanFor(t, noAt, tc.query, ev)
			if tc.usesAt != (err != nil) {
				t.Fatalf("%s %q with @ disabled: err=%v, want rejection=%v", id, tc.query, err, tc.usesAt)
			}
			if err != nil && releaseLanguageCode(t, err) != "engine.at-modifier-disabled" {
				t.Fatalf("%s %q with @ disabled: code %q", id, tc.query, releaseLanguageCode(t, err))
			}
			err = releasePlanFor(t, noNegative, tc.query, ev)
			if tc.usesNegative != (err != nil) {
				t.Fatalf("%s %q with negative offset disabled: err=%v, want rejection=%v", id, tc.query, err, tc.usesNegative)
			}
			if err != nil && releaseLanguageCode(t, err) != "engine.negative-offset-disabled" {
				t.Fatalf("%s %q with negative offset disabled: code %q", id, tc.query, releaseLanguageCode(t, err))
			}
		}
	}
}

// "Engine lookback 0 defaults to 5m."
func TestReleaseSemanticsEngineLookbackZeroDefaultsToFiveMinutes(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		configuration := map[string]json.RawMessage{}
		for k, v := range p.Configuration {
			configuration[k] = v
		}
		configuration["lookback_delta_ns"] = json.RawMessage(`"0"`)
		p.Configuration = configuration
		e, err := Parse("m", p)
		if err != nil {
			t.Fatal(err)
		}
		typed, _, err := Check(e, p)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := BuildPlan(typed, instantAt(20_000), p)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Lookback != 300_000_000_000 {
			t.Fatalf("%s: engine lookback 0 resolved to %d ns, want 5m", id, plan.Lookback)
		}
	}
}

func releaseVectorByJob(t *testing.T, r value.Result) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, s := range r.Vector {
		if len(s.Samples) != 1 || s.Samples[0].Histogram != nil {
			t.Fatalf("unexpected sample shape in %+v", s)
		}
		out[value.Label(s.Labels, "job")] = math.Float64frombits(uint64(s.Samples[0].Float))
	}
	return out
}

// "Fill substitutes only ABSENT matched side with a FLOAT, never present NaN or
// histogram. ... group_right swaps operand sides internally but preserves original
// operator orientation. ... Both empty vectors yield empty result even fill(0)."
func TestReleaseSemanticsFillSubstitutesOnlyAbsentSides(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", "promql-binop-fill-modifiers")
	job := func(v string) model.Labels { return model.Labels{{Name: "job", Value: v}} }
	a := []value.Series{metricSeries("a", job("x"), msSample(15_000, 4)), metricSeries("a", job("y"), msSample(15_000, 6))}
	b := []value.Series{metricSeries("b", job("x"), msSample(15_000, 2)), metricSeries("b", job("z"), msSample(15_000, 7))}
	run := func(query string, series ...value.Series) map[string]float64 {
		r, _, err := evalWith(t, p, query, instantAt(20_000), series...)
		if err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		return releaseVectorByJob(t, r)
	}
	eq := func(query string, got, want map[string]float64) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%q: got %v, want %v", query, got, want)
		}
		for k, w := range want {
			if g, ok := got[k]; !ok || !(g == w || math.IsNaN(g) && math.IsNaN(w)) {
				t.Fatalf("%q: got %v, want %v", query, got, want)
			}
		}
	}
	both := append(append([]value.Series{}, a...), b...)
	// Operator orientation is lhs OP rhs whichever side is filled.
	eq("fill_right", run("a - on(job) fill_right(10) b", both...), map[string]float64{"x": 2, "y": -4})
	eq("fill_left", run("a - on(job) fill_left(10) b", both...), map[string]float64{"x": 2, "z": 3})
	eq("fill", run("a - on(job) fill(10) b", both...), map[string]float64{"x": 2, "y": -4, "z": 3})
	eq("group_right fill", run("a - on(job) group_right fill(10) b", both...), map[string]float64{"x": 2, "y": -4, "z": 3})
	// Without a fill modifier unmatched series simply disappear.
	eq("no fill", run("a - on(job) b", both...), map[string]float64{"x": 2})
	// A present NaN is not an absent side.
	nan := metricSeries("b", job("y"), value.Sample{Time: 15_000_000_000, Float: model.FloatBits(math.Float64bits(math.NaN()))})
	eq("present NaN", run("a + on(job) fill(0) b", a[0], a[1], nan), map[string]float64{"x": 4, "y": math.NaN()})
	// Both sides empty stays empty.
	eq("both empty", run("missing_a + on(job) fill(0) missing_b", both...), map[string]float64{})
	// A present histogram is never replaced by the float fill.
	hist := metricSeries("a", job("x"), value.Sample{Time: 15_000_000_000, Histogram: nativeTestHistogram(4)})
	r, _, err := evalWith(t, p, "a + on(job) fill(0) b", instantAt(20_000), hist, b[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Vector {
		if value.Label(s.Labels, "job") == "x" {
			t.Fatalf("histogram was combined with the float fill: %+v", s)
		}
	}
}

// "Initial inner start is d*trunc(A/d), then add d if that result<=A": the inner
// grid is aligned to multiples of the resolution on the epoch, not to the parent
// start, and the range is left-open.
func TestReleaseSemanticsSubqueryGridIsGloballyAligned(t *testing.T) {
	series := metricSeries("m", nil, msSample(5_000, 1), msSample(10_000, 2), msSample(15_000, 3), msSample(20_000, 4))
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		sum := func(query string, at int64) float64 {
			r, _, err := evalWith(t, p, query, instantAt(at), series)
			if err != nil || len(r.Vector) != 1 {
				t.Fatalf("%s %q: err=%v result=%+v", id, query, err, r)
			}
			return math.Float64frombits(uint64(r.Vector[0].Samples[0].Float))
		}
		// t=22s, range 10s, d=4s: A=12s, 4*trunc(12/4)=12 <= A, so the first point is
		// 16s; the points are 16s (value 3) and 20s (value 4). A parent-start grid
		// (12s, 16s, 20s) would add the value 2 from 12s.
		if got := sum("sum_over_time(m[10s:4s])", 22_000); got != 7 {
			t.Fatalf("%s: misaligned subquery grid: got %v, want 7", id, got)
		}
		// t=20s, range 10s, d=5s: A=10s is itself a grid point and is excluded
		// (left-open), leaving 15s (3) and 20s (4).
		if got := sum("sum_over_time(m[10s:5s])", 20_000); got != 7 {
			t.Fatalf("%s: left-open boundary: got %v, want 7", id, got)
		}
		// An offset shifts A: t=22s, offset 2s, range 8s, d=3s: A=12s, 3*4=12<=A so the
		// points are 15s (3) and 18s (3); 21s is past t-offset=20s. Sum 6.
		if got := sum("sum_over_time(m[8s:3s] offset 2s)", 22_000); got != 6 {
			t.Fatalf("%s: offset alignment: got %v, want 6", id, got)
		}
	}
}

// "Duplicate matching group on the required one side of arithmetic/comparison
// errors; set operations explicitly allow many-to-many."
func TestReleaseSemanticsManyToManyNeedsUniqueOneSide(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "instance", Value: "1"}, {Name: "job", Value: "x"}}, msSample(15_000, 2)),
		metricSeries("a", model.Labels{{Name: "instance", Value: "2"}, {Name: "job", Value: "x"}}, msSample(15_000, 3)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 10)),
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, query := range []string{"b + on(job) a", "b > on(job) a", "b - on(job) group_left a"} {
			if _, _, err := evalWith(t, p, query, instantAt(20_000), series...); err == nil || releaseLanguageCode(t, err) != "binary.many-to-many" {
				t.Fatalf("%s %q: err=%v, want binary.many-to-many", id, query, err)
			}
		}
		// The duplicated side may be the many side of an explicit grouping.
		if r, _, err := evalWith(t, p, "a + on(job) group_left b", instantAt(20_000), series...); err != nil || len(r.Vector) != 2 {
			t.Fatalf("%s: group_left with a unique one side: err=%v result=%+v", id, err, r)
		}
		// Set operators allow many-to-many matching.
		for query, want := range map[string]int{"a and on(job) b": 2, "b and on(job) a": 1, "a or on(job) b": 2, "a unless on(job) b": 0} {
			if r, _, err := evalWith(t, p, query, instantAt(20_000), series...); err != nil || len(r.Vector) != want {
				t.Fatalf("%s %q: err=%v got %d series, want %d", id, query, err, len(r.Vector), want)
			}
		}
	}
}

// "Two resulting samples at the same step with identical resulting labels error;
// delayed stripping does not silently choose one."
func TestReleaseSemanticsDuplicateLabelsetErrorsAtTheSameStep(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 1)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 2)),
		metricSeries("c", model.Labels{{Name: "job", Value: "y"}}, msSample(15_000, 3)),
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, delayed := range []bool{false, true} {
			p := featureProfile(t, id)
			if delayed {
				p = featureProfile(t, id, "promql-delayed-name-removal")
			}
			// With delayed stripping a nested "+ 1" keeps the names until the final result,
			// so only the outermost stripping can collide.
			queries := []string{`{__name__=~"a|b"} + 1`, `abs({__name__=~"a|b"})`}
			if !delayed {
				queries = append(queries, `sum({__name__=~"a|b"} + 1)`)
			}
			for _, query := range queries {
				if _, _, err := evalWith(t, p, query, instantAt(20_000), series...); err == nil || releaseLanguageCode(t, err) != "result.duplicate-labelset" {
					t.Fatalf("%s delayed=%v %q: err=%v, want result.duplicate-labelset", id, delayed, query, err)
				}
			}
			// Distinct labels after the name is dropped are not duplicates.
			if r, _, err := evalWith(t, p, `{__name__=~"a|c"} + 1`, instantAt(20_000), series...); err != nil || len(r.Vector) != 2 {
				t.Fatalf("%s delayed=%v: distinct results: err=%v result=%+v", id, delayed, err, r)
			}
		}
	}
}

// "out-of-range integer aggregation parameter raises evaluation error; q outside
// [0,1] instead warns with defined numeric result."
func TestReleaseSemanticsInvalidParameterErrorsButQuantileWarns(t *testing.T) {
	series := []value.Series{metricSeries("m", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 4))}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, query := range []string{"topk(1e19, m)", "bottomk(1e19, m)", "topk(Inf, m)", "sum(topk(1e19, m))"} {
			if _, _, err := evalWith(t, p, query, instantAt(20_000), series...); err == nil || releaseLanguageCode(t, err) != "aggregation.parameter-range" {
				t.Fatalf("%s %q: err=%v, want aggregation.parameter-range", id, query, err)
			}
		}
		for query, want := range map[string]float64{"quantile(1.5, m)": math.Inf(1), "quantile(-0.5, m)": math.Inf(-1)} {
			r, notes, err := evalWith(t, p, query, instantAt(20_000), series...)
			if err != nil || len(r.Vector) != 1 || math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)) != want {
				t.Fatalf("%s %q: err=%v result=%+v, want %v", id, query, err, r, want)
			}
			if len(notes) == 0 {
				t.Fatalf("%s %q: no warning for an out-of-range quantile", id, query)
			}
		}
		if r, notes, err := evalWith(t, p, "quantile(0.5, m)", instantAt(20_000), series...); err != nil || len(r.Vector) != 1 || len(notes) != 0 {
			t.Fatalf("%s: in-range quantile: err=%v result=%+v notes=%v", id, err, r, notes)
		}
	}
}

// The collision check applies to every step of a range query: two series whose
// labels become identical after name removal are an error, never merged into one
// output series.
func TestReleaseSemanticsRangeQueryNameCollisionIsDuplicateLabelset(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "job", Value: "x"}}, msSample(5_000, 1), msSample(10_000, 2), msSample(15_000, 3)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}}, msSample(5_000, 4), msSample(10_000, 5), msSample(15_000, 6)),
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, delayed := range []bool{false, true} {
			p := featureProfile(t, id)
			if delayed {
				p = featureProfile(t, id, "promql-delayed-name-removal")
			}
			for _, query := range []string{`{__name__=~"a|b"} + 1`, `abs({__name__=~"a|b"})`} {
				r, _, err := evalWith(t, p, query, rangeOf(10_000, 15_000, 5_000), series...)
				if err == nil || releaseLanguageCode(t, err) != "result.duplicate-labelset" || len(r.Matrix) != 0 {
					t.Fatalf("%s delayed=%v %q: err=%v result=%+v, want result.duplicate-labelset", id, delayed, query, err, r)
				}
			}
		}
	}
}

// With delayed name removal 3.1.0 strips names from the whole range result once
// and rejects collisions between series that were present at different steps; the
// same series without delayed removal never share a step and stay separate until
// their names are dropped per step.
func TestReleaseSemanticsLegacyDelayedRangeCollisionAcrossSteps(t *testing.T) {
	series := []value.Series{
		metricSeries("a", model.Labels{{Name: "job", Value: "x"}}, msSample(10_000, 1)),
		metricSeries("b", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 2)),
	}
	run := func(delayed bool) (value.Result, error) {
		p := featureProfile(t, "promql-prometheus-3.1.0")
		if delayed {
			p = featureProfile(t, "promql-prometheus-3.1.0", "promql-delayed-name-removal")
		}
		e, err := Parse(`abs({__name__=~"a|b"})`, p)
		if err != nil {
			t.Fatal(err)
		}
		typed, _, err := Check(e, p)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := BuildPlan(typed, rangeOf(10_000, 20_000, 5_000), p)
		if err != nil {
			t.Fatal(err)
		}
		plan.Lookback = 1_000_000_000 // each series is visible at its own step only
		r, _, err := Evaluate(context.Background(), plan, seriesSource(series), value.NewBoundedAccount(1<<24))
		return r, err
	}
	r, err := run(true)
	if err == nil || releaseLanguageCode(t, err) != "result.duplicate-labelset" || len(r.Matrix) != 0 {
		t.Fatalf("delayed: err=%v result=%+v, want result.duplicate-labelset", err, r)
	}
	r, err = run(false)
	if err != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 {
		t.Fatalf("not delayed: err=%v result=%+v, want one merged series of two samples", err, r)
	}
}

func releaseConfiguredProfile(t *testing.T, id string, raw map[string]string) profile.Profile {
	t.Helper()
	p := featureProfile(t, id)
	configuration := map[string]json.RawMessage{}
	for k, v := range p.Configuration {
		configuration[k] = v
	}
	for key, v := range raw {
		configuration[key] = json.RawMessage(v)
	}
	p.Configuration = configuration
	return p
}

func releaseBuild(t *testing.T, p profile.Profile, query string, ev value.Evaluation) Plan {
	t.Helper()
	e, err := Parse(query, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// "Per-query lookback<=0 inherits engine lookback; positive value overrides engine
// lookback for this query." The sample is 5s before the evaluation time: it is
// visible under the 10s engine lookback, not under a 1s per-query override, and
// visible under a 6s override that is shorter than the 5m default.
func TestReleaseSemanticsPerQueryLookbackOption(t *testing.T) {
	const second = int64(1_000_000_000)
	series := metricSeries("m", nil, msSample(15_000, 1))
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := releaseConfiguredProfile(t, id, map[string]string{"lookback_delta_ns": `"10000000000"`})
		base := releaseBuild(t, p, "m", instantAt(20_000))
		if base.Lookback != 10*second {
			t.Fatalf("%s: engine lookback %d, want 10s", id, base.Lookback)
		}
		visible := func(o QueryOptions) bool {
			plan := base.WithQueryOptions(o)
			r, _, err := Evaluate(context.Background(), plan, seriesSource{series}, value.NewBoundedAccount(1<<24))
			if err != nil {
				t.Fatal(err)
			}
			return len(r.Vector) == 1
		}
		for _, tc := range []struct {
			lookback int64
			want     bool
			why      string
		}{
			{0, true, "zero inherits the 10s engine lookback"},
			{-1_000_000, true, "negative inherits the engine lookback"},
			{second, false, "a positive 1s override replaces the engine lookback"},
			{5 * second, false, "the window is left-open: a sample exactly 5s old is outside a 5s lookback"},
			{5*second + 1_000_000, true, "5s+1ms reaches the sample"},
			{600 * second, true, "a longer override replaces the engine lookback"},
		} {
			if got := visible(QueryOptions{Lookback: tc.lookback}); got != tc.want {
				t.Fatalf("%s lookback %d: visible=%v, want %v (%s)", id, tc.lookback, got, tc.want, tc.why)
			}
		}
		// The option is per query: the plan it was applied to is a copy.
		if base.Lookback != 10*second {
			t.Fatalf("%s: the override leaked into the engine plan", id)
		}
	}
}

// "Per-step statistics requires both engine and per-query opt-in but does not
// change values." Each of the 3 steps loads one point from each of the 2 series.
func TestReleaseSemanticsPerStepStatisticsNeedEngineAndQueryOptIn(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		var reference value.Result
		for _, tc := range []struct {
			engine map[string]string
			query  bool
			want   bool
		}{
			{nil, true, false}, // the engine switch is off by default
			{map[string]string{"engine.enable-per-step-stats": `{"default":"false"}`}, true, false},
			{map[string]string{"engine.enable-per-step-stats": `{"default":"true"}`}, false, false},
			{map[string]string{"engine.enable-per-step-stats": `{"default":"true"}`}, true, true},
		} {
			p := releaseConfiguredProfile(t, id, tc.engine)
			plan := releaseBuild(t, p, "m", rangeOf(10_000, 20_000, 5_000))
			var stats QueryStatistics
			plan = plan.WithQueryOptions(QueryOptions{PerStepStats: tc.query, Stats: &stats})
			r, _, err := Evaluate(context.Background(), plan, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
			if err != nil {
				t.Fatal(err)
			}
			if (len(stats.PerStep) != 0) != tc.want {
				t.Fatalf("%s engine=%v query=%v: per-step statistics %+v, want present=%v", id, tc.engine, tc.query, stats.PerStep, tc.want)
			}
			if tc.want {
				for i, step := range stats.PerStep {
					if len(stats.PerStep) != 3 || step.Time != model.UnixNano(10_000_000_000+int64(i)*5_000_000_000) || step.Samples != 2 {
						t.Fatalf("%s: per-step statistics %+v, want three steps loading 2 points each", id, stats.PerStep)
					}
				}
			}
			if reference.Type == "" {
				reference = r
			} else if !reflect.DeepEqual(reference, r) {
				t.Fatalf("%s: statistics changed the result values", id)
			}
		}
	}
}

// "query.max-samples bounds simultaneously retained sample units, not output row
// count alone. Float point costs 1; histogram point costs floor((histogram byte
// Size+8)/16). Peak includes retained subquery input/output and intermediate
// values. Exceeding limit causes ErrTooManySamples, not truncation."
//
// Hand-derived peaks over two series with samples at 5s, 10s, 15s, 20s, evaluated at
// 20s (a float point is 1 unit):
//
//	m                       selector loads 2 points, result holds 2                 -> 2
//	count(m)                one output row, but the 2 loaded points were retained  -> 2
//	m + m                   left result (2) retained while right loads 2            -> 4
//	sum_over_time(m[20s])   window loads 4 points per series                        -> 8
//	sum_over_time(m[10s:5s]) inner steps 15s and 20s: step 15s keeps 2 loaded + 2
//	                        accumulated, step 20s keeps 2 accumulated + 2 loaded +
//	                        2 accumulated                                           -> 6
func TestReleaseSemanticsSampleUnitPeaksAndLimit(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, tc := range []struct {
			query string
			peak  int64
		}{{"m", 2}, {"count(m)", 2}, {"m + m", 4}, {"sum_over_time(m[20s])", 8}, {"sum_over_time(m[10s:5s])", 6}} {
			plan := releaseBuild(t, p, tc.query, instantAt(20_000))
			run := func(limit int64) (value.Result, QueryStatistics, error) {
				var stats QueryStatistics
				q := plan.WithQueryOptions(QueryOptions{Stats: &stats})
				q.MaxSamples = limit
				r, _, err := Evaluate(context.Background(), q, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24))
				return r, stats, err
			}
			if r, stats, err := run(tc.peak); err != nil || stats.PeakSamples != tc.peak || len(r.Vector) == 0 {
				t.Fatalf("%s %q at limit=peak: err=%v peak=%d result=%+v, want peak %d", id, tc.query, err, stats.PeakSamples, r, tc.peak)
			}
			r, _, err := run(tc.peak - 1)
			if err == nil || releaseFault(t, err) != model.Quota || len(r.Vector) != 0 {
				t.Fatalf("%s %q at limit=peak-1: err=%v result=%+v, want the quota class and no truncated vector", id, tc.query, err, r)
			}
		}
		// A zero budget rejects any query that loads a point; a query that loads none passes.
		plan := releaseBuild(t, p, "m", instantAt(20_000))
		plan.MaxSamples = 0
		if _, _, err := Evaluate(context.Background(), plan, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24)); err == nil || releaseFault(t, err) != model.Quota {
			t.Fatalf("%s: zero budget: err=%v", id, err)
		}
		none := releaseBuild(t, p, "no_such_metric", instantAt(20_000))
		none.MaxSamples = 0
		if r, _, err := Evaluate(context.Background(), none, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24)); err != nil || len(r.Vector) != 0 {
			t.Fatalf("%s: query loading no point under a zero budget: err=%v result=%+v", id, err, r)
		}
		// The limit comes from query.max-samples in the profile configuration; its default is 50000000.
		if got := releaseBuild(t, p, "m", instantAt(20_000)).MaxSamples; got != 50_000_000 {
			t.Fatalf("%s: default max samples %d", id, got)
		}
		limited := releaseBuild(t, releaseConfiguredProfile(t, id, map[string]string{"query.max-samples": `{"default":"3"}`}), "m + m", instantAt(20_000))
		if limited.MaxSamples != 3 {
			t.Fatalf("%s: configured max samples %d", id, limited.MaxSamples)
		}
		if _, _, err := Evaluate(context.Background(), limited, seriesSource(releaseSemanticsFixture()), value.NewBoundedAccount(1<<24)); err == nil || releaseFault(t, err) != model.Quota {
			t.Fatalf("%s: configured limit 3 with peak 4: err=%v", id, err)
		}
	}
}

// A native histogram point costs floor((byte size+8)/16) units. The selector
// retains the float form: one span (8 bytes) and one bucket (8 bytes) on top of the
// 160-byte float histogram header = 176 bytes -> floor(184/16) = 11 units; a float
// point beside it costs 1.
func TestReleaseSemanticsHistogramPointCostsSizeUnits(t *testing.T) {
	hist := metricSeries("h", model.Labels{{Name: "job", Value: "x"}}, value.Sample{Time: 15_000_000_000, Histogram: nativeTestHistogram(4)})
	float := metricSeries("f", model.Labels{{Name: "job", Value: "x"}}, msSample(15_000, 1))
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for _, tc := range []struct {
			query string
			peak  int64
		}{{"h", 11}, {"f", 1}, {`{__name__=~"h|f"}`, 12}} {
			plan := releaseBuild(t, p, tc.query, instantAt(20_000))
			var stats QueryStatistics
			q := plan.WithQueryOptions(QueryOptions{Stats: &stats})
			q.MaxSamples = tc.peak
			if _, _, err := Evaluate(context.Background(), q, seriesSource{hist, float}, value.NewBoundedAccount(1<<24)); err != nil || stats.PeakSamples != tc.peak {
				t.Fatalf("%s %q: err=%v peak=%d, want %d", id, tc.query, err, stats.PeakSamples, tc.peak)
			}
			q.MaxSamples = tc.peak - 1
			if _, _, err := Evaluate(context.Background(), q, seriesSource{hist, float}, value.NewBoundedAccount(1<<24)); err == nil || releaseFault(t, err) != model.Quota {
				t.Fatalf("%s %q: limit %d: err=%v, want the quota class", id, tc.query, tc.peak-1, err)
			}
		}
	}
}
