// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"testing"
)

func executionProfile(t *testing.T) profile.Profile {
	t.Helper()
	r, e := profile.Load(os.DirFS("../../../profiles/query"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := r.Resolve("promql-prometheus-3.1.0", "promql-prometheus-3.1.0/semantic-sha256-1def724ec80987ebd117b52fbf8500c735f913efd1d1e16a7623f01699cc76a8")
	if e != nil {
		t.Fatal(e)
	}
	return p
}

type seriesSource []value.Series

func (s seriesSource) ProjectID() model.ID { return model.ID{1} }
func (s seriesSource) Select(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
	return &seriesIter{s: s}, nil
}

type seriesIter struct {
	s []value.Series
	i int
}

func (i *seriesIter) Next(ctx context.Context) (value.Series, error) {
	if e := ctx.Err(); e != nil {
		return value.Series{}, e
	}
	if i.i == len(i.s) {
		return value.Series{}, io.EOF
	}
	s := i.s[i.i]
	i.i++
	if s.Project == (model.ID{}) {
		s.Project = model.ID{1}
	}
	return s, nil
}
func (i *seriesIter) Close() error               { return nil }
func (i *seriesIter) Watermarks() []model.Cursor { return nil }
func (i *seriesIter) Partial() bool              { return false }
func sample(at int64, f float64) value.Sample {
	return value.Sample{Time: model.UnixNano(at), Float: model.FloatBits(math.Float64bits(f))}
}
func executeExpr(t *testing.T, q string, ev value.Evaluation, src scan.MetricSource) (value.Result, error) {
	t.Helper()
	if src == nil {
		src = seriesSource{}
	}
	p := executionProfile(t)
	e, err := Parse(q, p)
	if err != nil {
		t.Fatal(err)
	}
	te, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := BuildPlan(te, ev, p)
	if err != nil {
		return value.Result{}, err
	}
	r, _, err := Evaluate(context.Background(), pl, src, value.NewBoundedAccount(1<<24))
	return r, err
}
func TestLeftOpenWindowAndLookback(t *testing.T) {
	s := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1), sample(1e9, 2), sample(2e9, 4)}}}
	r, e := executeExpr(t, "m[2s]", value.Evaluation{Instant: true, Time: 2e9}, s)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 || r.Matrix[0].Samples[0].Time != 1e9 || r.Matrix[0].Samples[1].Time != 2e9 {
		t.Fatalf("left-open window: %+v", r)
	}
	r, e = executeExpr(t, "m", value.Evaluation{Instant: true, Time: 2e9}, s)
	if e != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Float != sample(0, 4).Float {
		t.Fatalf("instant: %+v %v", r, e)
	}
	s[0].Samples = append(s[0].Samples[:2], value.Sample{Time: 1500000000, Float: value.StaleBits})
	r, e = executeExpr(t, "m", value.Evaluation{Instant: true, Time: 1750000000}, s)
	if e != nil || len(r.Vector) != 0 {
		t.Fatalf("stale must suppress: %+v %v", r, e)
	}
}
func TestExactGridOffsetSubquery(t *testing.T) {
	g, e := EvaluationGrid(value.Evaluation{Start: 0, End: 2500000000, Step: 1e9})
	if e != nil || len(g) != 3 || g[2] != 2e9 {
		t.Fatalf("grid %v %v", g, e)
	}
	if _, e = EvaluationGrid(value.Evaluation{Start: math.MinInt64, End: math.MaxInt64, Step: 1}); e == nil {
		t.Fatal("unbounded grid admitted")
	}
	s := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1), sample(1e9, 2), sample(2e9, 4)}}}
	for _, q := range []string{"m @ 2 offset 1s", "m offset 1s @ 2"} {
		r, e := executeExpr(t, q, value.Evaluation{Instant: true, Time: 9e9}, s)
		if e != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Float != sample(0, 2).Float {
			t.Fatalf("%s: %+v %v", q, r, e)
		}
	}
	r, e := executeExpr(t, "m[2s:1s]", value.Evaluation{Instant: true, Time: 2500000000}, s)
	if e != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 || r.Matrix[0].Samples[0].Time != 1e9 {
		t.Fatalf("subquery %+v %v", r, e)
	}
}
func TestNonfiniteIsNotStale(t *testing.T) {
	for _, bits := range []model.FloatBits{0x7ff8000000000001, 0x8000000000000000, 0x7ff0000000000000} {
		s := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{{Time: 0, Float: bits}}}}
		r, e := executeExpr(t, "m", value.Evaluation{Instant: true}, s)
		if e != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Float != bits {
			t.Fatalf("bits %x: %+v %v", bits, r, e)
		}
	}
}

type metadataSource struct {
	series []value.Series
	calls  int
}

func (s *metadataSource) ProjectID() model.ID { return model.ID{1} }
func (s *metadataSource) Select(ctx context.Context, r scan.MetricSelection) (scan.SeriesIterator, error) {
	s.calls++
	cut := uint64(12)
	if s.calls > 1 {
		cut = 7
	}
	return &metadataSeriesIter{seriesIter: seriesIter{s: s.series}, cursors: []model.Cursor{{Group: model.ID{2}, Index: 9}, {Group: model.ID{1}, Index: model.Uint64(cut)}}}, nil
}

type metadataSeriesIter struct {
	seriesIter
	cursors []model.Cursor
}

func (i *metadataSeriesIter) Watermarks() []model.Cursor { return i.cursors }
func (i *metadataSeriesIter) Partial() bool              { return true }
func TestPartialMetadataSurvivesEmptyOperators(t *testing.T) {
	src := &metadataSource{series: []value.Series{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1)}}}}
	r, e := executeExpr(t, "m unless m", value.Evaluation{Instant: true}, src)
	if e != nil || len(r.Vector) != 0 || !r.Partial {
		t.Fatalf("empty partial output %+v %v", r, e)
	}
	if len(r.Watermarks) != 2 || r.Watermarks[0].Group != (model.ID{1}) || r.Watermarks[0].Index != 7 || r.Watermarks[1].Group != (model.ID{2}) || r.Watermarks[1].Index != 9 {
		t.Fatalf("unsafe input cuts %+v", r.Watermarks)
	}
}
func TestLookbackBoundaryAndCheckedTimeOverflow(t *testing.T) {
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1)}}}
	r, e := executeExpr(t, "m", value.Evaluation{Instant: true, Time: 300000000000}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("lookback exact boundary %+v %v", r, e)
	}
	r, e = executeExpr(t, "m", value.Evaluation{Instant: true, Time: 300000000001}, src)
	if e != nil || len(r.Vector) != 0 {
		t.Fatalf("lookback outside boundary %+v %v", r, e)
	}
	if _, e = executeExpr(t, "m", value.Evaluation{Instant: true, Time: math.MinInt64}, src); e == nil {
		t.Fatal("lookback arithmetic wrapped")
	}
	if _, e = executeExpr(t, "m @ 9223372036.855", value.Evaluation{Instant: true}, src); e == nil {
		t.Fatal("@ timestamp arithmetic wrapped")
	}
	g, e := EvaluationGrid(value.Evaluation{Start: math.MaxInt64 - 1, End: math.MaxInt64, Step: 2})
	if e != nil || len(g) != 1 || g[0] != math.MaxInt64-1 {
		t.Fatalf("terminal grid overflow %v %v", g, e)
	}
}
func TestPinnedTimestampAndDurationQuantization(t *testing.T) {
	for _, tc := range []struct {
		text string
		want int64
	}{{"0.0005", 1000000}, {"-0.0005", -1000000}, {"1.001", 1001000000}} {
		got, e := atNS(tc.text, value.Evaluation{Instant: true})
		if e != nil || got != tc.want {
			t.Fatalf("@ %s = %d %v want %d", tc.text, got, e, tc.want)
		}
	}
	expr := &Node{Kind: "duration_call", Text: "range"}
	got, e := durationNS(expr, "", value.Evaluation{Start: 1000000000, End: 4000000000, Step: 1000000000})
	if e != nil || got != 3000000000 {
		t.Fatalf("outer query duration %d %v", got, e)
	}
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(1000000, 1), sample(1500000, 2), sample(2000000, 3)}}}
	r, e := executeExpr(t, "m[0.0019]", value.Evaluation{Instant: true, Time: 2000000}, src)
	if e != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 || r.Matrix[0].Samples[0].Time != 1500000 {
		t.Fatalf("duration quantization or native ns lost %+v %v", r, e)
	}
}
func TestNestedSubqueryResolution(t *testing.T) {
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1), sample(1000000000, 2), sample(2000000000, 4), sample(3000000000, 8), sample(4000000000, 16)}}}
	r, e := executeExpr(t, "last_over_time(m[2s:1s])[4s:2s]", value.Evaluation{Instant: true, Time: 5000000000}, src)
	if e != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 {
		t.Fatalf("nested subquery %+v %v", r, e)
	}
	ps := r.Matrix[0].Samples
	if ps[0].Time != 2000000000 || ps[0].Float != 0x4010000000000000 || ps[1].Time != 4000000000 || ps[1].Float != 0x4030000000000000 {
		t.Fatalf("nested values %+v", ps)
	}
}
func TestRegexBudgetIsNotResetPerEvaluationStep(t *testing.T) {
	p := executionProfile(t)
	expr, e := Parse("m{job=~\"x\"}", p)
	if e != nil {
		t.Fatal(e)
	}
	typed, _, e := Check(expr, p)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
	if e != nil {
		t.Fatal(e)
	}
	scope, e := regexcompat.NewScope(p, regexcompat.Limits{CacheEntries: 8, CachePatternBytes: 128, ProgramUnits: 128, PatternBytes: 128, InputBytes: 128, Work: 2100, Matches: 128, OutputBytes: 128})
	if e != nil {
		t.Fatal(e)
	}
	account := value.NewBoundedAccount(1 << 20)
	state := &evaluationState{ctx: context.Background(), plan: plan, account: account, regexScope: scope, src: seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}, {Name: "job", Value: "x"}}, Samples: []value.Sample{sample(0, 1)}}}}
	defer func() { account.Release(state.reserved) }()
	for range 1000 {
		_, e = state.eval(plan.Expr, 0)
		if e != nil {
			if !errors.Is(e, regexcompat.ErrBudget) {
				t.Fatalf("unexpected query failure %v", e)
			}
			return
		}
	}
	t.Fatal("regex query work budget was reset between evaluation steps")
}
func TestNativeIntegerHistogramSelectorConversionBoundary(t *testing.T) {
	native := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", ResetHint: "unknown", Count: 18014398509481985, PositiveSpans: []model.HistogramSpan{{Length: 2}}, PositiveBuckets: []model.DeltaBucket{9007199254740993, -1}}}
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{{Time: 0, Histogram: native}}}}
	r, e := executeExpr(t, "m", value.Evaluation{Instant: true}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("selected native histogram %+v %v", r, e)
	}
	h := r.Vector[0].Samples[0].Histogram
	if h == nil || h.Integer != nil || h.Float == nil {
		t.Fatalf("language selector did not materialize float histogram %+v", h)
	}
	if h.Float.Count != 0x4350000000000000 || len(h.Float.PositiveBuckets) != 2 || h.Float.PositiveBuckets[0] != 0x4340000000000000 || h.Float.PositiveBuckets[1] != 0x4340000000000000 {
		t.Fatalf("incorrect declared integer conversion %+v", h.Float)
	}
	if native.Integer.Count != 18014398509481985 || native.Integer.PositiveBuckets[0] != 9007199254740993 || native.Integer.PositiveBuckets[1] != -1 {
		t.Fatal("selector mutated or rounded exact native source")
	}
	if h.Float.Flavor != "counter" || h.Float.ResetHint != "unknown" {
		t.Fatal("selector conversion changed reset/counter semantics")
	}
}

type zeroProjectSource struct{ seriesSource }

func (zeroProjectSource) ProjectID() model.ID { return model.ID{} }
func TestEvaluationRequiresCanonicalProjectSource(t *testing.T) {
	p := executionProfile(t)
	expr, e := Parse("1", p)
	if e != nil {
		t.Fatal(e)
	}
	typed, _, e := Check(expr, p)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := BuildPlan(typed, value.Evaluation{Instant: true}, p)
	if e != nil {
		t.Fatal(e)
	}
	for _, src := range []scan.MetricSource{nil, zeroProjectSource{}} {
		if _, _, e = Evaluate(context.Background(), plan, src, value.NewBoundedAccount(1<<20)); e == nil {
			t.Fatal("missing canonical project became successful result")
		}
	}
	wrong := seriesSource{{Project: model.ID{2}, Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(0, 1)}}}
	if _, e = executeExpr(t, "m", value.Evaluation{Instant: true}, wrong); e == nil || errors.Is(e, io.EOF) {
		t.Fatalf("wrong-project source result accepted: %v", e)
	}
}
func TestSelectorRetainsOptionalStartTimestamp(t *testing.T) {
	start := model.UnixNano(-42)
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{{Time: 0, Float: 0x3ff0000000000000, StartTimestamp: &start}}}}
	r, e := executeExpr(t, "m", value.Evaluation{Instant: true}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("selector %+v %v", r, e)
	}
	start = 99
	if got := r.Vector[0].Samples[0].StartTimestamp; got == nil || *got != -42 {
		t.Fatalf("borrowed start timestamp retained %v", got)
	}
}
func TestRawRangeStartMetadataDoesNotLeakIntoSubquery(t *testing.T) {
	start := model.UnixNano(0)
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{{Time: 1000000000, Float: 0x3ff0000000000000, StartTimestamp: &start}}}}
	raw, e := executeExpr(t, "m[2s]", value.Evaluation{Instant: true, Time: 2000000000}, src)
	if e != nil || len(raw.Matrix) != 1 || len(raw.Matrix[0].Samples) != 1 || raw.Matrix[0].Samples[0].StartTimestamp == nil {
		t.Fatalf("raw matrix start metadata lost %+v %v", raw, e)
	}
	derived, e := executeExpr(t, "m[2s:1s]", value.Evaluation{Instant: true, Time: 2000000000}, src)
	if e != nil || len(derived.Matrix) != 1 || len(derived.Matrix[0].Samples) != 2 {
		t.Fatalf("subquery %+v %v", derived, e)
	}
	for _, sample := range derived.Matrix[0].Samples {
		if sample.StartTimestamp != nil {
			t.Fatal("subquery invented native start timestamp side channel")
		}
	}
}
func TestTimestampDirectSelectorPreservesSourceTime(t *testing.T) {
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []value.Sample{sample(13000000000, 1), sample(15000000000, 2)}}}
	for _, p := range []profile.Profile{executionProfile(t), trimProfile(t)} {
		for _, tc := range []struct {
			query string
			bits  model.FloatBits
		}{
			{"timestamp(m)", 0x402e000000000000}, {"timestamp(((m)))", 0x402e000000000000},
			{"timestamp(m+0)", 0x4034000000000000}, {"timestamp(+m)", 0x4034000000000000},
			{"timestamp(m @ 15 offset 1s)", 0x402a000000000000},
		} {
			expr, e := Parse(tc.query, p)
			if e != nil {
				t.Fatal(e)
			}
			typed, _, e := Check(expr, p)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := BuildPlan(typed, value.Evaluation{Instant: true, Time: 20000000000}, p)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := Evaluate(context.Background(), plan, src, value.NewBoundedAccount(1<<20))
			if e != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Float != tc.bits || r.Vector[0].Samples[0].Time != 20000000000 {
				t.Fatalf("%s/%s: %+v %v", p.ID, tc.query, r, e)
			}
		}
	}
}
func TestLanguageErrorCodesAndNativeNameRanges(t *testing.T) {
	for _, tc := range []struct {
		query, code string
		start, end  int
	}{
		{"info(m)", "function.feature-disabled", 0, 4},
		{"step()", "function.unknown", 0, 4},
		{"abs()", "function.arity", 0, 5},
		{"abs(\"x\")", "function.argument-type", 4, 7},
		{"start()", "syntax.unexpected-token", 5, 6},
		{"end()", "syntax.unexpected-token", 3, 4},
	} {
		expr, err := Parse(tc.query, executionProfile(t))
		if err == nil {
			_, _, err = Check(expr, executionProfile(t))
		}
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Code != tc.code || language.Range.StartByte != tc.start || language.Range.EndByte != tc.end {
			t.Fatalf("%s: %+v %v", tc.query, language, err)
		}
	}
}
