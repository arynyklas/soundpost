// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Expected values in this file are derived by hand from the obligation rule
// text (annotation anchoring, reset detection, scaling, interpolation and trim
// arithmetic); none is read from an oracle or from the engine under test.

const (
	relP31  = "promql-prometheus-3.1.0"
	relP313 = "promql-prometheus-3.13.5"
)

func relBits(f float64) model.FloatBits { return model.FloatBits(math.Float64bits(f)) }

// relExp is an integer exponential (schema 0) histogram with one span of
// consecutive buckets starting at offset; bucket i covers (2^(i-1), 2^i].
func relExp(sum float64, offset int32, counts ...uint64) *model.NativeHistogram {
	total := uint64(0)
	abs := make([]model.AbsoluteBucket, len(counts))
	for i, c := range counts {
		total += c
		abs[i] = model.AbsoluteBucket(c)
	}
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: model.Uint64(total), Sum: relBits(sum),
		PositiveSpans: []model.HistogramSpan{{Offset: offset, Length: uint32(len(counts))}}, PositiveCounts: abs, ResetHint: "unknown"}}
}

// relCustom is an integer custom-bucket histogram: len(bounds)+1 buckets,
// (-Inf,b0], (b0,b1], ..., (b_last,+Inf].
func relCustom(sum float64, bounds []float64, counts ...uint64) *model.NativeHistogram {
	total := uint64(0)
	abs := make([]model.AbsoluteBucket, len(counts))
	for i, c := range counts {
		total += c
		abs[i] = model.AbsoluteBucket(c)
	}
	cb := make([]model.FloatBits, len(bounds))
	for i, b := range bounds {
		cb[i] = relBits(b)
	}
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: -53, Count: model.Uint64(total), Sum: relBits(sum),
		PositiveSpans: []model.HistogramSpan{{Offset: 0, Length: uint32(len(counts))}}, PositiveCounts: abs, CustomBounds: cb, ResetHint: "unknown"}}
}

func relHint(h *model.NativeHistogram, hint string) *model.NativeHistogram {
	h.Integer.ResetHint = hint
	return h
}

func relHistSample(seconds int64, h *model.NativeHistogram) value.Sample {
	return value.Sample{Time: model.UnixNano(seconds * 1_000_000_000), Histogram: h}
}

func relFloatSample(seconds int64, f float64) value.Sample {
	return value.Sample{Time: model.UnixNano(seconds * 1_000_000_000), Float: relBits(f)}
}

// relSpan returns the byte range of the first occurrence of part in query.
func relSpan(t *testing.T, query, part string) [2]int {
	t.Helper()
	i := strings.Index(query, part)
	if i < 0 {
		t.Fatalf("%q not in %q", part, query)
	}
	return [2]int{i, i + len(part)}
}

func relNote(t *testing.T, notes []syntax.Diagnostic, id string) (syntax.Diagnostic, bool) {
	t.Helper()
	for _, n := range notes {
		if n.Category == id {
			return n, true
		}
	}
	return syntax.Diagnostic{}, false
}

func relFloatOf(t *testing.T, r value.Result, index int) float64 {
	t.Helper()
	if len(r.Vector) <= index || len(r.Vector[index].Samples) != 1 || r.Vector[index].Samples[0].Histogram != nil {
		t.Fatalf("want a float vector sample at %d: %+v", index, r)
	}
	return math.Float64frombits(uint64(r.Vector[index].Samples[0].Float))
}

func relHistogramOf(t *testing.T, r value.Result, index int) model.FloatHistogram {
	t.Helper()
	if len(r.Vector) <= index || len(r.Vector[index].Samples) != 1 || r.Vector[index].Samples[0].Histogram == nil || r.Vector[index].Samples[0].Histogram.Float == nil {
		t.Fatalf("want a float histogram vector sample at %d: %+v", index, r)
	}
	return *r.Vector[index].Samples[0].Histogram.Float
}

func relFloat(bits model.FloatBits) float64 { return math.Float64frombits(uint64(bits)) }

func relNear(t *testing.T, what string, got, want float64) {
	t.Helper()
	if math.IsNaN(want) && math.IsNaN(got) || got == want {
		return
	}
	if math.IsNaN(got) || math.IsNaN(want) || math.Abs(got-want) > 1e-12*math.Max(1, math.Abs(want)) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// Aggregation annotations belong to the aggregated expression (its argument),
// not to the whole aggregation call.
func TestReleaseHistogramAggregationAnnotationAnchorsAtArgument(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		hs := metricSeries("hs_total", nil, relHistSample(15, relExp(6, 1, 4)))
		const ignored = "max(hs_total)"
		_, notes, err := evalWith(t, p, ignored, instantAt(20_000), hs)
		if err != nil {
			t.Fatal(err)
		}
		n, ok := relNote(t, notes, "HistogramIgnoredInAggregationInfo")
		if want := relSpan(t, ignored, "hs_total"); !ok || n.Range.StartByte != want[0] || n.Range.EndByte != want[1] {
			t.Fatalf("%s: %q annotation %+v, want range %v", id, ignored, n, want)
		}
		mixed := []value.Series{
			metricSeries("h_total", model.Labels{{Name: "a", Value: "1"}}, relHistSample(15, relExp(6, 1, 4))),
			metricSeries("h_total", model.Labels{{Name: "a", Value: "2"}}, relFloatSample(15, 1)),
		}
		const mix = "sum(h_total)"
		_, notes, err = evalWith(t, p, mix, instantAt(20_000), mixed...)
		if err != nil {
			t.Fatal(err)
		}
		n, ok = relNote(t, notes, "MixedFloatsHistogramsWarning")
		if want := relSpan(t, mix, "h_total"); !ok || n.Range.StartByte != want[0] || n.Range.EndByte != want[1] {
			t.Fatalf("%s: %q annotation %+v, want range %v", id, mix, n, want)
		}
	}
}

// Binary-operator histogram annotations span the whole binary expression and
// carry the pin's identity for the layout conflict.
func TestReleaseHistogramBinaryAnnotationsSpanWholeExpression(t *testing.T) {
	custom1 := relCustom(9, []float64{1, 2}, 1, 2, 3)
	custom2 := relCustom(9, []float64{1, 3}, 1, 2, 3)
	exp := relExp(6, 1, 4)
	for _, tc := range []struct {
		profile string
		left    *model.NativeHistogram
		right   *model.NativeHistogram
		want    string
	}{
		{relP31, custom1, custom2, "IncompatibleCustomBucketsHistogramsWarning"},
		{relP313, custom1, custom2, "MismatchedCustomBucketsHistogramsInfo"},
		{relP31, exp, custom1, "MixedExponentialCustomHistogramsWarning"},
		{relP313, exp, custom1, "IncompatibleBucketLayoutInBinOpWarning"},
	} {
		p := featureProfile(t, tc.profile)
		const query = "left_total + right_total"
		_, notes, err := evalWith(t, p, query, instantAt(20_000),
			metricSeries("left_total", nil, relHistSample(15, tc.left)), metricSeries("right_total", nil, relHistSample(15, tc.right)))
		if err != nil {
			t.Fatal(err)
		}
		n, ok := relNote(t, notes, tc.want)
		if !ok || n.Range.StartByte != 0 || n.Range.EndByte != len(query) {
			t.Fatalf("%s: want %s over 0..%d, got %+v", tc.profile, tc.want, len(query), notes)
		}
		if len(notes) != 1 {
			t.Fatalf("%s: want exactly one annotation, got %+v", tc.profile, notes)
		}
	}
	// 3.13.5 addition of an explicit reset hint to an explicit not-reset hint
	// cannot be reconciled: the pair is omitted and the collision is annotated.
	p := featureProfile(t, relP313)
	const query = "a_total + b_total"
	r, notes, err := evalWith(t, p, query, instantAt(20_000),
		metricSeries("a_total", nil, relHistSample(15, relHint(relExp(6, 1, 4), "reset"))),
		metricSeries("b_total", nil, relHistSample(15, relHint(relExp(6, 1, 4), "not_reset"))))
	if err != nil {
		t.Fatal(err)
	}
	n, ok := relNote(t, notes, "HistogramCounterResetCollisionWarning")
	if !ok || n.Range.StartByte != 0 || n.Range.EndByte != len(query) || len(r.Vector) != 0 {
		t.Fatalf("collision: notes %+v result %+v", notes, r)
	}
}

// A histogram counter whose second sample is a reset still measures the
// start-edge zero cap against the first sample's own count: counts 4 then 2
// over (0,20] extrapolate by (5+2.5+5)/5 = 2.5 (the 10s cap distance is not
// reached), so the count rate is 2*2.5/20 and the sum rate 3*2.5/20.
func TestReleaseHistogramRateResetKeepsFirstSampleCountForZeroCap(t *testing.T) {
	p := featureProfile(t, relP313)
	series := metricSeries("h_total", nil, relHistSample(10, relExp(6, 1, 4)), relHistSample(15, relExp(3, 1, 2)))
	r, _, err := evalWith(t, p, "rate(h_total[20s])", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	h := relHistogramOf(t, r, 0)
	relNear(t, "count rate", relFloat(h.Count), 0.25)
	relNear(t, "sum rate", relFloat(h.Sum), 0.375)
}

// Subquery materialization sets explicit reset/not-reset hints to unknown, so
// strictly increasing counts with a reset hint are not resets (3.13.5 only).
func TestReleaseHistogramSubqueryClearsExplicitResetHints(t *testing.T) {
	p := featureProfile(t, relP313)
	series := metricSeries("h_total", nil,
		relHistSample(5, relHint(relExp(1.5, 1, 1), "reset")), relHistSample(10, relHint(relExp(3, 1, 2), "reset")), relHistSample(15, relHint(relExp(4.5, 1, 3), "reset")))
	direct, _, err := evalWith(t, p, "resets(h_total[20s])", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "resets over raw samples (explicit hints win)", relFloatOf(t, direct, 0), 2)
	sub, _, err := evalWith(t, p, "resets(h_total[20s:5s])", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "resets over the subquery (hints cleared)", relFloatOf(t, sub, 0), 0)
}

// 3.1.0 variance: a bucket that spans zero (the first custom bucket, from
// -Inf) is represented by 0, so a histogram whose only observations sit in it
// has mean 0 and variance 0.
func TestReleaseHistogramVarianceZeroCrossingCustomBucketIsZero(t *testing.T) {
	p := featureProfile(t, relP31)
	series := metricSeries("h_total", nil, relHistSample(15, relCustom(0, []float64{1, 2, 4}, 2, 0, 0, 0)))
	r, _, err := evalWith(t, p, "histogram_stdvar(h_total)", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "stdvar", relFloatOf(t, r, 0), 0)
	// A populated (4,+Inf] bucket has an infinite representative: the
	// variance keeps the IEEE +Inf outcome instead of turning into NaN.
	series = metricSeries("h_total", nil, relHistSample(15, relCustom(30, []float64{1, 2, 4}, 2, 0, 0, 3)))
	r, _, err = evalWith(t, p, "histogram_stdvar(h_total)", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	if got := relFloatOf(t, r, 0); !math.IsInf(got, 1) {
		t.Fatalf("stdvar with an infinite representative = %v, want +Inf", got)
	}
}

// An info series is chosen by its original sample timestamp, not by the
// evaluation time the selector stamps on every vector sample.
func TestReleaseHistogramInfoNewerOriginalTimestampWins(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id, "promql-experimental-functions")
		base := metricSeries("m_total", model.Labels{{Name: "instance", Value: "a"}, {Name: "job", Value: "j"}}, relFloatSample(15, 1))
		eu := metricSeries("target_info", model.Labels{{Name: "instance", Value: "a"}, {Name: "job", Value: "j"}, {Name: "region", Value: "eu"}}, relFloatSample(15, 1))
		us := metricSeries("target_info", model.Labels{{Name: "instance", Value: "a"}, {Name: "job", Value: "j"}, {Name: "region", Value: "us"}}, relFloatSample(12, 1))
		r, _, err := evalWith(t, p, "info(m_total)", instantAt(20_000), base, eu, us)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if len(r.Vector) != 1 || value.Label(r.Vector[0].Labels, "region") != "eu" {
			t.Fatalf("%s: want the newer series (region=eu) copied, got %+v", id, r.Vector)
		}
	}
}

// Trimming recomputes the estimated sum from the surviving populations and
// representatives; the result must not depend on map iteration order.
func TestReleaseHistogramTrimSumIsDeterministic(t *testing.T) {
	p := featureProfile(t, relP313)
	h := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: 18, Sum: relBits(20), ZeroCount: 3, ZeroThreshold: relBits(0.5),
		PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 3}}, PositiveCounts: []model.AbsoluteBucket{2, 4, 6},
		NegativeSpans: []model.HistogramSpan{{Offset: 1, Length: 2}}, NegativeCounts: []model.AbsoluteBucket{1, 2}, ResetHint: "unknown"}}
	series := metricSeries("h_total", nil, relHistSample(15, h))
	var first uint64
	for i := 0; i < 64; i++ {
		r, _, err := evalWith(t, p, "h_total </ 3", instantAt(20_000), series)
		if err != nil {
			t.Fatal(err)
		}
		got := uint64(relHistogramOf(t, r, 0).Sum)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("trim sum differs between identical evaluations: %x vs %x", got, first)
		}
	}
}

// A custom bucket that spans zero in a histogram with no negative
// observations is walked as [0, upper], so (-1,1] contributes its whole
// population to the rank at 0: ranks at 0 and 3 are 2 and 2+5+8*(2/3), and
// the fraction is (5+16/3)/20.
func TestReleaseHistogramFractionCustomBucketSpanningZero(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		series := metricSeries("h_total", nil, relHistSample(15, relCustom(40, []float64{-1, 1, 4}, 2, 5, 8, 5)))
		r, _, err := evalWith(t, p, "histogram_fraction(0, 3, h_total)", instantAt(20_000), series)
		if err != nil {
			t.Fatal(err)
		}
		relNear(t, id+" fraction", relFloatOf(t, r, 0), (5+16.0/3)/20)
	}
}

// relH is a general integer histogram: schema, zero threshold, zero count and
// one span of consecutive populated buckets (absolute counts).
func relH(schema int32, zeroThreshold float64, zeroCount uint64, sum float64, offset int32, counts ...uint64) *model.NativeHistogram {
	total := zeroCount
	abs := make([]model.AbsoluteBucket, len(counts))
	for i, c := range counts {
		total += c
		abs[i] = model.AbsoluteBucket(c)
	}
	h := &model.IntegerHistogram{Flavor: "counter", Schema: schema, ZeroThreshold: relBits(zeroThreshold), ZeroCount: model.Uint64(zeroCount), Count: model.Uint64(total), Sum: relBits(sum), ResetHint: "unknown"}
	if len(counts) > 0 {
		h.PositiveSpans = []model.HistogramSpan{{Offset: offset, Length: uint32(len(counts))}}
		h.PositiveCounts = abs
	}
	return &model.NativeHistogram{Integer: h}
}

func relView(t *testing.T, h *model.NativeHistogram) model.FloatHistogram {
	t.Helper()
	if h == nil {
		t.Fatal("want a histogram sample")
	}
	return value.FloatHistogram(*h)
}

func relBuckets(h model.FloatHistogram) map[int32]float64 {
	return value.HistogramBuckets(h.PositiveSpans, h.PositiveBuckets)
}

func relSeriesBy(name string, extra ...string) model.Labels {
	labels := model.Labels{}
	for i := 0; i+1 < len(extra); i += 2 {
		labels = append(labels, model.Label{Name: extra[i], Value: extra[i+1]})
	}
	return labels
}

func relCategories(notes []syntax.Diagnostic) []string {
	out := []string{}
	for _, n := range notes {
		out = append(out, n.Category)
	}
	return out
}

// Every annotation rule: the firing input records exactly that identity, at the
// triggering expression or parameter; the nearest ineligible input records
// nothing. Ranges follow the rule text: aggregation and range-function
// annotations belong to the aggregated or range argument, binary-operator
// annotations to the whole binary expression, parameter warnings to the
// parameter.
func TestReleaseHistogramAnnotationRules(t *testing.T) {
	J := model.Labels{{Name: "job", Value: "generic"}}
	classicNamed := func(name string, counts ...float64) []value.Series {
		out := []value.Series{}
		for i, le := range []string{"1", "2", "+Inf"} {
			out = append(out, metricSeries(name, append(model.Labels{{Name: "le", Value: le}}, J...), relFloatSample(15, counts[i])))
		}
		return out
	}
	classic := func(counts ...float64) []value.Series { return classicNamed("cb_bucket", counts...) }
	hist := func(name string, h *model.NativeHistogram, extra ...model.Label) value.Series {
		return metricSeries(name, append(append(model.Labels{}, extra...), J...), relHistSample(15, h))
	}
	flt := func(name string, f float64, extra ...model.Label) value.Series {
		return metricSeries(name, append(append(model.Labels{}, extra...), J...), relFloatSample(15, f))
	}
	two := func(t1, t2 int64, h1, h2 *model.NativeHistogram) []value.Series {
		return []value.Series{metricSeries("g_total", J, relHistSample(t1, h1), relHistSample(t2, h2))}
	}
	gauge := func(h *model.NativeHistogram) *model.NativeHistogram {
		h.Integer.Flavor, h.Integer.ResetHint = "gauge", "gauge"
		return h
	}
	exp, custom := relExp(6, 1, 4), relCustom(9, []float64{1, 2}, 1, 2, 3)
	custom2 := relCustom(9, []float64{1, 3}, 1, 2, 3)
	a1, a2 := model.Label{Name: "a", Value: "1"}, model.Label{Name: "a", Value: "2"}
	type tc struct {
		id       string
		profiles []string
		enabled  []string
		query    string
		fire     []value.Series
		quiet    []value.Series
		span     string // substring of query the annotation must cover; "" = whole expression; "-" = unchecked
	}
	cases := []tc{
		{"BadBucketLabelWarning", []string{relP31, relP313}, nil, "histogram_quantile(0.5, cb_bucket)", append(classic(1, 2, 3), metricSeries("cb_bucket", model.Labels{{Name: "le", Value: "x"}, {Name: "job", Value: "generic"}}, relFloatSample(15, 1))), classic(1, 2, 3), "-"},
		{"HistogramIgnoredInAggregationInfo", []string{relP31, relP313}, nil, "max(hs_total)", []value.Series{hist("hs_total", exp)}, []value.Series{flt("hs_total", 5)}, "hs_total"},
		{"HistogramQuantileForcedMonotonicityInfo", []string{relP31, relP313}, nil, "histogram_quantile(0.5, cb_bucket)", classic(3, 2, 5), classic(1, 2, 5), "-"},
		{"IncompatibleCustomBucketsHistogramsWarning", []string{relP31}, nil, "left_total + right_total", []value.Series{hist("left_total", custom), hist("right_total", custom2)}, []value.Series{hist("left_total", custom), hist("right_total", custom)}, ""},
		{"MismatchedCustomBucketsHistogramsInfo", []string{relP313}, nil, "left_total + right_total", []value.Series{hist("left_total", custom), hist("right_total", custom2)}, []value.Series{hist("left_total", custom), hist("right_total", custom)}, ""},
		{"IncompatibleTypesInBinOpInfo", []string{relP31, relP313}, nil, "hs_total + 1", []value.Series{hist("hs_total", exp)}, []value.Series{flt("hs_total", 1)}, ""},
		{"InvalidQuantileWarning", []string{relP31, relP313}, nil, "quantile(2, fl_total)", []value.Series{flt("fl_total", 1)}, nil, "2"},
		{"InvalidRatioWarning", []string{relP31, relP313}, []string{"promql-experimental-functions"}, "limit_ratio(2, fl_total)", []value.Series{flt("fl_total", 1)}, nil, "2"},
		{"MixedClassicNativeHistogramsWarning", []string{relP31, relP313}, nil, "histogram_quantile(0.5, m)", append(classicNamed("m", 1, 2, 3), hist("m", exp)), classicNamed("m", 1, 2, 3), "-"},
		{"MixedExponentialCustomHistogramsWarning", []string{relP31, relP313}, nil, "sum(h_total)", []value.Series{hist("h_total", exp, a1), hist("h_total", custom, a2)}, []value.Series{hist("h_total", exp, a1), hist("h_total", relExp(12, 1, 8), a2)}, "h_total"},
		{"MixedFloatsHistogramsWarning", []string{relP31, relP313}, nil, "sum(h_total)", []value.Series{hist("h_total", exp, a1), flt("h_total", 1, a2)}, []value.Series{flt("h_total", 2, a1), flt("h_total", 1, a2)}, "h_total"},
		{"NativeHistogramNotCounterWarning", []string{relP31, relP313}, nil, "rate(g_total[20s])", two(10, 15, gauge(relExp(6, 1, 4)), gauge(relExp(6, 1, 4))), two(10, 15, relExp(6, 1, 4), relExp(6, 1, 4)), "g_total[20s]"},
		{"NativeHistogramNotGaugeWarning", []string{relP31, relP313}, nil, "delta(g_total[20s])", two(10, 15, relExp(6, 1, 4), relExp(6, 1, 4)), two(10, 15, gauge(relExp(6, 1, 4)), gauge(relExp(6, 1, 4))), "g_total[20s]"},
		{"PossibleNonCounterInfo", []string{relP31, relP313}, nil, "rate(gauge_metric[20s])", []value.Series{metricSeries("gauge_metric", J, relFloatSample(10, 1), relFloatSample(15, 2))}, []value.Series{metricSeries("gauge_metric_total", J, relFloatSample(10, 1), relFloatSample(15, 2))}, "gauge_metric[20s]"},
		{"HistogramCounterResetCollisionWarning", []string{relP313}, nil, "left_total + right_total", []value.Series{hist("left_total", relHint(relExp(6, 1, 4), "reset")), hist("right_total", relHint(relExp(6, 1, 4), "not_reset"))}, []value.Series{hist("left_total", relHint(relExp(6, 1, 4), "reset")), hist("right_total", relExp(6, 1, 4))}, ""},
		{"IncompatibleBucketLayoutInBinOpWarning", []string{relP313}, nil, "left_total + right_total", []value.Series{hist("left_total", exp), hist("right_total", custom)}, []value.Series{hist("left_total", exp), hist("right_total", relExp(6, 1, 4))}, ""},
		{"NativeHistogramQuantileNaNResultInfo", []string{relP313}, nil, "histogram_quantile(0.99, hn_total)", []value.Series{hist("hn_total", relNaNObservations())}, []value.Series{hist("hn_total", relExp(6, 1, 4))}, "-"},
		{"NativeHistogramQuantileNaNSkewInfo", []string{relP313}, nil, "histogram_quantile(0.3, hn_total)", []value.Series{hist("hn_total", relNaNObservations())}, []value.Series{hist("hn_total", relExp(6, 1, 4))}, "-"},
		{"NativeHistogramFractionNaNsInfo", []string{relP313}, nil, "histogram_fraction(0, 2, hn_total)", []value.Series{hist("hn_total", relNaNObservations())}, []value.Series{hist("hn_total", relExp(6, 1, 4))}, "-"},
	}
	for _, c := range cases {
		for _, id := range c.profiles {
			p := featureProfile(t, id, c.enabled...)
			_, notes, err := evalWith(t, p, c.query, instantAt(20_000), c.fire...)
			if err != nil {
				t.Fatalf("%s/%s fire: %v", id, c.id, err)
			}
			n, ok := relNote(t, notes, c.id)
			if !ok {
				t.Fatalf("%s/%s: %q did not annotate: %v", id, c.id, c.query, relCategories(notes))
			}
			if c.span != "-" {
				want := [2]int{0, len(c.query)}
				if c.span != "" {
					want = relSpan(t, c.query, c.span)
				}
				if n.Range.StartByte != want[0] || n.Range.EndByte != want[1] {
					t.Fatalf("%s/%s: range %d..%d, want %v", id, c.id, n.Range.StartByte, n.Range.EndByte, want)
				}
			}
			if c.quiet != nil {
				_, notes, err = evalWith(t, p, c.query, instantAt(20_000), c.quiet...)
				if err != nil {
					t.Fatalf("%s/%s quiet: %v", id, c.id, err)
				}
				if _, bad := relNote(t, notes, c.id); bad {
					t.Fatalf("%s/%s: the ineligible input annotated: %v", id, c.id, relCategories(notes))
				}
			}
		}
	}
	// Parameter warnings: the boundary values 0 and 1 are valid.
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, q := range []string{"quantile(0, fl_total)", "quantile(1, fl_total)"} {
			_, notes, err := evalWith(t, p, q, instantAt(20_000), metricSeries("fl_total", J, relFloatSample(15, 1)))
			if _, bad := relNote(t, notes, "InvalidQuantileWarning"); err != nil || bad {
				t.Fatalf("%s %s: %v %v", id, q, err, relCategories(notes))
			}
		}
		for _, q := range []string{"quantile(-0.5, fl_total)", "quantile(NaN, fl_total)"} {
			_, notes, err := evalWith(t, p, q, instantAt(20_000), metricSeries("fl_total", J, relFloatSample(15, 1)))
			if _, ok := relNote(t, notes, "InvalidQuantileWarning"); err != nil || !ok {
				t.Fatalf("%s %s must warn: %v %v", id, q, err, relCategories(notes))
			}
		}
	}
}

// relNaNObservations has 6 observations in buckets and 4 NaN observations that
// are in no bucket (count 10, NaN sum).
func relNaNObservations() *model.NativeHistogram {
	h := relExp(math.NaN(), 0, 1, 2, 3)
	h.Integer.Count = 10
	return h
}

// Annotations are keyed by their rendered text: a duplicate replaces the
// previous one, so one annotation survives however many series or steps raise
// it, while distinct annotations accumulate.
func TestReleaseHistogramAnnotationsDeduplicate(t *testing.T) {
	J := model.Labels{{Name: "job", Value: "generic"}}
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		var series []value.Series
		for _, a := range []string{"1", "2", "3"} {
			series = append(series, metricSeries("hs_total", append(model.Labels{{Name: "a", Value: a}}, J...), relHistSample(15, relExp(6, 1, 4)), relHistSample(20, relExp(6, 1, 4))))
		}
		series = append(series, metricSeries("hs_total", model.Labels{{Name: "a", Value: "4"}, {Name: "job", Value: "generic"}}, relFloatSample(15, 5), relFloatSample(20, 5)))
		_, notes, err := evalWith(t, p, "max(hs_total)", instantAt(20_000), series...)
		if err != nil {
			t.Fatal(err)
		}
		if len(notes) != 1 || notes[0].Category != "HistogramIgnoredInAggregationInfo" {
			t.Fatalf("%s instant: want one deduplicated annotation, got %v", id, relCategories(notes))
		}
		_, notes, err = evalWith(t, p, "max(hs_total)", rangeOf(15_000, 25_000, 5_000), series...)
		if err != nil {
			t.Fatal(err)
		}
		if len(notes) != 1 {
			t.Fatalf("%s range: want one deduplicated annotation, got %v", id, relCategories(notes))
		}
		all := append(series, metricSeries("fl_total", J, relFloatSample(15, 1)))
		_, notes, err = evalWith(t, p, "max(hs_total) or quantile(2, fl_total)", instantAt(20_000), all...)
		if err != nil {
			t.Fatal(err)
		}
		if len(notes) != 2 {
			t.Fatalf("%s: distinct annotations must accumulate, got %v", id, relCategories(notes))
		}
	}
}

// Reset detection (resets() over two samples), one case per clause of the rule:
// an explicit reset hint wins true and a not-reset hint wins false; otherwise a
// decreased count, an incompatible schema kind, an increased resolution, a
// decreased zero threshold, a larger zero threshold cutting a populated bucket,
// a reduced adjusted zero count, a disappeared populated bucket or any
// decreased comparable bucket is a reset. Gauge flavor alone is not.
func TestReleaseHistogramResetDetectionClauses(t *testing.T) {
	gaugeOf := func(h *model.NativeHistogram) *model.NativeHistogram {
		h.Integer.Flavor, h.Integer.ResetHint = "gauge", "gauge"
		return h
	}
	cases := []struct {
		name          string
		prev, current *model.NativeHistogram
		want          float64
	}{
		{"decreased count", relExp(6, 1, 4), relExp(6, 1, 3), 1},
		{"incompatible schema kind", relExp(6, 1, 4), relCustom(6, []float64{1, 2}, 0, 4, 0), 1},
		{"increased resolution", relExp(6, 1, 4), relH(1, 0, 0, 6, 1, 2, 2), 1},
		{"decreased zero threshold", relH(0, 0.5, 2, 6, 1, 4), relH(0, 0.1, 2, 6, 1, 4), 1},
		{"larger zero threshold cuts a populated bucket", relH(0, 0, 0, 6, 1, 4), relH(0, 1.5, 4, 6, 2, 0), 1},
		{"reduced adjusted zero count", relH(0, 0, 3, 6, 1, 1), relH(0, 2, 3, 6, 2, 1), 1},
		{"disappeared populated bucket", relExp(6, 1, 4), relExp(6, 2, 4), 1},
		{"decreased comparable bucket", relExp(6, 1, 2, 2), relExp(6, 1, 1, 4), 1},
		{"explicit reset hint wins true", relExp(6, 1, 4), relHint(relExp(6, 1, 5), "reset"), 1},
		{"explicit not-reset hint wins false", relExp(6, 1, 4), relHint(relExp(6, 1, 2), "not_reset"), 0},
		{"gauge flavor alone", relExp(6, 1, 4), gaugeOf(relExp(6, 1, 4)), 0},
		{"identical", relExp(6, 1, 4), relExp(6, 1, 4), 0},
		{"new bucket with unchanged others", relExp(6, 1, 4), relExp(6, 1, 4, 1), 0},
		{"reduced resolution with merged populations", relH(1, 0, 0, 6, 2, 2, 2), relExp(6, 1, 2, 2), 0},
		{"reduced resolution with a vanished merged bucket", relH(1, 0, 0, 6, 2, 2, 2), relExp(6, 1, 4), 1},
	}
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, c := range cases {
			r, _, err := evalWith(t, p, "resets(h_total[20s])", instantAt(20_000), metricSeries("h_total", nil, relHistSample(10, c.prev), relHistSample(15, c.current)))
			if err != nil {
				t.Fatalf("%s %s: %v", id, c.name, err)
			}
			if got := relFloatOf(t, r, 0); got != c.want {
				t.Fatalf("%s %s: resets = %v, want %v", id, c.name, got, c.want)
			}
		}
	}
}

// Scaling multiplies populations, count, sum and zero count and yields a
// histogram sample (never a float); a negative factor marks gauge (3.13.5);
// dividing by zero leaves no ordinary buckets and sends count, sum and zero
// count to +-Inf, or NaN where the numerator is zero.
func TestReleaseHistogramScaleFacts(t *testing.T) {
	p := featureProfile(t, relP313)
	h := relH(0, 0.5, 2, 12.5, 1, 1, 2, 3)
	series := metricSeries("h_total", nil, relHistSample(15, h))
	r, _, err := evalWith(t, p, "h_total * 2", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	f := relHistogramOf(t, r, 0)
	relNear(t, "count", relFloat(f.Count), 16)
	relNear(t, "sum", relFloat(f.Sum), 25)
	relNear(t, "zero count", relFloat(f.ZeroCount), 4)
	b := relBuckets(f)
	if len(b) != 3 || b[1] != 2 || b[2] != 4 || b[3] != 6 {
		t.Fatalf("scaled populations %v, want 2,4,6", b)
	}
	r, _, err = evalWith(t, p, "h_total * -1", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	if f = relHistogramOf(t, r, 0); f.Flavor != "gauge" || relFloat(f.Count) != -8 {
		t.Fatalf("negative scale: flavor %s count %v", f.Flavor, relFloat(f.Count))
	}
	r, _, err = evalWith(t, p, "h_total / 0", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	f = relHistogramOf(t, r, 0)
	if len(f.PositiveBuckets) != 0 || !math.IsInf(relFloat(f.Count), 1) || !math.IsInf(relFloat(f.Sum), 1) || !math.IsInf(relFloat(f.ZeroCount), 1) {
		t.Fatalf("divide by zero: %+v", f)
	}
	empty := metricSeries("h_total", nil, relHistSample(15, relH(0, 0, 0, 0, 0)))
	r, _, err = evalWith(t, p, "h_total / 0", instantAt(20_000), empty)
	if err != nil {
		t.Fatal(err)
	}
	if f = relHistogramOf(t, r, 0); !math.IsNaN(relFloat(f.Count)) || !math.IsNaN(relFloat(f.Sum)) {
		t.Fatalf("0/0 histogram: count %v sum %v, want NaN", relFloat(f.Count), relFloat(f.Sum))
	}
}

// Variance = compensated sum(bucket count * (representative - mean)^2) / count.
// The representative of a non-zero-crossing bucket is the signed geometric
// midpoint; custom buckets are the arithmetic midpoint in 3.13.5 and the
// geometric midpoint in 3.1.0.
func TestReleaseHistogramVarianceFacts(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		// One exponential bucket (1,2]: 4 observations, sum 6, mean 1.5,
		// representative sqrt(2): variance (sqrt(2)-1.5)^2.
		r, _, err := evalWith(t, p, "histogram_stdvar(h_total)", instantAt(20_000), metricSeries("h_total", nil, relHistSample(15, relExp(6, 1, 4))))
		if err != nil {
			t.Fatal(err)
		}
		want := (math.Sqrt2 - 1.5) * (math.Sqrt2 - 1.5)
		relNear(t, id+" exponential stdvar", relFloatOf(t, r, 0), want)
		r, _, err = evalWith(t, p, "histogram_stddev(h_total)", instantAt(20_000), metricSeries("h_total", nil, relHistSample(15, relExp(6, 1, 4))))
		if err != nil {
			t.Fatal(err)
		}
		relNear(t, id+" exponential stddev", relFloatOf(t, r, 0), math.Sqrt(want))
		// One custom bucket (1,3]: 4 observations, sum 8, mean 2.
		custom := metricSeries("h_total", nil, relHistSample(15, relCustom(8, []float64{1, 3}, 0, 4, 0)))
		r, _, err = evalWith(t, p, "histogram_stdvar(h_total)", instantAt(20_000), custom)
		if err != nil {
			t.Fatal(err)
		}
		wantCustom := 0.0 // arithmetic midpoint 2
		if id == relP31 {
			wantCustom = (2 - math.Sqrt(3)) * (2 - math.Sqrt(3)) // geometric midpoint sqrt(3)
		}
		relNear(t, id+" custom stdvar", relFloatOf(t, r, 0), wantCustom)
		r, _, err = evalWith(t, p, "histogram_stdvar(h_total)", instantAt(20_000), metricSeries("h_total", nil, relHistSample(15, relH(0, 0, 0, 0, 0))))
		if err != nil {
			t.Fatal(err)
		}
		if got := relFloatOf(t, r, 0); !math.IsNaN(got) {
			t.Fatalf("%s empty histogram stdvar = %v, want NaN", id, got)
		}
	}
}

// Native quantile and fraction on hand-interpolated histograms.
func TestReleaseHistogramQuantileAndFractionFacts(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		eval := func(q string, h *model.NativeHistogram) float64 {
			r, _, err := evalWith(t, p, q, instantAt(20_000), metricSeries("h_total", nil, relHistSample(15, h)))
			if err != nil {
				t.Fatalf("%s %s: %v", id, q, err)
			}
			return relFloatOf(t, r, 0)
		}
		exp := relExp(6, 1, 4) // (1,2], 4 observations
		// exponential buckets interpolate uniformly in log2: median sqrt(2)
		relNear(t, id+" exp q0.5", eval("histogram_quantile(0.5, h_total)", exp), math.Sqrt2)
		relNear(t, id+" exp fraction 1..1.5", eval("histogram_fraction(1, 1.5, h_total)", exp), math.Log2(1.5))
		relNear(t, id+" q<0", eval("histogram_quantile(-1, h_total)", exp), math.Inf(-1))
		relNear(t, id+" q>1", eval("histogram_quantile(2, h_total)", exp), math.Inf(1))
		relNear(t, id+" q NaN", eval("histogram_quantile(NaN, h_total)", exp), math.NaN())
		relNear(t, id+" lower>=upper", eval("histogram_fraction(2, 1, h_total)", exp), 0)
		relNear(t, id+" NaN bound", eval("histogram_fraction(NaN, 2, h_total)", exp), math.NaN())
		relNear(t, id+" infinite bounds", eval("histogram_fraction(-Inf, +Inf, h_total)", exp), 1)
		relNear(t, id+" empty histogram", eval("histogram_quantile(0.5, h_total)", relH(0, 0, 0, 0, 0)), math.NaN())
		// custom buckets interpolate linearly
		cb := []float64{1, 2, 4}
		relNear(t, id+" custom q0.5", eval("histogram_quantile(0.5, h_total)", relCustom(6, cb, 0, 4, 0, 0)), 1.5)
		relNear(t, id+" custom fraction", eval("histogram_fraction(1, 1.5, h_total)", relCustom(6, cb, 0, 4, 0, 0)), 0.5)
		relNear(t, id+" custom +Inf bucket returns its lower bound", eval("histogram_quantile(0.5, h_total)", relCustom(6, cb, 0, 0, 0, 4)), 4)
		relNear(t, id+" custom -Inf bucket with positive upper starts at 0", eval("histogram_quantile(0.5, h_total)", relCustom(2, cb, 4, 0, 0, 0)), 0.5)
		relNear(t, id+" custom -Inf bucket with non-positive upper returns upper", eval("histogram_quantile(0.5, h_total)", relCustom(-4, []float64{-1, 1}, 4, 0, 0)), -1)
	}
	// NaN observations (count above the bucket total, NaN sum), 3.13.5: a rank
	// beyond the real buckets is NaN with the result info; a rank inside them
	// keeps its value with the skew info; fraction keeps the original count as
	// denominator and notes the NaNs.
	p := featureProfile(t, relP313)
	series := metricSeries("hn_total", nil, relHistSample(15, relNaNObservations()))
	r, notes, err := evalWith(t, p, "histogram_quantile(0.99, hn_total)", instantAt(20_000), series)
	if _, ok := relNote(t, notes, "NativeHistogramQuantileNaNResultInfo"); err != nil || !ok || !math.IsNaN(relFloatOf(t, r, 0)) {
		t.Fatalf("rank beyond buckets: %v %v %v", r, notes, err)
	}
	r, notes, err = evalWith(t, p, "histogram_quantile(0.3, hn_total)", instantAt(20_000), series)
	if _, ok := relNote(t, notes, "NativeHistogramQuantileNaNSkewInfo"); err != nil || !ok || math.IsNaN(relFloatOf(t, r, 0)) {
		t.Fatalf("rank inside buckets: %v %v %v", r, notes, err)
	}
	r, notes, err = evalWith(t, p, "histogram_fraction(0, 2, hn_total)", instantAt(20_000), series)
	if _, ok := relNote(t, notes, "NativeHistogramFractionNaNsInfo"); err != nil || !ok {
		t.Fatalf("fraction NaNs: %v %v %v", r, notes, err)
	}
	// buckets (0.5,1]:1 (1,2]:2 (2,4]:3 with 10 observations: bounds 0..2 hold 1+2 of 10
	relNear(t, "fraction over the original count", relFloatOf(t, r, 0), 0.3)
}

// Trimming (3.13.5 `</` and `>/`), hand-derived from the rule text. Custom
// buckets (-Inf,1]:2 (1,2]:5 (2,4]:8 (4,+Inf]:5. Crossing finite buckets are
// cut linearly; the estimated sum is rebuilt from midpoints of the surviving
// populations.
func TestReleaseHistogramTrimFacts(t *testing.T) {
	p := featureProfile(t, relP313)
	custom := metricSeries("h_total", nil, relHistSample(15, relCustom(30, []float64{1, 2, 4}, 2, 5, 8, 5)))
	check := func(query string, series value.Series, count, sum float64) model.FloatHistogram {
		t.Helper()
		r, _, err := evalWith(t, p, query, instantAt(20_000), series)
		if err != nil {
			t.Fatal(err)
		}
		f := relHistogramOf(t, r, 0)
		relNear(t, query+" count", relFloat(f.Count), count)
		relNear(t, query+" sum", relFloat(f.Sum), sum)
		return f
	}
	// upper trim at 3: (2,4] keeps 8*(3-2)/(4-2)=4 with midpoint 2.5; (-Inf,1]
	// has an infinite lower bound and a positive upper: midpoint upper/2=0.5;
	// (4,+Inf] is dropped. sum = 2*0.5 + 5*1.5 + 4*2.5.
	check("h_total </ 3", custom, 11, 1+7.5+10)
	// lower trim at 3: (2,4] keeps 4 with midpoint 3.5; (4,+Inf] is kept whole
	// with the infinite upper endpoint represented by its lower bound 4.
	check("h_total >/ 3", custom, 9, 14+20)
	// infinity crossing: (-Inf,1] cut at 0.5 keeps 2*0.5/1 with midpoint 0.25.
	check("h_total </ 0.5", custom, 1, 0.25)
	// lower trim at 0.5 keeps 2*(1-0.5/1)=1 of (-Inf,1] with midpoint (0.5+1)/2
	// and everything above whole: 0.75 + 5*1.5 + 8*3 + 5*4.
	check("h_total >/ 0.5", custom, 19, 0.75+7.5+24+20)
	// upper trim far above every finite bound keeps the finite buckets and
	// drops the (4,+Inf] bucket.
	check("h_total </ 100", custom, 15, 1+7.5+24)
	// a NaN bound discards every ordinary bucket.
	check("h_total </ NaN", custom, 0, 0)
	// exponential (1,2] bucket cut at 1.5 keeps log2(1.5) of 4 observations
	exp := metricSeries("h_total", nil, relHistSample(15, relExp(6, 1, 4)))
	r, _, err := evalWith(t, p, "h_total </ 1.5", instantAt(20_000), exp)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "exponential upper trim count", relFloat(relHistogramOf(t, r, 0).Count), 4*math.Log2(1.5))
	r, _, err = evalWith(t, p, "h_total >/ 1.5", instantAt(20_000), exp)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "exponential lower trim count", relFloat(relHistogramOf(t, r, 0).Count), 4*(1-math.Log2(1.5)))
	// zero bucket [0,0.5] (only positive buckets exist) is cut linearly
	zero := metricSeries("h_total", nil, relHistSample(15, relH(0, 0.5, 3, 20, 1, 2, 4, 6)))
	r, _, err = evalWith(t, p, "h_total </ 0.25", instantAt(20_000), zero)
	if err != nil {
		t.Fatal(err)
	}
	f := relHistogramOf(t, r, 0)
	relNear(t, "zero bucket cut", relFloat(f.ZeroCount), 1.5)
	relNear(t, "count after the cut", relFloat(f.Count), 1.5)
	// a NaN bound propagates NaN through a populated zero bucket
	r, _, err = evalWith(t, p, "h_total </ NaN", instantAt(20_000), zero)
	if err != nil {
		t.Fatal(err)
	}
	f = relHistogramOf(t, r, 0)
	if !math.IsNaN(relFloat(f.Count)) || !math.IsNaN(relFloat(f.ZeroCount)) || !math.IsNaN(relFloat(f.Sum)) {
		t.Fatalf("NaN bound over a zero bucket: %+v", f)
	}
	// Only histogram lhs with float rhs trims; other kinds are removed with an
	// incompatible-types info, and the schema labels are kept.
	for _, q := range []string{"fl_total </ 2", "fl_total >/ 2"} {
		r, notes, err := evalWith(t, p, q, instantAt(20_000), metricSeries("fl_total", nil, relFloatSample(15, 3)))
		if _, ok := relNote(t, notes, "IncompatibleTypesInBinOpInfo"); err != nil || !ok || len(r.Vector) != 0 {
			t.Fatalf("%s: %v %v %v", q, r, notes, err)
		}
	}
	r, _, err = evalWith(t, p, "h_total </ 3", instantAt(20_000), metricSeries("h_total", model.Labels{{Name: "__type__", Value: "histogram"}, {Name: "__unit__", Value: "seconds"}}, relHistSample(15, relExp(6, 1, 4))))
	if err != nil {
		t.Fatal(err)
	}
	if got := value.Label(r.Vector[0].Labels, "__name__"); got != "h_total" || value.Label(r.Vector[0].Labels, "__type__") != "histogram" || value.Label(r.Vector[0].Labels, "__unit__") != "seconds" {
		t.Fatalf("trim must keep the metric schema labels, got %v", r.Vector[0].Labels)
	}
}

// Start-timestamp reset predicate (use-start-timestamps, 3.13.5), per the rule
// text, on two float samples at 10s and 15s whose values only grow: a current
// start timestamp of 0 or after its own sample time is no reset, before the
// previous sample time is no reset, after the previous sample time is a reset,
// and equal to the previous sample time is a reset only when the previous start
// timestamp is known (non-zero) and not after that sample.
func TestReleaseHistogramStartTimestampResetPredicate(t *testing.T) {
	ns := func(seconds int64) *model.UnixNano { v := model.UnixNano(seconds * 1_000_000_000); return &v }
	cases := []struct {
		name         string
		previous, at *model.UnixNano
		want         float64
	}{
		{"current start 0", ns(1), ns(0), 0},
		{"current start in the future", ns(1), ns(16), 0},
		{"current start before the previous sample", ns(1), ns(9), 0},
		{"current start after the previous sample", ns(1), ns(12), 1},
		{"equal to previous sample time, previous start known", ns(5), ns(10), 1},
		{"equal to previous sample time, previous start unknown", nil, ns(10), 0},
		{"equal to previous sample time, previous start after its sample", ns(11), ns(10), 0},
	}
	for _, c := range cases {
		a := relFloatSample(10, 10)
		a.StartTimestamp = c.previous
		b := relFloatSample(15, 20)
		b.StartTimestamp = c.at
		series := metricSeries("c_total", nil, a, b)
		on := featureProfile(t, relP313, "use-start-timestamps")
		r, _, err := evalWith(t, on, "resets(c_total[20s])", instantAt(20_000), series)
		if err != nil {
			t.Fatal(err)
		}
		if got := relFloatOf(t, r, 0); got != c.want {
			t.Fatalf("%s: resets = %v, want %v", c.name, got, c.want)
		}
		off := featureProfile(t, relP313)
		r, _, err = evalWith(t, off, "resets(c_total[20s])", instantAt(20_000), series)
		if err != nil {
			t.Fatal(err)
		}
		if got := relFloatOf(t, r, 0); got != 0 {
			t.Fatalf("%s: without the feature, resets = %v, want 0 (baseline)", c.name, got)
		}
	}
	// A start-timestamp reset is a counter reset: increase takes the last value
	// plus the pre-reset value, extrapolated (no zero cap reached), while a gauge
	// delta is never counter-corrected.
	on := featureProfile(t, relP313, "use-start-timestamps")
	a, b, c := relFloatSample(5, 10), relFloatSample(10, 20), relFloatSample(15, 30)
	a.StartTimestamp, b.StartTimestamp, c.StartTimestamp = ns(1), ns(6), ns(6)
	series := metricSeries("c_total", nil, a, b, c)
	r, _, err := evalWith(t, on, "increase(c_total[20s])", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	// raw 30-10=20 plus the pre-reset 10 = 30, factor (10+left+5)/10 with the
	// zero cap left = 10*(10/30): 30*(10+10/3+5)/10 = 55
	relNear(t, "increase with a start-timestamp reset", relFloatOf(t, r, 0), 55)
	r, _, err = evalWith(t, on, "delta(c_total[20s])", instantAt(20_000), series)
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "delta is not counter-corrected", relFloatOf(t, r, 0), 40)
}

// The start-edge zero cap applies to the histogram count: counts 1 then 11 over
// (0,20] extrapolate to the zero point 5*(1/10)=0.5 s before the first sample,
// factor (5+0.5+5)/5=2.1, so the count rate is 10*2.1/20 and the sum rate
// 15*2.1/20; counts 100 then 110 never reach the cap: factor (5+2.5+5)/5.
func TestReleaseHistogramRateZeroCap(t *testing.T) {
	p := featureProfile(t, relP313)
	h := func(n uint64) *model.NativeHistogram { return relH(0, 0, 0, 1.5*float64(n), 1, n) }
	r, _, err := evalWith(t, p, "rate(t_total[20s])", instantAt(20_000), metricSeries("t_total", nil, relHistSample(10, h(1)), relHistSample(15, h(11))))
	if err != nil {
		t.Fatal(err)
	}
	f := relHistogramOf(t, r, 0)
	relNear(t, "capped count rate", relFloat(f.Count), 1.05)
	relNear(t, "capped sum rate", relFloat(f.Sum), 15*2.1/20)
	r, _, err = evalWith(t, p, "rate(t_total[20s])", instantAt(20_000), metricSeries("t_total", nil, relHistSample(10, h(100)), relHistSample(15, h(110))))
	if err != nil {
		t.Fatal(err)
	}
	relNear(t, "uncapped count rate", relFloat(relHistogramOf(t, r, 0).Count), 10*2.5/20)
}

// After delayed name removal, range matrices that end up with identical labels
// merge when their timestamps do not overlap (here a_total answers at 15s and
// b_total at 25s); overlapping timestamps stay an error.
func TestReleaseHistogramDelayedNameRangeMerge(t *testing.T) {
	p := featureProfile(t, relP313, "promql-delayed-name-removal")
	lbl := model.Labels{{Name: "x", Value: "1"}}
	a := metricSeries("a_total", lbl, relFloatSample(10, 1), relFloatSample(15, 2))
	bLate := metricSeries("b_total", lbl, relFloatSample(20, 1), relFloatSample(25, 3))
	bSame := metricSeries("b_total", lbl, relFloatSample(10, 1), relFloatSample(15, 3))
	const query = `rate({__name__=~"a_total|b_total"}[6s])`
	r, _, err := evalWith(t, p, query, rangeOf(15_000, 25_000, 5_000), a, bLate)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 2 || value.Label(r.Matrix[0].Labels, "__name__") != "" {
		t.Fatalf("want one merged series without a name and two samples, got %+v", r.Matrix)
	}
	relNear(t, "a_total at 15s", math.Float64frombits(uint64(r.Matrix[0].Samples[0].Float)), 1.0/5)
	relNear(t, "b_total at 25s", math.Float64frombits(uint64(r.Matrix[0].Samples[1].Float)), 2.0/5)
	_, _, err = evalWith(t, p, query, rangeOf(15_000, 25_000, 5_000), a, bSame)
	var le *syntax.LanguageError
	if !errors.As(err, &le) || le.Code != "result.duplicate-labelset" {
		t.Fatalf("overlapping timestamps must stay an error, got %v", err)
	}
}

// A metadata-label-changing operation removes __name__, __type__ and
// __unit__ together whether or not type-and-unit-labels is enabled; trim
// operators do not change the metric schema.
func TestReleaseHistogramReservedNameRemoval(t *testing.T) {
	typed := metricSeries("m_total", model.Labels{{Name: "__type__", Value: "counter"}, {Name: "__unit__", Value: "seconds"}, {Name: "job", Value: "generic"}}, relFloatSample(10, 1), relFloatSample(15, 2))
	for _, enabled := range [][]string{nil, {"type-and-unit-labels"}} {
		p := featureProfile(t, relP313, enabled...)
		r, _, err := evalWith(t, p, "rate(m_total[20s])", instantAt(20_000), typed)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Vector) != 1 || len(r.Vector[0].Labels) != 1 || r.Vector[0].Labels[0].Name != "job" {
			t.Fatalf("features %v: rate must keep only job, got %v", enabled, r.Vector)
		}
	}
	p := featureProfile(t, relP313, "type-and-unit-labels", "promql-delayed-name-removal")
	r, _, err := evalWith(t, p, "rate(m_total[20s]) * 2", instantAt(20_000), typed)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Vector) != 1 || len(r.Vector[0].Labels) != 1 || r.Vector[0].Labels[0].Name != "job" {
		t.Fatalf("delayed removal must still strip the metadata labels at the end, got %v", r.Vector)
	}
}

// type-and-unit-labels switches the counter heuristic: enabled, a named float
// rate input is checked by its __type__ label; disabled, by the metric-name
// suffix.
func TestReleaseHistogramTypeUnitFeatureSwitchesCounterHeuristic(t *testing.T) {
	samples := []value.Sample{relFloatSample(10, 1), relFloatSample(15, 2)}
	typed := func(name, ty string) value.Series {
		return metricSeries(name, model.Labels{{Name: "__type__", Value: ty}, {Name: "job", Value: "generic"}}, samples...)
	}
	on := featureProfile(t, relP313, "type-and-unit-labels")
	off := featureProfile(t, relP313)
	for _, tc := range []struct {
		profile string
		series  value.Series
		want    string
	}{
		{"on", typed("m_total", "gauge"), "PossibleNonCounterLabelInfo"},
		{"on", typed("m", "counter"), ""},
		{"on", typed("m", "histogram"), ""},
		{"off", typed("m", "counter"), "PossibleNonCounterInfo"},
		{"off", typed("m_total", "gauge"), ""},
	} {
		p := on
		if tc.profile == "off" {
			p = off
		}
		_, notes, err := evalWith(t, p, "rate(m_total[20s])", instantAt(20_000), tc.series)
		if tc.series.Labels[0].Value == "m" {
			_, notes, err = evalWith(t, p, "rate(m[20s])", instantAt(20_000), tc.series)
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "" && len(notes) != 0 || tc.want != "" && (len(notes) != 1 || notes[0].Category != tc.want) {
			t.Fatalf("%s %v: want %q, got %v", tc.profile, tc.series.Labels, tc.want, relCategories(notes))
		}
	}
}

// Exponential histograms reconcile to the coarser schema and the larger
// compatible zero threshold; 3.13.5 reconciles custom bounds by their
// intersection and sums the populations into the common buckets, while 3.1.0
// rejects differing custom bounds (annotating and omitting the result);
// exponential and custom schemas never combine.
func TestReleaseHistogramLayoutReconciliation(t *testing.T) {
	a := metricSeries("h_total", model.Labels{{Name: "a", Value: "1"}}, relHistSample(15, relExp(9, 1, 1, 2, 3)))
	b := metricSeries("h_total", model.Labels{{Name: "a", Value: "2"}}, relHistSample(15, relH(1, 0, 0, 12, 2, 1, 2, 2, 3)))
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		r, _, err := evalWith(t, p, "sum(h_total)", instantAt(20_000), a, b)
		if err != nil {
			t.Fatal(err)
		}
		f := relHistogramOf(t, r, 0)
		// schema 1 buckets 2,3,4,5 fold into schema 0 buckets 1,2,2,3
		bk := relBuckets(f)
		if f.Schema != 0 || len(bk) != 3 || bk[1] != 2 || bk[2] != 6 || bk[3] != 6 {
			t.Fatalf("%s: schema %d buckets %v, want schema 0 with 2,6,6", id, f.Schema, bk)
		}
	}
	left := metricSeries("left_total", nil, relHistSample(15, relCustom(9, []float64{1, 2}, 1, 2, 3)))
	right := metricSeries("right_total", nil, relHistSample(15, relCustom(9, []float64{1, 3}, 1, 2, 3)))
	r, notes, err := evalWith(t, featureProfile(t, relP313), "left_total + right_total", instantAt(20_000), left, right)
	if err != nil {
		t.Fatal(err)
	}
	f := relHistogramOf(t, r, 0)
	bk := relBuckets(f)
	if len(f.CustomBounds) != 1 || relFloat(f.CustomBounds[0]) != 1 || bk[0] != 2 || bk[1] != 10 {
		t.Fatalf("3.13.5 intersection of bounds: bounds %v buckets %v, want [1] with 2,10", f.CustomBounds, bk)
	}
	if _, ok := relNote(t, notes, "MismatchedCustomBucketsHistogramsInfo"); !ok {
		t.Fatalf("missing info: %v", relCategories(notes))
	}
	r, notes, err = evalWith(t, featureProfile(t, relP31), "left_total + right_total", instantAt(20_000), left, right)
	if err != nil || len(r.Vector) != 0 {
		t.Fatalf("3.1.0 must omit the incompatible pair: %v %v", r, err)
	}
	if _, ok := relNote(t, notes, "IncompatibleCustomBucketsHistogramsWarning"); !ok {
		t.Fatalf("missing warning: %v", relCategories(notes))
	}
}

// Float-only window functions ignore histograms in a mixed window and say so
// (3.13.5, HistogramIgnoredInMixedRangeInfo); 3.1.0 ignores them silently;
// ts_of_first/last do not ignore histograms; a histogram-only window produces
// neither a result nor the info.
func TestReleaseHistogramMixedRangeAnnotations(t *testing.T) {
	mixed := metricSeries("m", nil, relFloatSample(10, 1), relFloatSample(12, 4), relHistSample(15, relExp(6, 1, 4)), relFloatSample(17, 2))
	only := metricSeries("m", nil, relHistSample(10, relExp(6, 1, 4)), relHistSample(15, relExp(6, 1, 4)))
	for _, fn := range []string{"mad_over_time(m[20s])", "quantile_over_time(0.5, m[20s])", "min_over_time(m[20s])", "max_over_time(m[20s])", "stddev_over_time(m[20s])", "stdvar_over_time(m[20s])", "deriv(m[20s])", "predict_linear(m[20s], 5)", "double_exponential_smoothing(m[20s], 0.5, 0.5)", "ts_of_min_over_time(m[20s])", "ts_of_max_over_time(m[20s])"} {
		p := featureProfile(t, relP313, "promql-experimental-functions")
		r, notes, err := evalWith(t, p, fn, instantAt(20_000), mixed)
		if err != nil || len(r.Vector) != 1 {
			t.Fatalf("%s: %v %v", fn, r, err)
		}
		n, ok := relNote(t, notes, "HistogramIgnoredInMixedRangeInfo")
		anchor := "m[20s]"
		if strings.HasPrefix(fn, "quantile_over_time") {
			anchor = "0.5" // the quantile parameter is the triggering parameter
		}
		if want := relSpan(t, fn, anchor); !ok || n.Range.StartByte != want[0] || n.Range.EndByte != want[1] {
			t.Fatalf("3.13.5 %s: want the info over %q %v, got %v %+v", fn, anchor, want, relCategories(notes), n.Range)
		}
		r, notes, err = evalWith(t, p, fn, instantAt(20_000), only)
		if err != nil || len(r.Vector) != 0 || len(notes) != 0 {
			t.Fatalf("3.13.5 %s on a histogram-only window: %v %v %v", fn, r, notes, err)
		}
	}
	for _, fn := range []string{"ts_of_first_over_time(m[20s])", "ts_of_last_over_time(m[20s])"} {
		p := featureProfile(t, relP313, "promql-experimental-functions")
		_, notes, err := evalWith(t, p, fn, instantAt(20_000), mixed)
		if err != nil || len(notes) != 0 {
			t.Fatalf("%s must not ignore histograms: %v %v", fn, relCategories(notes), err)
		}
	}
	p := featureProfile(t, relP31)
	for _, fn := range []string{"max_over_time(m[20s])", "stddev_over_time(m[20s])", "deriv(m[20s])"} {
		r, notes, err := evalWith(t, p, fn, instantAt(20_000), mixed)
		if err != nil || len(r.Vector) != 1 || len(notes) != 0 {
			t.Fatalf("3.1.0 %s must ignore histograms silently: %v %v %v", fn, r, relCategories(notes), err)
		}
	}
}

// info(): the base series keeps its values, sample kind and labels; extra
// labels of the matching target_info series are copied in, an existing base
// label is not overwritten, and a data-label matcher that no info series
// satisfies drops the base series.
func TestReleaseHistogramInfoJoinFacts(t *testing.T) {
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id, "promql-experimental-functions")
		lbl := func(extra ...model.Label) model.Labels {
			return append(model.Labels{{Name: "instance", Value: "a"}, {Name: "job", Value: "j"}}, extra...)
		}
		hist := metricSeries("m_total", lbl(model.Label{Name: "region", Value: "base"}), relHistSample(15, relExp(6, 1, 4)))
		info := metricSeries("target_info", lbl(model.Label{Name: "env", Value: "prod"}, model.Label{Name: "region", Value: "eu"}), relFloatSample(15, 1))
		r, _, err := evalWith(t, p, "info(m_total)", instantAt(20_000), hist, info)
		if err != nil || len(r.Vector) != 1 {
			t.Fatalf("%s: %v %v", id, r, err)
		}
		got := r.Vector[0]
		if got.Samples[0].Histogram == nil || value.Label(got.Labels, "env") != "prod" || value.Label(got.Labels, "region") != "base" || value.Label(got.Labels, "job") != "j" {
			t.Fatalf("%s: base kept, env copied, region not overwritten: %+v", id, got)
		}
		r, _, err = evalWith(t, p, `info(m_total, {env="dev"})`, instantAt(20_000), hist, info)
		if err != nil || len(r.Vector) != 0 {
			t.Fatalf("%s: unmatched data matcher must drop the base series: %v %v", id, r, err)
		}
	}
}
