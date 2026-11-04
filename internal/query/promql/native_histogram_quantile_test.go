// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"reflect"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/query/value"
)

// quantileHistogram has exponential buckets (0.5,1] (1,2] (2,4] holding 1, 2
// and 3 observations (6 in total); count and sum are set independently so the
// NaN-observation shapes of the pinned engines can be described.
func quantileHistogram(sum float64, count uint64) *model.NativeHistogram {
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{
		Flavor: "counter", Schema: 0, Count: model.Uint64(count), Sum: model.FloatBits(math.Float64bits(sum)),
		PositiveSpans:  []model.HistogramSpan{{Offset: 0, Length: 3}},
		PositiveCounts: []model.AbsoluteBucket{1, 2, 3}, ResetHint: "unknown",
	}}
}

var nanObservation = math.Float64frombits(0x7ff8000000000001)

func TestNativeHistogramQuantileNaNObservationRules(t *testing.T) {
	type outcome struct {
		value float64
		notes []string
	}
	skew := func(start, end int) []string {
		return []string{"NativeHistogramQuantileNaNSkewInfo@" + itoa(start) + "-" + itoa(end)}
	}
	nan := func(start, end int) []string {
		return []string{"NativeHistogramQuantileNaNResultInfo@" + itoa(start) + "-" + itoa(end)}
	}
	for _, tc := range []struct {
		profile string
		name    string
		sum     float64
		count   uint64
		q       string
		want    outcome
	}{
		// 3.1.0: running past the buckets answers with the highest bucket's upper bound; no annotations exist.
		{"promql-prometheus-3.1.0", "NaN sum, count>buckets q=0", nanObservation, 10, "0", outcome{0.5, nil}},
		{"promql-prometheus-3.1.0", "NaN sum, count>buckets q=.9", nanObservation, 10, "0.9", outcome{4, nil}},
		{"promql-prometheus-3.1.0", "NaN sum, count>buckets q=.99", nanObservation, 10, "0.99", outcome{4, nil}},
		{"promql-prometheus-3.1.0", "NaN sum, count>buckets q=1", nanObservation, 10, "1", outcome{4, nil}},
		{"promql-prometheus-3.1.0", "finite sum, reverse order of operations", 20, 10, "0.9", outcome{3.1748021039363987, nil}},
		// 3.13.5 with NaN observations: the NaN sum forces forward iteration, an exhausted
		// rank is NaN, and the interpolation bucket is the last bucket of the histogram.
		{"promql-prometheus-3.13.5", "NaN sum q=0", nanObservation, 10, "0", outcome{2, skew(19, 20)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.1", nanObservation, 10, "0.1", outcome{2.519842099789746, skew(19, 22)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.4", nanObservation, 10, "0.4", outcome{2.519842099789746, skew(19, 22)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.5", nanObservation, 10, "0.5", outcome{3.1748021039363987, skew(19, 22)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.6", nanObservation, 10, "0.6", outcome{4, skew(19, 22)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.9", nanObservation, 10, "0.9", outcome{math.NaN(), nan(19, 22)}},
		{"promql-prometheus-3.13.5", "NaN sum q=.99", nanObservation, 10, "0.99", outcome{math.NaN(), nan(19, 23)}},
		{"promql-prometheus-3.13.5", "NaN sum q=1", nanObservation, 10, "1", outcome{math.NaN(), nan(19, 20)}},
		// NaN sum but every observation sits in a bucket: no skew to report.
		{"promql-prometheus-3.13.5", "NaN sum count=buckets q=0", nanObservation, 6, "0", outcome{2, nil}},
		{"promql-prometheus-3.13.5", "NaN sum count=buckets q=.1", nanObservation, 6, "0.1", outcome{2.2973967099940698, nil}},
		{"promql-prometheus-3.13.5", "NaN sum count=buckets q=.4", nanObservation, 6, "0.4", outcome{2.7638257599355525, nil}},
		{"promql-prometheus-3.13.5", "NaN sum count=buckets q=.5", nanObservation, 6, "0.5", outcome{3.1748021039363987, nil}},
		// A finite sum never reports NaN skew, even when the count exceeds the bucket total.
		{"promql-prometheus-3.13.5", "finite sum q=0", 20, 10, "0", outcome{0.5, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.1", 20, 10, "0.1", outcome{1, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.4", 20, 10, "0.4", outcome{2.519842099789746, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.5", 20, 10, "0.5", outcome{1, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.6", 20, 10, "0.6", outcome{1.414213562373095, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.9", 20, 10, "0.9", outcome{3.1748021039363987, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=.99", 20, 10, "0.99", outcome{3.908639873736984, nil}},
		{"promql-prometheus-3.13.5", "finite sum q=1", 20, 10, "1", outcome{4, nil}},
	} {
		p := featureProfile(t, tc.profile)
		query := "histogram_quantile(" + tc.q + ", m)"
		series := metricSeries("m", nil, value.Sample{Time: 10_000_000_000, Histogram: quantileHistogram(tc.sum, tc.count)})
		r, notes, err := evalWith(t, p, query, instantAt(10_000), series)
		if err != nil || len(r.Vector) != 1 {
			t.Fatalf("%s %s: %+v %v", tc.profile, tc.name, r, err)
		}
		got := floatsOf(t, r.Vector[0])[0].Float
		if math.Float64bits(got) != math.Float64bits(tc.want.value) && !(math.IsNaN(got) && math.IsNaN(tc.want.value)) {
			t.Fatalf("%s %s: %v want %v", tc.profile, tc.name, got, tc.want.value)
		}
		// Annotation ranges name the quantile argument.
		keys := diagnosticKeys(notes)
		if len(keys) == 0 {
			keys = nil
		}
		if !reflect.DeepEqual(keys, tc.want.notes) {
			t.Fatalf("%s %s: annotations %v want %v", tc.profile, tc.name, keys, tc.want.notes)
		}
	}
}

func TestNativeHistogramFractionNaNInfoRequiresNaNSum(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5")
	for _, tc := range []struct {
		sum  float64
		want []string
	}{
		{nanObservation, []string{"NativeHistogramFractionNaNsInfo@19-20"}},
		{20, nil},
	} {
		series := metricSeries("m", nil, value.Sample{Time: 10_000_000_000, Histogram: quantileHistogram(tc.sum, 10)})
		r, notes, err := evalWith(t, p, "histogram_fraction(0, 2, m)", instantAt(10_000), series)
		if err != nil || len(r.Vector) != 1 {
			t.Fatalf("%+v %v", r, err)
		}
		keys := diagnosticKeys(notes)
		if len(keys) == 0 {
			keys = nil
		}
		if !reflect.DeepEqual(keys, tc.want) {
			t.Fatalf("sum %v: annotations %v want %v", tc.sum, keys, tc.want)
		}
	}
}

func TestNativeHistogramQuantilesLabelFormatting(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", "promql-experimental-functions")
	series := metricSeries("m", nil, value.Sample{Time: 10_000_000_000, Histogram: quantileHistogram(20, 6)})
	for _, tc := range []struct {
		quantiles string
		labels    []string
	}{
		{"1", []string{"1.0"}},
		{"0", []string{"0.0"}},
		{"-1", []string{"-1.0"}},
		{"2", []string{"2.0"}},
		{"1.5", []string{"1.5"}},
		{"0.9", []string{"0.9"}},
		{"0, 0.5, 1", []string{"0.0", "0.5", "1.0"}},
		{"100000", []string{"100000.0"}},
		{"1000000", []string{"1e+06"}},
		{"1e-7, 123456789.5, 1e21, 0.1234567890123456789", []string{"1e-07", "1.234567895e+08", "1e+21", "0.12345678901234568"}},
		{"nan", []string{"NaN"}},
		{"+Inf", []string{"+Inf"}},
		{"-Inf", []string{"-Inf"}},
	} {
		r, _, err := evalWith(t, p, `histogram_quantiles(m, "quantile", `+tc.quantiles+`)`, instantAt(10_000), series)
		if err != nil || len(r.Vector) != len(tc.labels) {
			t.Fatalf("%s: %+v %v", tc.quantiles, r, err)
		}
		for i, s := range r.Vector {
			if got := value.Label(s.Labels, "quantile"); got != tc.labels[i] {
				t.Fatalf("%s: label %d = %q want %q", tc.quantiles, i, got, tc.labels[i])
			}
		}
	}
}

func TestNativeHistogramQuantilesAnnotationRanges(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", "promql-experimental-functions")
	series := metricSeries("m", nil, value.Sample{Time: 10_000_000_000, Histogram: quantileHistogram(20, 6)})
	for _, tc := range []struct {
		query string
		want  []string
	}{
		// Every invalid quantile is reported at its own argument.
		{`histogram_quantiles(m, "quantile", 1e-7, 123456789.5, 1e21, 0.1234567890123456789)`, []string{"InvalidQuantileWarning@41-52", "InvalidQuantileWarning@54-58"}},
		{`histogram_quantiles(m, "quantile", -1)`, []string{"InvalidQuantileWarning@35-37"}},
		{`histogram_quantiles(m, "quantile", nan)`, []string{"InvalidQuantileWarning@35-38"}},
		{`histogram_quantiles(m, "quantile", 0, 0.5, 1)`, nil},
	} {
		_, notes, err := evalWith(t, p, tc.query, instantAt(10_000), series)
		if err != nil {
			t.Fatalf("%s: %v", tc.query, err)
		}
		keys := diagnosticKeys(notes)
		if len(keys) == 0 {
			keys = nil
		}
		if !reflect.DeepEqual(keys, tc.want) {
			t.Fatalf("%s: annotations %v want %v", tc.query, keys, tc.want)
		}
	}
	// Annotations that concern the input histogram name the vector argument.
	nanSeries := metricSeries("m", nil, value.Sample{Time: 10_000_000_000, Histogram: quantileHistogram(nanObservation, 10)})
	_, notes, err := evalWith(t, p, `histogram_quantiles(m, "quantile", 0.5)`, instantAt(10_000), nanSeries)
	if err != nil {
		t.Fatal(err)
	}
	if got := diagnosticKeys(notes); !reflect.DeepEqual(got, []string{"NativeHistogramQuantileNaNSkewInfo@20-21"}) {
		t.Fatalf("skew annotation %v", got)
	}
}
