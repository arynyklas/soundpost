// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "soundpost/internal/model"

// Histogram allocation form is not language value semantics: nil and a slice
// allocated with length zero both contain no spans/buckets/bounds. Only that
// representation distinction is projected. Nonempty arrays remain untouched,
// as do histogram variants, scalar counts/bits, schema/flavor/reset metadata.
// Raw observations are never mutated and need no allocation without this exact
// nil-versus-empty distinction.
func projectEvaluationSeriesHistograms(in []EvaluationSeries) []EvaluationSeries {
	var out []EvaluationSeries
	for i, series := range in {
		var samples []EvaluationSample
		for j, sample := range series.Samples {
			histogram := projectEvaluationHistogram(sample.Histogram)
			if histogram == sample.Histogram {
				continue
			}
			if out == nil {
				out = make([]EvaluationSeries, len(in))
				copy(out, in)
			}
			if samples == nil {
				samples = make([]EvaluationSample, len(series.Samples))
				copy(samples, series.Samples)
				out[i].Samples = samples
			}
			samples[j].Histogram = histogram
		}
	}
	if out == nil {
		return in
	}
	return out
}
func allocatedEmptyHistogramSlice[T any](s []T) bool { return s != nil && len(s) == 0 }
func projectEvaluationHistogram(in *model.NativeHistogram) *model.NativeHistogram {
	if in == nil {
		return nil
	}
	var out *model.NativeHistogram
	if h := in.Integer; h != nil && (allocatedEmptyHistogramSlice(h.PositiveSpans) || allocatedEmptyHistogramSlice(h.NegativeSpans) || allocatedEmptyHistogramSlice(h.PositiveBuckets) || allocatedEmptyHistogramSlice(h.NegativeBuckets) || allocatedEmptyHistogramSlice(h.PositiveCounts) || allocatedEmptyHistogramSlice(h.NegativeCounts) || allocatedEmptyHistogramSlice(h.CustomBounds)) {
		native := *in
		out = &native
		histogram := *h
		if len(histogram.PositiveSpans) == 0 {
			histogram.PositiveSpans = nil
		}
		if len(histogram.NegativeSpans) == 0 {
			histogram.NegativeSpans = nil
		}
		if len(histogram.PositiveBuckets) == 0 {
			histogram.PositiveBuckets = nil
		}
		if len(histogram.NegativeBuckets) == 0 {
			histogram.NegativeBuckets = nil
		}
		if len(histogram.PositiveCounts) == 0 {
			histogram.PositiveCounts = nil
		}
		if len(histogram.NegativeCounts) == 0 {
			histogram.NegativeCounts = nil
		}
		if len(histogram.CustomBounds) == 0 {
			histogram.CustomBounds = nil
		}
		out.Integer = &histogram
	}
	if h := in.Float; h != nil && (allocatedEmptyHistogramSlice(h.PositiveSpans) || allocatedEmptyHistogramSlice(h.NegativeSpans) || allocatedEmptyHistogramSlice(h.PositiveBuckets) || allocatedEmptyHistogramSlice(h.NegativeBuckets) || allocatedEmptyHistogramSlice(h.CustomBounds)) {
		if out == nil {
			native := *in
			out = &native
		}
		histogram := *h
		if len(histogram.PositiveSpans) == 0 {
			histogram.PositiveSpans = nil
		}
		if len(histogram.NegativeSpans) == 0 {
			histogram.NegativeSpans = nil
		}
		if len(histogram.PositiveBuckets) == 0 {
			histogram.PositiveBuckets = nil
		}
		if len(histogram.NegativeBuckets) == 0 {
			histogram.NegativeBuckets = nil
		}
		if len(histogram.CustomBounds) == 0 {
			histogram.CustomBounds = nil
		}
		out.Float = &histogram
	}
	if out == nil {
		return in
	}
	return out
}
