// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// quantileBuckets enumerates every bucket of the histogram, empty ones
// included, in ascending order of bounds (descending when reverse). The
// zero bucket is only part of the walk when it holds observations.
func quantileBuckets(view model.FloatHistogram, reverse bool) []nativeBucket {
	if view.Schema != -53 {
		all := nativeBuckets(view, reverse)
		out := all[:0]
		for _, b := range all {
			if b.zero && b.count == 0 {
				continue
			}
			out = append(out, b)
		}
		return out
	}
	var out []nativeBucket
	index, position := int32(0), 0
	for _, span := range view.PositiveSpans {
		index += span.Offset
		for range span.Length {
			lower, upper := math.Inf(-1), math.Inf(1)
			if index > 0 {
				lower = math.Float64frombits(uint64(view.CustomBounds[index-1]))
			}
			if int(index) < len(view.CustomBounds) {
				upper = math.Float64frombits(uint64(view.CustomBounds[index]))
			}
			out = append(out, nativeBucket{lower: lower, upper: upper, count: math.Float64frombits(uint64(view.PositiveBuckets[position]))})
			index++
			position++
		}
	}
	if reverse {
		for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
			out[left], out[right] = out[right], out[left]
		}
	}
	return out
}

// histogramNativeQuantile is histogram_quantile for one native histogram.
//
// Observations of NaN raise the observation count but sit in no bucket (the
// sum is then NaN as well), so a rank can lie beyond the buckets. 3.1.0
// answers such a rank with the upper bound of the last bucket it visited.
// 3.13.5 answers NaN instead, and when the sum is NaN it keeps walking after
// it has found the quantile's bucket: the last bucket of the histogram, not
// the one holding the rank, is then used to interpolate, and a shortfall of the
// bucket total against the count is reported as skew. The returned string is
// the annotation to report, if any.
func histogramNativeQuantile(q float64, h model.NativeHistogram, profileID string) (float64, string) {
	view := histogramView(h)
	total := math.Float64frombits(uint64(view.Count))
	sum := math.Float64frombits(uint64(view.Sum))
	switch {
	case q < 0:
		return math.Inf(-1), ""
	case q > 1:
		return math.Inf(1), ""
	case total == 0 || math.IsNaN(q):
		return math.NaN(), ""
	}
	modern := profileID == "promql-prometheus-3.13.5"
	nanObservations := math.IsNaN(sum)
	forward := nanObservations || q < .5
	rank := float64((1 - q) * total)
	if forward {
		rank = float64(q * total)
	}
	buckets := quantileBuckets(view, !forward)
	var bucket nativeBucket
	var seen float64
	next := 0
	for next < len(buckets) {
		bucket = buckets[next]
		next++
		if bucket.count == 0 {
			continue
		}
		seen += bucket.count
		if seen >= rank {
			break
		}
	}
	if view.Schema != -53 && bucket.lower < 0 && bucket.upper > 0 {
		switch {
		case len(view.NegativeBuckets) == 0 && len(view.PositiveBuckets) > 0:
			bucket.lower = 0 // only positive observations: the zero bucket starts at zero
		case len(view.PositiveBuckets) == 0 && len(view.NegativeBuckets) > 0:
			bucket.upper = 0
		}
	} else if view.Schema == -53 {
		if math.IsInf(bucket.lower, -1) {
			if bucket.upper <= 0 {
				return bucket.upper, ""
			}
			bucket.lower = 0
		} else if math.IsInf(bucket.upper, 1) {
			return bucket.lower, ""
		}
	}
	// Rounding may push the running population past the count.
	seen = math.Min(seen, total)
	if seen < rank {
		if modern && nanObservations {
			return math.NaN(), "NativeHistogramQuantileNaNResultInfo"
		}
		return bucket.upper, ""
	}
	if forward {
		rank -= seen - bucket.count
	} else {
		rank = seen - rank
	}
	annotation := ""
	if modern && nanObservations {
		for ; next < len(buckets); next++ {
			bucket = buckets[next]
			seen += bucket.count
		}
		if seen < total {
			annotation = "NativeHistogramQuantileNaNSkewInfo"
		}
	}
	fraction := value.Div(rank, bucket.count)
	if view.Schema == -53 || bucket.lower <= 0 && bucket.upper >= 0 {
		return value.Add(bucket.lower, value.Mul(value.Sub(bucket.upper, bucket.lower), fraction)), annotation
	}
	// Exponential buckets are interpolated on a logarithmic scale.
	logLower, logUpper := value.Log2(math.Abs(bucket.lower)), value.Log2(math.Abs(bucket.upper))
	if bucket.lower > 0 {
		return value.Exp2(value.Add(logLower, value.Mul(value.Sub(logUpper, logLower), fraction))), annotation
	}
	return -value.Exp2(value.Add(logUpper, value.Mul(value.Sub(logLower, logUpper), 1-fraction))), annotation
}

// openMetricsFloat formats a quantile for a label value: the shortest
// round-tripping %g form, with ".0" appended when that would otherwise show
// neither a decimal point nor an exponent.
func openMetricsFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case f == 0:
		return "0.0"
	}
	text := strconv.FormatFloat(f, 'g', -1, 64)
	if strings.ContainsAny(text, "e.") {
		return text
	}
	return text + ".0"
}
