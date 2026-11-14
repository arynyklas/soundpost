// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"

	"github.com/arynyklas/soundpost/internal/model"
	promhistbounds "github.com/arynyklas/soundpost/third_party/promhistbounds/v1"
)

// Exponential bucket geometry.
//
// Bucket i of a schema s histogram holds (bound(i-1), bound(i)]. The bounds
// are the pinned engines' own values, not a computed 2^(i / 2^s):
//
//   - schema < 0: bound(i) = 2^(i*2^-s), exact; the bound whose
//     exponent equals 1024 is math.MaxFloat64 (the last finite bucket).
//   - schema >= 0: f = mantissa(s, i mod 2^s) from the precalculated table in
//     third_party/promhistbounds, e = (i >> s) + 1, bound = f * 2^e; f == 0.5
//     with e == 1025 is math.MaxFloat64.
//   - schema > 8 has no table; its bound is NaN rather than an invented value.
//
// A bucket lower bound below the zero threshold is raised to it (negative
// buckets likewise at their upper bound); the zero bucket spans
// [-threshold, threshold].

// exponentialBound is the upper bound of bucket index of an exponential
// schema.
func exponentialBound(schema int32, index int32) float64 {
	if schema < 0 {
		exponent := int64(index) << uint(-schema)
		if exponent == 1024 {
			return math.MaxFloat64
		}
		if exponent > 4096 {
			exponent = 4096
		} else if exponent < -4096 {
			exponent = -4096
		}
		return math.Ldexp(1, int(exponent))
	}
	fraction, ok := promhistbounds.Mantissa(int(schema), int(index&(int32(1)<<schema-1)))
	if !ok {
		return math.NaN()
	}
	exponent := int(index>>schema) + 1
	if fraction == 0.5 && exponent == 1025 {
		return math.MaxFloat64
	}
	return math.Ldexp(fraction, exponent)
}

// nativeBucket is one bucket as the pinned engines enumerate the whole
// histogram: bounds exactly as stored (no clamping to the zero threshold).
type nativeBucket struct {
	lower, upper, count float64
	zero                bool // the zero bucket
}

// nativeBuckets enumerates the buckets of an exponential histogram in
// ascending order of bounds (descending when reverse): negative buckets,
// the zero bucket, positive buckets. Empty buckets are included.
func nativeBuckets(view model.FloatHistogram, reverse bool) []nativeBucket {
	count := func(b model.FloatBits) float64 { return math.Float64frombits(uint64(b)) }
	side := func(spans []model.HistogramSpan, populations []model.FloatBits, bounds func(int32) (float64, float64)) []nativeBucket {
		var out []nativeBucket
		index, position := int32(0), 0
		for _, span := range spans {
			index += span.Offset
			for range span.Length {
				lower, upper := bounds(index)
				out = append(out, nativeBucket{lower: lower, upper: upper, count: count(populations[position])})
				index++
				position++
			}
		}
		return out
	}
	threshold := math.Float64frombits(uint64(view.ZeroThreshold))
	positive := side(view.PositiveSpans, view.PositiveBuckets, func(i int32) (float64, float64) {
		lower := exponentialBound(view.Schema, i-1)
		if lower < threshold {
			lower = threshold
		}
		return lower, exponentialBound(view.Schema, i)
	})
	negative := side(view.NegativeSpans, view.NegativeBuckets, func(i int32) (float64, float64) {
		upper := -exponentialBound(view.Schema, i-1)
		if upper > -threshold {
			upper = -threshold
		}
		return -exponentialBound(view.Schema, i), upper
	})
	zero := nativeBucket{-threshold, threshold, count(view.ZeroCount), true}
	out := make([]nativeBucket, 0, len(positive)+len(negative)+1)
	if reverse {
		for i := len(positive) - 1; i >= 0; i-- {
			out = append(out, positive[i])
		}
		out = append(out, zero)
		return append(out, negative...)
	}
	for i := len(negative) - 1; i >= 0; i-- {
		out = append(out, negative[i])
	}
	out = append(out, zero)
	return append(out, positive...)
}
