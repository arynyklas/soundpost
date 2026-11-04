// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"math"
	"sort"
	"soundpost/internal/model"
)

func histogramFloat(v model.FloatBits) float64 { return math.Float64frombits(uint64(v)) }
func histogramBits(v float64) model.FloatBits  { return model.FloatBits(math.Float64bits(v)) }
func histogramIntegerBuckets(spans []model.HistogramSpan, deltas []model.DeltaBucket, absolute []model.AbsoluteBucket) map[int32]uint64 {
	out := map[int32]uint64{}
	index, pos := int32(0), 0
	var count uint64
	for _, s := range spans {
		index += s.Offset
		for j := uint32(0); j < s.Length; j++ {
			if len(absolute) > 0 {
				count = uint64(absolute[pos])
			} else {
				d := int64(deltas[pos])
				if d < 0 {
					count -= uint64(-(d + 1)) + 1
				} else {
					count += uint64(d)
				}
			}
			out[index] = count
			index++
			pos++
		}
	}
	return out
}
func HistogramBuckets(spans []model.HistogramSpan, counts []model.FloatBits) map[int32]float64 {
	out := map[int32]float64{}
	index, pos := int32(0), 0
	for _, s := range spans {
		index += s.Offset
		for j := uint32(0); j < s.Length; j++ {
			out[index] = histogramFloat(counts[pos])
			index++
			pos++
		}
	}
	return out
}
func histogramEncode(counts map[int32]float64) ([]model.HistogramSpan, []model.FloatBits) {
	keys := make([]int32, 0, len(counts))
	for k, v := range counts {
		if v != 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var spans []model.HistogramSpan
	var values []model.FloatBits
	var next int32
	for _, k := range keys {
		if len(spans) == 0 || k != next {
			spans = append(spans, model.HistogramSpan{Offset: k - next, Length: 1})
		} else {
			spans[len(spans)-1].Length++
		}
		values = append(values, histogramBits(counts[k]))
		next = k + 1
	}
	return spans, values
}

// FloatHistogram is the explicit semantic conversion point. Retention and clone
// paths never pass integer counts through binary64.
func FloatHistogram(h model.NativeHistogram) model.FloatHistogram {
	if h.Float != nil {
		copy := CloneHistogram(h)
		return *copy.Float
	}
	integer := h.Integer
	converted := model.FloatHistogram{Flavor: integer.Flavor, Schema: integer.Schema, ZeroThreshold: integer.ZeroThreshold, Sum: integer.Sum, Count: histogramBits(float64(integer.Count)), ZeroCount: histogramBits(float64(integer.ZeroCount)), ResetHint: integer.ResetHint, CustomBounds: append([]model.FloatBits(nil), integer.CustomBounds...), PositiveSpans: append([]model.HistogramSpan(nil), integer.PositiveSpans...), NegativeSpans: append([]model.HistogramSpan(nil), integer.NegativeSpans...)}
	convert := func(deltas []model.DeltaBucket, absolute []model.AbsoluteBucket) []model.FloatBits {
		length := len(deltas)
		if len(absolute) > 0 {
			length = len(absolute)
		}
		buckets := make([]model.FloatBits, length)
		var population uint64
		for index := range length {
			if len(absolute) > 0 {
				population = uint64(absolute[index])
			} else {
				delta := int64(deltas[index])
				if delta < 0 {
					population -= uint64(-(delta + 1)) + 1
				} else {
					population += uint64(delta)
				}
			}
			buckets[index] = histogramBits(float64(population))
		}
		return buckets
	}
	converted.PositiveBuckets = convert(integer.PositiveBuckets, integer.PositiveCounts)
	converted.NegativeBuckets = convert(integer.NegativeBuckets, integer.NegativeCounts)
	return converted
}
func ScaleHistogram(h model.NativeHistogram, factor float64) model.NativeHistogram {
	f := FloatHistogram(h)
	f.Count = histogramBits(histogramFloat(f.Count) * factor)
	f.ZeroCount = histogramBits(histogramFloat(f.ZeroCount) * factor)
	f.Sum = histogramBits(histogramFloat(f.Sum) * factor)
	for i, v := range f.PositiveBuckets {
		f.PositiveBuckets[i] = histogramBits(histogramFloat(v) * factor)
	}
	for i, v := range f.NegativeBuckets {
		f.NegativeBuckets[i] = histogramBits(histogramFloat(v) * factor)
	}
	if factor < 0 {
		f.Flavor = "gauge"
		f.ResetHint = "gauge"
	}
	return model.NativeHistogram{Float: &f}
}

// DivideHistogram performs the language division operation directly. Replacing
// division with multiplication by a rounded reciprocal changes binary64 bits.
func DivideHistogram(histogram model.NativeHistogram, divisor float64) model.NativeHistogram {
	converted := FloatHistogram(histogram)
	converted.Count = histogramBits(histogramFloat(converted.Count) / divisor)
	converted.ZeroCount = histogramBits(histogramFloat(converted.ZeroCount) / divisor)
	converted.Sum = histogramBits(histogramFloat(converted.Sum) / divisor)
	if divisor == 0 {
		converted.PositiveSpans = nil
		converted.PositiveBuckets = nil
		converted.NegativeSpans = nil
		converted.NegativeBuckets = nil
	} else {
		for index, count := range converted.PositiveBuckets {
			converted.PositiveBuckets[index] = histogramBits(histogramFloat(count) / divisor)
		}
		for index, count := range converted.NegativeBuckets {
			converted.NegativeBuckets[index] = histogramBits(histogramFloat(count) / divisor)
		}
	}
	if divisor < 0 {
		converted.Flavor = "gauge"
		converted.ResetHint = "gauge"
	}
	return model.NativeHistogram{Float: &converted}
}
func ReduceHistogramSchema(f model.FloatHistogram, schema int32) model.FloatHistogram {
	if f.Schema <= schema || f.Schema == -53 {
		return f
	}
	shift := uint(f.Schema - schema)
	reduce := func(sp []model.HistogramSpan, bs []model.FloatBits) ([]model.HistogramSpan, []model.FloatBits) {
		out := map[int32]float64{}
		for index, count := range HistogramBuckets(sp, bs) {
			out[((index-1)>>shift)+1] += count
		}
		return histogramEncode(out)
	}
	f.PositiveSpans, f.PositiveBuckets = reduce(f.PositiveSpans, f.PositiveBuckets)
	f.NegativeSpans, f.NegativeBuckets = reduce(f.NegativeSpans, f.NegativeBuckets)
	f.Schema = schema
	return f
}
func histogramBoundsEqual(a, b []model.FloatBits) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func histogramCustomCommon(a, b []model.FloatBits) []model.FloatBits {
	out := []model.FloatBits{}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		x, y := histogramFloat(a[i]), histogramFloat(b[j])
		if x == y {
			out = append(out, a[i])
			i++
			j++
		} else if x < y {
			i++
		} else {
			j++
		}
	}
	return out
}
func histogramCustomRollup(f model.FloatHistogram, bounds []model.FloatBits) model.FloatHistogram {
	out := map[int32]float64{}
	for index, count := range HistogramBuckets(f.PositiveSpans, f.PositiveBuckets) {
		upper := math.Inf(1)
		if int(index) < len(f.CustomBounds) {
			upper = histogramFloat(f.CustomBounds[index])
		}
		target := sort.Search(len(bounds), func(i int) bool { return histogramFloat(bounds[i]) >= upper })
		out[int32(target)] += count
	}
	f.CustomBounds = append([]model.FloatBits(nil), bounds...)
	f.PositiveSpans, f.PositiveBuckets = histogramEncode(out)
	return f
}
func histogramGrowZero(f model.FloatHistogram, threshold float64) model.FloatHistogram {
	if f.Schema == -53 {
		return f
	}
	zero := histogramFloat(f.ZeroCount)
	grow := func(sp []model.HistogramSpan, bs []model.FloatBits) ([]model.HistogramSpan, []model.FloatBits) {
		m := HistogramBuckets(sp, bs)
		for k, v := range m {
			upper := math.Exp2(float64(k) * math.Exp2(-float64(f.Schema)))
			if upper <= threshold {
				zero += v
				delete(m, k)
			}
		}
		return histogramEncode(m)
	}
	f.PositiveSpans, f.PositiveBuckets = grow(f.PositiveSpans, f.PositiveBuckets)
	f.NegativeSpans, f.NegativeBuckets = grow(f.NegativeSpans, f.NegativeBuckets)
	f.ZeroThreshold = histogramBits(threshold)
	f.ZeroCount = histogramBits(zero)
	return f
}

// CombineHistograms reconciles exponential resolution and custom common bounds.
// The returned reason is factual information for the profile-specific caller.
func CombineHistograms(a, b model.NativeHistogram, subtract bool) (model.NativeHistogram, string) {
	x, y := FloatHistogram(a), FloatHistogram(b)
	if (x.Schema == -53) != (y.Schema == -53) {
		return model.NativeHistogram{}, "MixedExponentialCustomHistogramsWarning"
	}
	reason := ""
	if x.Schema == -53 {
		if !histogramBoundsEqual(x.CustomBounds, y.CustomBounds) {
			reason = "MismatchedCustomBucketsHistogramsInfo"
			bounds := histogramCustomCommon(x.CustomBounds, y.CustomBounds)
			x = histogramCustomRollup(x, bounds)
			y = histogramCustomRollup(y, bounds)
		}
	} else {
		schema := x.Schema
		if y.Schema < schema {
			schema = y.Schema
		}
		x = ReduceHistogramSchema(x, schema)
		y = ReduceHistogramSchema(y, schema)
		threshold := math.Max(histogramFloat(x.ZeroThreshold), histogramFloat(y.ZeroThreshold))
		for {
			larger := threshold
			for _, f := range []model.FloatHistogram{x, y} {
				for _, side := range []map[int32]float64{HistogramBuckets(f.PositiveSpans, f.PositiveBuckets), HistogramBuckets(f.NegativeSpans, f.NegativeBuckets)} {
					for k, n := range side {
						lower := math.Exp2(float64(k-1) * math.Exp2(-float64(f.Schema)))
						upper := math.Exp2(float64(k) * math.Exp2(-float64(f.Schema)))
						if n != 0 && lower < threshold && upper > larger {
							larger = upper
						}
					}
				}
			}
			if larger == threshold {
				break
			}
			threshold = larger
		}
		x = histogramGrowZero(x, threshold)
		y = histogramGrowZero(y, threshold)
	}
	factor := 1.0
	if subtract {
		factor = -1
	}
	merge := func(as []model.HistogramSpan, ab []model.FloatBits, bs []model.HistogramSpan, bb []model.FloatBits) ([]model.HistogramSpan, []model.FloatBits) {
		m := HistogramBuckets(as, ab)
		for k, v := range HistogramBuckets(bs, bb) {
			m[k] += factor * v
		}
		return histogramEncode(m)
	}
	x.PositiveSpans, x.PositiveBuckets = merge(x.PositiveSpans, x.PositiveBuckets, y.PositiveSpans, y.PositiveBuckets)
	x.NegativeSpans, x.NegativeBuckets = merge(x.NegativeSpans, x.NegativeBuckets, y.NegativeSpans, y.NegativeBuckets)
	x.Count = histogramBits(histogramFloat(x.Count) + factor*histogramFloat(y.Count))
	x.ZeroCount = histogramBits(histogramFloat(x.ZeroCount) + factor*histogramFloat(y.ZeroCount))
	x.Sum = histogramBits(histogramFloat(x.Sum) + factor*histogramFloat(y.Sum))
	if subtract || x.Flavor == "gauge" || y.Flavor == "gauge" {
		x.Flavor = "gauge"
		x.ResetHint = "gauge"
	} else if x.ResetHint != y.ResetHint {
		if x.ResetHint == "reset" && y.ResetHint == "not_reset" || x.ResetHint == "not_reset" && y.ResetHint == "reset" {
			reason = "HistogramCounterResetCollisionWarning"
		}
		x.ResetHint = "unknown"
	}
	return model.NativeHistogram{Float: &x}, reason
}
func histogramUintDecreased(a, b map[int32]uint64) bool {
	for k, v := range a {
		if b[k] < v {
			return true
		}
	}
	return false
}
func HistogramReset(previous, current model.NativeHistogram) bool {
	// Compare integer populations before any rate/average conversion.
	if a, b := previous.Integer, current.Integer; a != nil && b != nil {
		return histogramIntegerReset(a, b)
	}
	a, b := FloatHistogram(previous), FloatHistogram(current)
	if b.ResetHint == "reset" {
		return true
	}
	if b.ResetHint == "not_reset" {
		return false
	}
	if a.Schema == -53 && b.Schema == -53 {
		return HistogramCustomReset(previous, current)
	}
	if (a.Schema == -53) != (b.Schema == -53) || b.Schema > a.Schema || histogramFloat(b.ZeroThreshold) < histogramFloat(a.ZeroThreshold) {
		return true
	}
	a = ReduceHistogramSchema(a, b.Schema)
	threshold := histogramFloat(b.ZeroThreshold)
	for _, m := range []map[int32]float64{HistogramBuckets(a.PositiveSpans, a.PositiveBuckets), HistogramBuckets(a.NegativeSpans, a.NegativeBuckets)} {
		for k, n := range m {
			lower := math.Exp2(float64(k-1) * math.Exp2(-float64(a.Schema)))
			upper := math.Exp2(float64(k) * math.Exp2(-float64(a.Schema)))
			if n != 0 && lower < threshold && upper > threshold {
				return true
			}
		}
	}
	a = histogramGrowZero(a, threshold)
	if histogramFloat(b.Count) < histogramFloat(a.Count) || histogramFloat(b.ZeroCount) < histogramFloat(a.ZeroCount) {
		return true
	}
	for _, pair := range [][2]map[int32]float64{{HistogramBuckets(a.PositiveSpans, a.PositiveBuckets), HistogramBuckets(b.PositiveSpans, b.PositiveBuckets)}, {HistogramBuckets(a.NegativeSpans, a.NegativeBuckets), HistogramBuckets(b.NegativeSpans, b.NegativeBuckets)}} {
		for k, v := range pair[0] {
			if pair[1][k] < v {
				return true
			}
		}
	}
	return false
}
