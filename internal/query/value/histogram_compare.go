// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"math"
	"soundpost/internal/model"
)

func histogramUintEqual(a, b map[int32]uint64) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}
func histogramPopulationEqual(a, b map[int32]float64) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

// EquivalentHistogram ignores flavor/reset metadata, but never rounds integer
// populations merely to compare two retained integer observations.
func EquivalentHistogram(a, b model.NativeHistogram) bool {
	if x, y := a.Integer, b.Integer; x != nil && y != nil {
		if x.Schema != y.Schema || x.ZeroThreshold != y.ZeroThreshold || x.Sum != y.Sum || x.Count != y.Count || x.ZeroCount != y.ZeroCount || !histogramBoundsEqual(x.CustomBounds, y.CustomBounds) {
			return false
		}
		return histogramUintEqual(histogramIntegerBuckets(x.PositiveSpans, x.PositiveBuckets, x.PositiveCounts), histogramIntegerBuckets(y.PositiveSpans, y.PositiveBuckets, y.PositiveCounts)) && histogramUintEqual(histogramIntegerBuckets(x.NegativeSpans, x.NegativeBuckets, x.NegativeCounts), histogramIntegerBuckets(y.NegativeSpans, y.NegativeBuckets, y.NegativeCounts))
	}
	x, y := FloatHistogram(a), FloatHistogram(b)
	if x.Schema != y.Schema || x.ZeroThreshold != y.ZeroThreshold || x.Sum != y.Sum || x.Count != y.Count || x.ZeroCount != y.ZeroCount || !histogramBoundsEqual(x.CustomBounds, y.CustomBounds) {
		return false
	}
	return histogramPopulationEqual(HistogramBuckets(x.PositiveSpans, x.PositiveBuckets), HistogramBuckets(y.PositiveSpans, y.PositiveBuckets)) && histogramPopulationEqual(HistogramBuckets(x.NegativeSpans, x.NegativeBuckets), HistogramBuckets(y.NegativeSpans, y.NegativeBuckets))
}
func histogramCustomRollupUint(h *model.IntegerHistogram, bounds []model.FloatBits) map[int32]uint64 {
	result := map[int32]uint64{}
	for index, count := range histogramIntegerBuckets(h.PositiveSpans, h.PositiveBuckets, h.PositiveCounts) {
		target := 0
		if int(index) >= len(h.CustomBounds) {
			target = len(bounds)
		} else {
			upper := histogramFloat(h.CustomBounds[index])
			for target < len(bounds) && histogramFloat(bounds[target]) < upper {
				target++
			}
		}
		result[int32(target)] += count
	}
	return result
}

// HistogramCustomReset reconciles custom boundaries at the newer profile's
// semantic comparison point. The integer path stays exact across rollups.
func HistogramCustomReset(a, b model.NativeHistogram) bool {
	if x, y := a.Integer, b.Integer; x != nil && y != nil {
		if y.ResetHint == "reset" {
			return true
		}
		if y.ResetHint == "not_reset" {
			return false
		}
		common := histogramCustomCommon(x.CustomBounds, y.CustomBounds)
		return y.Count < x.Count || histogramUintDecreased(histogramCustomRollupUint(x, common), histogramCustomRollupUint(y, common))
	}
	x, y := FloatHistogram(a), FloatHistogram(b)
	if y.ResetHint == "reset" {
		return true
	}
	if y.ResetHint == "not_reset" {
		return false
	}
	common := histogramCustomCommon(x.CustomBounds, y.CustomBounds)
	x = histogramCustomRollup(x, common)
	y = histogramCustomRollup(y, common)
	if histogramFloat(y.Count) < histogramFloat(x.Count) {
		return true
	}
	before, after := HistogramBuckets(x.PositiveSpans, x.PositiveBuckets), HistogramBuckets(y.PositiveSpans, y.PositiveBuckets)
	for k, v := range before {
		if after[k] < v {
			return true
		}
	}
	return false
}
func histogramIntegerReset(a, b *model.IntegerHistogram) bool {
	if b.ResetHint == "reset" {
		return true
	}
	if b.ResetHint == "not_reset" {
		return false
	}
	if a.Schema == -53 && b.Schema == -53 {
		return HistogramCustomReset(model.NativeHistogram{Integer: a}, model.NativeHistogram{Integer: b})
	}
	if (a.Schema == -53) != (b.Schema == -53) || b.Schema > a.Schema || histogramFloat(b.ZeroThreshold) < histogramFloat(a.ZeroThreshold) || b.Count < a.Count {
		return true
	}
	zero := uint64(a.ZeroCount)
	reduce := func(sp []model.HistogramSpan, d []model.DeltaBucket, abs []model.AbsoluteBucket) (map[int32]uint64, bool) {
		merged := map[int32]uint64{}
		shift := uint(a.Schema - b.Schema)
		for index, count := range histogramIntegerBuckets(sp, d, abs) {
			merged[((index-1)>>shift)+1] += count
		}
		threshold := histogramFloat(b.ZeroThreshold)
		unit := math.Exp2(-float64(b.Schema))
		for index, count := range merged {
			lower := math.Exp2(float64(index-1) * unit)
			upper := math.Exp2(float64(index) * unit)
			if count != 0 && lower < threshold && upper > threshold {
				return nil, false
			}
			if upper <= threshold {
				zero += count
				delete(merged, index)
			}
		}
		return merged, true
	}
	positive, ok := reduce(a.PositiveSpans, a.PositiveBuckets, a.PositiveCounts)
	if !ok {
		return true
	}
	negative, ok := reduce(a.NegativeSpans, a.NegativeBuckets, a.NegativeCounts)
	if !ok {
		return true
	}
	return uint64(b.ZeroCount) < zero || histogramUintDecreased(positive, histogramIntegerBuckets(b.PositiveSpans, b.PositiveBuckets, b.PositiveCounts)) || histogramUintDecreased(negative, histogramIntegerBuckets(b.NegativeSpans, b.NegativeBuckets, b.NegativeCounts))
}
