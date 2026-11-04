// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"reflect"
	"soundpost/internal/model"
)

func CloneHistogram(h model.NativeHistogram) model.NativeHistogram {
	var out model.NativeHistogram
	if h.Integer != nil {
		v := *h.Integer
		v.PositiveSpans = append([]model.HistogramSpan(nil), v.PositiveSpans...)
		v.NegativeSpans = append([]model.HistogramSpan(nil), v.NegativeSpans...)
		v.PositiveBuckets = append([]model.DeltaBucket(nil), v.PositiveBuckets...)
		v.NegativeBuckets = append([]model.DeltaBucket(nil), v.NegativeBuckets...)
		v.PositiveCounts = append([]model.AbsoluteBucket(nil), v.PositiveCounts...)
		v.NegativeCounts = append([]model.AbsoluteBucket(nil), v.NegativeCounts...)
		v.CustomBounds = append([]model.FloatBits(nil), v.CustomBounds...)
		out.Integer = &v
	}
	if h.Float != nil {
		v := *h.Float
		v.PositiveSpans = append([]model.HistogramSpan(nil), v.PositiveSpans...)
		v.NegativeSpans = append([]model.HistogramSpan(nil), v.NegativeSpans...)
		v.PositiveBuckets = append([]model.FloatBits(nil), v.PositiveBuckets...)
		v.NegativeBuckets = append([]model.FloatBits(nil), v.NegativeBuckets...)
		v.CustomBounds = append([]model.FloatBits(nil), v.CustomBounds...)
		out.Float = &v
	}
	return out
}
func HistogramBytes(h model.NativeHistogram) int64 {
	if v := h.Integer; v != nil {
		return int64(192 + 8*(len(v.PositiveSpans)+len(v.NegativeSpans)+len(v.PositiveBuckets)+len(v.NegativeBuckets)+len(v.PositiveCounts)+len(v.NegativeCounts)+len(v.CustomBounds)))
	}
	if v := h.Float; v != nil {
		return int64(160 + 8*(len(v.PositiveSpans)+len(v.NegativeSpans)+len(v.PositiveBuckets)+len(v.NegativeBuckets)+len(v.CustomBounds)))
	}
	return 0
}
func EqualHistogram(a, b model.NativeHistogram) bool { return reflect.DeepEqual(a, b) }
