// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"math"

	"github.com/arynyklas/soundpost/internal/model"
)

// CheckHistogramLayout refuses a stored native histogram whose spans name
// buckets that are not there: the spans must cover exactly the stored bucket
// counts, every bucket index of a custom-bucket histogram must lie in
// 0..len(bounds) (len(bounds) is the +Inf bucket; such a histogram has no
// negative side), and every other index must fit int32. Ingest enforces the
// same rule (model.histogramShape); this is the evaluation-side check of what
// the store hands back, so that the code that indexes CustomBounds and the
// bucket arrays by span position never sees data it cannot index. The answer is
// the typed `corrupt` error, like the other stored-data invariants of the
// selector.
func CheckHistogramLayout(h model.NativeHistogram) error {
	if (h.Integer == nil) == (h.Float == nil) {
		return model.Fail(model.Corrupt)
	}
	if i := h.Integer; i != nil {
		if len(i.PositiveCounts) > 0 && len(i.PositiveBuckets) > 0 || len(i.NegativeCounts) > 0 && len(i.NegativeBuckets) > 0 {
			return model.Fail(model.Corrupt)
		}
		return histogramLayout(i.Schema, i.CustomBounds, i.PositiveSpans, len(i.PositiveBuckets)+len(i.PositiveCounts), i.NegativeSpans, len(i.NegativeBuckets)+len(i.NegativeCounts))
	}
	f := h.Float
	return histogramLayout(f.Schema, f.CustomBounds, f.PositiveSpans, len(f.PositiveBuckets), f.NegativeSpans, len(f.NegativeBuckets))
}

func histogramLayout(schema int32, bounds []model.FloatBits, positive []model.HistogramSpan, positiveBuckets int, negative []model.HistogramSpan, negativeBuckets int) error {
	low, high := int64(math.MinInt32), int64(math.MaxInt32)
	if schema == -53 {
		if len(negative) > 0 || negativeBuckets > 0 {
			return model.Fail(model.Corrupt)
		}
		low, high = 0, int64(len(bounds))
	}
	if !spansCover(positive, positiveBuckets, low, high) || !spansCover(negative, negativeBuckets, low, high) {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// spansCover reports whether the spans hold exactly buckets buckets and all of
// their indices lie in low..high.
func spansCover(spans []model.HistogramSpan, buckets int, low, high int64) bool {
	index, total := int64(0), uint64(0)
	for _, span := range spans {
		index += int64(span.Offset)
		if span.Length > 0 && (index < low || index+int64(span.Length)-1 > high) {
			return false
		}
		total += uint64(span.Length)
		if total > uint64(buckets) {
			return false
		}
		index += int64(span.Length)
	}
	return total == uint64(buckets)
}
