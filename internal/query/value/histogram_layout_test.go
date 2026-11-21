// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"errors"
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func TestCheckHistogramLayoutBoundaries(t *testing.T) {
	bounds := []model.FloatBits{model.FloatBits(math.Float64bits(1)), model.FloatBits(math.Float64bits(2))}
	custom := func(spans []model.HistogramSpan, counts int) model.NativeHistogram {
		return model.NativeHistogram{Integer: &model.IntegerHistogram{Schema: -53, CustomBounds: bounds, PositiveSpans: spans, PositiveCounts: make([]model.AbsoluteBucket, counts)}}
	}
	exponential := func(spans []model.HistogramSpan, counts int) model.NativeHistogram {
		return model.NativeHistogram{Float: &model.FloatHistogram{Schema: 0, PositiveSpans: spans, PositiveBuckets: make([]model.FloatBits, counts)}}
	}
	for _, c := range []struct {
		name string
		h    model.NativeHistogram
		ok   bool
	}{
		{"custom: every bucket including +Inf", custom([]model.HistogramSpan{{Offset: 0, Length: 3}}, 3), true},
		{"custom: only +Inf", custom([]model.HistogramSpan{{Offset: 2, Length: 1}}, 1), true},
		{"custom: one past +Inf", custom([]model.HistogramSpan{{Offset: 3, Length: 1}}, 1), false},
		{"custom: last bucket one past", custom([]model.HistogramSpan{{Offset: 0, Length: 4}}, 4), false},
		{"custom: index -1", custom([]model.HistogramSpan{{Offset: -1, Length: 1}}, 1), false},
		{"custom: an empty span may move the index but holds nothing", custom([]model.HistogramSpan{{Offset: 9, Length: 0}, {Offset: -9, Length: 1}}, 1), true},
		{"custom: fewer buckets than the spans name", custom([]model.HistogramSpan{{Offset: 0, Length: 2}}, 1), false},
		{"custom: more buckets than the spans name", custom([]model.HistogramSpan{{Offset: 0, Length: 1}}, 2), false},
		{"custom: negative side", model.NativeHistogram{Float: &model.FloatHistogram{Schema: -53, CustomBounds: bounds, NegativeSpans: []model.HistogramSpan{{Length: 1}}, NegativeBuckets: make([]model.FloatBits, 1)}}, false},
		{"exponential: negative index", exponential([]model.HistogramSpan{{Offset: -5, Length: 2}}, 2), true},
		{"exponential: top of int32", exponential([]model.HistogramSpan{{Offset: math.MaxInt32, Length: 1}}, 1), true},
		{"exponential: past int32", exponential([]model.HistogramSpan{{Offset: math.MaxInt32, Length: 2}}, 2), false},
		{"exponential: below int32", exponential([]model.HistogramSpan{{Offset: math.MinInt32, Length: 1}, {Offset: -2, Length: 1}}, 2), false},
		{"exponential: bottom of int32", exponential([]model.HistogramSpan{{Offset: math.MinInt32, Length: 1}}, 1), true},
		{"exponential: no buckets named", exponential(nil, 1), false},
		{"neither variant", model.NativeHistogram{}, false},
		{"both counts and deltas", model.NativeHistogram{Integer: &model.IntegerHistogram{Schema: 0, PositiveSpans: []model.HistogramSpan{{Length: 1}}, PositiveBuckets: make([]model.DeltaBucket, 1), PositiveCounts: make([]model.AbsoluteBucket, 1)}}, false},
	} {
		err := CheckHistogramLayout(c.h)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok {
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Corrupt {
				t.Errorf("%s: %v, want a corrupt fault", c.name, err)
			}
		}
	}
}
