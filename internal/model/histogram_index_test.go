// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A native histogram names its buckets by index: spans give the indices of the
// populated buckets. A custom-bucket histogram (schema -53) has one bucket per
// bound plus the +Inf bucket, bucket i lying below bound i, so the only indices
// that exist are 0..len(bounds). Readers index the bound list with the bucket
// index, so a histogram whose spans name any other bucket (or an index that an
// int32 cannot hold) must never be accepted: it would be stored and then panic
// the query that reads it.
func TestHistogramSpansNameOnlyBucketsThatExist(t *testing.T) {
	const custom, exponential = -53, 3
	span := func(offset int32, length uint32) model.HistogramSpan {
		return model.HistogramSpan{Offset: offset, Length: length}
	}
	bits := func(v float64) model.FloatBits { return model.FloatBits(math.Float64bits(v)) }
	cases := []struct {
		name     string
		schema   int32
		bounds   int
		spans    []model.HistogramSpan
		negative bool // the spans describe the negative side (exponential only)
		ok       bool
	}{
		{"custom: spans end exactly on the +Inf bucket", custom, 2, []model.HistogramSpan{span(0, 3)}, false, true},
		{"custom: an offset and spans that reach the +Inf bucket", custom, 2, []model.HistogramSpan{span(1, 2)}, false, true},
		{"custom: only the +Inf bucket, no bounds", custom, 0, []model.HistogramSpan{span(0, 1)}, false, true},
		{"custom: a gap between two spans that reaches the +Inf bucket", custom, 2, []model.HistogramSpan{span(0, 1), span(1, 1)}, false, true},
		{"custom: no populated bucket at all", custom, 2, nil, false, true},
		{"custom: one bucket past the +Inf bucket", custom, 2, []model.HistogramSpan{span(1, 3)}, false, false},
		{"custom: offset far beyond the bounds", custom, 1, []model.HistogramSpan{span(5, 1)}, false, false},
		{"custom: negative first offset", custom, 3, []model.HistogramSpan{span(-1, 2)}, false, false},
		{"custom: two buckets without any bound", custom, 0, []model.HistogramSpan{span(0, 2)}, false, false},
		{"custom: a second span that starts past the +Inf bucket", custom, 2, []model.HistogramSpan{span(0, 1), span(2, 1)}, false, false},
		{"exponential: first offset negative, a second span after a gap", exponential, 0, []model.HistogramSpan{span(-3, 2), span(1, 1)}, false, true},
		{"exponential: the lowest index an int32 holds", exponential, 0, []model.HistogramSpan{span(math.MinInt32, 1)}, false, true},
		{"exponential: the highest index an int32 holds", exponential, 0, []model.HistogramSpan{span(math.MaxInt32, 1)}, false, true},
		{"exponential: the running index leaves int32 in a second span", exponential, 0, []model.HistogramSpan{span(math.MaxInt32, 1), span(1, 1)}, false, false},
		{"exponential: one span that runs past the highest int32 index", exponential, 0, []model.HistogramSpan{span(math.MaxInt32, 2)}, false, false},
		{"exponential: the negative side leaves int32 too", exponential, 0, []model.HistogramSpan{span(math.MaxInt32, 2)}, true, false},
	}
	for _, c := range cases {
		total := 0
		for _, s := range c.spans {
			total += int(s.Length)
		}
		bounds := make([]model.FloatBits, c.bounds)
		for i := range bounds {
			bounds[i] = bits(float64(i + 1))
		}
		deltas := make([]model.DeltaBucket, total)
		floats := make([]model.FloatBits, total)
		for i := range floats {
			floats[i] = bits(1)
		}
		if total > 0 {
			deltas[0] = 1
		}
		integer := &model.IntegerHistogram{Flavor: "counter", Schema: c.schema, ResetHint: "unknown", Count: model.Uint64(total), Sum: bits(1), CustomBounds: bounds}
		float := &model.FloatHistogram{Flavor: "counter", Schema: c.schema, ResetHint: "unknown", Count: bits(float64(total)), Sum: bits(1), CustomBounds: bounds}
		if c.negative {
			integer.NegativeSpans, integer.NegativeBuckets = c.spans, deltas
			float.NegativeSpans, float.NegativeBuckets = c.spans, floats
		} else {
			integer.PositiveSpans, integer.PositiveBuckets = c.spans, deltas
			float.PositiveSpans, float.PositiveBuckets = c.spans, floats
		}
		for repr, h := range map[string]model.NativeHistogram{"integer": {Integer: integer}, "float": {Float: float}} {
			err := h.Validate()
			switch {
			case c.ok && err != nil:
				t.Errorf("%s (%s): a valid histogram was refused: %v", c.name, repr, err)
			case !c.ok && err == nil:
				t.Errorf("%s (%s): a histogram that names buckets that do not exist was accepted", c.name, repr)
			}
		}
	}
}
