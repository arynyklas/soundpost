// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"strconv"

	"github.com/arynyklas/soundpost/internal/model"
)

// HistogramInput renders a native histogram as the exact-field record the input
// normalization check compares (counts as canonical decimals or IEEE bits, the
// spans, the bucket deltas or bits, the custom bounds). The smoke producer
// renders the histograms it authored and the ones it read back from storage with
// this one function, so a difference between them is a difference of the
// histograms: nil and allocated-empty lists are one list, nothing else is
// dropped. A histogram this record cannot carry exactly (a non-counter flavor,
// the optional absolute-count form) is refused, never rendered lossily: a gate
// that cannot see a field must not be shown a histogram that uses it.
func HistogramInput(h *model.NativeHistogram) (*Histogram, error) {
	if h == nil || (h.Integer == nil) == (h.Float == nil) {
		return nil, fmt.Errorf("a native histogram has exactly one of the integer and float forms")
	}
	spans := func(in []model.HistogramSpan) []HistogramSpan {
		out := make([]HistogramSpan, 0, len(in))
		for _, s := range in {
			out = append(out, HistogramSpan{Offset: s.Offset, Length: s.Length})
		}
		return out
	}
	bits := func(in []model.FloatBits) []string {
		if len(in) == 0 {
			return nil
		}
		out := make([]string, 0, len(in))
		for _, b := range in {
			out = append(out, fmt.Sprintf("%016x", uint64(b)))
		}
		return out
	}
	deltas := func(in []model.DeltaBucket) []string {
		if len(in) == 0 {
			return nil
		}
		out := make([]string, 0, len(in))
		for _, d := range in {
			out = append(out, strconv.FormatInt(int64(d), 10))
		}
		return out
	}
	if i := h.Integer; i != nil {
		if i.Flavor != "counter" {
			return nil, fmt.Errorf("integer histogram flavor %q is not representable in the normalization record", i.Flavor)
		}
		if len(i.PositiveCounts) != 0 || len(i.NegativeCounts) != 0 {
			return nil, fmt.Errorf("integer histogram absolute counts are not representable in the normalization record")
		}
		return &Histogram{Kind: "integer", Schema: i.Schema, ResetHint: i.ResetHint, Count: strconv.FormatUint(uint64(i.Count), 10), ZeroCount: strconv.FormatUint(uint64(i.ZeroCount), 10),
			ZeroThresholdBits: fmt.Sprintf("%016x", uint64(i.ZeroThreshold)), SumBits: fmt.Sprintf("%016x", uint64(i.Sum)),
			PositiveSpans: spans(i.PositiveSpans), NegativeSpans: spans(i.NegativeSpans), PositiveDeltas: deltas(i.PositiveBuckets), NegativeDeltas: deltas(i.NegativeBuckets),
			CustomBoundaryBits: bits(i.CustomBounds)}, nil
	}
	f := h.Float
	if f.Flavor != "counter" {
		return nil, fmt.Errorf("float histogram flavor %q is not representable in the normalization record", f.Flavor)
	}
	return &Histogram{Kind: "float", Schema: f.Schema, ResetHint: f.ResetHint, CountBits: fmt.Sprintf("%016x", uint64(f.Count)), ZeroCountBits: fmt.Sprintf("%016x", uint64(f.ZeroCount)),
		ZeroThresholdBits: fmt.Sprintf("%016x", uint64(f.ZeroThreshold)), SumBits: fmt.Sprintf("%016x", uint64(f.Sum)),
		PositiveSpans: spans(f.PositiveSpans), NegativeSpans: spans(f.NegativeSpans), PositiveBucketBits: bits(f.PositiveBuckets), NegativeBucketBits: bits(f.NegativeBuckets),
		CustomBoundaryBits: bits(f.CustomBounds)}, nil
}
