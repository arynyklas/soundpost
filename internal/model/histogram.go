// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"errors"
	"math"
)

func histogramShape(schema int32, threshold FloatBits, flavor, reset string, bounds []FloatBits, positive, negative []HistogramSpan, np, nn int) error {
	if schema < -4 || schema > 8 {
		if schema != -53 {
			return errors.New("invalid histogram schema")
		}
	}
	if flavor != "counter" && flavor != "gauge" {
		return errors.New("invalid histogram flavor")
	}
	switch reset {
	case "unknown", "reset", "not_reset", "gauge":
	default:
		return errors.New("invalid reset hint")
	}
	zero := math.Float64frombits(uint64(threshold))
	if math.IsNaN(zero) || math.IsInf(zero, 0) || zero < 0 {
		return errors.New("invalid zero threshold")
	}
	if schema != -53 && len(bounds) > 0 {
		return errors.New("unexpected custom bounds")
	}
	previous := math.Inf(-1)
	for _, bits := range bounds {
		value := math.Float64frombits(uint64(bits))
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= previous {
			return errors.New("invalid custom bounds")
		}
		previous = value
	}
	if schema == -53 && (zero != 0 || nn != 0) {
		return errors.New("invalid custom histogram shape")
	}
	for side, spans := range [][]HistogramSpan{positive, negative} {
		count := uint64(0)
		for i, span := range spans {
			if span.Length == 0 || i > 0 && span.Offset < 0 {
				return errors.New("invalid histogram span")
			}
			count += uint64(span.Length)
		}
		want := np
		if side == 1 {
			want = nn
		}
		if count != uint64(want) {
			return errors.New("histogram span length mismatch")
		}
	}
	return nil
}
func sumIntegerBuckets(deltas []DeltaBucket) (uint64, error) {
	var bucket, total uint64
	for _, delta := range deltas {
		if delta < 0 {
			amount := uint64(-(delta + 1)) + 1
			if amount > bucket {
				return 0, errors.New("negative histogram bucket")
			}
			bucket -= amount
		} else {
			amount := uint64(delta)
			if math.MaxUint64-bucket < amount {
				return 0, errors.New("histogram bucket overflow")
			}
			bucket += amount
		}
		if math.MaxUint64-total < bucket {
			return 0, errors.New("histogram total overflow")
		}
		total += bucket
	}
	return total, nil
}
func sumAbsoluteBuckets(counts []AbsoluteBucket) (uint64, error) {
	var total uint64
	for _, count := range counts {
		if ^uint64(0)-total < uint64(count) {
			return 0, errors.New("histogram total overflow")
		}
		total += uint64(count)
	}
	return total, nil
}
func (h IntegerHistogram) validateHistogram() error {
	if len(h.PositiveCounts) > 0 && len(h.PositiveBuckets) > 0 || len(h.NegativeCounts) > 0 && len(h.NegativeBuckets) > 0 {
		return errors.New("mixed histogram bucket representations")
	}
	if err := histogramShape(h.Schema, h.ZeroThreshold, h.Flavor, h.ResetHint, h.CustomBounds, h.PositiveSpans, h.NegativeSpans, len(h.PositiveBuckets)+len(h.PositiveCounts), len(h.NegativeBuckets)+len(h.NegativeCounts)); err != nil {
		return err
	}
	positive, err := sumIntegerBuckets(h.PositiveBuckets)
	if err != nil {
		return err
	}
	if len(h.PositiveCounts) > 0 {
		positive, err = sumAbsoluteBuckets(h.PositiveCounts)
		if err != nil {
			return err
		}
	}
	negative, err := sumIntegerBuckets(h.NegativeBuckets)
	if err != nil {
		return err
	}
	if len(h.NegativeCounts) > 0 {
		negative, err = sumAbsoluteBuckets(h.NegativeCounts)
		if err != nil {
			return err
		}
	}
	count, zero := uint64(h.Count), uint64(h.ZeroCount)
	if zero > count || positive > count-zero || negative > count-zero-positive {
		return errors.New("histogram count mismatch")
	}
	if h.Schema == -53 && h.ZeroCount != 0 {
		return errors.New("custom histogram zero count")
	}
	return nil
}
func (h FloatHistogram) validateHistogram() error {
	if err := histogramShape(h.Schema, h.ZeroThreshold, h.Flavor, h.ResetHint, h.CustomBounds, h.PositiveSpans, h.NegativeSpans, len(h.PositiveBuckets), len(h.NegativeBuckets)); err != nil {
		return err
	}
	count, zero := math.Float64frombits(uint64(h.Count)), math.Float64frombits(uint64(h.ZeroCount))
	if math.IsNaN(count) || math.IsInf(count, 0) || count < 0 || math.IsNaN(zero) || math.IsInf(zero, 0) || zero < 0 || zero > count {
		return errors.New("invalid histogram count")
	}
	total := zero
	for _, buckets := range [][]FloatBits{h.PositiveBuckets, h.NegativeBuckets} {
		for _, bits := range buckets {
			value := math.Float64frombits(uint64(bits))
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				return errors.New("invalid histogram bucket")
			}
			total += value
		}
	}
	if total > count || h.Schema == -53 && zero != 0 {
		return errors.New("histogram count mismatch")
	}
	return nil
}
