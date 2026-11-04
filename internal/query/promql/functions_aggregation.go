// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"encoding/binary"
	"math"
	"math/bits"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
)

// EvalAggregation reduces the project-local group assembled by the plan. The
// grouping labels are calculated by the operator layer, not injected as data.
func EvalAggregation(ctx context.Context, agg AggregationPlan, input value.Result, f Frame) (result value.Result, diagnostics []syntax.Diagnostic, err error) {
	defer func() { value.InheritMetadata(&result, input, agg.Parameter) }()
	out := value.Result{Type: "vector"}
	var d []syntax.Diagnostic
	if err = validateProfile(f.Profile); err != nil {
		return out, d, err
	}
	if err := functionCheck(ctx, f); err != nil {
		return out, d, err
	}
	if input.Type != "vector" {
		return out, d, functionError(agg.Expr, "aggregation.input-type", "aggregation requires an instant vector")
	}
	known := false
	for _, name := range aggregationNames() {
		if name == agg.Name {
			known = true
			break
		}
	}
	if !known {
		return out, d, functionError(agg.Expr, "aggregation.unknown", "unknown aggregation")
	}
	if (agg.Name == "limitk" || agg.Name == "limit_ratio") && !enabled(f.Profile, "promql-experimental-functions") {
		return out, d, functionError(agg.Expr, "aggregation.feature-disabled", "aggregation feature is disabled")
	}
	parameter := 0.0
	if agg.Name == "topk" || agg.Name == "bottomk" || agg.Name == "limitk" || agg.Name == "limit_ratio" || agg.Name == "quantile" {
		if agg.Parameter.Type != "scalar" {
			return out, d, functionError(agg.Expr, "aggregation.parameter-type", "aggregation parameter requires scalar")
		}
		parameter = functionFloat(agg.Parameter.Scalar)
	}
	if agg.Name == "count_values" {
		if agg.Parameter.Type != "string" {
			return out, d, functionError(agg.Expr, "aggregation.parameter-type", "count_values parameter requires string")
		}
		if !functionLabelValid(agg.Parameter.String, f.Profile.ID) {
			return out, d, functionError(agg.Expr, "aggregation.invalid-label", "invalid count_values label")
		}
	}
	if agg.Name == "topk" || agg.Name == "bottomk" || agg.Name == "limitk" {
		// 3.13.5 answers a parameter below one with an empty result before it
		// validates the range, so only an overflow upward (or NaN) fails there;
		// 3.1.0 validates first, so a parameter that does not fit int64 fails
		// on either side. The bounds are the binary64 values around 2^63: 3.1.0
		// accepts everything strictly below 2^63; 3.13.5 only what lies strictly
		// below 2^63-1024, the largest binary64 under 2^63, which it rejects
		// (recorded: 9223372036854774784 fails, 4611686018427387904 passes).
		upper := math.Exp2(63)
		if f.Profile.ID == "promql-prometheus-3.13.5" {
			if parameter < 1 {
				return out, d, nil
			}
			upper = math.Nextafter(upper, 0)
		}
		if math.IsNaN(parameter) || parameter < -math.Exp2(63) || parameter >= upper {
			return out, d, functionError(agg.Expr, "aggregation.parameter-range", "aggregation parameter is outside int64 range")
		}
		if parameter < 1 {
			return out, d, nil
		}
	}
	if agg.Name == "limit_ratio" {
		if math.IsNaN(parameter) {
			return out, d, functionError(agg.Expr, "aggregation.parameter-nan", "limit ratio cannot be NaN")
		}
		if parameter < -1 || parameter > 1 {
			d = append(d, functionDiagnostic(agg.Expr, "InvalidRatioWarning"))
			parameter = math.Max(-1, math.Min(1, parameter))
		}
	}
	if agg.Name == "quantile" && (math.IsNaN(parameter) || parameter < 0 || parameter > 1) {
		d = append(d, functionDiagnostic(agg.Expr, "InvalidQuantileWarning"))
	}
	if len(input.Vector) == 0 {
		return out, d, nil
	}
	release, err := functionScratch([]value.Result{input}, f.Account)
	if err != nil {
		return out, d, err
	}
	defer release()
	series := make([]value.Series, 0, len(input.Vector))
	floats := make([]float64, 0, len(input.Vector))
	histograms := make([]*model.NativeHistogram, 0, len(input.Vector))
	for _, s := range input.Vector {
		if err := functionCheck(ctx, f); err != nil {
			return out, d, err
		}
		if len(s.Samples) == 0 {
			continue
		}
		if s.Project != input.Vector[0].Project {
			return out, d, functionError(agg.Expr, "aggregation.project-mismatch", "aggregation cannot combine projects")
		}
		series = append(series, s)
		if s.Samples[0].Histogram == nil {
			floats = append(floats, functionFloat(s.Samples[0]))
		} else {
			histograms = append(histograms, s.Samples[0].Histogram)
		}
	}
	if len(series) == 0 {
		return out, d, nil
	}
	base := series[0]
	base.Labels = nil
	if n, ok := agg.Expr.Expr.(*Node); ok {
		base.Labels = GroupingLabels(series[0].Labels, n.Labels, n.GroupWithout)
	}
	base.DropName = false
	switch agg.Name {
	case "topk", "bottomk":
		candidates := make([]value.Series, 0, len(series))
		for _, s := range series {
			if s.Samples[0].Histogram == nil {
				candidates = append(candidates, s)
			}
		}
		if len(histograms) > 0 {
			d = append(d, functionDiagnostic(agg.Expr, "HistogramIgnoredInAggregationInfo"))
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			x, y := functionFloat(candidates[i].Samples[0]), functionFloat(candidates[j].Samples[0])
			if math.IsNaN(x) {
				return false
			}
			if math.IsNaN(y) {
				return true
			}
			if agg.Name == "topk" {
				return x > y
			}
			return x < y
		})
		k := int64(parameter)
		if k < int64(len(candidates)) {
			candidates = candidates[:k]
		}
		out.Vector = candidates
		return out, d, nil
	case "limitk":
		k := int64(parameter)
		if k > int64(len(series)) {
			k = int64(len(series))
		}
		for _, candidate := range series[:k] {
			out.Vector = functionSelectionPush(out.Vector, candidate)
		}
		return out, d, nil
	case "limit_ratio":
		if parameter == 0 {
			return out, d, nil
		}
		for _, candidate := range series {
			offset := float64(functionLabelHash(candidate.Labels, f.Profile.ID)) / float64(^uint64(0))
			keep := parameter >= 0 && offset < parameter || parameter < 0 && offset >= 1+parameter
			if keep {
				out.Vector = functionSelectionPush(out.Vector, candidate)
			}
		}
		return out, d, nil
	case "count_values":
		counts := map[string]int{}
		order := []string{}
		for _, s := range series {
			key := functionValueString(s.Samples[0])
			if counts[key] == 0 {
				order = append(order, key)
			}
			counts[key]++
		}
		for _, key := range order {
			s := base
			s.Labels = value.SetLabel(base.Labels, agg.Parameter.String, key)
			s.Samples = []value.Sample{functionSample(float64(counts[key]), f.Time)}
			out.Vector = append(out.Vector, s)
		}
		return out, d, nil
	}
	x := math.NaN()
	var histogram *model.NativeHistogram
	switch agg.Name {
	case "group":
		x = 1
	case "count":
		x = float64(len(series))
	case "sum", "avg":
		if len(floats) > 0 && len(histograms) > 0 {
			d = append(d, functionDiagnostic(agg.Expr, "MixedFloatsHistogramsWarning"))
			return out, d, nil
		}
		if len(histograms) > 0 {
			h := value.CloneHistogram(*histograms[0])
			for _, next := range histograms[1:] {
				var reason string
				h, reason = histogramCombineForProfile(h, *next, false, f.Profile.ID)
				if reason != "" {
					if reason == "MismatchedCustomBucketsHistogramsInfo" && f.Profile.ID == "promql-prometheus-3.1.0" {
						d = append(d, functionDiagnostic(agg.Expr, "MixedExponentialCustomHistogramsWarning"))
						return out, d, nil
					}
					if f.Profile.ID == "promql-prometheus-3.13.5" || reason != "HistogramCounterResetCollisionWarning" {
						d = append(d, functionDiagnostic(agg.Expr, reason))
					}
					if h.Float == nil {
						return out, d, nil
					}
				}
			}
			if agg.Name == "avg" {
				h = value.ScaleHistogram(h, 1/float64(len(histograms)))
			}
			histogram = &h
		} else {
			x = functionSum(floats)
			if agg.Name == "avg" {
				x = functionMean(floats, f.Profile.ID)
			}
		}
	case "min", "max":
		if len(floats) == 0 {
			return out, append(d, functionDiagnostic(agg.Expr, "HistogramIgnoredInAggregationInfo")), nil
		}
		x = floats[0]
		for _, y := range floats[1:] {
			if math.IsNaN(x) || agg.Name == "min" && y < x || agg.Name == "max" && y > x {
				x = y
			}
		}
	case "stdvar", "stddev":
		if len(floats) == 0 {
			return out, append(d, functionDiagnostic(agg.Expr, "HistogramIgnoredInAggregationInfo")), nil
		}
		x = functionVariance(floats)
		if agg.Name == "stddev" {
			x = math.Sqrt(x)
		}
	case "quantile":
		if len(floats) == 0 {
			return out, d, nil
		}
		x = functionQuantile(parameter, floats)
	}
	if len(histograms) > 0 && (agg.Name == "min" || agg.Name == "max" || agg.Name == "stddev" || agg.Name == "stdvar" || agg.Name == "quantile") {
		d = append(d, functionDiagnostic(agg.Expr, "HistogramIgnoredInAggregationInfo"))
	}
	sample := functionSample(x, f.Time)
	sample.Histogram = histogram
	base.Samples = []value.Sample{sample}
	out.Vector = []value.Series{base}
	return out, d, nil
}

// XXH64 is a public noncryptographic hash algorithm; these constants and rounds
// implement that algorithm directly, not a telemetry engine implementation.
func functionLabelHash(labels model.Labels, profileID string) uint64 {
	size := 0
	for _, label := range labels {
		size += len(label.Name) + len(label.Value) + 8
	}
	data := make([]byte, 0, size)
	if profileID == "promql-prometheus-3.13.5" {
		// The default string-label representation hashes successive length-prefixed
		// names and values. Short lengths use one byte; 255 marks a 24-bit length.
		appendString := func(text string) {
			length := len(text)
			if length < 255 {
				data = append(data, byte(length))
			} else {
				data = append(data, 255, byte(length), byte(length>>8), byte(length>>16))
			}
			data = append(data, text...)
		}
		for _, label := range labels {
			appendString(label.Name)
			appendString(label.Value)
		}
	} else {
		for _, label := range labels {
			data = append(data, label.Name...)
			data = append(data, 255)
			data = append(data, label.Value...)
			data = append(data, 255)
		}
	}
	return functionXXH64(data)
}
func functionXXH64(data []byte) uint64 {
	const p1 uint64 = 11400714785074694791
	const p2 uint64 = 14029467366897019727
	const p3 uint64 = 1609587929392839161
	const p4 uint64 = 9650029242287828579
	const p5 uint64 = 2870177450012600261
	round := func(a, b uint64) uint64 { return bits.RotateLeft64(a+b*p2, 31) * p1 }
	length := len(data)
	var hash uint64
	if length >= 32 {
		v1 := p1
		v1 += p2
		v2 := p2
		v3 := uint64(0)
		v4 := uint64(0)
		v4 -= p1
		for len(data) >= 32 {
			v1 = round(v1, binary.LittleEndian.Uint64(data))
			v2 = round(v2, binary.LittleEndian.Uint64(data[8:]))
			v3 = round(v3, binary.LittleEndian.Uint64(data[16:]))
			v4 = round(v4, binary.LittleEndian.Uint64(data[24:]))
			data = data[32:]
		}
		hash = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) + bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		for _, v := range [4]uint64{v1, v2, v3, v4} {
			hash ^= round(0, v)
			hash = hash*p1 + p4
		}
	} else {
		hash = p5
	}
	hash += uint64(length)
	for len(data) >= 8 {
		hash ^= round(0, binary.LittleEndian.Uint64(data))
		hash = bits.RotateLeft64(hash, 27)*p1 + p4
		data = data[8:]
	}
	if len(data) >= 4 {
		hash ^= uint64(binary.LittleEndian.Uint32(data)) * p1
		hash = bits.RotateLeft64(hash, 23)*p2 + p3
		data = data[4:]
	}
	for _, b := range data {
		hash ^= uint64(b) * p5
		hash = bits.RotateLeft64(hash, 11) * p1
	}
	hash ^= hash >> 33
	hash *= p2
	hash ^= hash >> 29
	hash *= p3
	hash ^= hash >> 32
	return hash
}
func functionSelectionPush(heap []value.Series, series value.Series) []value.Series {
	heap = append(heap, series)
	for child := len(heap) - 1; child > 0; {
		parent := (child - 1) / 2
		a, b := functionFloat(heap[child].Samples[0]), functionFloat(heap[parent].Samples[0])
		if !math.IsNaN(a) && !(a < b) {
			break
		}
		heap[parent], heap[child] = heap[child], heap[parent]
		child = parent
	}
	return heap
}
