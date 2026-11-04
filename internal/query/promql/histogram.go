// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"strconv"
)

type histogramObservationBucket struct {
	lower, upper, count float64
	exponential         bool
}

func histogramView(histogram model.NativeHistogram) model.FloatHistogram {
	if histogram.Float != nil {
		return *histogram.Float
	}
	return value.FloatHistogram(histogram)
}
func histogramObservationBuckets(histogram model.NativeHistogram) []histogramObservationBucket {
	view := histogramView(histogram)
	output := make([]histogramObservationBucket, 0, len(view.PositiveBuckets)+len(view.NegativeBuckets)+1)
	visit := func(spans []model.HistogramSpan, populations []model.FloatBits, callback func(int32, float64)) {
		index, position := int32(0), 0
		for _, span := range spans {
			index += span.Offset
			for range span.Length {
				callback(index, math.Float64frombits(uint64(populations[position])))
				index++
				position++
			}
		}
	}
	if view.Schema == -53 {
		visit(view.PositiveSpans, view.PositiveBuckets, func(index int32, count float64) {
			lower, upper := math.Inf(-1), math.Inf(1)
			if index > 0 {
				lower = math.Float64frombits(uint64(view.CustomBounds[index-1]))
			}
			if int(index) < len(view.CustomBounds) {
				upper = math.Float64frombits(uint64(view.CustomBounds[index]))
			}
			output = append(output, histogramObservationBucket{lower: lower, upper: upper, count: count})
		})
		return output
	}
	threshold := math.Float64frombits(uint64(view.ZeroThreshold))
	visit(view.NegativeSpans, view.NegativeBuckets, func(index int32, count float64) {
		lower := -exponentialBound(view.Schema, index)
		upper := -exponentialBound(view.Schema, index-1)
		if lower >= -threshold {
			return
		}
		output = append(output, histogramObservationBucket{lower: lower, upper: math.Min(upper, -threshold), count: count, exponential: true})
	})
	for left, right := 0, len(output)-1; left < right; left, right = left+1, right-1 {
		output[left], output[right] = output[right], output[left]
	}
	zero := math.Float64frombits(uint64(view.ZeroCount))
	if zero != 0 {
		lower, upper := -threshold, threshold
		if len(view.NegativeBuckets) == 0 {
			lower = 0
		}
		if len(view.PositiveBuckets) == 0 {
			upper = 0
		}
		output = append(output, histogramObservationBucket{lower: lower, upper: upper, count: zero})
	}
	visit(view.PositiveSpans, view.PositiveBuckets, func(index int32, count float64) {
		lower := exponentialBound(view.Schema, index-1)
		upper := exponentialBound(view.Schema, index)
		if upper <= threshold {
			return
		}
		output = append(output, histogramObservationBucket{lower: math.Max(lower, threshold), upper: upper, count: count, exponential: true})
	})
	return output
}
func histogramEquivalent(a, b model.NativeHistogram) bool { return value.EquivalentHistogram(a, b) }
func histogramBucketFraction(b histogramObservationBucket, bound float64) float64 {
	if bound <= b.lower {
		return 0
	}
	if bound >= b.upper {
		return 1
	}
	if b.lower == b.upper {
		return 1
	}
	if b.exponential {
		if b.upper < 0 {
			return (math.Log2(-b.lower) - math.Log2(-bound)) / (math.Log2(-b.lower) - math.Log2(-b.upper))
		}
		return (math.Log2(bound) - math.Log2(b.lower)) / (math.Log2(b.upper) - math.Log2(b.lower))
	}
	if math.IsInf(b.lower, -1) {
		if b.upper <= 0 {
			return 0
		}
		return bound / b.upper
	}
	if math.IsInf(b.upper, 1) {
		return 0
	}
	return (bound - b.lower) / (b.upper - b.lower)
}
func histogramNativeFraction(lower, upper float64, h model.NativeHistogram, profileID string) (float64, string) {
	f := histogramView(h)
	total := math.Float64frombits(uint64(f.Count))
	if total == 0 || math.IsNaN(lower) || math.IsNaN(upper) {
		return math.NaN(), ""
	}
	if lower >= upper {
		return 0, ""
	}
	if f.Schema != -53 {
		return histogramExponentialFraction(lower, upper, f, total, profileID)
	}
	lo, hi, population := 0.0, 0.0, 0.0
	for _, bucket := range histogramObservationBuckets(h) {
		population += bucket.count
		lo += bucket.count * histogramBucketFraction(bucket, lower)
		hi += bucket.count * histogramBucketFraction(bucket, upper)
	}
	reason := ""
	if population < total && math.IsNaN(math.Float64frombits(uint64(f.Sum))) {
		reason = "NativeHistogramFractionNaNsInfo"
	}
	return (math.Min(hi, population) - math.Min(lo, population)) / total, reason
}

// histogramExponentialFraction is the fraction of observations in
// [lower, upper] of an exponential-schema histogram. Buckets are walked in
// ascending order of bounds, exactly as stored (a bucket that straddles the
// zero threshold is not clamped, and a bucket entirely inside it is still
// visited). A bound's rank is the population of the buckets below it plus the
// interpolated share of the bucket that contains it; a bound that is never
// placed (above every bucket, or above the buckets that hold anything) takes
// the whole observation count, not the bucket total, so observations that are
// in no bucket count as lying below it. Only the 3.13 profile differs: when the
// sum is NaN (NaN observations exist, which are in no bucket and in no
// fraction) an unplaced bound takes the bucket population, while the
// denominator stays the observation count.
func histogramExponentialFraction(lower, upper float64, f model.FloatHistogram, total float64, profileID string) (float64, string) {
	var rank, lowerRank, upperRank, population float64
	var lowerSet, upperSet bool
	buckets := nativeBuckets(f, false)
	for _, b := range buckets {
		population += b.count
	}
	for _, b := range buckets {
		zero := b.lower <= 0 && b.upper >= 0
		if zero {
			switch {
			case len(f.NegativeBuckets) == 0 && len(f.PositiveBuckets) > 0:
				b.lower = 0
			case len(f.PositiveBuckets) == 0 && len(f.NegativeBuckets) > 0:
				b.upper = 0
			}
		}
		if !lowerSet && b.lower >= lower {
			lowerRank, lowerSet = rank, true
		}
		if !upperSet && b.lower >= upper {
			upperRank, upperSet = rank, true
		}
		if lowerSet && upperSet {
			break
		}
		share := func(bound float64) float64 {
			if zero {
				return (bound - b.lower) / (b.upper - b.lower)
			}
			logLower, logUpper := math.Log2(math.Abs(b.lower)), math.Log2(math.Abs(b.upper))
			return (math.Log2(math.Abs(bound)) - logLower) / (logUpper - logLower)
		}
		if !lowerSet && b.lower < lower && b.upper > lower {
			lowerRank, lowerSet = rank+b.count*share(lower), true
		}
		if !upperSet && b.lower < upper && b.upper > upper {
			upperRank, upperSet = rank+b.count*share(upper), true
		}
		rank += b.count
	}
	ceiling := total
	reason := ""
	if population < total && math.IsNaN(math.Float64frombits(uint64(f.Sum))) {
		reason = "NativeHistogramFractionNaNsInfo"
		if profileID != "promql-prometheus-3.1.0" {
			ceiling = population
		}
	}
	if !lowerSet || lowerRank > ceiling {
		lowerRank = ceiling
	}
	if !upperSet || upperRank > ceiling {
		upperRank = ceiling
	}
	return (upperRank - lowerRank) / total, reason
}
func histogramNativeVariance(h model.NativeHistogram, profileID string) float64 {
	f := histogramView(h)
	count := math.Float64frombits(uint64(f.Count))
	mean := math.Float64frombits(uint64(f.Sum)) / count
	if f.Schema != -53 {
		terms := make([]float64, 0, len(f.PositiveBuckets)+len(f.NegativeBuckets)+1)
		for _, b := range nativeBuckets(f, false) {
			if b.count == 0 {
				continue
			}
			representative := 0.0
			if !(b.lower <= 0 && b.upper >= 0) {
				representative = math.Sqrt(b.upper * b.lower)
				if b.upper < 0 {
					representative = -representative
				}
			}
			delta := representative - mean
			terms = append(terms, b.count*delta*delta)
		}
		return functionSum(terms) / count
	}
	buckets := histogramObservationBuckets(h)
	terms := make([]float64, 0, len(buckets))
	for _, bucket := range buckets {
		representative := (bucket.lower + bucket.upper) / 2
		if profileID == "promql-prometheus-3.1.0" {
			representative = math.Sqrt(bucket.lower * bucket.upper)
			if bucket.upper < 0 {
				representative = -representative
			}
		}
		delta := representative - mean
		terms = append(terms, bucket.count*delta*delta)
	}
	return functionSum(terms) / count
}

type histogramClassicBucket struct{ upper, count float64 }

func histogramClassicCoalesce(buckets []histogramClassicBucket) ([]histogramClassicBucket, bool) {
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].upper < buckets[j].upper })
	out := make([]histogramClassicBucket, 0, len(buckets))
	for _, b := range buckets {
		if len(out) > 0 && out[len(out)-1].upper == b.upper {
			out[len(out)-1].count += b.count
		} else {
			out = append(out, b)
		}
	}
	forced := false
	for i := 1; i < len(out); i++ {
		previous := out[i-1].count
		current := out[i].count
		if histogramAlmostEqual(current, previous) {
			out[i].count = previous
		} else if current < previous {
			out[i].count = previous
			forced = true
		}
	}
	return out, forced
}
func histogramClassicQuantile(q float64, b []histogramClassicBucket) (float64, bool) {
	if math.IsNaN(q) {
		return math.NaN(), false
	}
	if q < 0 {
		return math.Inf(-1), false
	}
	if q > 1 {
		return math.Inf(1), false
	}
	b, forced := histogramClassicCoalesce(b)
	if len(b) < 2 || !math.IsInf(b[len(b)-1].upper, 1) || b[len(b)-1].count == 0 {
		return math.NaN(), forced
	}
	rank := q * b[len(b)-1].count
	index := sort.Search(len(b)-1, func(i int) bool { return b[i].count >= rank })
	if index == len(b)-1 {
		return b[len(b)-2].upper, forced
	}
	if index == 0 && b[0].upper <= 0 {
		return b[0].upper, forced
	}
	lower, previous := 0.0, 0.0
	if index > 0 {
		lower, previous = b[index-1].upper, b[index-1].count
	}
	return lower + (b[index].upper-lower)*(rank-previous)/(b[index].count-previous), forced
}
func histogramClassicFraction(lower, upper float64, b []histogramClassicBucket) float64 {
	b, _ = histogramClassicCoalesce(b)
	if len(b) < 2 || !math.IsInf(b[len(b)-1].upper, 1) || b[len(b)-1].count == 0 || math.IsNaN(lower) || math.IsNaN(upper) {
		return math.NaN()
	}
	if lower >= upper {
		return 0
	}
	rank := func(bound float64) float64 {
		previous, previousCount := 0.0, 0.0
		for _, bucket := range b {
			if bucket.upper >= bound {
				if math.IsInf(bucket.upper, 1) {
					if math.IsInf(bound, 1) {
						return bucket.count
					}
					return previousCount
				}
				if previous == bucket.upper {
					return bucket.count
				}
				return previousCount + (bucket.count-previousCount)*math.Max(0, (bound-previous)/(bucket.upper-previous))
			}
			previous, previousCount = bucket.upper, bucket.count
		}
		return b[len(b)-1].count
	}
	return (rank(upper) - rank(lower)) / b[len(b)-1].count
}
func functionHistogram(ctx context.Context, call CallPlan, args []value.Result, f Frame) (value.Result, []syntax.Diagnostic, error) {
	out := value.Result{Type: "vector"}
	var d []syntax.Diagnostic
	name := call.Name
	if name == "histogram_quantiles" {
		label := args[1].String
		if !functionLabelValid(label) {
			return out, nil, functionError(call.Expr, "function.invalid-label", "invalid quantile destination label")
		}
		for i, quantile := range args[2:] {
			if q := functionFloat(quantile.Scalar); math.IsNaN(q) || q < 0 || q > 1 {
				d = append(d, functionDiagnosticArg(call.Expr, "InvalidQuantileWarning", 2+i))
			}
			single := CallPlan{Name: "histogram_quantile", Expr: call.Expr}
			r, ds, e := functionHistogramOne(ctx, single, []value.Result{quantile, args[0]}, f, false)
			d = append(d, ds...)
			if e != nil {
				return out, d, e
			}
			for _, s := range r.Vector {
				s.Labels = value.SetLabel(s.Labels, label, openMetricsFloat(functionFloat(quantile.Scalar)))
				out.Vector = append(out.Vector, s)
			}
		}
		return out, d, nil
	}
	return functionHistogramOne(ctx, call, args, f, true)
}

// functionHistogramOne evaluates one histogram function; reportInvalid says
// whether an out-of-range quantile is reported by this call (histogram_quantiles
// reports each of its quantiles itself, at the quantile's own argument).
func functionHistogramOne(ctx context.Context, call CallPlan, args []value.Result, f Frame, reportInvalid bool) (value.Result, []syntax.Diagnostic, error) {
	out := value.Result{Type: "vector"}
	var d []syntax.Diagnostic
	name := call.Name
	index := 0
	if name == "histogram_quantile" {
		index = 1
	}
	if name == "histogram_fraction" {
		index = 2
	}
	quantile := name == "histogram_quantile"
	fraction := name == "histogram_fraction"
	if !quantile && !fraction {
		for _, series := range args[index].Vector {
			if err := functionCheck(ctx, f); err != nil {
				return out, d, err
			}
			if len(series.Samples) == 0 || series.Samples[0].Histogram == nil {
				continue
			}
			histogram := series.Samples[0].Histogram
			view := histogramView(*histogram)
			count, sum := math.Float64frombits(uint64(view.Count)), math.Float64frombits(uint64(view.Sum))
			result := 0.0
			switch name {
			case "histogram_count":
				result = count
			case "histogram_sum":
				result = sum
			case "histogram_avg":
				result = sum / count
			case "histogram_stdvar":
				result = histogramNativeVariance(*histogram, f.Profile.ID)
			case "histogram_stddev":
				result = math.Sqrt(histogramNativeVariance(*histogram, f.Profile.ID))
			default:
				return out, d, functionError(call.Expr, "function.internal-unbound", "unbound histogram function")
			}
			out.Vector = append(out.Vector, functionSeries(series, functionSample(result, f.Time), true))
		}
		return out, d, nil
	}
	q := functionFloat(args[0].Scalar)
	if reportInvalid && quantile && (math.IsNaN(q) || q < 0 || q > 1) {
		d = append(d, functionDiagnostic(call.Expr, "InvalidQuantileWarning"))
	}
	type group struct {
		series  value.Series
		classic []histogramClassicBucket
		native  *model.NativeHistogram
	}
	groups := map[string]*group{}
	order := []string{}
	for _, series := range args[index].Vector {
		if err := functionCheck(ctx, f); err != nil {
			return out, d, err
		}
		if len(series.Samples) == 0 {
			continue
		}
		point := series.Samples[0]
		labels := series.Labels
		if point.Histogram == nil {
			if fraction && f.Profile.ID == "promql-prometheus-3.1.0" {
				continue
			}
			labels = value.SetLabel(labels, "le", "")
		}
		key := string(series.Project[:]) + value.LabelKey(labels)
		entry := groups[key]
		if point.Histogram == nil {
			upper, err := strconv.ParseFloat(value.Label(series.Labels, "le"), 64)
			if err != nil {
				d = append(d, functionDiagnostic(call.Expr, "BadBucketLabelWarning"))
				continue
			}
			if entry == nil {
				base := series
				base.Labels = labels
				entry = &group{series: base}
				groups[key] = entry
				order = append(order, key)
			}
			entry.classic = append(entry.classic, histogramClassicBucket{upper: upper, count: functionFloat(point)})
		} else {
			if entry == nil {
				base := series
				base.Labels = labels
				entry = &group{series: base}
				groups[key] = entry
				order = append(order, key)
			}
			if entry.native != nil {
				return out, d, functionError(call.Expr, "result.duplicate-labelset", "duplicate native histogram identity")
			}
			entry.native = point.Histogram
		}
	}
	for _, key := range order {
		entry := groups[key]
		if entry.native != nil && len(entry.classic) > 0 {
			d = append(d, functionDiagnostic(call.Expr, "MixedClassicNativeHistogramsWarning"))
			delete(groups, key)
		}
	}
	for _, nativePass := range [2]bool{true, false} {
		for _, key := range order {
			entry := groups[key]
			if entry == nil || (entry.native != nil) != nativePass {
				continue
			}
			result := math.NaN()
			reason := ""
			if entry.native != nil {
				if quantile {
					result, reason = histogramNativeQuantile(q, *entry.native, f.Profile.ID)
				} else {
					result, reason = histogramNativeFraction(q, functionFloat(args[1].Scalar), *entry.native, f.Profile.ID)
				}
			} else if len(entry.classic) > 0 {
				if quantile {
					var forced bool
					result, forced = histogramClassicQuantile(q, entry.classic)
					if forced {
						reason = "HistogramQuantileForcedMonotonicityInfo"
					}
				} else {
					result = histogramClassicFraction(q, functionFloat(args[1].Scalar), entry.classic)
				}
			} else {
				continue
			}
			if reason != "" && (f.Profile.ID == "promql-prometheus-3.13.5" || reason == "HistogramQuantileForcedMonotonicityInfo") {
				d = append(d, functionDiagnostic(call.Expr, reason))
			}
			out.Vector = append(out.Vector, functionSeries(entry.series, functionSample(result, f.Time), true))
		}
	}
	return out, d, nil
}
func histogramBinary(op string, a, b value.Sample) (value.Sample, bool, []syntax.Diagnostic, error) {
	return histogramBinaryProfile(op, a, b, profile.Profile{ID: "promql-prometheus-3.13.5"})
}
func histogramBinaryProfile(op string, a, b value.Sample, p profile.Profile) (value.Sample, bool, []syntax.Diagnostic, error) {
	incompatible := func() (value.Sample, bool, []syntax.Diagnostic, error) {
		return value.Sample{}, false, []syntax.Diagnostic{functionDiagnostic(TypedExpr{}, "IncompatibleTypesInBinOpInfo")}, nil
	}
	if a.Histogram != nil && b.Histogram != nil {
		switch op {
		case "==", "!=":
			equal := histogramEquivalent(*a.Histogram, *b.Histogram)
			if op == "!=" {
				equal = !equal
			}
			return value.CloneSample(a), equal, nil, nil
		case "+", "-":
			h, reason := histogramCombineForProfile(*a.Histogram, *b.Histogram, op == "-", p.ID)
			var d []syntax.Diagnostic
			if reason != "" {
				if reason == "MixedExponentialCustomHistogramsWarning" {
					reason = "IncompatibleBucketLayoutInBinOpWarning"
				}
				if p.ID == "promql-prometheus-3.1.0" && reason == "MismatchedCustomBucketsHistogramsInfo" {
					return value.Sample{}, false, []syntax.Diagnostic{functionDiagnostic(TypedExpr{}, "MixedExponentialCustomHistogramsWarning")}, nil
				}
				if p.ID == "promql-prometheus-3.13.5" || reason != "HistogramCounterResetCollisionWarning" {
					d = append(d, functionDiagnostic(TypedExpr{}, reason))
				}
			}
			return value.Sample{Time: a.Time, Histogram: &h}, h.Float != nil, d, nil
		default:
			return incompatible()
		}
	}
	if op == "*" {
		h, factor := a.Histogram, functionFloat(b)
		if h == nil {
			h = b.Histogram
			factor = functionFloat(a)
		}
		if h == nil {
			return incompatible()
		}
		result := histogramScaleForProfile(*h, factor, p.ID)
		return value.Sample{Time: a.Time, Histogram: &result}, true, nil, nil
	}
	if op == "/" && a.Histogram != nil {
		h := histogramDivideForProfile(*a.Histogram, functionFloat(b), p.ID)
		return value.Sample{Time: a.Time, Histogram: &h}, true, nil, nil
	}
	if (op == "</" || op == ">/") && a.Histogram != nil && b.Histogram == nil && p.ID == "promql-prometheus-3.13.5" {
		h := histogramTrim(*a.Histogram, functionFloat(b), op == "</")
		return value.Sample{Time: a.Time, Histogram: &h}, true, nil, nil
	}
	return incompatible()
}
func histogramTrim(h model.NativeHistogram, bound float64, upper bool) model.NativeHistogram {
	f := histogramView(h)
	positive := value.HistogramBuckets(f.PositiveSpans, f.PositiveBuckets)
	negative := value.HistogramBuckets(f.NegativeSpans, f.NegativeBuckets)
	changed := false
	count, sum := 0.0, 0.0
	trim := func(index int32, n float64, neg bool) (float64, float64) {
		b := histogramObservationBucket{count: n}
		if f.Schema == -53 {
			b.lower = math.Inf(-1)
			b.upper = math.Inf(1)
			if index > 0 {
				b.lower = math.Float64frombits(uint64(f.CustomBounds[index-1]))
			}
			if int(index) < len(f.CustomBounds) {
				b.upper = math.Float64frombits(uint64(f.CustomBounds[index]))
			}
		} else {
			b.lower = exponentialBound(f.Schema, index-1)
			b.upper = exponentialBound(f.Schema, index)
			b.exponential = true
			if neg {
				b.lower, b.upper = -b.upper, -b.lower
			}
		}
		return histogramTrimBucket(b, bound, upper, false)
	}
	for k, v := range positive {
		n, s := trim(k, v, false)
		if n != v {
			changed = true
		}
		positive[k] = n
		count += n
		sum += s
	}
	for k, v := range negative {
		n, s := trim(k, v, true)
		if n != v {
			changed = true
		}
		negative[k] = n
		count += n
		sum += s
	}
	zero := math.Float64frombits(uint64(f.ZeroCount))
	if zero != 0 {
		threshold := math.Float64frombits(uint64(f.ZeroThreshold))
		lower, higher := -threshold, threshold
		if len(negative) == 0 {
			lower = 0
		}
		if len(positive) == 0 {
			higher = 0
		}
		n, s := histogramTrimBucket(histogramObservationBucket{lower: lower, upper: higher, count: zero}, bound, upper, true)
		if n != zero {
			changed = true
		}
		zero = n
		count += n
		sum += s
	}
	if !changed {
		return h
	}
	f.Count = model.FloatBits(math.Float64bits(count))
	f.Sum = model.FloatBits(math.Float64bits(sum))
	f.ZeroCount = model.FloatBits(math.Float64bits(zero))
	f.PositiveSpans, f.PositiveBuckets = histogramEncodeTrim(positive)
	f.NegativeSpans, f.NegativeBuckets = histogramEncodeTrim(negative)
	return model.NativeHistogram{Float: &f}
}
func histogramBucketRepresentative(b histogramObservationBucket) float64 {
	if math.IsInf(b.lower, -1) {
		if math.IsInf(b.upper, 1) {
			return 0
		}
		if b.upper > 0 {
			return b.upper / 2
		}
		return b.upper
	}
	if math.IsInf(b.upper, 1) {
		return b.lower
	}
	if b.exponential {
		mid := math.Sqrt(math.Abs(b.lower)) * math.Sqrt(math.Abs(b.upper))
		if b.upper < 0 {
			return -mid
		}
		return mid
	}
	return (b.lower + b.upper) / 2
}
func histogramTrimBucket(b histogramObservationBucket, bound float64, upper, zero bool) (float64, float64) {
	if b.count == 0 {
		return 0, 0
	}
	if upper {
		if b.upper <= bound {
			return b.count, b.count * histogramBucketRepresentative(b)
		}
		if b.lower >= bound {
			return 0, 0
		}
	} else {
		if b.lower >= bound {
			return b.count, b.count * histogramBucketRepresentative(b)
		}
		if b.upper <= bound {
			return 0, 0
		}
	}
	if math.IsNaN(bound) {
		if zero {
			return math.NaN(), math.NaN()
		}
		return 0, 0
	}
	if math.IsInf(b.lower, -1) {
		if upper {
			if b.upper <= 0 {
				return b.count, b.count * bound
			}
			if bound > 0 && bound < b.upper {
				n := b.count * bound / b.upper
				return n, n * bound / 2
			}
			return 0, 0
		}
		if bound >= 0 && bound < b.upper {
			n := b.count * (1 - bound/b.upper)
			return n, n * (bound + b.upper) / 2
		}
		return 0, 0
	}
	if math.IsInf(b.upper, 1) {
		if !upper && bound >= b.lower {
			return b.count, b.count * bound
		}
		return 0, 0
	}
	fraction := histogramBucketFraction(b, bound)
	if !upper {
		fraction = 1 - fraction
		b.lower = bound
	} else {
		b.upper = bound
	}
	n := b.count * fraction
	return n, n * histogramBucketRepresentative(b)
}
func histogramEncodeTrim(m map[int32]float64) ([]model.HistogramSpan, []model.FloatBits) {
	keys := []int32{}
	for k, v := range m {
		if v != 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	spans := []model.HistogramSpan{}
	buckets := []model.FloatBits{}
	next := int32(0)
	for _, k := range keys {
		if len(spans) == 0 || k != next {
			spans = append(spans, model.HistogramSpan{Offset: k - next, Length: 1})
		} else {
			spans[len(spans)-1].Length++
		}
		next = k + 1
		buckets = append(buckets, model.FloatBits(math.Float64bits(m[k])))
	}
	return spans, buckets
}
func histogramResetForProfile(previous, current model.NativeHistogram, profileID string) bool {
	if profileID == "promql-prometheus-3.1.0" {
		a, b := histogramView(previous), histogramView(current)
		if b.ResetHint == "reset" {
			return true
		}
		if b.ResetHint == "not_reset" {
			return false
		}
		if a.Schema == -53 && b.Schema == -53 {
			if len(a.CustomBounds) != len(b.CustomBounds) {
				return true
			}
			for i, bound := range a.CustomBounds {
				if bound != b.CustomBounds[i] {
					return true
				}
			}
		}
	}
	return value.HistogramReset(previous, current)
}
func histogramAlmostEqual(a, b float64) bool {
	if a == b {
		return true
	}
	if math.IsNaN(a) && math.IsNaN(b) {
		return (math.Float64bits(a) == uint64(value.StaleBits)) == (math.Float64bits(b) == uint64(value.StaleBits))
	}
	difference := math.Abs(a - b)
	norm := math.Abs(a) + math.Abs(b)
	minimum := math.Float64frombits(0x0010000000000000)
	if a == 0 || b == 0 || norm < minimum {
		return difference < 1e-12*minimum
	}
	return difference/math.Min(norm, math.MaxFloat64) < 1e-12
}
func histogramCombineForProfile(a, b model.NativeHistogram, subtract bool, profileID string) (model.NativeHistogram, string) {
	histogram, reason := value.CombineHistograms(a, b, subtract)
	if profileID == "promql-prometheus-3.1.0" {
		if reason == "MismatchedCustomBucketsHistogramsInfo" {
			return model.NativeHistogram{}, "IncompatibleCustomBucketsHistogramsWarning"
		}
		if reason == "HistogramCounterResetCollisionWarning" {
			reason = ""
		}
		if subtract && histogram.Float != nil {
			left := histogramView(a)
			histogram.Float.Flavor, histogram.Float.ResetHint = left.Flavor, left.ResetHint
		}
	}
	return histogram, reason
}
func histogramScaleForProfile(histogram model.NativeHistogram, factor float64, profileID string) model.NativeHistogram {
	result := value.ScaleHistogram(histogram, factor)
	if profileID == "promql-prometheus-3.1.0" {
		input := histogramView(histogram)
		result.Float.Flavor, result.Float.ResetHint = input.Flavor, input.ResetHint
	}
	return result
}
func histogramDivideForProfile(histogram model.NativeHistogram, divisor float64, profileID string) model.NativeHistogram {
	result := value.DivideHistogram(histogram, divisor)
	if profileID == "promql-prometheus-3.1.0" {
		input := histogramView(histogram)
		result.Float.Flavor, result.Float.ResetHint = input.Flavor, input.ResetHint
	}
	return result
}
