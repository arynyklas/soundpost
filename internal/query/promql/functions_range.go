// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"strings"
	"time"
)

func functionQuantile(q float64, xs []float64) float64 {
	if math.IsNaN(q) || len(xs) == 0 {
		return math.NaN()
	}
	if q < 0 {
		return math.Inf(-1)
	}
	if q > 1 {
		return math.Inf(1)
	}
	sort.Float64s(xs)
	rank := q * float64(len(xs)-1)
	lo := int(math.Floor(rank))
	hi := lo + 1
	if hi >= len(xs) {
		hi = lo
	}
	weight := rank - float64(lo)
	return xs[lo]*(1-weight) + xs[hi]*weight
}
func functionSum(xs []float64) float64 {
	sum, comp := 0.0, 0.0
	for _, x := range xs {
		next := sum + x
		if math.IsInf(next, 0) {
			comp = 0
		} else if math.Abs(sum) >= math.Abs(x) {
			comp += (sum - next) + x
		} else {
			comp += (x - next) + sum
		}
		sum = next
	}
	return sum + comp
}
func functionMean(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	sum := functionSum(xs)
	if !math.IsInf(sum, 0) {
		return sum / float64(len(xs))
	}
	allFinite := true
	for _, x := range xs {
		if math.IsInf(x, 0) || math.IsNaN(x) {
			allFinite = false
			break
		}
	}
	if !allFinite {
		return sum / float64(len(xs))
	}
	mean := xs[0]
	for i, x := range xs[1:] {
		n := float64(i + 2)
		mean += x/n - mean/n
	}
	return mean
}
func functionVariance(xs []float64) float64 {
	mean, m2 := 0.0, 0.0
	for i, x := range xs {
		d := x - mean
		mean += d / float64(i+1)
		m2 += d * (x - mean)
	}
	return m2 / float64(len(xs))
}
func functionRegression(xs []value.Sample, reference model.UnixNano) (float64, float64) {
	if len(xs) < 2 {
		return math.NaN(), math.NaN()
	}
	first := functionFloat(xs[0])
	constant := true
	var sums, compensation [4]float64
	add := func(index int, v float64) {
		sum := sums[index]
		next := sum + v
		if math.IsInf(next, 0) {
			compensation[index] = 0
		} else if math.Abs(sum) >= math.Abs(v) {
			compensation[index] += (sum - next) + v
		} else {
			compensation[index] += (v - next) + sum
		}
		sums[index] = next
	}
	for _, point := range xs {
		x := float64(point.Time-reference) / 1e9
		y := functionFloat(point)
		if y != first {
			constant = false
		}
		add(0, x)
		add(1, y)
		add(2, x*y)
		add(3, x*x)
	}
	if constant {
		if math.IsInf(first, 0) {
			return math.NaN(), math.NaN()
		}
		return 0, first
	}
	for i := range sums {
		sums[i] += compensation[i]
	}
	n := float64(len(xs))
	slope := (sums[2] - sums[0]*sums[1]/n) / (sums[3] - sums[0]*sums[0]/n)
	return slope, sums[1]/n - slope*sums[0]/n
}
func functionRangeBounds(call CallPlan, f Frame) (model.UnixNano, model.UnixNano, string) {
	if f.HasWindow {
		return f.WindowStart, f.WindowEnd, functionRangeExtension(call)
	}
	duration := int64(0)
	var n *Node
	if len(call.Expr.Children) > 0 {
		n, _ = call.Expr.Children[0].Expr.(*Node)
	}
	if n == nil {
		if root, ok := call.Expr.Expr.(*Node); ok && len(root.Children) > 0 {
			n, _ = root.Children[0].(*Node)
		}
	}
	if n != nil {
		if d, e := time.ParseDuration(n.RangeText); e == nil {
			duration = int64(d)
		}
	}
	if duration <= 0 {
		duration = 5 * 60 * 1e9
	}
	return f.Time - model.UnixNano(duration), f.Time, functionRangeExtension(call)
}
func functionRangeExtension(call CallPlan) string {
	if n, ok := call.Expr.Expr.(*Node); ok {
		for _, e := range n.Children {
			if x, ok := e.(*Node); ok && x.Extension != "" {
				return x.Extension
			}
		}
	}
	for _, e := range call.Expr.Children {
		if n, ok := e.Expr.(*Node); ok && n.Extension != "" {
			return n.Extension
		}
	}
	return ""
}
func functionRange(ctx context.Context, call CallPlan, args []value.Result, index int, f Frame) (value.Result, []syntax.Diagnostic, error) {
	out := value.Result{Type: "vector"}
	var diagnostics []syntax.Diagnostic
	name := call.Name
	start, end, extension := functionRangeBounds(call, f)
	if extension != "" {
		allowed := name == "rate" || name == "increase" || name == "delta" || extension == "anchored" && (name == "changes" || name == "resets")
		if !allowed {
			return out, nil, functionError(call.Expr, "function.range-extension", "range extension is invalid for this function")
		}
	}
	if name == "double_exponential_smoothing" {
		sf, tf := functionFloat(args[1].Scalar), functionFloat(args[2].Scalar)
		if sf <= 0 || sf >= 1 || tf <= 0 || tf >= 1 {
			return out, nil, functionError(call.Expr, "function.invalid-parameter", "smoothing and trend factors must be between zero and one")
		}
	}
	if name == "quantile_over_time" {
		q := functionFloat(args[0].Scalar)
		if math.IsNaN(q) || q < 0 || q > 1 {
			diagnostics = append(diagnostics, functionDiagnostic(call.Expr, "InvalidQuantileWarning"))
		}
	}
	for _, series := range args[index].Matrix {
		if e := functionCheck(ctx, f); e != nil {
			return out, diagnostics, e
		}
		samples := series.Samples
		if len(samples) == 0 {
			continue
		}
		floats := make([]value.Sample, 0, len(samples))
		xs := make([]float64, 0, len(samples))
		histCount := 0
		for _, p := range samples {
			if p.Histogram == nil {
				floats = append(floats, p)
				xs = append(xs, functionFloat(p))
			} else {
				histCount++
			}
		}
		mixed := len(floats) > 0 && histCount > 0
		emit := true
		drop := true
		sample := functionSample(0, f.Time)
		var ds []syntax.Diagnostic
		switch name {
		case "last_over_time", "first_over_time":
			p := samples[len(samples)-1]
			if name == "first_over_time" {
				p = samples[0]
			}
			sample = value.CloneSample(p)
			sample.Time = f.Time
			drop = false
		case "ts_of_first_over_time":
			sample = functionSample(float64(samples[0].Time)/1e9, f.Time)
		case "ts_of_last_over_time":
			sample = functionSample(float64(samples[len(samples)-1].Time)/1e9, f.Time)
		case "count_over_time":
			sample = functionSample(float64(len(samples)), f.Time)
		case "present_over_time":
			sample = functionSample(1, f.Time)
		case "changes", "resets":
			count := 0.0
			for i := 1; i < len(samples); i++ {
				previous, current := samples[i-1], samples[i]
				changed := false
				if (previous.Histogram == nil) != (current.Histogram == nil) {
					changed = true
				} else if previous.Histogram == nil {
					a, b := functionFloat(previous), functionFloat(current)
					if name == "resets" {
						changed = b < a || functionStartTimestampReset(previous, current, f)
					} else {
						changed = a != b && !(math.IsNaN(a) && math.IsNaN(b))
					}
				} else if name == "resets" {
					changed = histogramResetForProfile(*previous.Histogram, *current.Histogram, f.Profile.ID) || functionStartTimestampReset(previous, current, f)
				} else {
					changed = !histogramEquivalent(*previous.Histogram, *current.Histogram)
				}
				if changed {
					count++
				}
			}
			if extension != "" && samples[len(samples)-1].Time <= start {
				emit = false
			}
			sample = functionSample(count, f.Time)
		case "sum_over_time", "avg_over_time":
			if mixed {
				emit = false
				ds = append(ds, functionDiagnostic(call.Expr, "MixedFloatsHistogramsWarning"))
			} else if histCount > 0 {
				h := value.CloneHistogram(*samples[0].Histogram)
				for _, p := range samples[1:] {
					var reason string
					h, reason = histogramCombineForProfile(h, *p.Histogram, false, f.Profile.ID)
					if reason != "" {
						ds = append(ds, functionDiagnostic(call.Expr, reason))
						if h.Float == nil || reason == "MismatchedCustomBucketsHistogramsInfo" && f.Profile.ID == "promql-prometheus-3.1.0" {
							emit = false
							break
						}
					}
				}
				if emit {
					if name == "avg_over_time" {
						h = value.ScaleHistogram(h, 1/float64(len(samples)))
					}
					sample = value.Sample{Time: f.Time, Histogram: &h}
				}
			} else {
				x := functionSum(xs)
				if name == "avg_over_time" {
					x = functionMean(xs)
				}
				sample = functionSample(x, f.Time)
			}
		case "rate", "increase", "delta", "irate", "idelta":
			var e error
			sample, emit, ds, e = functionRate(call, series, start, end, extension, f)
			if e != nil {
				return out, append(diagnostics, ds...), e
			}
		default:
			if len(floats) == 0 {
				emit = false
				break
			}
			if mixed && f.Profile.ID == "promql-prometheus-3.13.5" {
				ds = append(ds, functionDiagnostic(call.Expr, "HistogramIgnoredInMixedRangeInfo"))
			}
			x := math.NaN()
			switch name {
			case "min_over_time", "max_over_time", "ts_of_min_over_time", "ts_of_max_over_time":
				chosen := floats[0]
				x = functionFloat(chosen)
				minimum := strings.Contains(name, "min")
				for _, p := range floats[1:] {
					y := functionFloat(p)
					if math.IsNaN(x) || minimum && y <= x || !minimum && y >= x {
						chosen = p
						x = y
					}
				}
				if strings.HasPrefix(name, "ts_of_") {
					x = float64(chosen.Time) / 1e9
				}
			case "quantile_over_time":
				x = functionQuantile(functionFloat(args[0].Scalar), xs)
			case "mad_over_time":
				median := functionQuantile(.5, append([]float64(nil), xs...))
				for i, v := range xs {
					xs[i] = math.Abs(v - median)
				}
				x = functionQuantile(.5, xs)
			case "stdvar_over_time", "stddev_over_time":
				x = functionVariance(xs)
				if name == "stddev_over_time" {
					x = math.Sqrt(x)
				}
			case "deriv", "predict_linear":
				if len(floats) < 2 {
					emit = false
					break
				}
				slope, intercept := functionRegression(floats, f.Time)
				x = slope
				if name == "predict_linear" {
					x = intercept + slope*functionFloat(args[1].Scalar)
				}
			case "double_exponential_smoothing":
				if len(xs) < 2 {
					emit = false
					break
				}
				sf, tf := functionFloat(args[1].Scalar), functionFloat(args[2].Scalar)
				level, trend := xs[0], xs[1]-xs[0]
				for _, observation := range xs[1:] {
					next := sf*observation + (1-sf)*(level+trend)
					trend = tf*(next-level) + (1-tf)*trend
					level = next
				}
				x = level
			default:
				return out, diagnostics, functionError(call.Expr, "function.internal-unbound", "unbound range function implementation")
			}
			sample = functionSample(x, f.Time)
		}
		diagnostics = append(diagnostics, ds...)
		if emit {
			out.Vector = append(out.Vector, functionSeries(series, sample, drop))
		}
	}
	return out, diagnostics, nil
}
func functionRate(call CallPlan, s value.Series, start, end model.UnixNano, extension string, f Frame) (value.Sample, bool, []syntax.Diagnostic, error) {
	name := call.Name
	instant := name == "irate" || name == "idelta"
	counter := name == "rate" || name == "increase" || name == "irate"
	points := s.Samples
	if instant && f.Profile.ID == "promql-prometheus-3.1.0" {
		points = make([]value.Sample, 0, len(s.Samples))
		for _, p := range s.Samples {
			if p.Histogram == nil {
				points = append(points, p)
			}
		}
	}
	if instant && len(points) > 2 {
		points = points[len(points)-2:]
	}
	if len(points) < 2 {
		return value.Sample{}, false, nil, nil
	}
	var d []syntax.Diagnostic
	first, last := points[0], points[len(points)-1]
	hist := first.Histogram != nil
	for _, p := range points {
		if (p.Histogram != nil) != hist {
			return value.Sample{}, false, []syntax.Diagnostic{functionDiagnostic(call.Expr, "MixedFloatsHistogramsWarning")}, nil
		}
	}
	span := float64(last.Time-first.Time) / 1e9
	if span <= 0 {
		return value.Sample{}, false, nil, nil
	}
	var result value.Sample
	counterInitial := functionFloat(first)
	if hist {
		for _, point := range points {
			view := histogramView(*point.Histogram)
			id := ""
			if counter && view.Flavor == "gauge" {
				id = "NativeHistogramNotCounterWarning"
			}
			if !counter && view.Flavor != "gauge" {
				id = "NativeHistogramNotGaugeWarning"
			}
			if id != "" {
				d = append(d, functionDiagnostic(call.Expr, id))
				break
			}
		}
		baseline := *first.Histogram
		firstIgnored := false
		if counter && f.Profile.ID == "promql-prometheus-3.13.5" && (histogramResetForProfile(*points[0].Histogram, *points[1].Histogram, f.Profile.ID) || functionStartTimestampReset(points[0], points[1], f)) {
			baseline = histogramEmptyShape(*points[1].Histogram)
			firstIgnored = true
		}
		counterInitial = math.Float64frombits(uint64(histogramView(baseline).Count))
		histogram, reason := histogramCombineForProfile(*last.Histogram, baseline, true, f.Profile.ID)
		if reason != "" {
			d = append(d, functionDiagnostic(call.Expr, reason))
		}
		if histogram.Float == nil {
			return value.Sample{}, false, d, nil
		}
		if counter {
			for i := 1; i < len(points); i++ {
				if histogramResetForProfile(*points[i-1].Histogram, *points[i].Histogram, f.Profile.ID) || functionStartTimestampReset(points[i-1], points[i], f) {
					if i == 1 && firstIgnored {
						continue
					}
					histogram, reason = histogramCombineForProfile(histogram, *points[i-1].Histogram, false, f.Profile.ID)
					if reason != "" {
						d = append(d, functionDiagnostic(call.Expr, reason))
					}
					if histogram.Float == nil {
						return value.Sample{}, false, d, nil
					}
				}
			}
		}
		// All observations constrain the output layout, including an interior
		// coarser schema that did not itself cause a reset.
		begin := 0
		if firstIgnored {
			begin = 1
		}
		for _, point := range points[begin:] {
			histogram, reason = histogramCombineForProfile(histogram, histogramEmptyShape(*point.Histogram), false, f.Profile.ID)
			if reason != "" {
				d = append(d, functionDiagnostic(call.Expr, reason))
			}
			if histogram.Float == nil {
				return value.Sample{}, false, d, nil
			}
		}
		result = value.Sample{Time: f.Time, Histogram: &histogram}
	} else {
		change := functionFloat(last) - functionFloat(first)
		if counter {
			for i := 1; i < len(points); i++ {
				previous, current := functionFloat(points[i-1]), functionFloat(points[i])
				if current < previous || functionStartTimestampReset(points[i-1], points[i], f) {
					change += previous
				}
			}
		}
		result = functionSample(change, f.Time)
		if counter && !instant {
			metricName := value.Label(s.Labels, "__name__")
			if metricName != "" {
				if f.Profile.ID == "promql-prometheus-3.13.5" && enabled(f.Profile, "type-and-unit-labels") {
					metricType := value.Label(s.Labels, "__type__")
					if metricType != "counter" && metricType != "histogram" {
						d = append(d, functionDiagnostic(call.Expr, "PossibleNonCounterLabelInfo"))
					}
				} else if !strings.HasSuffix(metricName, "_total") && !strings.HasSuffix(metricName, "_sum") && !strings.HasSuffix(metricName, "_count") && !strings.HasSuffix(metricName, "_bucket") {
					d = append(d, functionDiagnostic(call.Expr, "PossibleNonCounterInfo"))
				}
			}
		}
	}
	factor := 1.0
	if instant {
		if name == "irate" {
			if result.Histogram != nil {
				histogram := value.DivideHistogram(*result.Histogram, span)
				result.Histogram = &histogram
			} else {
				result.Float = model.FloatBits(math.Float64bits(functionFloat(result) / span))
			}
		}
		if result.Histogram != nil {
			result.Histogram.Float.Flavor = "gauge"
			result.Histogram.Float.ResetHint = "gauge"
		}
		return result, true, d, nil
	} else if extension != "" {
		var keep bool
		var err error
		result, keep, err = functionExtendedRate(points, start, end, extension, counter, f)
		if err != nil || !keep {
			return value.Sample{}, false, d, err
		}
		if name == "rate" {
			duration := float64(end-start) / 1e9
			if result.Histogram != nil {
				histogram := value.DivideHistogram(*result.Histogram, duration)
				result.Histogram = &histogram
			} else {
				result.Float = model.FloatBits(math.Float64bits(functionFloat(result) / duration))
			}
		}
		if result.Histogram != nil {
			result.Histogram.Float.Flavor = "gauge"
			result.Histogram.Float.ResetHint = "gauge"
		}
		return result, true, d, nil
	} else {
		left, right := float64(first.Time-start)/1e9, float64(end-last.Time)/1e9
		average := span / float64(len(points)-1)
		if left >= average*1.1 {
			left = average / 2
		}
		if right >= average*1.1 {
			right = average / 2
		}
		if counter {
			change := functionFloat(result)
			if hist {
				change = math.Float64frombits(uint64(histogramView(*result.Histogram).Count))
			}
			if (!hist || f.Profile.ID == "promql-prometheus-3.13.5") && change > 0 && counterInitial >= 0 {
				toZero := span * (counterInitial / change)
				if toZero < left {
					left = toZero
				}
			}
		}
		factor = (span + left + right) / span
		if name == "rate" {
			factor /= float64(end-start) / 1e9
		}
	}
	if result.Histogram != nil {
		histogram := value.ScaleHistogram(*result.Histogram, factor)
		histogram.Float.Flavor = "gauge"
		histogram.Float.ResetHint = "gauge"
		result.Histogram = &histogram
	} else {
		result.Float = model.FloatBits(math.Float64bits(functionFloat(result) * factor))
	}
	return result, true, d, nil
}
func functionInterpolate(previous, current value.Sample, at model.UnixNano, counter bool, frame Frame) (value.Sample, bool) {
	if previous.Time == current.Time || at == previous.Time {
		return value.CloneSample(previous), true
	}
	fraction := float64(at-previous.Time) / float64(current.Time-previous.Time)
	if (previous.Histogram == nil) != (current.Histogram == nil) {
		return value.Sample{}, false
	}
	if previous.Histogram == nil {
		left, right := functionFloat(previous), functionFloat(current)
		if counter && (right < left || functionStartTimestampReset(previous, current, frame)) {
			left = 0
		}
		return functionSample(left+(right-left)*fraction, at), true
	}
	baseline := *previous.Histogram
	if counter && (histogramResetForProfile(baseline, *current.Histogram, frame.Profile.ID) || functionStartTimestampReset(previous, current, frame)) {
		baseline = histogramEmptyShape(*current.Histogram)
	}
	left, right := value.ScaleHistogram(baseline, 1-fraction), value.ScaleHistogram(*current.Histogram, fraction)
	histogram, _ := histogramCombineForProfile(left, right, false, frame.Profile.ID)
	if histogram.Float == nil {
		return value.Sample{}, false
	}
	return value.Sample{Time: at, Histogram: &histogram}, true
}
func functionExtendedRate(points []value.Sample, start, end model.UnixNano, extension string, counter bool, f Frame) (value.Sample, bool, error) {
	if points[len(points)-1].Time <= start || points[0].Time > end {
		return value.Sample{}, false, nil
	}
	left := points[0]
	if extension == "smoothed" && len(points) > 1 && left.Time < start {
		for i := 1; i < len(points); i++ {
			if points[i].Time >= start {
				var ok bool
				left, ok = functionInterpolate(points[i-1], points[i], start, counter, f)
				if !ok {
					return value.Sample{}, false, nil
				}
				break
			}
		}
	}
	right := points[len(points)-1]
	if extension == "smoothed" && right.Time > end {
		for i := 1; i < len(points); i++ {
			if points[i].Time >= end {
				var ok bool
				right, ok = functionInterpolate(points[i-1], points[i], end, counter, f)
				if !ok {
					return value.Sample{}, false, nil
				}
				break
			}
		}
	}
	if left.Histogram == nil {
		change := functionFloat(right) - functionFloat(left)
		if counter {
			previous := left
			for _, point := range points {
				if point.Time <= start || point.Time > end {
					continue
				}
				currentValue, previousValue := functionFloat(point), functionFloat(previous)
				if currentValue < previousValue || functionStartTimestampReset(previous, point, f) {
					change += previousValue
				}
				previous = point
			}
		}
		return functionSample(change, f.Time), true, nil
	}
	h, _ := histogramCombineForProfile(*right.Histogram, *left.Histogram, true, f.Profile.ID)
	if h.Float == nil {
		return value.Sample{}, false, nil
	}
	if counter {
		for i := 1; i < len(points); i++ {
			if points[i].Time > start && points[i].Time <= end && (histogramResetForProfile(*points[i-1].Histogram, *points[i].Histogram, f.Profile.ID) || functionStartTimestampReset(points[i-1], points[i], f)) {
				h, _ = histogramCombineForProfile(h, *points[i-1].Histogram, false, f.Profile.ID)
				if h.Float == nil {
					return value.Sample{}, false, nil
				}
			}
		}
	}
	return value.Sample{Time: f.Time, Histogram: &h}, true, nil
}
func histogramEmptyShape(histogram model.NativeHistogram) model.NativeHistogram {
	view := histogramView(histogram)
	return model.NativeHistogram{Float: &model.FloatHistogram{Schema: view.Schema, Flavor: "gauge", ResetHint: "gauge", ZeroThreshold: view.ZeroThreshold, CustomBounds: append([]model.FloatBits(nil), view.CustomBounds...)}}
}
func functionStartTimestampReset(previous, current value.Sample, frame Frame) bool {
	if frame.Profile.ID != "promql-prometheus-3.13.5" || !enabled(frame.Profile, "use-start-timestamps") {
		return false
	}
	previousStart, currentStart := int64(0), int64(0)
	if previous.StartTimestamp != nil {
		previousStart = int64(*previous.StartTimestamp) / 1_000_000
	}
	if current.StartTimestamp != nil {
		currentStart = int64(*current.StartTimestamp) / 1_000_000
	}
	previousTime, currentTime := int64(previous.Time)/1_000_000, int64(current.Time)/1_000_000
	if currentStart == 0 || currentStart > currentTime || currentStart < previousTime {
		return false
	}
	if currentStart > previousTime {
		return true
	}
	return previousStart != 0 && previousStart <= previousTime
}
