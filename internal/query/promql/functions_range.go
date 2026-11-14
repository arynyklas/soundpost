// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"sort"
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
	rank := float64(q * float64(len(xs)-1))
	lo := int(math.Floor(rank))
	hi := lo + 1
	if hi >= len(xs) {
		hi = lo
	}
	weight := rank - float64(lo)
	return value.Add(value.Mul(xs[lo], 1-weight), value.Mul(xs[hi], weight))
}
func functionKahan(xs []float64) (float64, float64) {
	sum, comp := 0.0, 0.0
	for _, x := range xs {
		sum, comp = functionKahanAdd(sum, comp, x)
	}
	return sum, comp
}

func functionKahanAdd(sum, comp, x float64) (float64, float64) {
	next := value.Add(sum, x)
	if math.IsInf(next, 0) {
		return next, 0
	}
	if math.Abs(sum) >= math.Abs(x) {
		return next, value.Add(comp, value.Add(value.Sub(sum, next), x))
	}
	return next, value.Add(comp, value.Add(value.Sub(x, next), sum))
}

func functionSum(xs []float64) float64 {
	sum, comp := functionKahan(xs)
	return value.Add(sum, comp)
}

// functionMean is the compensated mean shared by avg_over_time and the avg
// aggregation. Both pinned releases sum with Neumaier compensation and divide
// once at the end, but switch mid-stream to an incremental mean that keeps the
// compensation as soon as the running sum would become +/-Inf (a finite input
// set can overflow the sum while its mean is representable; an infinite input
// also trips the switch). The two releases differ in the divide and in the
// incremental step:
//
//	3.1.0:  (sum+c)/n; incremental step folds f/n - (mean+c)/n into mean,
//	        with an Inf-mean guard.
//	3.13.5: sum/n + c/n; incremental step scales mean and c by (n-1)/n and
//	        folds f/n.
func functionMean(xs []float64, profileID string) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	if profileID == "promql-prometheus-3.13.5" {
		return functionMean3135(xs)
	}
	return functionMean310(xs)
}

func functionMean310(xs []float64) float64 {
	var sum, mean, count, comp float64
	incremental := false
	for _, x := range xs {
		count++
		if !incremental {
			next, nextComp := functionKahanAdd(sum, comp, x)
			// The first value is always accepted, even if infinite, so the
			// switch never divides by a zero count.
			if count == 1 || !math.IsInf(next, 0) {
				sum, comp = next, nextComp
				continue
			}
			incremental = true
			mean = sum / (count - 1)
			comp /= count - 1
		}
		if math.IsInf(mean, 0) {
			// An infinite mean cannot absorb a finite value or an equal
			// infinity through the subtraction below (Inf - Inf = NaN).
			if math.IsInf(x, 0) && (mean > 0) == (x > 0) {
				continue
			}
			if !math.IsInf(x, 0) && !math.IsNaN(x) {
				continue
			}
		}
		corrected := mean + comp
		mean, comp = functionKahanAdd(mean, comp, x/count-corrected/count)
	}
	if incremental {
		return mean + comp
	}
	return (sum + comp) / count
}

func functionMean3135(xs []float64) float64 {
	sum, count := xs[0], 1.0
	var mean, comp float64
	incremental := false
	for i, x := range xs[1:] {
		count = float64(i + 2)
		if !incremental {
			next, nextComp := functionKahanAdd(sum, comp, x)
			if !math.IsInf(next, 0) {
				sum, comp = next, nextComp
				continue
			}
			incremental = true
			mean = sum / (count - 1)
			comp /= count - 1
		}
		// Explicit conversions keep the products rounded to float64 on
		// targets that would otherwise fuse them into the following add.
		q := (count - 1) / count
		scaledMean, scaledComp := float64(q*mean), float64(q*comp)
		mean, comp = functionKahanAdd(scaledMean, scaledComp, x/count)
	}
	if incremental {
		return mean + comp
	}
	return sum/count + comp/count
}

// functionRangeVariance is the window (`*_over_time`) population variance: a
// Kahan-compensated incremental mean and a Kahan-compensated sum of squared
// deviations, on both pinned releases. The aggregation operators use
// functionVariance (plain Welford), which matches the recorded observations.
func functionRangeVariance(xs []float64) float64 {
	var count, mean, meanComp, m2, m2Comp float64
	for _, x := range xs {
		count++
		delta := value.Sub(x, value.Add(mean, meanComp))
		mean, meanComp = functionKahanAdd(mean, meanComp, value.Div(delta, count))
		m2, m2Comp = functionKahanAdd(m2, m2Comp, value.Mul(delta, value.Sub(x, value.Add(mean, meanComp))))
	}
	return value.Div(value.Add(m2, m2Comp), count)
}
func functionVariance(xs []float64) float64 {
	mean, m2 := 0.0, 0.0
	for i, x := range xs {
		d := value.Sub(x, mean)
		mean = value.Add(mean, value.Div(d, float64(i+1)))
		m2 = value.Add(m2, value.Mul(d, value.Sub(x, mean)))
	}
	return value.Div(m2, float64(len(xs)))
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
		add(2, float64(x*y))
		add(3, float64(x*x))
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
		if extension != "" {
			// The window holds the raw samples around the range; see functions_extended.go.
			var extended value.Sample
			var emit bool
			var ds []syntax.Diagnostic
			if name == "changes" || name == "resets" {
				var count float64
				count, emit = functionAnchoredChanges(name, samples, int64(start), f)
				extended = functionSample(count, f.Time)
			} else {
				extended, emit, ds = functionExtendedRate(call, series, int64(start), int64(end), extension, f)
			}
			diagnostics = append(diagnostics, ds...)
			if emit {
				out.Vector = append(out.Vector, functionSeries(series, extended, true))
			}
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
			sample = functionSample(functionChangeCount(name, samples, f), f.Time)
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
					x = functionMean(xs, f.Profile.ID)
				}
				sample = functionSample(x, f.Time)
			}
		case "rate", "increase", "delta", "irate", "idelta":
			var e error
			sample, emit, ds, e = functionRate(call, series, start, end, f)
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
				x = functionRangeVariance(xs)
				if name == "stddev_over_time" {
					x = math.Sqrt(x)
				}
			case "deriv", "predict_linear":
				if len(floats) < 2 {
					emit = false
					break
				}
				reference := f.Time
				if name == "deriv" {
					reference = floats[0].Time
				}
				slope, intercept := functionRegression(floats, reference)
				x = slope
				if name == "predict_linear" {
					x = intercept + float64(slope*functionFloat(args[1].Scalar))
				}
			case "double_exponential_smoothing":
				if len(xs) < 2 {
					emit = false
					break
				}
				sf, tf := functionFloat(args[1].Scalar), functionFloat(args[2].Scalar)
				level, trend := xs[0], xs[1]-xs[0]
				for _, observation := range xs[1:] {
					next := float64(sf*observation) + float64((1-sf)*(level+trend))
					trend = float64(tf*(next-level)) + float64((1-tf)*trend)
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
func functionRate(call CallPlan, s value.Series, start, end model.UnixNano, f Frame) (value.Sample, bool, []syntax.Diagnostic, error) {
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
					if instant {
						// A reset restarts the counter: the last sample is the whole increase.
						change = current
					} else {
						change += previous
					}
				}
			}
		}
		result = functionSample(change, f.Time)
		if counter && !instant {
			d = append(d, possibleNonCounterNotes(call, s.Labels, f)...)
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
			factor /= rangeSeconds(int64(end - start))
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

// functionChangeCount counts, over the samples in order, the steps at which a
// value changed (changes) or a counter reset (resets).
func functionChangeCount(name string, samples []value.Sample, f Frame) float64 {
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
	return count
}

// possibleNonCounterNotes reports a counter function applied to a float series
// that does not look like a counter.
func possibleNonCounterNotes(call CallPlan, labels model.Labels, f Frame) []syntax.Diagnostic {
	metricName := value.Label(labels, "__name__")
	if metricName == "" {
		return nil
	}
	if f.Profile.ID == "promql-prometheus-3.13.5" && enabled(f.Profile, "type-and-unit-labels") {
		metricType := value.Label(labels, "__type__")
		if metricType != "counter" && metricType != "histogram" {
			return []syntax.Diagnostic{functionDiagnostic(call.Expr, "PossibleNonCounterLabelInfo")}
		}
	} else if !strings.HasSuffix(metricName, "_total") && !strings.HasSuffix(metricName, "_sum") && !strings.HasSuffix(metricName, "_count") && !strings.HasSuffix(metricName, "_bucket") {
		return []syntax.Diagnostic{functionDiagnostic(call.Expr, "PossibleNonCounterInfo")}
	}
	return nil
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
