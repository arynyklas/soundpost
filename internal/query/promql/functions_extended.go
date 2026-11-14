// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Range functions over a selector with the anchored or smoothed modifier
// receive the raw samples of the extended window: every non-stale sample in
// (start-lookback, end] for anchored and (start-lookback, end+lookback] for
// smoothed, where (start, end] is the nominal range. The functions below find
// the samples that bound the nominal range themselves.

// functionExtendedRate evaluates rate, increase and delta over such a window.
func functionExtendedRate(call CallPlan, series value.Series, start, end int64, extension string, f Frame) (value.Sample, bool, []syntax.Diagnostic) {
	var floats, histograms []value.Sample
	for _, p := range series.Samples {
		if p.Histogram != nil {
			histograms = append(histograms, p)
		} else {
			floats = append(floats, p)
		}
	}
	switch {
	case len(floats) > 0 && len(histograms) > 0:
		return value.Sample{}, false, []syntax.Diagnostic{functionDiagnostic(call.Expr, "MixedFloatsHistogramsWarning")}
	case len(histograms) > 0:
		return extendedHistogramRate(call, histograms, start, end, extension == "smoothed", f)
	}
	counter := call.Name != "delta"
	rangeStart, rangeEnd := start, end
	points := make([]timedFloat, len(floats))
	for i, p := range floats {
		points[i] = timedFloat{int64(p.Time), functionFloat(p)}
	}
	result, ok := extendedFloatChange(points, rangeStart, rangeEnd, extension == "smoothed", counter)
	if !ok {
		return value.Sample{}, false, nil
	}
	if call.Name == "rate" {
		result /= rangeSeconds(end - start)
	}
	var notes []syntax.Diagnostic
	if counter {
		notes = possibleNonCounterNotes(call, series.Labels, f)
	}
	return functionSample(result, f.Time), true, notes
}

type timedFloat struct {
	t int64
	f float64
}

// rangeSeconds converts a nanosecond duration to seconds as time.Duration.Seconds does.
func rangeSeconds(d int64) float64 {
	return float64(d/1_000_000_000) + float64(d%1_000_000_000)/1e9
}

// extendedBounds finds the samples bounding (start, end]: first is the last
// sample at or before start (or the first sample when none is), last the first
// sample at or after end for smoothed windows (otherwise the last sample).
func extendedBounds(times func(int) int64, n int, start, end int64, smoothed bool) (first, last int) {
	last = n - 1
	first = max(0, sort.Search(last, func(i int) bool { return times(i) > start })-1)
	if smoothed {
		last = sort.Search(last, func(i int) bool { return times(i) >= end })
	}
	return first, last
}

func extendedFloatChange(points []timedFloat, start, end int64, smoothed, counter bool) (float64, bool) {
	first, last := extendedBounds(func(i int) int64 { return points[i].t }, len(points), start, end, smoothed)
	if points[last].t <= start || smoothed && points[first].t > end {
		return 0, false
	}
	left, right := points[first].f, points[last].f
	if smoothed && points[first].t < start {
		left = interpolateFloat(points[first].t, points[first].f, points[first+1].t, points[first+1].f, start, counter)
	}
	if smoothed && last > 0 && points[last].t > end {
		right = interpolateFloat(points[last-1].t, points[last-1].f, points[last].t, points[last].f, end, counter)
	}
	result := right - left
	if counter {
		// Resets at the boundaries are already part of the interpolated values;
		// only the samples strictly inside the range can still hide one.
		if points[first].t <= start {
			first++
		}
		if points[last].t >= end {
			last--
		}
		var correction float64
		previous := left
		if first <= last {
			for _, p := range points[first : last+1] {
				if p.f < previous {
					correction += previous
				}
				previous = p.f
			}
		}
		if right < previous {
			correction += previous
		}
		result += correction
	}
	return result, true
}

// extendedHistogramRate is the native-histogram form of extendedFloatChange.
func extendedHistogramRate(call CallPlan, samples []value.Sample, start, end int64, smoothed bool, f Frame) (value.Sample, bool, []syntax.Diagnostic) {
	var notes []syntax.Diagnostic
	note := func(id string) { notes = append(notes, functionDiagnostic(call.Expr, id)) }
	counter := call.Name != "delta"
	rangeStart, rangeEnd := start, end
	times := func(i int) int64 { return int64(samples[i].Time) }
	first, last := extendedBounds(times, len(samples), rangeStart, rangeEnd, smoothed)
	if times(last) <= rangeStart || smoothed && times(first) > rangeEnd {
		return value.Sample{}, false, nil
	}
	custom := histogramView(*samples[first].Histogram).Schema == -53
	for _, p := range samples[first : last+1] {
		view := histogramView(*p.Histogram)
		if (view.Schema == -53) != custom {
			note("MixedExponentialCustomHistogramsWarning")
			return value.Sample{}, false, notes
		}
		if counter && view.Flavor == "gauge" {
			note("NativeHistogramNotCounterWarning")
		}
	}
	profileID := f.Profile.ID
	boundary := func(i int, at int64, interpolateFrom int) (model.NativeHistogram, bool) {
		h := value.CloneHistogram(*samples[i].Histogram)
		if interpolateFrom < 0 {
			return h, true
		}
		a, b := interpolateFrom, i
		if a > b {
			a, b = b, a
		}
		interpolated, reasons, ok := interpolateHistogram(samples[a], times(a), samples[b], times(b), at, counter, profileID)
		for _, reason := range reasons {
			note(reason)
		}
		return interpolated, ok
	}
	leftFrom, rightFrom := -1, -1
	if smoothed && times(first) < rangeStart {
		leftFrom = first + 1
	}
	if smoothed && last > 0 && times(last) > rangeEnd {
		rightFrom = last - 1
	}
	left, ok := boundary(first, rangeStart, leftFrom)
	if !ok {
		return value.Sample{}, false, notes
	}
	right, ok := boundary(last, rangeEnd, rightFrom)
	if !ok {
		return value.Sample{}, false, notes
	}
	if !counter && (histogramHint(left) != "gauge" || histogramHint(right) != "gauge") {
		note("NativeHistogramNotGaugeWarning")
	}
	result, reason := histogramCombineForProfile(right, left, true, profileID)
	if reason != "" && reason != "HistogramCounterResetCollisionWarning" {
		note(reason)
	}
	if result.Float == nil {
		return value.Sample{}, false, notes
	}
	setHistogramHint(&result, adjustedHint(histogramHint(right), histogramHint(left)))
	if counter {
		correction, reasons, ok := histogramResetCorrection(samples, first, last, left, right, rangeStart, smoothed, times, profileID)
		for _, reason := range reasons {
			note(reason)
		}
		if !ok {
			return value.Sample{}, false, notes
		}
		if correction != nil {
			hint := adjustedHint(histogramHint(result), histogramHint(*correction))
			sum, reason := histogramCombineForProfile(result, *correction, false, profileID)
			if reason != "" && reason != "HistogramCounterResetCollisionWarning" {
				note(reason)
			}
			if sum.Float == nil {
				return value.Sample{}, false, notes
			}
			result = sum
			setHistogramHint(&result, hint)
		}
	}
	if call.Name == "rate" {
		result = histogramDivideForProfile(result, rangeSeconds(end-start), profileID)
	}
	setHistogramHint(&result, "gauge")
	return value.Sample{Time: f.Time, Histogram: &result}, true, notes
}

// histogramResetCorrection sums the histograms that preceded a counter reset
// strictly inside the range. A reset already spanned by an interpolated left
// boundary is not counted again.
func histogramResetCorrection(samples []value.Sample, first, last int, left, right model.NativeHistogram, rangeStart int64, smoothed bool, times func(int) int64, profileID string) (*model.NativeHistogram, []string, bool) {
	var reasons []string
	begin := first + 1
	previous := left
	if smoothed && times(first) < rangeStart && histogramResetForProfile(*samples[first].Histogram, *samples[first+1].Histogram, profileID) {
		previous = *samples[first+1].Histogram
		begin++
	}
	end := last - 1
	if begin > end+1 {
		return nil, nil, true
	}
	var correction *model.NativeHistogram
	add := func(h model.NativeHistogram) bool {
		if correction == nil {
			clone := value.CloneHistogram(h)
			correction = &clone
			return true
		}
		hint := adjustedHint(histogramHint(*correction), histogramHint(h))
		sum, reason := histogramCombineForProfile(*correction, h, false, profileID)
		if reason != "" && reason != "HistogramCounterResetCollisionWarning" {
			reasons = append(reasons, reason)
		}
		if sum.Float == nil {
			return false
		}
		correction = &sum
		setHistogramHint(correction, hint)
		return true
	}
	if begin <= end {
		for _, p := range samples[begin : end+1] {
			if histogramResetForProfile(previous, *p.Histogram, profileID) {
				if !add(previous) {
					return nil, reasons, false
				}
			}
			previous = *p.Histogram
		}
	}
	if histogramResetForProfile(previous, right, profileID) {
		if !add(previous) {
			return nil, reasons, false
		}
	}
	return correction, reasons, true
}

// functionAnchoredChanges counts changes or resets from the sample that
// anchors the range start: the latest sample at or before it, or the first one
// when there is none. Without a sample after the start there is nothing to count.
func functionAnchoredChanges(name string, samples []value.Sample, start int64, f Frame) (float64, bool) {
	anchor := -1
	for i, p := range samples {
		if int64(p.Time) <= start {
			anchor = i
		}
	}
	if anchor == len(samples)-1 {
		return 0, false
	}
	return functionChangeCount(name, samples[max(anchor, 0):], f), true
}

// interpolateHistogram is the value at time t between two histograms. A counter
// reset between them restarts from zero. The returned reasons are annotations
// to report; ok is false when the histograms cannot be combined.
func interpolateHistogram(a value.Sample, t1 int64, b value.Sample, t2, t int64, counter bool, profileID string) (model.NativeHistogram, []string, bool) {
	if t == t1 {
		return value.CloneHistogram(*a.Histogram), nil, true
	}
	if t == t2 {
		return value.CloneHistogram(*b.Histogram), nil, true
	}
	fraction := (float64(t-t1) / 1e6) / (float64(t2-t1) / 1e6)
	if counter && histogramResetForProfile(*a.Histogram, *b.Histogram, profileID) {
		scaled := histogramScaleForProfile(*b.Histogram, fraction, profileID)
		setHistogramHint(&scaled, histogramHint(*b.Histogram))
		return scaled, nil, true
	}
	var reasons []string
	keep := func(reason string) {
		if reason != "" && reason != "HistogramCounterResetCollisionWarning" {
			reasons = append(reasons, reason)
		}
	}
	difference, reason := histogramCombineForProfile(*b.Histogram, *a.Histogram, true, profileID)
	keep(reason)
	if difference.Float == nil {
		return model.NativeHistogram{}, reasons, false
	}
	hint := adjustedHint(histogramHint(*b.Histogram), histogramHint(*a.Histogram))
	scaled := histogramScaleForProfile(difference, fraction, profileID)
	sum, reason := histogramCombineForProfile(scaled, *a.Histogram, false, profileID)
	keep(reason)
	if sum.Float == nil {
		return model.NativeHistogram{}, reasons, false
	}
	setHistogramHint(&sum, adjustedHint(hint, histogramHint(*a.Histogram)))
	return sum, reasons, true
}

func histogramFlavorOf(p value.Sample) string { return histogramHint(*p.Histogram) }

// histogramHint is the native counter-reset hint of a histogram: "gauge",
// "unknown", "reset" or "not_reset".
func histogramHint(h model.NativeHistogram) string {
	view := histogramView(h)
	if view.Flavor == "gauge" {
		return "gauge"
	}
	if view.ResetHint == "" {
		return "unknown"
	}
	return view.ResetHint
}

func setHistogramHint(h *model.NativeHistogram, hint string) {
	view := h.Float
	if view == nil {
		converted := value.FloatHistogram(*h)
		*h = model.NativeHistogram{Float: &converted}
		view = h.Float
	}
	view.ResetHint = hint
	view.Flavor = "counter"
	if hint == "gauge" {
		view.Flavor = "gauge"
	}
}

// adjustedHint is the hint of a sum or difference of two histograms.
func adjustedHint(receiver, other string) string {
	switch {
	case receiver == other, receiver == "gauge":
		return receiver
	case other == "gauge":
		return "gauge"
	default:
		return "unknown"
	}
}
