// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Both pinned engines decode only the sum and count of a native histogram when
// the selector feeds histogram_count/histogram_sum (3.13.5 also histogram_avg)
// and nothing that needs buckets (detectHistogramStatsDecoding in the engine
// source; the decoded histogram carries Count, Sum, Schema and the counter-reset
// hint only). Everything computed from such a selector, interpolation at an
// extended range boundary included, therefore sees no buckets: no custom-bounds
// reconciliation, no zero-bucket or bucket decrease in a reset test. A sample
// whose hint is unknown gets its hint from the previous sample read through the
// same iterator (HistogramStatsIterator.getResetHint), which compares the full
// histograms.

// statsOnlySelectors returns the selectors of the typed tree the reference
// decodes statistics-only. Selectors are keyed by the node pointers both the
// typed tree and the AST children of its nodes hand to the evaluator (the
// evaluator reads a function's range argument through the AST).
func statsOnlySelectors(root TypedExpr, profileID string) map[*Node]bool {
	out := map[*Node]bool{}
	var walk func(e TypedExpr, path []*Node)
	walk = func(e TypedExpr, path []*Node) {
		n, ok := e.Expr.(*Node)
		if !ok {
			return
		}
		if n.Kind == "selector" {
			if statsOnlyPath(path, profileID) {
				out[n] = true
			}
			return
		}
		if n.Kind == "binary" && profileID == "promql-prometheus-3.1.0" {
			// 3.1.0 decides every operand of a binary expression on its own, with
			// the ancestors above the binary expression out of sight.
			path = nil
		}
		path = append(path[:len(path):len(path)], n)
		if statsOnlyPath(path, profileID) {
			for _, c := range n.Children {
				if child, ok := c.(*Node); ok && child.Kind == "selector" {
					out[child] = true
				}
			}
		}
		for _, c := range e.Children {
			walk(c, path)
		}
	}
	walk(root, nil)
	return out
}

// statsOnlyPath decides one selector from its ancestors, root first.
func statsOnlyPath(path []*Node, profileID string) bool {
	if profileID == "promql-prometheus-3.1.0" {
		// The outermost histogram function on the path decides.
		for _, n := range path {
			if n.Kind != "call" {
				continue
			}
			switch n.Text {
			case "histogram_count", "histogram_sum":
				return true
			case "histogram_quantile", "histogram_fraction":
				return false
			}
		}
		return false
	}
	skip := false
	for i := len(path) - 1; i >= 0; i-- {
		n := path[i]
		switch {
		case n.Kind == "subquery":
			return false
		case n.Kind == "call":
			switch n.Text {
			case "histogram_count", "histogram_sum", "histogram_avg":
				skip = true
			case "histogram_quantile", "histogram_quantiles", "histogram_fraction":
				return false
			}
		case n.Kind == "binary" && (n.Text == "</" || n.Text == ">/"):
			return false
		}
	}
	return skip
}

// statsOnlySequence reduces the retained samples of one selector to what the
// statistics-only decoding returns, in the order the iterator reads them. The
// iterator keeps the previous histogram with its buckets, so the hint it
// computes for a sample whose hint is unknown is the full counter-reset test;
// a gauge hint is kept as given, and later arithmetic on the bucket-less result
// can only compare counts.
func statsOnlySequence(samples []value.Sample) {
	var previous *model.NativeHistogram
	for i := range samples {
		h := samples[i].Histogram
		if h == nil || h.Float == nil {
			// A float sample is not read through the histogram iterator state.
			continue
		}
		full := *h
		hint := h.Float.ResetHint
		stale := math.Float64bits(math.Float64frombits(uint64(h.Float.Sum))) == uint64(value.StaleBits)
		if !stale && previous != nil && h.Float.Flavor != "gauge" && (hint == "" || hint == "unknown") {
			if value.HistogramReset(*previous, full) {
				hint = "reset"
			} else {
				hint = "not_reset"
			}
		}
		stats := model.FloatHistogram{Flavor: h.Float.Flavor, Schema: h.Float.Schema, Sum: h.Float.Sum, Count: h.Float.Count, ResetHint: hint}
		samples[i].Histogram = &model.NativeHistogram{Float: &stats}
		if !stale {
			previous = &full
		}
	}
}
