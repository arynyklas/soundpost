// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

func timeError() error {
	return &syntax.LanguageError{Code: "time.bounds", Category: "execution", SafeMessage: "evaluation time or duration is out of bounds"}
}
func operatorError(n *Node, code, message string) error {
	return &syntax.LanguageError{Code: code, Category: "execution", Range: n.OperatorRange, SafeMessage: message}
}

// firstWinsKey marks a key whose annotation keeps the source range of its first
// occurrence; every other keyed annotation keeps the range of its last one.
const firstWinsKey = "\x01first\x00"

// annotationKey is the identity the pinned engines give an annotation: the
// rendered text, i.e. the category's message plus the facts the pinned release
// puts into it (metric name, quantile value, operator, aggregation name...).
// Prometheus keeps annotations in a map keyed by that text, so annotations from
// different call sites with the same text are one annotation.
func annotationKey(d syntax.Diagnostic, details ...string) string {
	return d.Category + "\x00" + d.SafeMessage + "\x00" + strings.Join(details, "\x00")
}

// keyed returns d with the de-duplication identity of its rendered text. The
// details are exactly the facts the pinned release renders; a fact the text of
// that release does not contain must not be passed.
func keyed(d syntax.Diagnostic, details ...string) syntax.Diagnostic {
	d.Key = annotationKey(d, details...)
	return d
}

// keyedFirst is keyed for the annotation whose merge keeps the first call site
// (3.13.5 histogram_quantile forced-monotonicity: its Merge returns the earlier
// error with widened bounds, where every other annotation's Merge returns the
// later one).
func keyedFirst(d syntax.Diagnostic, details ...string) syntax.Diagnostic {
	d.Key = firstWinsKey + annotationKey(d, details...)
	return d
}

// annotationFloat renders a float the way the pinned engines' %g does, so equal
// text means equal bits except for NaN payloads, which render alike.
func annotationFloat(x float64) string { return strconv.FormatFloat(x, 'g', -1, 64) }

// seriesMetricName is the metric name the pinned engines read from a series.
func seriesMetricName(s value.Series) string { return value.Label(s.Labels, "__name__") }

// Annotations are emitted in depth-first source evaluation order. A keyed
// annotation whose Key is already present merges with it (one annotation, the
// later call site's range, or the first's for firstWinsKey); an unkeyed one is
// dropped only when an identical diagnostic exists.
func appendAnnotations(dst []syntax.Diagnostic, src ...syntax.Diagnostic) []syntax.Diagnostic {
	for _, d := range src {
		if d.Key == "" && d.Category == "SortInRangeQueryWarning" {
			// The sort warning's text carries no fact, so every call site renders the same text.
			d = keyed(d)
		}
		seen := false
		for i, old := range dst {
			if d.Key != "" && old.Key == d.Key {
				if !strings.HasPrefix(d.Key, firstWinsKey) {
					dst[i] = d
				}
				seen = true
				break
			}
			if old == d {
				seen = true
				break
			}
		}
		if !seen {
			dst = append(dst, d)
		}
	}
	return dst
}

// histogramReasonKey keys a histogram-reconciliation annotation by the facts
// the pinned text carries: the exponential/custom-layout and incompatible-bounds
// warnings name the metric; the reconciliation info and the counter-reset
// collision name the operation (addition, subtraction, aggregation).
func histogramReasonKey(d syntax.Diagnostic, name, operation string) syntax.Diagnostic {
	switch d.Category {
	case "MixedExponentialCustomHistogramsWarning", "IncompatibleCustomBucketsHistogramsWarning":
		return keyed(d, name)
	case "MismatchedCustomBucketsHistogramsInfo", "HistogramCounterResetCollisionWarning":
		return keyed(d, operation)
	}
	return d
}

// histogramInputName is the metric name a histogram function's annotation
// renders for its input series: 3.1.0 always reads the series' own name; 3.13.5
// reads it only under delayed name removal (the name is dropped before the
// function body otherwise, and the empty name is left out of the text).
func histogramInputName(p profile.Profile, name string) string {
	if p.ID == "promql-prometheus-3.13.5" && !enabled(p, "promql-delayed-name-removal") {
		return ""
	}
	return name
}

// histogramQuantileReasonKey keys the annotations a native or classic quantile
// or fraction raises. 3.1.0 only has the forced-monotonicity info, which renders
// an empty name; 3.13.5 renders the name only under delayed name removal, and
// its forced-monotonicity merge keeps the first call site.
func histogramQuantileReasonKey(p profile.Profile, d syntax.Diagnostic, name string) syntax.Diagnostic {
	if p.ID != "promql-prometheus-3.13.5" {
		return keyed(d, "")
	}
	name = histogramInputName(p, name)
	if d.Category == "HistogramQuantileForcedMonotonicityInfo" {
		return keyedFirst(d, name)
	}
	return keyed(d, name)
}

// binaryOperandType is the sample type name of a binary operand in the
// incompatible-types text.
func binaryOperandType(s value.Sample) string {
	if s.Histogram != nil {
		return "histogram"
	}
	return "float"
}

// binaryHistogramOperation is the histogram operation a binary operator performs.
func binaryHistogramOperation(op string) string {
	if op == "-" {
		return "subtraction"
	}
	return "addition"
}

// binaryReasonKey keys a histogram binary-operator annotation: the reconciliation
// and collision texts name the operation, the 3.13.5 incompatible-layout warning
// names the operator, and the 3.1.0 vector binary-operator warnings render an
// empty metric name.
func binaryReasonKey(p profile.Profile, d syntax.Diagnostic, op string) syntax.Diagnostic {
	if d.Category == "IncompatibleBucketLayoutInBinOpWarning" {
		return keyed(d, op)
	}
	return histogramReasonKey(d, "", binaryHistogramOperation(op))
}

// engineBoundaryError gives every failure that leaves Evaluate a typed form:
// cancellation, deadline and regex budget errors of the packages below do not
// escape as raw sentinel errors.
func engineBoundaryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	case errors.Is(err, regexcompat.ErrBudget):
		return model.Fail(model.Quota)
	case errors.Is(err, regexcompat.ErrScope):
		return model.Fail(model.Invalid)
	}
	return err
}
