//go:build soundpost_evaluation_oracle && prometheus_313

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/util/annotations"
)

func configureEngine(opts *promql.EngineOpts, enabled []string) {
	opts.Parser = parser.NewParser(parser.Options{EnableExperimentalFunctions: feature(enabled, "promql-experimental-functions"), ExperimentalDurationExpr: feature(enabled, "promql-duration-expr"), EnableExtendedRangeSelectors: feature(enabled, "promql-extended-range-selectors"), EnableBinopFillModifiers: feature(enabled, "promql-binop-fill-modifiers")})
	opts.EnableDelayedNameRemoval = feature(enabled, "promql-delayed-name-removal")
	opts.EnableTypeAndUnitLabels = feature(enabled, "type-and-unit-labels")
	opts.UseStartTimestamps = feature(enabled, "use-start-timestamps")
}
func allowedFeature(name string) bool {
	switch name {
	case "promql-experimental-functions", "promql-duration-expr", "promql-extended-range-selectors", "promql-binop-fill-modifiers", "promql-delayed-name-removal", "type-and-unit-labels", "use-start-timestamps":
		return true
	}
	return false
}
func annotationIdentity(err error) string {
	for _, candidate := range []struct {
		id       string
		sentinel error
	}{
		{"IncompatibleBucketLayoutInBinOpWarning", annotations.IncompatibleBucketLayoutInBinOpWarning},
		{"SortInRangeQueryWarning", annotations.SortInRangeQueryWarning},
		{"PossibleNonCounterLabelInfo", annotations.PossibleNonCounterLabelInfo},
		{"HistogramIgnoredInMixedRangeInfo", annotations.HistogramIgnoredInMixedRangeInfo},
		{"NativeHistogramQuantileNaNResultInfo", annotations.NativeHistogramQuantileNaNResultInfo},
		{"NativeHistogramQuantileNaNSkewInfo", annotations.NativeHistogramQuantileNaNSkewInfo},
		{"NativeHistogramFractionNaNsInfo", annotations.NativeHistogramFractionNaNsInfo},
		{"HistogramCounterResetCollisionWarning", annotations.HistogramCounterResetCollisionWarning},
		{"MismatchedCustomBucketsHistogramsInfo", annotations.MismatchedCustomBucketsHistogramsInfo},
	} {
		if errors.Is(err, candidate.sentinel) {
			return candidate.id
		}
	}
	return commonAnnotationIdentity(err)
}
