//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"github.com/prometheus/prometheus/util/annotations"
)

func commonAnnotationIdentity(err error) string {
	for _, candidate := range []struct {
		id       string
		sentinel error
	}{
		{"InvalidRatioWarning", annotations.InvalidRatioWarning},
		{"InvalidQuantileWarning", annotations.InvalidQuantileWarning},
		{"BadBucketLabelWarning", annotations.BadBucketLabelWarning},
		{"MixedFloatsHistogramsWarning", annotations.MixedFloatsHistogramsWarning},
		{"MixedClassicNativeHistogramsWarning", annotations.MixedClassicNativeHistogramsWarning},
		{"NativeHistogramNotCounterWarning", annotations.NativeHistogramNotCounterWarning},
		{"NativeHistogramNotGaugeWarning", annotations.NativeHistogramNotGaugeWarning},
		{"MixedExponentialCustomHistogramsWarning", annotations.MixedExponentialCustomHistogramsWarning},
		{"PossibleNonCounterInfo", annotations.PossibleNonCounterInfo},
		{"HistogramQuantileForcedMonotonicityInfo", annotations.HistogramQuantileForcedMonotonicityInfo},
		{"IncompatibleTypesInBinOpInfo", annotations.IncompatibleTypesInBinOpInfo},
		{"HistogramIgnoredInAggregationInfo", annotations.HistogramIgnoredInAggregationInfo},
	} {
		if errors.Is(err, candidate.sentinel) {
			return candidate.id
		}
	}
	return ""
}
