// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

// Category carries the pinned annotation identity; its Info/Warning suffix is
// the severity. Messages intentionally contain no series names or query text.
func functionAnnotationText(id string) string {
	switch id {
	case "InvalidRatioWarning":
		return "ratio value should be between -1 and 1"
	case "InvalidQuantileWarning":
		return "quantile value should be between 0 and 1"
	case "BadBucketLabelWarning":
		return "bucket label is missing or has a malformed value"
	case "MixedFloatsHistogramsWarning":
		return "encountered a mix of histograms and floats"
	case "MixedClassicNativeHistogramsWarning":
		return "vector contains a mix of classic and native histograms"
	case "NativeHistogramNotCounterWarning":
		return "this native histogram metric is not a counter"
	case "NativeHistogramNotGaugeWarning":
		return "this native histogram metric is not a gauge"
	case "MixedExponentialCustomHistogramsWarning":
		return "vector contains a mix of histograms with exponential and custom bucket schemas"
	case "IncompatibleBucketLayoutInBinOpWarning":
		return "incompatible bucket layout encountered for binary operator"
	case "IncompatibleCustomBucketsHistogramsWarning":
		return "histograms have incompatible custom bucket bounds"
	case "SortInRangeQueryWarning":
		return "sort is ineffective for range queries since results are ordered by labels"
	case "PossibleNonCounterInfo":
		return "metric might not be a counter; name does not end in _total/_sum/_count/_bucket"
	case "PossibleNonCounterLabelInfo":
		return "metric might not be a counter; __type__ is not counter or histogram"
	case "HistogramQuantileForcedMonotonicityInfo":
		return "input to histogram_quantile needed to be fixed for monotonicity"
	case "IncompatibleTypesInBinOpInfo":
		return "incompatible sample types encountered for binary operator"
	case "HistogramIgnoredInAggregationInfo":
		return "ignored histogram in float aggregation"
	case "HistogramIgnoredInMixedRangeInfo":
		return "ignored histograms in a range containing both floats and histograms"
	case "NativeHistogramQuantileNaNResultInfo":
		return "input to histogram_quantile has NaN observations; result is NaN"
	case "NativeHistogramQuantileNaNSkewInfo":
		return "input to histogram_quantile has NaN observations; result is skewed higher"
	case "NativeHistogramFractionNaNsInfo":
		return "input to histogram_fraction has NaN observations excluded from all fractions"
	case "HistogramCounterResetCollisionWarning":
		return "conflicting counter resets during histogram addition"
	case "MismatchedCustomBucketsHistogramsInfo":
		return "mismatched custom buckets were reconciled"
	}
	return id
}
