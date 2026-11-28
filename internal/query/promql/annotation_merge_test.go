// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

func annotationAt(id string, start int, details ...string) syntax.Diagnostic {
	d := syntax.Diagnostic{Category: id, Range: syntax.SourceRange{StartByte: start, EndByte: start + 1}, SafeMessage: functionAnnotationText(id)}
	if details == nil {
		return d
	}
	return keyed(d, details...)
}

// TestAnnotationsWithTheSameRenderedTextMerge pins the reference's map keyed by rendered text:
// identical-text annotations from different call sites are one annotation that keeps the later
// call site; differing metric names, values, operators or aggregation names stay separate.
func TestAnnotationsWithTheSameRenderedTextMerge(t *testing.T) {
	type pos struct {
		id    string
		start int
	}
	cases := []struct {
		name string
		in   []syntax.Diagnostic
		want []pos
	}{
		{"same name merges, later call site wins", []syntax.Diagnostic{annotationAt("PossibleNonCounterInfo", 3, "foo"), annotationAt("PossibleNonCounterInfo", 20, "foo")}, []pos{{"PossibleNonCounterInfo", 20}}},
		{"different names stay separate", []syntax.Diagnostic{annotationAt("PossibleNonCounterInfo", 3, "foo"), annotationAt("PossibleNonCounterInfo", 20, "bar")}, []pos{{"PossibleNonCounterInfo", 3}, {"PossibleNonCounterInfo", 20}}},
		{"different quantile values stay separate", []syntax.Diagnostic{annotationAt("InvalidQuantileWarning", 3, "2"), annotationAt("InvalidQuantileWarning", 20, "3")}, []pos{{"InvalidQuantileWarning", 3}, {"InvalidQuantileWarning", 20}}},
		{"same quantile value merges", []syntax.Diagnostic{annotationAt("InvalidQuantileWarning", 3, "2"), annotationAt("InvalidQuantileWarning", 20, "2"), annotationAt("InvalidQuantileWarning", 40, "2")}, []pos{{"InvalidQuantileWarning", 40}}},
		{"different aggregation names stay separate", []syntax.Diagnostic{annotationAt("HistogramIgnoredInAggregationInfo", 3, "min"), annotationAt("HistogramIgnoredInAggregationInfo", 20, "max")}, []pos{{"HistogramIgnoredInAggregationInfo", 3}, {"HistogramIgnoredInAggregationInfo", 20}}},
		{"unkeyed identical annotations collapse", []syntax.Diagnostic{annotationAt("MixedFloatsHistogramsWarning", 3), annotationAt("MixedFloatsHistogramsWarning", 3)}, []pos{{"MixedFloatsHistogramsWarning", 3}}},
		{"unkeyed annotations at different ranges stay separate", []syntax.Diagnostic{annotationAt("MixedFloatsHistogramsWarning", 3), annotationAt("MixedFloatsHistogramsWarning", 20)}, []pos{{"MixedFloatsHistogramsWarning", 3}, {"MixedFloatsHistogramsWarning", 20}}},
		{"the first-wins key keeps the first call site", []syntax.Diagnostic{keyedFirst(annotationAt("HistogramQuantileForcedMonotonicityInfo", 3), ""), keyedFirst(annotationAt("HistogramQuantileForcedMonotonicityInfo", 20), "")}, []pos{{"HistogramQuantileForcedMonotonicityInfo", 3}}},
		{"the sort warning has no fact so call sites merge", []syntax.Diagnostic{annotationAt("SortInRangeQueryWarning", 3), annotationAt("SortInRangeQueryWarning", 20)}, []pos{{"SortInRangeQueryWarning", 20}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []syntax.Diagnostic
			for _, d := range tc.in {
				got = appendAnnotations(got, d)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d annotations %+v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].Category != w.id || got[i].Range.StartByte != w.start {
					t.Fatalf("annotation %d = %s@%d, want %s@%d", i, got[i].Category, got[i].Range.StartByte, w.id, w.start)
				}
			}
		})
	}
}

// TestAnnotationRenderedFactsFollowThePinnedRelease pins which facts each release's text carries:
// 3.1.0 renders the bad-bucket metric name always, 3.13.5 only under delayed name removal, and
// only 3.13.5's forced-monotonicity info merges to the first call site.
func TestAnnotationRenderedFactsFollowThePinnedRelease(t *testing.T) {
	p310 := profile.Profile{ID: "promql-prometheus-3.1.0"}
	p3135 := profile.Profile{ID: "promql-prometheus-3.13.5"}
	delayed := profile.Profile{ID: "promql-prometheus-3.13.5", ActiveFeatureSet: profile.FeatureSet{Enabled: []string{"promql-delayed-name-removal"}}}
	if got := histogramInputName(p310, "m"); got != "m" {
		t.Fatalf("3.1.0 renders the name: %q", got)
	}
	if got := histogramInputName(p3135, "m"); got != "" {
		t.Fatalf("3.13.5 drops the name before the function body: %q", got)
	}
	if got := histogramInputName(delayed, "m"); got != "m" {
		t.Fatalf("3.13.5 with delayed name removal keeps the name: %q", got)
	}
	forced := func(p profile.Profile, start int) syntax.Diagnostic {
		return histogramQuantileReasonKey(p, annotationAt("HistogramQuantileForcedMonotonicityInfo", start), "m")
	}
	var old []syntax.Diagnostic
	old = appendAnnotations(appendAnnotations(old, forced(p310, 3)), forced(p310, 20))
	if len(old) != 1 || old[0].Range.StartByte != 20 {
		t.Fatalf("3.1.0 keeps the later call site: %+v", old)
	}
	var current []syntax.Diagnostic
	current = appendAnnotations(appendAnnotations(current, forced(p3135, 3)), forced(p3135, 20))
	if len(current) != 1 || current[0].Range.StartByte != 3 {
		t.Fatalf("3.13.5 keeps the first call site: %+v", current)
	}
}
