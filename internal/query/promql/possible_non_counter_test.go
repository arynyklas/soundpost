// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Review 02.03-07 M3: both pinned releases add PossibleNonCounterInfo only when
// the window has float samples (`len(samples.Floats) > 0`), so a counter function
// over a native-histogram-only series of a name without a counter suffix is not
// annotated, while the same name over floats is.
func TestPossibleNonCounterNeedsFloatSamples(t *testing.T) {
	job := model.Labels{{Name: "job", Value: "a"}}
	histograms := []value.Series{metricSeries("plain_metric", job, relHistSample(10, relExp(6, 1, 4)), relHistSample(15, relExp(9, 1, 6)))}
	floats := []value.Series{metricSeries("plain_metric", job, relFloatSample(10, 1), relFloatSample(15, 2))}
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, query := range []string{"rate(plain_metric[20s])", "increase(plain_metric[20s])"} {
			if _, notes, err := evalWith(t, p, query, instantAt(20_000), histograms...); err != nil {
				t.Fatalf("%s %s over histograms: %v", id, query, err)
			} else {
				for _, category := range []string{"PossibleNonCounterInfo", "PossibleNonCounterLabelInfo"} {
					if _, bad := relNote(t, notes, category); bad {
						t.Errorf("%s %s over a histogram-only series carries %s: %v", id, query, category, relCategories(notes))
					}
				}
			}
			if _, notes, err := evalWith(t, p, query, instantAt(20_000), floats...); err != nil {
				t.Fatalf("%s %s over floats: %v", id, query, err)
			} else if _, ok := relNote(t, notes, "PossibleNonCounterInfo"); !ok {
				t.Errorf("%s %s over floats lost PossibleNonCounterInfo: %v", id, query, relCategories(notes))
			}
		}
	}
}
