// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// 02.04#13: the probe against the natively built pinned 3.13.5 reference
// (l2w16-evidence/lane2/ext-probe-report.md, rows 20-exp-then-custom/q09 and q11
// at t=10) showed that a smoothed instant selector between an exponential-schema
// and a custom-bucket histogram yields NO sample and one
// MixedExponentialCustomHistogramsWarning at the selector
// (promql/engine.go, `prev.H.UsesCustomBuckets() != next.H.UsesCustomBuckets()`).
func TestSmoothedInstantSelectorDropsAMixOfExponentialAndCustomBuckets(t *testing.T) {
	job := model.Labels{{Name: "job", Value: "generic"}}
	exp := relExp(6, 1, 4)
	custom := relCustom(18, []float64{1, 2}, 2, 4, 6)
	p := featureProfile(t, relP313, "promql-extended-range-selectors")
	for _, c := range []struct {
		query      string
		start, end int // the selector `m` as the reference reports it
	}{
		{"m smoothed", 0, 1},
		{"histogram_count(m smoothed)", 16, 17},
	} {
		for _, order := range []struct {
			name   string
			series []value.Series
		}{
			{"exponential then custom", []value.Series{metricSeries("m", job, relHistSample(5, exp), relHistSample(15, custom))}},
			{"custom then exponential", []value.Series{metricSeries("m", job, relHistSample(5, custom), relHistSample(15, exp))}},
		} {
			r, notes, err := evalWith(t, p, c.query, instantAt(10_000), order.series...)
			if err != nil {
				t.Fatalf("%s %s: %v", c.query, order.name, err)
			}
			if len(r.Vector) != 0 {
				t.Errorf("%s %s: a mixed-schema interpolation produced a sample: %+v", c.query, order.name, r.Vector)
			}
			n, ok := relNote(t, notes, "MixedExponentialCustomHistogramsWarning")
			if !ok {
				t.Errorf("%s %s: no MixedExponentialCustomHistogramsWarning: %v", c.query, order.name, relCategories(notes))
				continue
			}
			if n.Range.StartByte != c.start || n.Range.EndByte != c.end {
				t.Errorf("%s %s: warning range %d..%d, want %d..%d", c.query, order.name, n.Range.StartByte, n.Range.EndByte, c.start, c.end)
			}
		}
	}
	// Same-kind pairs still interpolate (control).
	r, _, err := evalWith(t, p, "m smoothed", instantAt(10_000), metricSeries("m", job, relHistSample(5, exp), relHistSample(15, relExp(12, 1, 8))))
	if err != nil || len(r.Vector) != 1 {
		t.Fatalf("exponential pair no longer interpolates: %v %+v", err, r.Vector)
	}
}
