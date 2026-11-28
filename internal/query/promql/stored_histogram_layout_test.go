// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// 02.08#14 F04, engine side. Ingest refuses a histogram whose spans name
// buckets that do not exist (model.histogramShape), but a histogram stored by an
// older build, or handed to the engine by any source that skipped validation,
// must not reach the code that indexes CustomBounds and the bucket arrays by span
// position: that code answered such data with an index-out-of-range panic (the
// project goroutine of internal/query recovers it as `unavailable`, a library
// caller crashes). Invalid stored data is `corrupt`, as the other stored-data
// invariants of select.go (foreign project, non-increasing times, a histogram
// with no or two variants) are.
func storedLayoutHistogram(spans []model.HistogramSpan, bounds []float64, counts ...uint64) *model.NativeHistogram {
	h := relCustom(10, bounds, counts...)
	h.Integer.PositiveSpans = spans
	return h
}

func TestStoredHistogramWithImpossibleSpansIsCorruptNotAPanic(t *testing.T) {
	job := model.Labels{{Name: "job", Value: "a"}}
	span := func(offset int32, length uint32) model.HistogramSpan {
		return model.HistogramSpan{Offset: offset, Length: length}
	}
	asFloat := func(h *model.NativeHistogram) *model.NativeHistogram {
		f := value.FloatHistogram(*h)
		return &model.NativeHistogram{Float: &f}
	}
	exponentialShort := relExp(6, 1, 4, 2)
	exponentialShort.Integer.PositiveSpans[0].Length = 3 // three buckets named, two stored
	for _, shape := range []struct {
		name string
		h    *model.NativeHistogram
	}{
		{"custom: one span runs past the +Inf bucket", storedLayoutHistogram([]model.HistogramSpan{span(0, 4)}, []float64{1, 2}, 1, 1, 1, 1)},
		{"custom: first offset beyond the bounds", storedLayoutHistogram([]model.HistogramSpan{span(5, 1)}, []float64{1, 2}, 3)},
		{"custom: negative first offset", storedLayoutHistogram([]model.HistogramSpan{span(-1, 2)}, []float64{1, 2}, 1, 2)},
		{"custom: second span past the end", storedLayoutHistogram([]model.HistogramSpan{span(0, 1), span(1, 3)}, []float64{1, 2}, 1, 1, 1, 1)},
		{"custom: no bounds, two buckets", storedLayoutHistogram([]model.HistogramSpan{span(0, 2)}, nil, 1, 2)},
		{"custom: span longer than the stored buckets", storedLayoutHistogram([]model.HistogramSpan{span(0, 3)}, []float64{1, 2}, 1, 2)},
		{"custom: float variant, span past +Inf", asFloat(storedLayoutHistogram([]model.HistogramSpan{span(0, 4)}, []float64{1, 2}, 1, 1, 1, 1))},
		{"exponential: span longer than the stored buckets", exponentialShort},
	} {
		for _, query := range []string{
			"m", "histogram_quantile(0.5, m)", "histogram_fraction(0, 1, m)", "histogram_count(m)", "rate(m[10s])", "m </ 1",
		} {
			t.Run(shape.name+"/"+query, func(t *testing.T) {
				p := featureProfile(t, relP313, "promql-experimental-functions")
				series := metricSeries("m", job, relHistSample(10, shape.h), relHistSample(15, shape.h))
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							err = fmt.Errorf("PANIC: %v", r)
						}
					}()
					_, _, err = evalWith(t, p, query, instantAt(20_000), series)
				}()
				if err == nil {
					t.Fatal("an impossible stored histogram was answered")
				}
				if code := releaseFault(t, err); code != model.Corrupt {
					t.Fatalf("code %q (%v), want corrupt", code, err)
				}
			})
		}
	}
}

// Valid stored histograms of the same kinds keep answering (the guard is not a
// blanket refusal): the +Inf bucket (index len(bounds)), gaps and two spans.
func TestStoredHistogramLayoutGuardAcceptsEveryPossibleLayout(t *testing.T) {
	job := model.Labels{{Name: "job", Value: "a"}}
	p := featureProfile(t, relP313, "promql-experimental-functions")
	for name, h := range map[string]*model.NativeHistogram{
		"all buckets":    relCustom(10, []float64{1, 2}, 1, 2, 3),
		"only +Inf":      storedLayoutHistogram([]model.HistogramSpan{{Offset: 2, Length: 1}}, []float64{1, 2}, 3),
		"two spans":      storedLayoutHistogram([]model.HistogramSpan{{Offset: 0, Length: 1}, {Offset: 1, Length: 1}}, []float64{1, 2}, 1, 3),
		"no bounds":      relCustom(10, nil, 4),
		"exponential":    relExp(6, 1, 4, 2),
		"exp negative-1": relExp(6, -1, 4, 2),
	} {
		series := metricSeries("m", job, relHistSample(10, h), relHistSample(15, h))
		for _, query := range []string{"m", "histogram_quantile(0.5, m)", "histogram_fraction(0, 1, m)", "histogram_count(m)", "rate(m[10s])", "m </ 1"} {
			if _, _, err := evalWith(t, p, query, instantAt(20_000), series); err != nil {
				t.Errorf("%s %s: valid stored histogram refused: %v", name, query, err)
			}
		}
	}
}
