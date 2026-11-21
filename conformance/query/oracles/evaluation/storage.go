//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/util/annotations"
)

// fixtureQueryable contains only authored materialized samples. The real pinned
// engine owns selectors, windows, stale handling, operators and functions.
type fixtureQueryable struct{ rows []*fixtureSeries }
type fixtureSeries struct {
	metric  labels.Labels
	samples []sample
}
type fixtureQuerier struct {
	rows       []*fixtureSeries
	mint, maxt int64
}

func makeQueryable(c fixtureCase) (fixtureQueryable, error) {
	var q fixtureQueryable
	for _, s := range c.Series {
		metric := map[string]string{}
		for _, l := range s.Labels {
			if _, exists := metric[l.Name]; exists {
				return q, fmt.Errorf("duplicate fixture label")
			}
			metric[l.Name] = l.Value
		}
		for i, p := range s.Samples {
			if (p.Float == nil) == (p.Histogram == nil) {
				return q, fmt.Errorf("invalid sample variant")
			}
			if i > 0 && millis(p.Time) <= millis(s.Samples[i-1].Time) {
				return q, fmt.Errorf("distinct native timestamps collide in reference millisecond storage; no silent input merge")
			}
		}
		q.rows = append(q.rows, &fixtureSeries{metric: labels.FromMap(metric), samples: s.Samples})
	}
	return q, nil
}
func millis(n nano) int64 {
	v := int64(n)
	q := v / 1_000_000
	if v < 0 && v%1_000_000 != 0 {
		q--
	}
	return q
}
func (q fixtureQueryable) Querier(mint, maxt int64) (storage.Querier, error) {
	return &fixtureQuerier{rows: q.rows, mint: mint, maxt: maxt}, nil
}
func (q *fixtureQuerier) Select(ctx context.Context, sorted bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	if err := ctx.Err(); err != nil {
		return storage.ErrSeriesSet(err)
	}
	var out []storage.Series
	for _, s := range q.rows {
		match := true
		for _, m := range matchers {
			if !m.Matches(s.metric.Get(m.Name)) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		var selected []sample
		for _, p := range s.samples {
			t := millis(p.Time)
			if t >= q.mint && t <= q.maxt {
				selected = append(selected, p)
			}
		}
		if len(selected) > 0 {
			out = append(out, &fixtureSeries{metric: s.metric, samples: selected})
		}
	}
	if sorted {
		sort.SliceStable(out, func(i, j int) bool { return labels.Compare(out[i].Labels(), out[j].Labels()) < 0 })
	}
	return &fixtureSeriesSet{rows: out, index: -1, ctx: ctx}
}
func (q *fixtureQuerier) LabelValues(ctx context.Context, name string, _ *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	values := map[string]bool{}
	for _, s := range q.rows {
		matched := true
		for _, m := range matchers {
			if !m.Matches(s.metric.Get(m.Name)) {
				matched = false
			}
		}
		if matched && s.metric.Has(name) {
			values[s.metric.Get(name)] = true
		}
	}
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil, nil
}
func (q *fixtureQuerier) LabelNames(ctx context.Context, _ *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	names := map[string]bool{}
	for _, s := range q.rows {
		matched := true
		for _, m := range matchers {
			if !m.Matches(s.metric.Get(m.Name)) {
				matched = false
			}
		}
		if matched {
			s.metric.Range(func(l labels.Label) { names[l.Name] = true })
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil, nil
}
func (q *fixtureQuerier) Close() error { return nil }

type fixtureSeriesSet struct {
	rows  []storage.Series
	index int
	ctx   context.Context
	err   error
}

func (s *fixtureSeriesSet) Next() bool {
	if s.err = s.ctx.Err(); s.err != nil {
		return false
	}
	s.index++
	return s.index < len(s.rows)
}
func (s *fixtureSeriesSet) At() storage.Series                { return s.rows[s.index] }
func (s *fixtureSeriesSet) Err() error                        { return s.err }
func (s *fixtureSeriesSet) Warnings() annotations.Annotations { return nil }
func (s *fixtureSeries) Labels() labels.Labels                { return s.metric }
func (s *fixtureSeries) Iterator(chunkenc.Iterator) chunkenc.Iterator {
	return &fixtureIterator{samples: s.samples, index: -1}
}

type fixtureIterator struct {
	samples []sample
	index   int
}

func (i *fixtureIterator) Next() chunkenc.ValueType { i.index++; return i.kind() }
func (i *fixtureIterator) Seek(t int64) chunkenc.ValueType {
	if i.index < 0 {
		i.index = 0
	}
	for i.index < len(i.samples) && millis(i.samples[i.index].Time) < t {
		i.index++
	}
	return i.kind()
}
func (i *fixtureIterator) kind() chunkenc.ValueType {
	if i.index < 0 || i.index >= len(i.samples) {
		return chunkenc.ValNone
	}
	p := i.samples[i.index]
	if p.Float != nil {
		return chunkenc.ValFloat
	}
	if p.Histogram.Integer != nil {
		return chunkenc.ValHistogram
	}
	return chunkenc.ValFloatHistogram
}
func (i *fixtureIterator) At() (int64, float64) {
	p := i.samples[i.index]
	return millis(p.Time), p.Float.number()
}
func (i *fixtureIterator) AtT() int64 { return millis(i.samples[i.index].Time) }

// AtST supplies genuine optional authored metadata, never sample/observed time.
// The 3.13 iterator contract uses zero for absent ST; older engines ignore it.
func (i *fixtureIterator) AtST() int64 {
	start := i.samples[i.index].StartTimestamp
	if start == nil {
		return 0
	}
	return millis(*start)
}
func (i *fixtureIterator) Err() error { return nil }
func resetHint(flavor, hint string) histogram.CounterResetHint {
	if flavor == "gauge" || hint == "gauge" {
		return histogram.GaugeType
	}
	switch hint {
	case "reset":
		return histogram.CounterReset
	case "not_reset":
		return histogram.NotCounterReset
	default:
		return histogram.UnknownCounterReset
	}
}
func spans(in []span) []histogram.Span {
	var out []histogram.Span
	for _, s := range in {
		out = append(out, histogram.Span{Offset: s.Offset, Length: s.Length})
	}
	return out
}
func floats(in []bits) []float64 {
	var out []float64
	for _, b := range in {
		out = append(out, b.number())
	}
	return out
}
func integerDeltas(d []delta, a []absolute) []int64 {
	if len(a) == 0 {
		out := make([]int64, len(d))
		for j, b := range d {
			out[j] = int64(b)
		}
		if len(d) == 0 {
			return nil
		}
		return out
	}
	out := make([]int64, len(a))
	var previous uint64
	for j, b := range a {
		current := uint64(b)
		if current >= previous {
			difference := current - previous
			if difference > math.MaxInt64 {
				panic("absolute histogram delta outside pinned signed representation")
			}
			out[j] = int64(difference)
		} else {
			difference := previous - current
			if difference > uint64(math.MaxInt64)+1 {
				panic("absolute histogram delta outside pinned signed representation")
			}
			if difference == uint64(math.MaxInt64)+1 {
				out[j] = math.MinInt64
			} else {
				out[j] = -int64(difference)
			}
		}
		previous = current
	}
	return out
}
func (i *fixtureIterator) AtHistogram(reuse *histogram.Histogram) (int64, *histogram.Histogram) {
	p := i.samples[i.index]
	h := p.Histogram.Integer
	if reuse == nil {
		reuse = &histogram.Histogram{}
	}
	*reuse = histogram.Histogram{CounterResetHint: resetHint(h.Flavor, h.ResetHint), Schema: h.Schema, ZeroThreshold: h.ZeroThreshold.number(), ZeroCount: h.ZeroCount, Count: h.Count, Sum: h.Sum.number(), PositiveSpans: spans(h.PositiveSpans), NegativeSpans: spans(h.NegativeSpans), PositiveBuckets: integerDeltas(h.PositiveBuckets, h.PositiveCounts), NegativeBuckets: integerDeltas(h.NegativeBuckets, h.NegativeCounts), CustomValues: floats(h.CustomBounds)}
	return millis(p.Time), reuse
}
func (i *fixtureIterator) AtFloatHistogram(reuse *histogram.FloatHistogram) (int64, *histogram.FloatHistogram) {
	p := i.samples[i.index]
	if p.Histogram.Integer != nil {
		t, h := i.AtHistogram(nil)
		return t, h.ToFloat(reuse)
	}
	h := p.Histogram.Float
	if reuse == nil {
		reuse = &histogram.FloatHistogram{}
	}
	*reuse = histogram.FloatHistogram{CounterResetHint: resetHint(h.Flavor, h.ResetHint), Schema: h.Schema, ZeroThreshold: h.ZeroThreshold.number(), ZeroCount: h.ZeroCount.number(), Count: h.Count.number(), Sum: h.Sum.number(), PositiveSpans: spans(h.PositiveSpans), NegativeSpans: spans(h.NegativeSpans), PositiveBuckets: floats(h.PositiveBuckets), NegativeBuckets: floats(h.NegativeBuckets), CustomValues: floats(h.CustomBounds)}
	return millis(p.Time), reuse
}
