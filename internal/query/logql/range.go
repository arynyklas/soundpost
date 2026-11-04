// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"io"
	"math"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/value"
)

type RangePlan struct {
	Function  string
	Range     *RangeExpr
	Pipeline  PipelinePlan
	Parameter float64
	Grouping  []string
	Without   bool
	checked   bool
}
type Frame struct {
	Time    model.UnixNano
	Profile profile.Profile
	Project model.ID
	Account value.Account
}
type MetricPipelineError struct{ Category string }

func (e *MetricPipelineError) Error() string {
	return "LogQL metric input contains pipeline error: " + e.Category
}

type rangePoint struct {
	at model.UnixNano
	v  float64
	n  uint64
	id model.ID
}
type rangeGroup struct {
	labels model.Labels
	points []rangePoint
}

// EvaluateRange owns and closes input. Metric windows are (left,right], unlike
// the raw source's [start,end). A surviving error is not an absent sample.
func EvaluateRange(ctx context.Context, p RangePlan, input EntryIterator, frame Frame) (result value.Result, err error) {
	if ctx == nil || input == nil || frame.Account == nil || p.Range == nil || p.Range.Log == nil || p.Range.Interval <= 0 || frame.Project == (model.ID{}) || !rangeNames[p.Function] {
		if input != nil {
			input.Close()
		}
		return result, model.Fail(model.Invalid)
	}
	a := frame.Account
	held := int64(0)
	result.Type = "vector"
	defer func() {
		closeErr := input.Close()
		if err == nil {
			err = closeErr
		}
		value.InheritMetadata(&result, value.Result{Partial: input.Partial(), Watermarks: input.Watermarks()})
		a.Release(held)
		if err == nil {
			err = a.Check(ctx)
		}
		if err == nil {
			err = a.Reserve(value.ResultBytes(result))
		}
	}()
	if err = a.Check(ctx); err != nil {
		return result, err
	}
	if !p.checked {
		args := []Expr{p.Range}
		if p.Function == "quantile_over_time" {
			args = []Expr{&LiteralExpr{Value: p.Parameter}, p.Range}
		}
		if _, _, err = Check(&CallExpr{Name: p.Function, Args: args, Grouping: p.Grouping, Without: p.Without}, frame.Profile); err != nil {
			return result, err
		}
	}
	right, e := metricSub(int64(frame.Time), p.Range.Offset)
	if e != nil {
		return result, e
	}
	left, e := metricSub(right, p.Range.Interval)
	if e != nil {
		return result, e
	}
	unwrap := ""
	for _, s := range p.Range.Log.Stages {
		if s.Kind == "unwrap" {
			unwrap = s.UnwrapLabel
		}
	}
	groups := map[string]*rangeGroup{}
	anyEntry := false
	for {
		if e = a.Check(ctx); e != nil {
			return result, e
		}
		r, e := input.Next(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return result, e
		}
		if !r.Retained || int64(r.Entry.Timestamp) <= left || int64(r.Entry.Timestamp) > right {
			a.Release(r.Bytes)
			continue
		}
		category := value.Label(r.Labels, "__error__")
		if category != "" {
			a.Release(r.Bytes)
			return result, &MetricPipelineError{Category: category}
		}
		if r.Entry.Multiplicity == 0 {
			a.Release(r.Bytes)
			return result, model.Fail(model.Corrupt)
		}
		anyEntry = true
		if p.Function == "absent_over_time" {
			a.Release(r.Bytes)
			continue
		}
		scratch := int64(256 + len(r.Labels)*64)
		for _, l := range r.Labels {
			scratch += int64(len(l.Name)+len(l.Value)) * 2
		}
		if e = a.Reserve(scratch); e != nil {
			a.Release(r.Bytes)
			return result, e
		}
		held += scratch
		labels := r.Labels
		if unwrap != "" {
			labels = removeMetricLabels(labels, []string{unwrap, "__error__", "__error_details__"})
		}
		if p.Grouping != nil {
			labels = groupLabels(labels, p.Grouping, p.Without)
		}
		cost := int64(192)
		key := value.LabelKey(labels)
		g := groups[key]
		if g == nil {
			cost += int64(len(key)) + value.SeriesBytes(value.Series{Labels: labels})
		}
		if e = a.Reserve(cost); e != nil {
			a.Release(r.Bytes)
			return result, e
		}
		held += cost
		if g == nil {
			g = &rangeGroup{labels: value.CloneLabels(labels)}
			groups[key] = g
		}
		v := float64(1)
		if unwrap != "" {
			if r.Unwrapped == nil {
				a.Release(r.Bytes)
				return result, model.Fail(model.Corrupt)
			}
			v = *r.Unwrapped
		} else if p.Function == "bytes_rate" || p.Function == "bytes_over_time" {
			v = float64(len(r.Entry.Line))
		}
		g.points = append(g.points, rangePoint{r.Entry.Timestamp, v, uint64(r.Entry.Multiplicity), r.Entry.ID})
		a.Release(r.Bytes)
		a.Release(scratch)
		held -= scratch
	}
	if p.Function == "absent_over_time" {
		if !anyEntry {
			labels := absentLabels(p.Range.Log.Matchers)
			result.Vector = []value.Series{metricSeries(frame.Project, labels, frame.Time, 1)}
		}
		return result, nil
	}
	check := func() error { return a.Check(ctx) }
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	if e = metricSort(keys, func(i, j int) bool { return keys[i] < keys[j] }, check); e != nil {
		return result, e
	}
	for _, k := range keys {
		if e = a.Check(ctx); e != nil {
			return result, e
		}
		g := groups[k]
		if e = metricSort(g.points, func(i, j int) bool { return g.points[i].at < g.points[j].at }, check); e != nil {
			return result, e
		}
		v, ok, e := rangeStatistic(p.Function, g.points, p.Parameter, left, right, p.Range.Interval, check)
		if e != nil {
			return result, e
		}
		if ok {
			result.Vector = append(result.Vector, metricSeries(frame.Project, g.labels, frame.Time, v))
		}
	}
	return result, nil
}
func absentLabels(ms []Matcher) model.Labels {
	var out model.Labels
	seen := map[string]bool{}
	for _, m := range ms {
		if m.Name == "__name__" {
			continue
		}
		if seen[m.Name] {
			out = removeMetricLabels(out, []string{m.Name})
			continue
		}
		seen[m.Name] = true
		if m.Op == "=" {
			out = append(out, model.Label{Name: m.Name, Value: m.Value})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func rangeStatistic(name string, ps []rangePoint, q float64, left, right, interval int64, checks ...func() error) (float64, bool, error) {
	if len(ps) == 0 {
		return 0, false, nil
	}
	if err := metricCheck(checks); err != nil {
		return 0, false, err
	}
	if name == "first_over_time" {
		return ps[0].v, true, nil
	}
	if name == "last_over_time" {
		return ps[len(ps)-1].v, true, nil
	}
	var count uint64
	sum, comp, mean, m2 := 0.0, 0.0, 0.0, 0.0
	lo, hi := ps[0].v, ps[0].v
	for i, p := range ps {
		if i%1024 == 0 {
			if err := metricCheck(checks); err != nil {
				return 0, false, err
			}
		}
		if p.n > math.MaxUint64-count {
			return 0, false, model.Fail(model.Quota)
		}
		old := count
		count += p.n
		weighted := p.v * float64(p.n)
		if !math.IsInf(sum, 0) && !math.IsInf(weighted, 0) {
			y := weighted - comp
			t := sum + y
			comp = (t - sum) - y
			sum = t
		} else {
			sum += weighted
			comp = 0
		}
		if old == 0 {
			mean = p.v
		} else {
			switch {
			case math.IsNaN(mean) || math.IsNaN(p.v):
				mean = math.NaN()
				m2 = math.NaN()
			case math.IsInf(mean, 0):
				if math.IsInf(p.v, 0) && mean != p.v {
					mean = math.NaN()
				}
				m2 = math.NaN()
			case math.IsInf(p.v, 0):
				mean = p.v
				m2 = math.NaN()
			default:
				delta := p.v - mean
				next := mean + delta*(float64(p.n)/float64(count))
				if math.IsInf(delta, 0) {
					next = mean*(float64(old)/float64(count)) + p.v*(float64(p.n)/float64(count))
				}
				m2 += delta * (p.v - next) * float64(p.n)
				mean = next
			}
		}
		if math.IsNaN(lo) || p.v < lo {
			lo = p.v
		}
		if math.IsNaN(hi) || p.v > hi {
			hi = p.v
		}
	}
	switch name {
	case "count_over_time":
		return float64(count), true, nil
	case "sum_over_time", "bytes_over_time":
		return sum, true, nil
	case "rate", "bytes_rate":
		return sum / (float64(interval) / 1e9), true, nil
	case "avg_over_time":
		return mean, true, nil
	case "min_over_time":
		return lo, true, nil
	case "max_over_time":
		return hi, true, nil
	case "stdvar_over_time":
		if math.IsInf(mean, 0) {
			return math.NaN(), true, nil
		}
		return m2 / float64(count), true, nil
	case "stddev_over_time":
		if math.IsInf(mean, 0) {
			return math.NaN(), true, nil
		}
		return math.Sqrt(m2 / float64(count)), true, nil
	case "quantile_over_time":
		f, err := weightedQuantile(q, ps, count, checks...)
		return f, true, err
	case "rate_counter":
		if count < 2 {
			return 0, true, nil
		}
		first, last := ps[0], ps[len(ps)-1]
		// The pinned Loki kernel uses raw-ns observation differences divided by
		//1000, while its first-observation range displacement is range-ms. It
		// anchors the right edge at the last observation, not Frame.Time.
		elapsed := float64(int64(last.at)-int64(first.at)) / 1000
		if elapsed <= 0 {
			return math.NaN(), true, nil
		}
		increase := last.v - first.v
		previous := first.v
		for i, p := range ps[1:] {
			if i%1024 == 0 {
				if err := metricCheck(checks); err != nil {
					return 0, false, err
				}
			}
			if p.v < previous {
				increase += previous
			}
			previous = p.v
		}
		toStart := float64(interval/1000000) / 1000
		spacing := elapsed / float64(count-1)
		if increase > 0 && first.v >= 0 {
			toZero := elapsed * (first.v / increase)
			if toZero < toStart {
				toStart = toZero
			}
		}
		threshold := spacing * 1.1
		if toStart >= threshold {
			toStart = spacing / 2
		}
		factor := (elapsed + toStart) / elapsed
		return increase * factor / (float64(interval) / 1e9), true, nil
	}
	return 0, false, model.Fail(model.Invalid)
}
func weightedQuantile(q float64, ps []rangePoint, count uint64, checks ...func() error) (float64, error) {
	if math.IsNaN(q) {
		return math.NaN(), nil
	}
	if q < 0 {
		return math.Inf(-1), nil
	}
	if q > 1 {
		return math.Inf(1), nil
	}
	if err := metricSort(ps, func(i, j int) bool {
		if math.IsNaN(ps[i].v) {
			return !math.IsNaN(ps[j].v)
		}
		return ps[i].v < ps[j].v
	}, func() error { return metricCheck(checks) }); err != nil {
		return 0, err
	}
	if q == 0 {
		return ps[0].v, nil
	}
	if q == 1 {
		return ps[len(ps)-1].v, nil
	}
	rank := q * float64(count-1)
	low := uint64(math.Floor(rank))
	if low >= count {
		low = count - 1
	}
	high := low
	if rank > float64(low) && low < count-1 {
		high++
	}
	var n uint64
	lv, hv := ps[0].v, ps[len(ps)-1].v
	found := false
	for i, p := range ps {
		if i%1024 == 0 {
			if err := metricCheck(checks); err != nil {
				return 0, err
			}
		}
		n += p.n
		if !found && low < n {
			lv = p.v
			found = true
		}
		if high < n {
			hv = p.v
			break
		}
	}
	if low == high {
		return lv, nil
	}
	w := rank - float64(low)
	return lv*(1-w) + hv*w, nil
}
func metricSub(a, b int64) (int64, error) {
	if b > 0 && a < math.MinInt64+b || b < 0 && a > math.MaxInt64+b {
		return 0, model.Fail(model.Invalid)
	}
	return a - b, nil
}
func metricSeries(project model.ID, labels model.Labels, at model.UnixNano, v float64) value.Series {
	return value.Series{Project: project, Labels: labels, Samples: []value.Sample{{Time: at, Float: model.FloatBits(math.Float64bits(v))}}}
}
func removeMetricLabels(ls model.Labels, names []string) model.Labels {
	out := make(model.Labels, 0, len(ls))
	for _, l := range ls {
		drop := false
		for _, n := range names {
			drop = drop || l.Name == n
		}
		if !drop {
			out = append(out, l)
		}
	}
	return out
}
func groupLabels(ls model.Labels, names []string, without bool) model.Labels {
	out := make(model.Labels, 0, len(ls))
	for _, l := range ls {
		found := false
		for _, n := range names {
			found = found || n == l.Name
		}
		if l.Name != "__name__" && found != without {
			out = append(out, l)
		}
	}
	return out
}
