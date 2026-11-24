// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
	"io"
	"math"
	"sort"
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
	// budget is shared by every window of one query; a nil budget gives the
	// call its own.
	budget *repetitionBudget
}

// MaxAccumulatorRepetitions bounds the accumulator steps one query may spend
// unfolding entry multiplicities (sum/rate/avg/stddev/stdvar over unwrap).
// Bit-exact results need one step per repetition, so a stored multiplicity
// would otherwise be an arbitrary CPU cost. 2^26 steps (about 67 million) is
// far above any recorded or realistic multiplicity total in a query and costs
// well under a second of arithmetic; exceeding it fails with model.Quota.
const MaxAccumulatorRepetitions uint64 = 1 << 26

type repetitionBudget struct{ left uint64 }

func newRepetitionBudget() *repetitionBudget {
	return &repetitionBudget{left: MaxAccumulatorRepetitions}
}

// charge spends n repetitions or fails with the typed quota fault.
func (b *repetitionBudget) charge(n uint64) error {
	if b == nil {
		return nil
	}
	if n > b.left {
		b.left = 0
		return model.Fail(model.Quota)
	}
	b.left -= n
	return nil
}

// MetricPipelineError is the failure of a metric whose input carries an
// __error__ label. EngineSet reports whether the engine set that label itself (a
// pipeline stage failed, so Category is one of the closed engine error kinds) or
// whether the record's own data produced a label of that name (Category is then
// arbitrary record text and is never a diagnostic).
type MetricPipelineError struct {
	Category  string
	EngineSet bool
}

func (e *MetricPipelineError) Error() string {
	return "LogQL metric input contains pipeline error: " + e.Category
}

type rangePoint struct {
	at model.UnixNano
	v  float64
	n  uint64
	id model.ID
	// hash is the original stream hash; samples with equal timestamps merge by it.
	hash uint64
}
type rangeGroup struct {
	labels model.Labels
	points []rangePoint
}

// rangeLabels is the label set of pipelined rows together with everything the
// accumulation derives from it. The derivation depends on the label set and
// the range plan only, never on the row, so rows that share a set (and a plan)
// share the work.
type rangeLabels struct {
	labels model.Labels
	// category is the value of the __error__ label, empty for a clean row.
	category string
	prepared bool
	// scratch is the transient charge of one row of this set.
	scratch int64
	// grouped are the labels of the group the row folds into, key their map
	// key and newGroup the charge of the first row of a group.
	grouped  model.Labels
	key      string
	newGroup int64
}

func newRangeLabels(ls model.Labels) *rangeLabels {
	return &rangeLabels{labels: ls, category: value.Label(ls, "__error__")}
}

// prepare derives the charge and the group of the set for one range plan.
func (l *rangeLabels) prepare(unwrap string, p RangePlan) {
	if l.prepared {
		return
	}
	l.prepared = true
	l.scratch = int64(256 + len(l.labels)*64)
	for _, x := range l.labels {
		l.scratch += int64(len(x.Name)+len(x.Value)) * 2
	}
	g := l.labels
	if unwrap != "" {
		g = removeMetricLabels(g, []string{unwrap, "__error__", "__error_details__"})
	}
	if p.Grouping != nil {
		g = groupLabels(g, p.Grouping, p.Without)
	}
	l.grouped = g
	l.key = value.LabelKey(g)
	l.newGroup = int64(len(l.key)) + value.SeriesBytes(value.Series{Labels: g})
}

// rangeRow is what the range accumulation needs of one pipelined row. bytes is
// the account charge the consumer releases once it is done with the row.
type rangeRow struct {
	retained      bool
	at            model.UnixNano
	multiplicity  model.Uint64
	id            model.ID
	labels        *rangeLabels
	value         float64
	hasValue      bool
	lineLen       int
	hash          uint64
	languageError bool
	bytes         int64
}

// rangeRows feeds the accumulation, either straight from a pipeline iterator
// or from rows a union scan retained.
type rangeRows interface {
	next(context.Context) (rangeRow, error)
	close() error
	partial() bool
	watermarks() []model.Cursor
}

// iteratorRows adapts an EntryIterator: one pipelined row per call, nothing kept.
type iteratorRows struct {
	input      EntryIterator
	hashBuffer []byte
}

func (e *iteratorRows) next(ctx context.Context) (rangeRow, error) {
	r, err := e.input.Next(ctx)
	if err != nil {
		return rangeRow{}, err
	}
	row := rangeRow{retained: r.Retained, at: r.Entry.Timestamp, bytes: r.Bytes}
	if !r.Retained {
		return row, nil
	}
	row.multiplicity, row.id, row.lineLen = r.Entry.Multiplicity, r.Entry.ID, len(r.Entry.Line)
	row.labels = newRangeLabels(r.Labels)
	row.languageError = r.Entry.languageError != ""
	if r.Unwrapped != nil {
		row.value, row.hasValue = *r.Unwrapped, true
	}
	if len(r.OriginalStreamLabels) > 0 {
		e.hashBuffer = metricStreamHashBytes(e.hashBuffer, r.OriginalStreamLabels)
		row.hash = metricXXH64(e.hashBuffer)
	}
	return row, nil
}
func (e *iteratorRows) close() error               { return e.input.Close() }
func (e *iteratorRows) partial() bool              { return e.input.Partial() }
func (e *iteratorRows) watermarks() []model.Cursor { return e.input.Watermarks() }

// EvaluateRange owns and closes input. Metric windows are (left,right], unlike
// the raw source's [start,end). A surviving error is not an absent sample.
func EvaluateRange(ctx context.Context, p RangePlan, input EntryIterator, frame Frame) (result value.Result, err error) {
	if input == nil {
		return result, model.Fail(model.Invalid)
	}
	return evaluateRange(ctx, p, &iteratorRows{input: input}, frame)
}

// evaluateRange is EvaluateRange over any row feed. It owns and closes rows.
func evaluateRange(ctx context.Context, p RangePlan, rows rangeRows, frame Frame) (result value.Result, err error) {
	defer func() { err = boundaryErr(err) }()
	if ctx == nil || frame.Account == nil || p.Range == nil || p.Range.Log == nil || p.Range.Interval < 0 || frame.Project == (model.ID{}) || !rangeNames[p.Function] {
		rows.close()
		return result, model.Fail(model.Invalid)
	}
	a := frame.Account
	budget := frame.budget
	if budget == nil {
		budget = newRepetitionBudget()
	}
	held := int64(0)
	result.Type = "vector"
	defer func() {
		closeErr := rows.close()
		if err == nil {
			err = closeErr
		}
		value.InheritMetadata(&result, value.Result{Partial: rows.partial(), Watermarks: rows.watermarks()})
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
		r, e := rows.next(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return result, e
		}
		if !r.retained || int64(r.at) <= left || int64(r.at) > right {
			a.Release(r.bytes)
			continue
		}
		if category := r.labels.category; category != "" {
			a.Release(r.bytes)
			return result, &MetricPipelineError{Category: category, EngineSet: r.languageError}
		}
		if r.multiplicity == 0 {
			a.Release(r.bytes)
			return result, model.Fail(model.Corrupt)
		}
		anyEntry = true
		if p.Function == "absent_over_time" {
			a.Release(r.bytes)
			continue
		}
		r.labels.prepare(unwrap, p)
		scratch := r.labels.scratch
		if e = a.Reserve(scratch); e != nil {
			a.Release(r.bytes)
			return result, e
		}
		held += scratch
		cost := int64(192)
		g := groups[r.labels.key]
		if g == nil {
			cost += r.labels.newGroup
		}
		if e = a.Reserve(cost); e != nil {
			a.Release(r.bytes)
			return result, e
		}
		held += cost
		if g == nil {
			g = &rangeGroup{labels: value.CloneLabels(r.labels.grouped)}
			groups[r.labels.key] = g
		}
		v := float64(1)
		if unwrap != "" {
			if !r.hasValue {
				a.Release(r.bytes)
				return result, model.Fail(model.Corrupt)
			}
			v = r.value
		} else if p.Function == "bytes_rate" || p.Function == "bytes_over_time" {
			v = float64(r.lineLen)
		}
		g.points = append(g.points, rangePoint{at: r.at, v: v, n: uint64(r.multiplicity), id: r.id, hash: r.hash})
		a.Release(r.bytes)
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
		// Samples merge by timestamp, then by ascending stream hash when both have one;
		// the sort is stable, so equal-stream equal-time samples keep their encounter order.
		if e = metricSort(g.points, func(i, j int) bool {
			a, b := g.points[i], g.points[j]
			if a.at != b.at {
				return a.at < b.at
			}
			return a.hash != 0 && b.hash != 0 && a.hash < b.hash
		}, check); e != nil {
			return result, e
		}
		v, ok, e := rangeStatistic(p.Function, g.points, p.Parameter, left, right, p.Range.Interval, budget, check)
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

// invalidOperationNaN is the NaN an x86 division of zero by zero produces.
var invalidOperationNaN = math.Float64frombits(0xfff8000000000000)

// nextMean folds the n-th sample (1-based) into a running mean as
// mean + (v/n - mean/n). The explicit parentheses and the absence of a product
// keep the result independent of fused multiply-add.
func nextMean(mean, v float64, n uint64) float64 {
	switch {
	case n == 1:
		return v
	case math.IsNaN(mean) || math.IsNaN(v):
		return math.NaN()
	case math.IsInf(mean, 0):
		if math.IsInf(v, 0) && mean != v {
			return math.NaN()
		}
		return mean
	case math.IsInf(v, 0):
		return v
	}
	c := float64(n)
	return mean + (v/c - mean/c)
}

// nextMoments folds the n-th sample (1-based) into a Welford mean and sum of
// squared deviations: delta = v-mean, mean += delta/n, m2 += delta*(v-mean).
// Once a non-finite value enters, m2 is NaN and a surviving infinite mean makes
// the variance NaN. float64(...) around the product forbids fused multiply-add.
func nextMoments(mean, m2, v float64, n uint64) (float64, float64) {
	switch {
	case n == 1:
		return v, 0
	case math.IsNaN(mean) || math.IsNaN(v):
		return math.NaN(), math.NaN()
	case math.IsInf(mean, 0):
		if math.IsInf(v, 0) && mean != v {
			mean = math.NaN()
		}
		return mean, math.NaN()
	case math.IsInf(v, 0):
		return v, math.NaN()
	}
	c := float64(n)
	delta := v - mean
	next := mean + delta/c
	if math.IsInf(delta, 0) {
		// v-mean overflowed: rebuild the mean from scaled operands.
		next = float64(mean*((c-1)/c)) + v/c
	}
	return next, m2 + float64(delta*(v-next))
}

func rangeStatistic(name string, ps []rangePoint, q float64, left, right, interval int64, budget *repetitionBudget, checks ...func() error) (float64, bool, error) {
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
	sum, mean, m2 := 0.0, 0.0, 0.0
	lo, hi := ps[0].v, ps[0].v
	accumulates := false
	switch name {
	case "sum_over_time", "bytes_over_time", "rate", "bytes_rate", "avg_over_time", "stdvar_over_time", "stddev_over_time":
		accumulates = true
	}
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
		if math.IsNaN(lo) || p.v < lo {
			lo = p.v
		}
		if math.IsNaN(hi) || p.v > hi {
			hi = p.v
		}
		if !accumulates {
			continue
		}
		// An entry of multiplicity m is m separate samples of one value. The
		// sums and moments are order- and repetition-sensitive in the last bit,
		// so each repetition enters its accumulator on its own, in entry order.
		if name != "sum_over_time" && name != "bytes_over_time" && name != "rate" && name != "bytes_rate" {
			// These loops never skip, so the whole run is charged up front.
			if err := budget.charge(p.n); err != nil {
				return 0, false, err
			}
		}
	repeat:
		for k := uint64(0); k < p.n; k++ {
			if k&1023 == 1023 {
				if err := metricCheck(checks); err != nil {
					return 0, false, err
				}
			}
			switch name {
			case "sum_over_time", "bytes_over_time", "rate", "bytes_rate":
				if err := budget.charge(1); err != nil {
					return 0, false, err
				}
				next := sum + p.v
				if next == sum || math.IsNaN(sum) {
					// A repeated addend no longer changes the sum.
					break repeat
				}
				sum = next
			case "avg_over_time":
				mean = nextMean(mean, p.v, old+k+1)
			default:
				mean, m2 = nextMoments(mean, m2, p.v, old+k+1)
			}
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
			// Observations at one instant (a multiplicity above one) divide 0 by
			// 0. The reference result is the hardware invalid-operation NaN, sign
			// bit set (mx-0033..0038), not the positive library NaN.
			return invalidOperationNaN, true, nil
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
	rank := float64(q * float64(count-1))
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
	return float64(lv*(1-w)) + float64(hv*w), nil
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
