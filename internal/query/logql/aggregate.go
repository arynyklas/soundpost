// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"container/heap"
	"encoding/json"
	"hash/fnv"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/value"
	"strconv"
)

func aggregateMetric(n *CallExpr, args []value.Result, at model.UnixNano, project model.ID, p profile.Profile, checks ...func() error) (value.Result, error) {
	r := value.Result{Type: "vector"}
	if args[len(args)-1].Type != "vector" {
		return r, typeError(n, "aggregation operand is not a vector", "function.arguments")
	}
	v := args[len(args)-1].Vector
	check := func() error { return metricCheck(checks) }
	if n.Name == "approx_topk" {
		var err error
		v, err = approximateMetric(v, p, check)
		if err != nil {
			return r, err
		}
	}
	if n.Name == "sort" || n.Name == "sort_desc" {
		r.Vector = append([]value.Series(nil), v...)
		err := sortMetric(r.Vector, n.Name == "sort_desc", check)
		return r, err
	}
	k := 0
	if n.Name == "topk" || n.Name == "bottomk" || n.Name == "approx_topk" {
		f := math.Float64frombits(uint64(args[0].Scalar.Float))
		if math.IsNaN(f) || math.IsInf(f, 0) || f >= float64(math.MaxInt64) || f < float64(math.MinInt64) {
			return r, typeError(n, "aggregation parameter outside integer range")
		}
		if f <= 0 {
			return r, nil
		}
		k = int(f)
	}
	type group struct {
		labels model.Labels
		series []value.Series
	}
	groups := map[string]*group{}
	var keys []string
	for _, series := range v {
		if err := check(); err != nil {
			return r, err
		}
		labels := groupLabels(series.Labels, n.Grouping, n.Without)
		key := value.LabelKey(labels)
		g := groups[key]
		if g == nil {
			g = &group{labels: labels}
			groups[key] = g
			keys = append(keys, key)
		}
		g.series = append(g.series, series)
	}
	if err := metricSort(keys, func(i, j int) bool { return keys[i] < keys[j] }, check); err != nil {
		return r, err
	}
	for _, key := range keys {
		if err := check(); err != nil {
			return r, err
		}
		g := groups[key]
		if k > 0 {
			if err := sortMetric(g.series, n.Name != "bottomk", check); err != nil {
				return r, err
			}
			r.Vector = append(r.Vector, g.series[:min(k, len(g.series))]...)
			continue
		}
		ps := make([]rangePoint, len(g.series))
		for i, series := range g.series {
			if i%1024 == 0 {
				if err := check(); err != nil {
					return r, err
				}
			}
			ps[i] = rangePoint{v: math.Float64frombits(uint64(series.Samples[0].Float)), n: 1}
		}
		name := n.Name + "_over_time"
		if n.Name == "count" {
			name = "count_over_time"
		}
		f, ok, err := rangeStatistic(name, ps, 0, 0, 0, 1, nil, check)
		if err != nil {
			return r, err
		}
		if ok {
			r.Vector = append(r.Vector, metricSeries(project, g.labels, at, f))
		}
	}
	return r, nil
}
func sortMetric(v []value.Series, desc bool, checks ...func() error) error {
	return metricSort(v, func(i, j int) bool {
		a, b := math.Float64frombits(uint64(v[i].Samples[0].Float)), math.Float64frombits(uint64(v[j].Samples[0].Float))
		if math.IsNaN(a) {
			return false
		}
		if math.IsNaN(b) {
			return true
		}
		if a == b {
			return value.CompareLabels(v[i].Labels, v[j].Labels) < 0
		}
		if desc {
			return a > b
		}
		return a < b
	}, func() error { return metricCheck(checks) })
}

// approximateMetric is an independently authored count-min sketch with bounded
// candidate retention. It is not an exact-topk fallback when a gate is enabled.
func approximateMetric(v []value.Series, p profile.Profile, checks ...func() error) ([]value.Series, error) {
	capacity := 10000
	if raw := p.Configuration["count_min_sketch_heap_size"]; len(raw) > 0 {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			n, e := strconv.Atoi(text)
			if e != nil {
				return nil, model.Fail(model.Invalid)
			}
			capacity = n
		} else if json.Unmarshal(raw, &capacity) != nil {
			return nil, model.Fail(model.Invalid)
		}
	}
	if capacity < -1 {
		return nil, model.Fail(model.Invalid)
	}
	if capacity <= 0 {
		return nil, nil
	}
	sketch := &metricSketch{buckets: make([]float64, metricSketchWidth*metricSketchDepth)}
	candidates := &metricCandidates{sketch: sketch}
	observed := make(map[uint64]bool, min(capacity, len(v)))
	var buffer []byte
	for _, series := range v {
		if err := metricCheck(checks); err != nil {
			return nil, err
		}
		buffer = metricAppendLabelBytes(buffer, series.Labels)
		candidate := metricCandidate{series: series, id: metricXXH64(buffer)}
		candidate.positions = metricSketchPositions(buffer)
		weight := math.Float64frombits(uint64(series.Samples[0].Float))
		for _, pos := range candidate.positions {
			sketch.buckets[pos] += weight
		}
		if !observed[candidate.id] {
			heap.Push(candidates, candidate)
			observed[candidate.id] = true
		} else if candidates.Len() > 0 && value.CompareLabels(candidates.items[0].series.Labels, series.Labels) == 0 {
			heap.Fix(candidates, 0)
		}
		if candidates.Len() > capacity {
			gone := heap.Pop(candidates).(metricCandidate)
			delete(observed, gone.id)
		}
	}
	out := make([]value.Series, candidates.Len())
	for i, candidate := range candidates.items {
		series := candidate.series
		series.Samples = []value.Sample{{Time: series.Samples[0].Time, Float: model.FloatBits(math.Float64bits(sketch.estimate(candidate.positions)))}}
		out[i] = series
	}
	return out, nil
}

// Fixed pinned numerical facts: ceil(e/0.0001)=27183 columns, and
// ceil(log(0.01)/log(0.5))=7 rows of binary64 counters.
const metricSketchWidth = 27183
const metricSketchDepth = 7

type metricSketch struct{ buckets []float64 }
type metricCandidate struct {
	series    value.Series
	id        uint64
	positions [metricSketchDepth]uint32
}
type metricCandidates struct {
	items  []metricCandidate
	sketch *metricSketch
}

func (h metricCandidates) Len() int { return len(h.items) }
func (h metricCandidates) Less(i, j int) bool {
	return h.sketch.estimate(h.items[i].positions) < h.sketch.estimate(h.items[j].positions)
}
func (h metricCandidates) Swap(i, j int)  { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *metricCandidates) Push(item any) { h.items = append(h.items, item.(metricCandidate)) }
func (h *metricCandidates) Pop() any {
	n := len(h.items) - 1
	item := h.items[n]
	h.items[n] = metricCandidate{}
	h.items = h.items[:n]
	return item
}
func (s *metricSketch) estimate(positions [metricSketchDepth]uint32) float64 {
	result := float64(math.MaxUint64)
	for _, pos := range positions {
		if s.buckets[pos] < result {
			result = s.buckets[pos]
		}
	}
	return result
}
func metricSketchPositions(data []byte) (out [metricSketchDepth]uint32) {
	hasher := fnv.New32a()
	hasher.Write(data)
	first := hasher.Sum32()
	var second uint32
	// Bob Jenkins' public one-at-a-time hash, combined with FNV-1a by
	// Kirsch/Mitzenmacher double hashing. uint32 overflow is intentional.
	for _, octet := range data {
		second = (second + uint32(octet)) * 1025
		second ^= second >> 6
	}
	second *= 9
	second ^= second >> 11
	second *= 32769
	for row := range out {
		out[row] = (first+uint32(row)*second)%metricSketchWidth + uint32(row*metricSketchWidth)
	}
	return out
}
func binaryMetric(n *BinaryExpr, a, b value.Result, at model.UnixNano, project model.ID, checks ...func() error) (value.Result, error) {
	r := value.Result{Type: "vector"}
	check := func() error { return metricCheck(checks) }
	if a.Type == "scalar" && b.Type == "scalar" {
		f, _, err := metricOperation(n.Op, math.Float64frombits(uint64(a.Scalar.Float)), math.Float64frombits(uint64(b.Scalar.Float)))
		return value.Result{Type: "scalar", Scalar: value.Sample{Time: at, Float: model.FloatBits(math.Float64bits(f))}}, err
	}
	if a.Type == "scalar" || b.Type == "scalar" {
		v, scalar := a.Vector, b.Scalar
		leftScalar := a.Type == "scalar"
		if leftScalar {
			v = b.Vector
			scalar = a.Scalar
		}
		for _, series := range v {
			if err := check(); err != nil {
				return r, err
			}
			x, y := math.Float64frombits(uint64(series.Samples[0].Float)), math.Float64frombits(uint64(scalar.Float))
			if leftScalar {
				x, y = y, x
			}
			f, keep, err := metricOperation(n.Op, x, y)
			if err != nil {
				return r, err
			}
			if comparisonMetric(n.Op) && !n.Bool {
				f = math.Float64frombits(uint64(series.Samples[0].Float))
			}
			if keep || n.Bool {
				r.Vector = append(r.Vector, metricSeries(project, series.Labels, at, f))
			}
		}
		return r, nil
	}
	left, right := a.Vector, b.Vector
	set := n.Op == "and" || n.Op == "or" || n.Op == "unless"
	swap := n.Matching.Cardinality == "group_right"
	if swap {
		left, right = right, left
	}
	groups := map[string][]int{}
	seen := map[string]bool{}
	used := map[int]bool{}
	for i, x := range right {
		if err := check(); err != nil {
			return r, err
		}
		key := matchMetricLabels(x.Labels, n.Matching)
		if !set && len(groups[key]) > 0 {
			return r, typeError(n, "many-to-many vector matching is not allowed")
		}
		groups[key] = append(groups[key], i)
	}
	for _, x := range left {
		if err := check(); err != nil {
			return r, err
		}
		key := matchMetricLabels(x.Labels, n.Matching)
		matches := groups[key]
		if set {
			keep := n.Op == "or" || n.Op == "and" && len(matches) > 0 || n.Op == "unless" && len(matches) == 0
			if keep {
				r.Vector = append(r.Vector, x)
			}
			for _, j := range matches {
				used[j] = true
			}
			continue
		}
		if len(matches) == 0 {
			continue
		}
		if seen[key] && n.Matching.Cardinality == "" {
			return r, typeError(n, "many-to-one vector matching requires grouping")
		}
		seen[key] = true
		y := right[matches[0]]
		xf, yf := math.Float64frombits(uint64(x.Samples[0].Float)), math.Float64frombits(uint64(y.Samples[0].Float))
		if swap {
			xf, yf = yf, xf
		}
		f, keep, err := metricOperation(n.Op, xf, yf)
		if err != nil {
			return r, err
		}
		labels := x.Labels
		if comparisonMetric(n.Op) && !n.Bool {
			f = xf
		}
		if n.Matching.Cardinality == "" {
			if n.Matching.On {
				labels = onMetricLabels(labels, n.Matching.Labels)
			} else if n.Matching.Labels != nil {
				labels = removeMetricLabels(labels, n.Matching.Labels)
			}
		} else {
			for _, name := range n.Matching.Include {
				labels = value.SetLabel(labels, name, value.Label(y.Labels, name))
			}
		}
		if keep || n.Bool {
			r.Vector = append(r.Vector, metricSeries(project, labels, at, f))
		}
	}
	if n.Op == "or" {
		for i, y := range right {
			if err := check(); err != nil {
				return r, err
			}
			if !used[i] {
				r.Vector = append(r.Vector, y)
			}
		}
	}
	if !set {
		if err := uniqueMetricSeries(r.Vector); err != nil {
			return r, err
		}
	}
	return r, nil
}
func matchMetricLabels(ls model.Labels, m VectorMatching) string {
	if m.On {
		return value.LabelKey(onMetricLabels(ls, m.Labels))
	}
	return value.LabelKey(removeMetricLabels(ls, append([]string{"__name__"}, m.Labels...)))
}
func onMetricLabels(ls model.Labels, names []string) model.Labels {
	out := make(model.Labels, 0, len(names))
	for _, l := range ls {
		for _, name := range names {
			if l.Name == name {
				out = append(out, l)
				break
			}
		}
	}
	return out
}
func comparisonMetric(op string) bool {
	switch op {
	case "==", "!=", ">", "<", ">=", "<=":
		return true
	}
	return false
}
func metricOperation(op string, a, b float64) (float64, bool, error) {
	var yes bool
	switch op {
	case "+":
		return a + b, true, nil
	case "-":
		return a - b, true, nil
	case "*":
		return a * b, true, nil
	case "/":
		return a / b, true, nil
	case "%":
		return math.Mod(a, b), true, nil
	case "^":
		return math.Pow(a, b), true, nil
	case "==":
		yes = a == b
	case "!=":
		yes = a != b
	case ">":
		yes = a > b
	case "<":
		yes = a < b
	case ">=":
		yes = a >= b
	case "<=":
		yes = a <= b
	default:
		return 0, false, model.Fail(model.Invalid)
	}
	if yes {
		return 1, true, nil
	}
	return 0, false, nil
}
func uniqueMetricSeries(v []value.Series) error {
	seen := map[string]bool{}
	for _, s := range v {
		k := value.LabelKey(s.Labels)
		if seen[k] {
			return model.Fail(model.Conflict)
		}
		seen[k] = true
	}
	return nil
}
func (s *metricState) labelReplace(n *CallExpr, r value.Result) (value.Result, error) {
	dst, replacement, src, pattern := n.Args[1].(*StringExpr).Value, n.Args[2].(*StringExpr).Value, n.Args[3].(*StringExpr).Value, n.Args[4].(*StringExpr).Value
	if s.regexScope == nil && len(s.plan.Pipelines) > 0 {
		s.regexScope = s.plan.Pipelines[0].RegexScope
	}
	if s.regexScope == nil {
		scope, e := newRegexScope(s.plan.Profile)
		if e != nil {
			return r, e
		}
		s.regexScope = scope
	}
	scope := s.regexScope
	re, err := scope.Compile(s.ctx, pattern, regexcompat.Label)
	if err != nil {
		return r, err
	}
	for i := range r.Vector {
		if err = s.account.Check(s.ctx); err != nil {
			return r, err
		}
		text := value.Label(r.Vector[i].Labels, src)
		yes, e := scope.MatchString(s.ctx, re, text)
		if e != nil {
			return r, e
		}
		if !yes {
			continue
		}
		if len(replacement) > math.MaxInt32 || len(text) > math.MaxInt32 {
			return r, model.Fail(model.Quota)
		}
		bound := (int64(len(text))+1)*(int64(len(replacement))+1) + 128
		if err = s.reserve(bound); err != nil {
			return r, err
		}
		next, e := scope.ReplaceAllString(s.ctx, re, text, replacement)
		if e != nil {
			return r, e
		}
		r.Vector[i].Labels = value.SetLabel(r.Vector[i].Labels, dst, next)
	}
	return r, uniqueMetricSeries(r.Vector)
}
