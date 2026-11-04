// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
)

type metricSource struct {
	scanner Scanner
	scope   auth.Scope
	project model.ID
	fence   storage.ReadFence
}

func NewMetricSource(scanner Scanner, scope auth.Scope, project model.ID, fence storage.ReadFence) MetricSource {
	fence.Min = append([]model.Cursor(nil), fence.Min...)
	return &metricSource{scanner, scope, project, fence}
}
func (s *metricSource) ProjectID() model.ID { return s.project }

type metricIterator struct {
	series   []value.Series
	index    int
	account  value.Account
	bytes    int64
	closed   bool
	metadata value.Result
}

func (i *metricIterator) Next(ctx context.Context) (value.Series, error) {
	if e := ctx.Err(); e != nil {
		_ = i.Close()
		return value.Series{}, e
	}
	if i.closed || i.index >= len(i.series) {
		return value.Series{}, io.EOF
	}
	if e := i.account.Check(ctx); e != nil {
		_ = i.Close()
		return value.Series{}, e
	}
	s := i.series[i.index]
	i.index++
	return s, nil
}
func (i *metricIterator) Close() error {
	if !i.closed {
		i.closed = true
		i.account.Release(i.bytes)
		i.series = nil
	}
	return nil
}
func (i *metricIterator) Watermarks() []model.Cursor {
	return append([]model.Cursor(nil), i.metadata.Watermarks...)
}
func (i *metricIterator) Partial() bool { return i.metadata.Partial }
func (i *metricIterator) mergeMetadata(cursors []model.Cursor, partial bool) error {
	before := len(i.metadata.Watermarks)
	value.InheritMetadata(&i.metadata, value.Result{Partial: partial, Watermarks: cursors})
	cost := int64(len(i.metadata.Watermarks)-before) * 24
	if err := i.account.Reserve(cost); err != nil {
		return err
	}
	i.bytes += cost
	return nil
}
func (s *metricSource) Select(ctx context.Context, r MetricSelection) (out SeriesIterator, err error) {
	if r.Account == nil || s.scanner == nil || r.Start >= r.End {
		return nil, model.Fail(model.Invalid)
	}
	if err = r.Account.Check(ctx); err != nil {
		return nil, err
	}
	matchers, err := CompileMatchers(ctx, r)
	if err != nil {
		return nil, err
	}
	rows, err := s.scanner.Scan(ctx, s.scope, storage.ScanRequest{Projects: []model.ID{s.project}, Signal: model.Metric, Start: r.Start, End: r.End, Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldMetric}, Fence: s.fence})
	if err != nil {
		return nil, err
	}
	defer func() {
		ce := rows.Close()
		if err == nil && ce != nil {
			if out != nil {
				_ = out.Close()
			}
			out = nil
			err = ce
		}
	}()
	it := &metricIterator{account: r.Account}
	defer func() {
		if err != nil {
			_ = it.Close()
		}
	}()
	groups := map[string]int{}
	for {
		if err = r.Account.Check(ctx); err != nil {
			return nil, err
		}
		page, e := rows.Next(ctx)
		if e != nil {
			if errors.Is(e, io.EOF) {
				if err = r.Account.Check(ctx); err != nil {
					return nil, err
				}
				if err = it.mergeMetadata(rows.Watermarks(), false); err != nil {
					return nil, err
				}
				break
			}
			return nil, e
		}
		n := page.Len()
		if len(page.Times) != n || len(page.Values) != n || len(page.Projects) != n {
			return nil, model.Fail(model.Corrupt)
		}
		if page.Partial && !s.fence.AllowPartial {
			return nil, model.Fail(model.Unavailable)
		}
		if err = it.mergeMetadata(rows.Watermarks(), page.Partial); err != nil {
			return nil, err
		}
		for j := range n {
			if err = r.Account.Check(ctx); err != nil {
				return nil, err
			}
			if page.Projects[j] != s.project {
				return nil, model.Fail(model.Corrupt)
			}
			if _, e = page.Values[j].Value(model.Metric); e != nil {
				return nil, model.Fail(model.Corrupt)
			}
			m := page.Values[j].Metric
			if m == nil || m.Name == "" || (m.Value == nil) == (m.Histogram == nil) {
				return nil, model.Fail(model.Corrupt)
			}
			if e = m.Labels.Validate(); e != nil {
				return nil, model.Fail(model.Corrupt)
			}
			if m.Histogram != nil {
				if e = m.Histogram.Validate(); e != nil {
					return nil, model.Fail(model.Corrupt)
				}
			}
			if page.Times[j] < r.Start || page.Times[j] >= r.End {
				continue
			}
			ls := value.SetLabel(m.Labels, "__name__", m.Name)
			ok, e := matchers.Match(ctx, ls)
			if e != nil {
				return nil, e
			}
			if !ok {
				continue
			}
			key := value.LabelKey(ls)
			k, exists := groups[key]
			if !exists {
				cost := value.SeriesBytes(value.Series{Labels: ls})
				if err = r.Account.Reserve(cost); err != nil {
					return nil, err
				}
				it.bytes += cost
				k = len(it.series)
				groups[key] = k
				it.series = append(it.series, value.Series{Project: s.project, Labels: value.CloneLabels(ls)})
			}
			p := value.Sample{Time: page.Times[j], Histogram: m.Histogram, StartTimestamp: m.StartTimestamp}
			if m.Value != nil {
				p.Float = *m.Value
			}
			cost := value.SampleBytes(p)
			if err = r.Account.Reserve(cost); err != nil {
				return nil, err
			}
			it.bytes += cost
			it.series[k].Samples = append(it.series[k].Samples, value.CloneSample(p))
		}
	}
	for k := range it.series {
		ps := it.series[k].Samples
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Time < ps[j].Time })
		dst := ps[:0]
		for _, p := range ps {
			if len(dst) > 0 && dst[len(dst)-1].Time == p.Time {
				if !value.EqualSample(dst[len(dst)-1], p) {
					return nil, model.Fail(model.Conflict)
				}
				continue
			}
			dst = append(dst, p)
		}
		it.series[k].Samples = dst
	}
	sort.Slice(it.series, func(i, j int) bool { return value.CompareLabels(it.series[i].Labels, it.series[j].Labels) < 0 })
	return it, nil
}

// MatcherSet preserves missing-label-as-empty semantics; no unsafe negative or
// regex matcher is pushed into the storage index. Compilation is per selection.
type MatcherSet struct {
	matchers []LabelMatcher
	regex    []*regexcompat.Regexp
	scope    *regexcompat.Scope
}

// NewMatcherScope supplies one shared bounded regex budget for an evaluation.
// Entry capacity does not allocate eagerly; source/program/work limits are the
// actual bounds. Direct Select callers can use one bounded selection instead.
func NewMatcherScope(p profile.Profile) (*regexcompat.Scope, error) {
	return regexcompat.NewScope(p, regexcompat.Limits{CacheEntries: 1 << 20, CachePatternBytes: 1 << 20, ProgramUnits: 1 << 20, PatternBytes: 1 << 20, InputBytes: 1 << 24, Work: 1 << 34, Matches: 1 << 20, OutputBytes: 1 << 24})
}
func CompileMatchers(ctx context.Context, r MetricSelection) (*MatcherSet, error) {
	set := &MatcherSet{matchers: append([]LabelMatcher(nil), r.Matchers...), regex: make([]*regexcompat.Regexp, len(r.Matchers)), scope: r.RegexScope}
	for i, m := range r.Matchers {
		if m.Op == "=" || m.Op == "!=" {
			continue
		}
		if m.Op != "=~" && m.Op != "!~" {
			return nil, model.Fail(model.Invalid)
		}
		if set.scope == nil {
			var e error
			set.scope, e = NewMatcherScope(r.Profile)
			if e != nil {
				return nil, e
			}
		}
		var e error
		set.regex[i], e = set.scope.Compile(ctx, m.Value, regexcompat.Label)
		if e != nil {
			return nil, e
		}
	}
	return set, nil
}
func (set *MatcherSet) Match(ctx context.Context, ls model.Labels) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	for i, m := range set.matchers {
		v := value.Label(ls, m.Name)
		match := false
		switch m.Op {
		case "=":
			match = v == m.Value
		case "!=":
			match = v != m.Value
		default:
			var e error
			match, e = set.scope.MatchString(ctx, set.regex[i], v)
			if e != nil {
				return false, e
			}
			if m.Op == "!~" {
				match = !match
			}
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}
