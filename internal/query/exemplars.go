// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/promql"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
	"unicode/utf8"
)

const maxExemplarSelectors = 64

// exemplarKey is the total order of exemplars and the position a cursor holds:
// project, then series identity, then sample time, then record identity.
type exemplarKey struct {
	Project model.ID       `json:"p"`
	Series  []byte         `json:"s"`
	Time    model.UnixNano `json:"t"`
	Record  model.ID       `json:"r"`
}

func (k exemplarKey) less(o exemplarKey) bool {
	if k.Project != o.Project {
		return idLess(k.Project, o.Project)
	}
	if c := bytes.Compare(k.Series, o.Series); c != 0 {
		return c < 0
	}
	if k.Time != o.Time {
		return k.Time < o.Time
	}
	return idLess(k.Record, o.Record)
}

type exemplarItem struct {
	key exemplarKey
	ex  Exemplar
}

func exemplarCost(it exemplarItem) int64 {
	n := int64(512 + 2*len(it.key.Series))
	for _, l := range it.ex.Labels {
		n += int64(32 + len(l.Name) + len(l.Value))
	}
	if it.ex.Sample.Histogram != nil {
		n += value.HistogramBytes(*it.ex.Sample.Histogram)
	}
	return n
}

type exemplarParams struct {
	Projects   []model.ID `json:"p"`
	Profile    string     `json:"pr"`
	FeatureSet string     `json:"fs"`
	Expression string     `json:"e"`
	Window     TimeRange  `json:"w"`
}

// selectorSet is one selector's compiled matchers, with its own bounded regex
// scope.
type selectorSet struct {
	matchers []scan.LabelMatcher
	regex    *regexcompat.Scope
	set      *scan.MatcherSet
}

// selectorMatchers returns, for every series selector of the expression, its
// matchers with the metric name as a `__name__` equality matcher.
func selectorMatchers(expr promql.Expr) [][]Matcher {
	var out [][]Matcher
	promql.Walk(expr, func(e promql.Expr) bool {
		n, ok := e.(*promql.Node)
		if !ok || n.Kind != "selector" {
			return true
		}
		var ms []Matcher
		if n.Text != "" {
			ms = append(ms, Matcher{Name: "__name__", Op: "=", Value: n.Text})
		}
		for _, m := range n.Matchers {
			ms = append(ms, Matcher{Name: m.Name, Op: m.Op, Value: m.Value})
		}
		out = append(out, ms)
		return true
	})
	return out
}

// Exemplars returns one page of exemplars (a sample's value and the trace that
// produced it) of the series the expression's selectors match, in the projects
// and window, ordered by (project, series, time, record). Reads go through the
// caller's scope only, so another project's or another principal's exemplars
// and counts are unreachable.
func (e *Engine) Exemplars(ctx context.Context, scope auth.Scope, req ExemplarRequest) (ExemplarResult, error) {
	res, err := e.exemplars(ctx, scope, req)
	if err != nil {
		return ExemplarResult{}, normalizeError(err, false)
	}
	return res, nil
}

func (e *Engine) exemplars(ctx context.Context, scope auth.Scope, req ExemplarRequest) (ExemplarResult, error) {
	projects, err := e.checkProjects(req.Projects)
	if err != nil {
		return ExemplarResult{}, err
	}
	if req.Profile == "" || len(req.Profile) > 128 || req.FeatureSet == "" || len(req.FeatureSet) > 128 || !profileMatchesLanguage(LanguagePromQL, req.Profile) {
		return ExemplarResult{}, model.Fail(model.Invalid)
	}
	if len(req.Expression) == 0 || len(req.Expression) > e.limits.MaxExpressionBytes || !utf8.ValidString(req.Expression) {
		return ExemplarResult{}, model.Fail(model.Invalid)
	}
	if req.Limit < 1 || req.Limit > e.limits.MaxDiscoveryItems || req.Window.Start >= req.Window.End || len(req.Cursor) > 16384 {
		return ExemplarResult{}, model.Fail(model.Invalid)
	}
	if err = e.authorize(ctx, scope, projects, nil, false); err != nil {
		return ExemplarResult{}, err
	}
	prof, err := e.resolveProfile(LanguagePromQL, req.Profile, req.FeatureSet)
	if err != nil {
		return ExemplarResult{}, err
	}
	// Admission follows authorization and precedes parsing, the cursor check and
	// the cache lookup: the expression's syntax tree is charged to the account
	// before it is built, and a cache hit is charged and released like a cold page.
	s, err := e.begin(ctx, scope, projects, e.limits.DefaultTimeout, e.limits.DefaultMemory)
	if err != nil {
		return ExemplarResult{}, err
	}
	defer func() { _ = s.finish(ctx, false) }()
	if err = s.acct.Reserve(planCharge(req.Expression)); err != nil {
		return ExemplarResult{}, err
	}
	s.wire.Add(planCharge(req.Expression))
	expr, err := promql.Parse(req.Expression, prof)
	if err != nil {
		return ExemplarResult{}, normalizeError(err, true)
	}
	if _, _, err = promql.Check(expr, prof); err != nil {
		return ExemplarResult{}, normalizeError(err, true)
	}
	selectors := selectorMatchers(expr)
	if len(selectors) == 0 {
		return ExemplarResult{}, &syntax.LanguageError{Code: "exemplars.no-selector", Category: "type", Range: expr.SourceRange(), SafeMessage: "expression contains no series selector"}
	}
	if len(selectors) > maxExemplarSelectors {
		return ExemplarResult{}, model.Fail(model.TooLarge)
	}
	sets := make([]selectorSet, len(selectors))
	for i, ms := range selectors {
		if _, err = validMatchers(ms); err != nil {
			return ExemplarResult{}, err
		}
		sets[i].matchers = scanMatchers(ms)
	}
	params := exemplarParams{Projects: projects, Profile: req.Profile, FeatureSet: req.FeatureSet, Expression: req.Expression, Window: req.Window}
	digest, err := paramsDigest("exemplars", params)
	if err != nil {
		return ExemplarResult{}, err
	}
	var after *exemplarKey
	if req.Cursor != "" {
		var position exemplarKey
		if err = e.openCursor(s.ctx, scope, "exemplars", digest, req.Cursor, &position); err != nil {
			return ExemplarResult{}, err
		}
		after = &position
	}
	cacheable := e.cache != nil && e.settled(Evaluation{Instant: true, Time: req.Window.End})
	var ticket cacheTicket
	if cacheable {
		var raw []byte
		raw, ticket, err = e.cacheLookup(s.ctx, scope, prof.Identity, req.Expression, jsonKey(struct {
			P exemplarParams
			L uint32
			C string
		}{params, req.Limit, req.Cursor}))
		if err != nil {
			return ExemplarResult{}, err
		}
		if raw != nil {
			if cost, ok, cerr := s.chargeHit(raw); cerr != nil {
				return ExemplarResult{}, cerr
			} else if ok {
				var hit ExemplarResult
				if json.Unmarshal(raw, &hit) == nil && hit.Freshness.Completeness == CompletenessComplete && len(hit.Exemplars) <= int(req.Limit) {
					hit.Freshness.Cached = true
					if err = s.finish(ctx, true); err != nil {
						return ExemplarResult{}, err
					}
					return hit, nil
				}
				s.releaseHit(cost)
			}
		}
	}
	collect := &topK[exemplarItem]{max: int(req.Limit) + 1, less: func(a, b exemplarItem) bool { return a.key.less(b.key) }, cost: exemplarCost, acct: s.acct}
	defer collect.close()
	for i := range sets {
		for _, m := range sets[i].matchers {
			if m.Op == "=~" || m.Op == "!~" {
				if sets[i].regex, err = scan.NewMatcherScope(prof); err != nil {
					return ExemplarResult{}, normalizeError(err, true)
				}
				break
			}
		}
		if sets[i].set, err = scan.CompileMatchers(s.ctx, scan.MetricSelection{Matchers: sets[i].matchers, Profile: prof, RegexScope: sets[i].regex}); err != nil {
			return ExemplarResult{}, normalizeError(err, true)
		}
	}
	tracked := &trackedScanner{inner: e.scanner, open: &e.openIterators, stats: &scanStats{}}
	var meta value.Result
	for _, project := range projects {
		marks, err := e.exemplarProject(s.ctx, tracked, scope, project, req.Window, sets, after, collect, s.acct)
		if err != nil {
			return ExemplarResult{}, err
		}
		value.InheritMetadata(&meta, value.Result{Watermarks: marks})
	}
	items := append([]exemplarItem(nil), collect.items...)
	collect.close()
	if err = s.finish(ctx, true); err != nil {
		return ExemplarResult{}, err
	}
	out := ExemplarResult{Exemplars: []Exemplar{}, Freshness: Freshness{Completeness: CompletenessComplete, Watermarks: append([]model.Cursor{}, meta.Watermarks...)}}
	if len(items) > int(req.Limit) {
		items = items[:req.Limit]
		out.More = true
		if out.NextCursor, err = e.issueCursor(ctx, scope, "exemplars", digest, items[len(items)-1].key); err != nil {
			return ExemplarResult{}, err
		}
	}
	for _, it := range items {
		out.Exemplars = append(out.Exemplars, it.ex)
	}
	if cacheable {
		if raw, err := json.Marshal(out); err == nil {
			e.cacheStore(ctx, scope, ticket, raw)
		}
	}
	return out, nil
}

// exemplarProject scans one project's metric rows that carry an exemplar and
// offers each one matching any selector. Page memory is borrowed: a candidate
// is copied only if the collector would keep it.
func (e *Engine) exemplarProject(ctx context.Context, scanner Scanner, scope auth.Scope, project model.ID, window TimeRange, sets []selectorSet, after *exemplarKey, collect *topK[exemplarItem], acct value.Account) ([]model.Cursor, error) {
	rows, err := scanner.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Metric, Start: window.Start, End: window.End, Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldMetric}})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for {
		if err = acct.Check(ctx); err != nil {
			return nil, err
		}
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !pageShapeOK(page, false) || len(page.IDs) != page.Len() {
			return nil, model.Fail(model.Corrupt)
		}
		if page.Partial {
			return nil, model.Fail(model.Unavailable)
		}
		for j := range page.Len() {
			if err = acct.Check(ctx); err != nil {
				return nil, err
			}
			if page.Projects[j] != project {
				return nil, model.Fail(model.Corrupt)
			}
			if page.Times[j] < window.Start || page.Times[j] >= window.End {
				continue
			}
			payload := page.Values[j]
			if _, err = payload.Value(model.Metric); err != nil || payload.Metric == nil || payload.Metric.Name == "" {
				return nil, model.Fail(model.Corrupt)
			}
			m := payload.Metric
			if m.ExemplarTrace == nil {
				continue
			}
			if err = m.Labels.Validate(); err != nil {
				return nil, model.Fail(model.Corrupt)
			}
			labels := value.SetLabel(m.Labels, "__name__", m.Name)
			matched := false
			for i := range sets {
				if matched, err = sets[i].set.Match(ctx, labels); err != nil {
					return nil, err
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
			key := exemplarKey{Project: project, Series: []byte(value.LabelKey(labels)), Time: page.Times[j], Record: page.IDs[j]}
			if after != nil && !after.less(key) {
				continue
			}
			sample := Sample{Time: page.Times[j]}
			if m.StartTimestamp != nil {
				at := *m.StartTimestamp
				sample.StartTimestamp = &at
			}
			if m.Histogram != nil {
				h := value.CloneHistogram(*m.Histogram)
				sample.Histogram = &h
			} else if m.Value != nil {
				f := *m.Value
				sample.Float = &f
			} else {
				return nil, model.Fail(model.Corrupt)
			}
			ex := Exemplar{Project: project, Labels: value.CloneLabels(labels), Sample: sample, Trace: *m.ExemplarTrace, Record: page.IDs[j]}
			if m.ExemplarSpan != nil {
				span := *m.ExemplarSpan
				ex.Span = &span
			}
			if err = collect.offer(exemplarItem{key: key, ex: ex}); err != nil {
				return nil, err
			}
		}
	}
	if err = acct.Check(ctx); err != nil {
		return nil, err
	}
	marks := append([]model.Cursor(nil), rows.Watermarks()...)
	if err = rows.Close(); err != nil {
		return nil, err
	}
	return marks, nil
}
