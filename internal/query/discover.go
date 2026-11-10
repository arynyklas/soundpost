// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
	"strings"
	"unicode/utf8"
)

// topK keeps the max smallest distinct items offered, in order. Memory is
// bounded by max items, and every retained item is charged to the account
// before it is stored and released when it is evicted or the collector closes.
// Because each offered item is compared with the retained ones, an item evicted
// once can never re-enter, so the retained set is exactly the max smallest
// distinct items of everything offered.
type topK[T any] struct {
	max   int
	less  func(a, b T) bool
	cost  func(T) int64
	acct  value.Account
	items []T
	held  int64
}

func (k *topK[T]) offer(item T) error {
	i := sort.Search(len(k.items), func(i int) bool { return !k.less(k.items[i], item) })
	if i < len(k.items) && !k.less(item, k.items[i]) {
		return nil // an equal item is already retained
	}
	if i >= k.max {
		return nil // larger than everything retained and the collector is full
	}
	c := k.cost(item)
	if err := k.acct.Reserve(c); err != nil {
		return err
	}
	k.held += c
	k.items = append(k.items, item)
	copy(k.items[i+1:], k.items[i:])
	k.items[i] = item
	if len(k.items) > k.max {
		last := k.items[len(k.items)-1]
		k.items = k.items[:len(k.items)-1]
		k.acct.Release(k.cost(last))
		k.held -= k.cost(last)
	}
	return nil
}
func (k *topK[T]) close() {
	k.acct.Release(k.held)
	k.held = 0
	k.items = nil
}

const (
	maxMatchers   = 32
	maxNameBytes  = 256
	maxMatchValue = 4096
)

// discoveryKinds lists the discovery kinds each signal supports. Native trace,
// profile, issue and replay search is typed Soundpost reads elsewhere and is not
// discovery of PromQL/LogQL names.
var discoveryKinds = map[model.Kind][]string{
	model.Metric: {DiscoverMetricNames, DiscoverLabelNames, DiscoverLabelValues},
	model.Log:    {DiscoverLabelNames, DiscoverLabelValues, DiscoverTemplates, DiscoverFields},
}

func validMatchers(ms []Matcher) (needsProfile bool, err error) {
	if len(ms) > maxMatchers {
		return false, model.Fail(model.Invalid)
	}
	for _, m := range ms {
		if m.Name == "" || len(m.Name) > maxNameBytes || len(m.Value) > maxMatchValue || !utf8.ValidString(m.Name) || !utf8.ValidString(m.Value) {
			return false, model.Fail(model.Invalid)
		}
		switch m.Op {
		case "=", "!=":
		case "=~", "!~":
			needsProfile = true
		default:
			return false, model.Fail(model.Invalid)
		}
	}
	return needsProfile, nil
}

func scanMatchers(ms []Matcher) []scan.LabelMatcher {
	out := make([]scan.LabelMatcher, len(ms))
	for i, m := range ms {
		out[i] = scan.LabelMatcher{Name: m.Name, Op: m.Op, Value: m.Value}
	}
	return out
}

type discoverParams struct {
	Projects   []model.ID `json:"p"`
	Signal     model.Kind `json:"s"`
	Kind       string     `json:"k"`
	Field      string     `json:"f"`
	Matchers   []Matcher  `json:"m"`
	Time       TimeRange  `json:"t"`
	Source     *model.ID  `json:"o,omitempty"`
	Profile    string     `json:"pr,omitempty"`
	FeatureSet string     `json:"fs,omitempty"`
}

// Discover returns one page of sorted distinct metric names, label names, label
// values, template IDs or field names visible to the scope in the projects and
// time range. It only ever reads through the caller's scope, so another
// project's, another principal's or a restricted source's names, values and
// counts are never reachable. Pagination is exact: every matching row of the
// range is read, More says whether anything follows the page, and a cursor
// continues strictly after the last returned item.
func (e *Engine) Discover(ctx context.Context, scope auth.Scope, req DiscoveryRequest) (DiscoveryResult, error) {
	res, err := e.discover(ctx, scope, req)
	if err != nil {
		return DiscoveryResult{}, normalizeError(err, false)
	}
	return res, nil
}

func (e *Engine) discover(ctx context.Context, scope auth.Scope, req DiscoveryRequest) (DiscoveryResult, error) {
	projects, err := e.checkProjects(req.Projects)
	if err != nil {
		return DiscoveryResult{}, err
	}
	kinds, ok := discoveryKinds[req.Signal]
	if !ok {
		if req.Signal.Valid() {
			return DiscoveryResult{}, model.Fail(model.Unsupported)
		}
		return DiscoveryResult{}, model.Fail(model.Invalid)
	}
	found := false
	for _, k := range kinds {
		found = found || k == req.Kind
	}
	valuesKind := req.Kind == DiscoverLabelValues
	if !found || valuesKind != (req.Field != "") || len(req.Field) > maxNameBytes || !utf8.ValidString(req.Field) {
		return DiscoveryResult{}, model.Fail(model.Invalid)
	}
	if req.Limit < 1 || req.Limit > e.limits.MaxDiscoveryItems || req.Time.Start >= req.Time.End || len(req.Cursor) > 16384 {
		return DiscoveryResult{}, model.Fail(model.Invalid)
	}
	needsProfile, err := validMatchers(req.Matchers)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if needsProfile && (req.Profile == "" || req.FeatureSet == "") {
		return DiscoveryResult{}, model.Fail(model.Invalid)
	}
	if req.Source != nil && *req.Source == (model.ID{}) {
		return DiscoveryResult{}, model.Fail(model.Invalid)
	}
	if err = e.authorize(ctx, scope, projects, req.Source, req.Signal == model.Log); err != nil {
		return DiscoveryResult{}, err
	}
	var prof profile.Profile
	if needsProfile {
		language := LanguagePromQL
		if req.Signal == model.Log {
			language = LanguageLogQL
		}
		if prof, err = e.resolveProfile(language, req.Profile, req.FeatureSet); err != nil {
			return DiscoveryResult{}, err
		}
	}
	// Admission follows authorization and precedes the cache lookup, the cursor
	// check and the scans: a cache hit is charged and released like a cold page.
	timeout, memory := e.limits.DefaultTimeout, e.limits.DefaultMemory
	s, err := e.begin(ctx, scope, projects, timeout, memory)
	if err != nil {
		return DiscoveryResult{}, err
	}
	defer func() { _ = s.finish(ctx, false) }()
	params := discoverParams{Projects: projects, Signal: req.Signal, Kind: req.Kind, Field: req.Field, Matchers: req.Matchers, Time: req.Time, Source: req.Source, Profile: req.Profile, FeatureSet: req.FeatureSet}
	digest, err := paramsDigest("discover", params)
	if err != nil {
		return DiscoveryResult{}, err
	}
	var after *string
	if req.Cursor != "" {
		var position string
		if err = e.openCursor(s.ctx, scope, "discover", digest, req.Cursor, &position); err != nil {
			return DiscoveryResult{}, err
		}
		after = &position
	}
	cacheable := e.settled(Evaluation{Instant: true, Time: req.Time.End}) && e.cache != nil
	var ticket cacheTicket
	if cacheable {
		var raw []byte
		raw, ticket, err = e.cacheLookup(s.ctx, scope, prof.Identity, "discover", jsonKey(struct {
			P discoverParams
			L uint32
			C string
		}{params, req.Limit, req.Cursor}))
		if err != nil {
			return DiscoveryResult{}, err
		}
		if raw != nil {
			if cost, ok, cerr := s.chargeHit(raw); cerr != nil {
				return DiscoveryResult{}, cerr
			} else if ok {
				var hit DiscoveryResult
				if json.Unmarshal(raw, &hit) == nil && hit.Freshness.Completeness == CompletenessComplete && len(hit.Items) <= int(req.Limit) {
					hit.Freshness.Cached = true
					if err = s.finish(ctx, true); err != nil {
						return DiscoveryResult{}, err
					}
					return hit, nil
				}
				s.releaseHit(cost)
			}
		}
	}

	collect := &topK[string]{max: int(req.Limit) + 1, less: func(a, b string) bool { return a < b }, cost: func(v string) int64 { return int64(len(v)) + 48 }, acct: s.acct}
	defer collect.close()
	matchers := scanMatchers(req.Matchers)
	stats := &scanStats{}
	tracked := &trackedScanner{inner: e.scanner, open: &e.openIterators, stats: stats}
	var meta value.Result
	for _, project := range projects {
		marks, err := e.discoverProject(s.ctx, tracked, scope, project, req, matchers, prof, after, collect, s.acct)
		if err != nil {
			return DiscoveryResult{}, err
		}
		value.InheritMetadata(&meta, value.Result{Watermarks: marks})
	}
	items := append([]string{}, collect.items...)
	collect.close()
	if err = s.finish(ctx, true); err != nil {
		return DiscoveryResult{}, err
	}
	out := DiscoveryResult{Freshness: Freshness{Completeness: CompletenessComplete, Watermarks: append([]model.Cursor{}, meta.Watermarks...)}}
	if len(items) > int(req.Limit) {
		items = items[:req.Limit]
		out.More = true
		out.NextCursor, err = e.issueCursor(ctx, scope, "discover", digest, items[len(items)-1])
		if err != nil {
			return DiscoveryResult{}, err
		}
	}
	out.Items = items
	if cacheable {
		if raw, err := json.Marshal(out); err == nil {
			e.cacheStore(ctx, scope, ticket, raw)
		}
	}
	return out, nil
}

func pageShapeOK(p storage.Page, withSources bool) bool {
	n := p.Len()
	return len(p.Times) == n && len(p.Values) == n && len(p.Projects) == n && (!withSources || len(p.Sources) == n)
}

// discoverProject scans one project and offers every matching candidate.
func (e *Engine) discoverProject(ctx context.Context, scanner Scanner, scope auth.Scope, project model.ID, req DiscoveryRequest, matchers []scan.LabelMatcher, prof profile.Profile, after *string, collect *topK[string], acct value.Account) ([]model.Cursor, error) {
	selection := scan.MetricSelection{Matchers: matchers, Profile: prof}
	if len(matchers) > 0 {
		for _, m := range matchers {
			if m.Op == "=~" || m.Op == "!~" {
				rs, err := scan.NewMatcherScope(prof)
				if err != nil {
					return nil, err
				}
				selection.RegexScope = rs
				break
			}
		}
	}
	set, err := scan.CompileMatchers(ctx, selection)
	if err != nil {
		return nil, err
	}
	sr := storage.ScanRequest{Projects: []model.ID{project}, Signal: req.Signal, Start: req.Time.Start, End: req.Time.End}
	switch req.Signal {
	case model.Metric:
		sr.Projection = []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldMetric}
	default:
		sr.Projection = []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldLog}
		if req.Source != nil {
			sr.Selectors = []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: req.Source.String()}}}
		}
	}
	rows, err := scanner.Scan(ctx, scope, sr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	offer := func(v string) error {
		if v == "" || after != nil && v <= *after {
			return nil
		}
		return collect.offer(strings.Clone(v))
	}
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
		if !pageShapeOK(page, req.Signal == model.Log) {
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
			if page.Times[j] < req.Time.Start || page.Times[j] >= req.Time.End {
				continue
			}
			if req.Signal == model.Metric {
				err = discoverMetricRow(ctx, page.Values[j], req, set, offer)
			} else {
				if req.Source != nil && page.Sources[j] != *req.Source {
					continue
				}
				err = discoverLogRow(ctx, page.Values[j], req, set, offer)
			}
			if err != nil {
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

func discoverMetricRow(ctx context.Context, payload model.Payload, req DiscoveryRequest, set *scan.MatcherSet, offer func(string) error) error {
	if _, err := payload.Value(model.Metric); err != nil || payload.Metric == nil || payload.Metric.Name == "" {
		return model.Fail(model.Corrupt)
	}
	m := payload.Metric
	if err := m.Labels.Validate(); err != nil {
		return model.Fail(model.Corrupt)
	}
	labels := value.SetLabel(m.Labels, "__name__", m.Name)
	ok, err := set.Match(ctx, labels)
	if err != nil || !ok {
		return err
	}
	switch req.Kind {
	case DiscoverMetricNames:
		return offer(m.Name)
	case DiscoverLabelNames:
		for _, l := range labels {
			if err := offer(l.Name); err != nil {
				return err
			}
		}
	case DiscoverLabelValues:
		return offer(value.Label(labels, req.Field))
	}
	return nil
}

func discoverLogRow(ctx context.Context, payload model.Payload, req DiscoveryRequest, set *scan.MatcherSet, offer func(string) error) error {
	if _, err := payload.Value(model.Log); err != nil || payload.Log == nil {
		return model.Fail(model.Corrupt)
	}
	l := payload.Log
	if err := l.StreamLabels.Validate(); err != nil {
		return model.Fail(model.Corrupt)
	}
	ok, err := set.Match(ctx, l.StreamLabels)
	if err != nil || !ok {
		return err
	}
	switch req.Kind {
	case DiscoverLabelNames:
		for _, x := range l.StreamLabels {
			if err := offer(x.Name); err != nil {
				return err
			}
		}
	case DiscoverLabelValues:
		return offer(value.Label(l.StreamLabels, req.Field))
	case DiscoverTemplates:
		return offer(l.TemplateID)
	case DiscoverFields:
		for name := range l.Fields {
			if err := offer(name); err != nil {
				return err
			}
		}
	}
	return nil
}
