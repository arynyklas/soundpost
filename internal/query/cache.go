// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// cacheTicket carries the miss's authorization proof to the store, which only
// accepts a value computed under the authorization state the miss observed.
type cacheTicket struct {
	fill    auth.CacheFill
	enabled bool
}

// cacheLookup consults the C02 cache. The cache key is org, effective
// visibility (principal and every project/action/named-source grant), policy
// epoch, delete generation, profile identity, query text and parameters;
// auth.Cache revalidates the scope and reads the delete generation before it
// touches an entry, so neither a revoked caller nor a deleted-from range ever
// reaches a hit. A negative entry is never produced by this package, so one is
// treated as a miss.
func (e *Engine) cacheLookup(ctx context.Context, scope auth.Scope, profileIdentity, query, params string) ([]byte, cacheTicket, error) {
	if e.cache == nil {
		return nil, cacheTicket{}, nil
	}
	res, err := e.cache.Lookup(ctx, scope, profileIdentity, query, params)
	if err != nil {
		return nil, cacheTicket{}, err
	}
	t := cacheTicket{fill: res.Fill, enabled: true}
	if res.Hit && !res.Negative {
		return res.Value, t, nil
	}
	return nil, t, nil
}

// cacheStore never fails a request: a response too large for the cache, or one
// whose authorization state moved while it was computed, is simply not stored.
func (e *Engine) cacheStore(ctx context.Context, scope auth.Scope, t cacheTicket, raw []byte) {
	if !t.enabled || e.cache == nil || len(raw) == 0 {
		return
	}
	_ = e.cache.Store(ctx, scope, t.fill, raw, false)
}

type queryParams struct {
	Projects []model.ID `json:"p"`
	Eval     Evaluation `json:"e"`
	Source   *model.ID  `json:"s,omitempty"`
}

// lookupQuery returns a cached complete result when one exists for exactly this
// visibility and request. Only PromQL results are cached: a LogQL template can
// read the wall clock, so its answer is not a function of the request and data.
// It runs inside the request's admitted session: the hit's payload is charged to
// the session's account before it is decoded, and a hit is used only if it still
// satisfies this request's minimum read cuts, returned-value budget and memory
// budget.
func (e *Engine) lookupQuery(s *session, scope auth.Scope, prof profile.Profile, n normalized) (*Result, cacheTicket, error) {
	if e.cache == nil || n.Language != LanguagePromQL || !e.settled(n.Request.Evaluation) {
		return nil, cacheTicket{}, nil
	}
	raw, ticket, err := e.cacheLookup(s.ctx, scope, prof.Identity, n.Expression, jsonKey(queryParams{Projects: n.Projects, Eval: n.Request.Evaluation, Source: n.Source}))
	if err != nil || raw == nil {
		return nil, ticket, err
	}
	cost, ok, err := s.chargeHit(raw)
	if !ok {
		return nil, ticket, err
	}
	served := false
	defer func() {
		if !served {
			s.releaseHit(cost) // an unusable hit must not shrink the cold run's budget
		}
	}()
	var cached Result
	if json.Unmarshal(raw, &cached) != nil || len(cached.Projects) != len(n.Projects) {
		return nil, ticket, nil
	}
	var total uint64
	for i := range cached.Projects {
		pr := &cached.Projects[i]
		// A project whose value is nil is a failed or partial project. It is never
		// stored (storeQuery refuses any failure or non-complete project) and is
		// refused here as well, so the {"value":null} wire form of a failed project
		// can never come back out of the cache as if it were data.
		if pr.ProjectID != n.Projects[i] || pr.Value == nil || pr.Failure != nil || pr.Completeness != CompletenessComplete {
			return nil, ticket, nil
		}
		if completenessOf(value.Result{Watermarks: pr.Watermarks}, n.MinCursors, pr.Stats.ScansStarted > 0) != CompletenessComplete {
			return nil, ticket, nil
		}
		total += uint64(pr.Stats.SamplesReturned)
		pr.Stats.Cached = true
	}
	if total > n.returned {
		return nil, ticket, nil
	}
	served = true
	return &cached, ticket, nil
}

// storeQuery caches a fully complete PromQL result.
func (e *Engine) storeQuery(ctx context.Context, scope auth.Scope, t cacheTicket, n normalized, res Result) {
	if !t.enabled {
		return
	}
	for _, pr := range res.Projects {
		if pr.Failure != nil || pr.Completeness != CompletenessComplete {
			return
		}
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return
	}
	e.cacheStore(ctx, scope, t, raw)
}
