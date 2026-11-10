// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

func series40(st *tstore, project model.ID, name string) {
	for i := range 40 {
		st.add(metricRow(project, name, model.Labels{{Name: "job", Value: "api" + string(rune('a'+i%26)) + string(rune('a'+i/26))}}, testEpoch, 1))
	}
}

// TestCacheServesOnlySettledWindows: a window whose newest time is not yet
// older than CacheSettle could still receive late data, so it is neither stored
// in nor served from the result cache.
func TestCacheServesOnlySettledWindows(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("settle", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	series40(st, ps[0], "up")
	e := f.engineWith(st, testLimits(), true)

	now := model.UnixNano(f.now.Load())
	fresh := Request{Language: LanguagePromQL, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "up", Evaluation: Evaluation{Instant: true, Time: now}, Projects: ps}
	first, err := e.engine.Execute(f.ctx, scope, fresh)
	if err != nil {
		t.Fatal(err)
	}
	scans := st.scans.Load()
	second, err := e.engine.Execute(f.ctx, scope, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if first.Projects[0].Stats.Cached || second.Projects[0].Stats.Cached || st.scans.Load() == scans {
		t.Fatalf("an unsettled window was cached (first=%v second=%v new scans=%d)", first.Projects[0].Stats.Cached, second.Projects[0].Stats.Cached, st.scans.Load()-scans)
	}
	if e.cache.stores.Load() != 0 {
		t.Fatalf("an unsettled window was stored: %d stores", e.cache.stores.Load())
	}

	// The same expression a settle period behind the clock is cached.
	settled := fresh
	settled.Evaluation.Time = now - model.UnixNano(testLimits().CacheSettle) - 1
	if _, err = e.engine.Execute(f.ctx, scope, settled); err != nil {
		t.Fatal(err)
	}
	if again, err := e.engine.Execute(f.ctx, scope, settled); err != nil || !again.Projects[0].Stats.Cached {
		t.Fatalf("a settled window must be served from the cache: %v", err)
	}
	e.idle(t)
}

// TestCacheHitHonoursThisRequestsBudgets: a cached answer is only ever handed to
// a caller whose memory and returned-value budgets it fits; otherwise the
// request is recomputed under those budgets and fails with a typed Quota,
// never silently served or trimmed.
func TestCacheHitHonoursThisRequestsBudgets(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("hitbudget", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	series40(st, ps[0], "cpu")
	e := f.engineWith(st, testLimits(), true)
	warm := promReq("cpu", testEpoch+1, ps[0])
	res, err := e.engine.Execute(f.ctx, scope, warm)
	if err != nil || len(res.Projects[0].Value.Vector) != 40 {
		t.Fatalf("%v", err)
	}
	if hit, err := e.engine.Execute(f.ctx, scope, warm); err != nil || !hit.Projects[0].Stats.Cached {
		t.Fatalf("the answer must be cached before the budgets are tightened: %v", err)
	}

	memory := warm
	memory.Budget.MemoryBytes = 1
	if got, err := e.engine.Execute(f.ctx, scope, memory); code(err) != model.Quota {
		t.Fatalf("a cached payload must not be served to a 1-byte memory budget: cached=%v err=%v", got.Projects != nil && got.Projects[0].Stats.Cached, err)
	}
	tight := warm
	tight.Budget.MaxReturned = 1
	if got, err := e.engine.Execute(f.ctx, scope, tight); code(err) != model.Quota {
		n := 0
		if got.Projects != nil && got.Projects[0].Value != nil {
			n = len(got.Projects[0].Value.Vector)
		}
		t.Fatalf("a cached answer of 40 series must not be served to max_returned=1 (got %d series, err=%v)", n, err)
	}
	e.idle(t)
}

// TestLogQLResultsAreNeverCached: a LogQL template can read the wall clock, so
// its answer is not a function of the request and the data and every run
// re-reads storage, even for a long-settled window.
func TestLogQLResultsAreNeverCached(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("lognocache", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read, auth.RawRead), org, ps...)
	st := newStore()
	st.add(logRow(t, ps[0], 500, "hello world", model.Labels{{Name: "app", Value: "web"}}))
	e := f.engineWith(st, testLimits(), true)
	req := logReq(`{app="web"}`, 0, 1000, ps[0])
	if _, err := e.engine.Execute(f.ctx, scope, req); err != nil {
		t.Fatal(err)
	}
	scans := st.scans.Load()
	res, err := e.engine.Execute(f.ctx, scope, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Projects[0].Stats.Cached || st.scans.Load() == scans || e.cache.stores.Load() != 0 || e.cache.lookups.Load() != 0 {
		t.Fatalf("a LogQL result touched the cache: cached=%v new scans=%d stores=%d lookups=%d", res.Projects[0].Stats.Cached, st.scans.Load()-scans, e.cache.stores.Load(), e.cache.lookups.Load())
	}
	e.idle(t)
}

// TestCacheHitIsRefusedBehindTheMinimumReadCut: a stored answer carries the read
// cuts it was computed at; a request whose minimum cut is ahead of them gets a
// typed refusal, never the stored answer.
func TestCacheHitIsRefusedBehindTheMinimumReadCut(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("mincut", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	group := model.ID{4}
	st.marks = []model.Cursor{{Group: group, Index: 5}}
	st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1))
	e := f.engineWith(st, testLimits(), true)
	if _, err := e.engine.Execute(f.ctx, scope, promReq("up", testEpoch+1, ps[0])); err != nil {
		t.Fatal(err)
	}
	req := promReq("up", testEpoch+1, ps[0])
	req.MinCursors = []model.Cursor{{Group: group, Index: 9}}
	if res, err := e.engine.Execute(f.ctx, scope, req); err == nil {
		t.Fatalf("a cache hit behind the minimum read cut was released as %q cached=%v", res.Projects[0].Completeness, res.Projects[0].Stats.Cached)
	}
	e.idle(t)
}

// TestCachedEntryWithoutAValueIsNeverServed pins the guard the streaming wire
// form relies on: a project result with a null value is a failed or partial
// project (it round-trips through JSON as exactly that), the engine never stores
// one, and if one is ever found in the cache it is recomputed, not returned as an
// answer.
func TestCachedEntryWithoutAValueIsNeverServed(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("nullvalue", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1))
	e := f.engineWith(st, testLimits(), true)
	req := promReq("up", testEpoch+1, ps[0])

	// A project without a value, even one claiming to be complete.
	poisoned := Result{Projects: []ProjectResult{{ProjectID: ps[0], Completeness: CompletenessComplete, Diagnostics: []Diagnostic{}, Watermarks: []model.Cursor{}}}}
	raw, err := json.Marshal(poisoned)
	if err != nil {
		t.Fatal(err)
	}
	var back Result
	if err = json.Unmarshal(raw, &back); err != nil || back.Projects[0].Value != nil {
		t.Fatalf("a value-less project must round-trip as value-less: %v %+v", err, back)
	}
	prof, err := e.registry.Resolve(prom310, baseFeatureSet)
	if err != nil {
		t.Fatal(err)
	}
	_, ticket, err := e.engine.cacheLookup(f.ctx, scope, prof.Identity, req.Expression, jsonKey(queryParams{Projects: ps, Eval: req.Evaluation}))
	if err != nil || !ticket.enabled {
		t.Fatalf("no cache ticket: %v", err)
	}
	e.engine.cacheStore(f.ctx, scope, ticket, raw)
	if _, _, err = e.engine.cacheLookup(f.ctx, scope, prof.Identity, req.Expression, jsonKey(queryParams{Projects: ps, Eval: req.Evaluation})); err != nil {
		t.Fatal(err)
	}
	res, err := e.engine.Execute(f.ctx, scope, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Projects[0].Stats.Cached || res.Projects[0].Value == nil || len(res.Projects[0].Value.Vector) != 1 {
		t.Fatalf("a cached entry without a value was served: cached=%v value=%+v", res.Projects[0].Stats.Cached, res.Projects[0].Value)
	}
	e.idle(t)
}

// TestLimitsRefuseARevalidationIntervalAboveFiveSeconds: the revalidation guard
// is the bound on how long a revoked query keeps computing, so the operator
// cannot configure it beyond five seconds, and a zero interval is refused.
func TestLimitsRefuseARevalidationIntervalAboveFiveSeconds(t *testing.T) {
	for interval, ok := range map[time.Duration]bool{
		time.Nanosecond:         true,
		5 * time.Second:         true,
		5*time.Second + 1:       false,
		30 * time.Second:        false,
		0:                       false,
		-1 * time.Millisecond:   false,
		time.Hour:               false,
		5*time.Second - 1:       true,
		2 * time.Second:         true,
		10 * time.Second:        false,
		6 * time.Second:         false,
		5*time.Second + 1000000: false,
	} {
		l := DefaultLimits()
		l.RevalidateInterval = interval
		if err := l.validate(); (err == nil) != ok {
			t.Errorf("RevalidateInterval %v: accepted=%v, want %v", interval, err == nil, ok)
		}
	}
	f := newFx(t)
	bad := DefaultLimits()
	bad.RevalidateInterval = 30 * time.Second
	if _, err := New(newStore(), f.svc, testRegistry(t), bad); code(err) != model.Invalid {
		t.Fatalf("New must refuse a 30 second revalidation interval: %v", err)
	}
}

// TestUnusableCacheHitGivesItsChargeBack: a stored entry that cannot be used
// (here: a project without a value) is charged while it is examined, and that
// charge is returned before the request is recomputed, so a stale entry never
// shrinks the budget of the cold run that replaces it.
func TestUnusableCacheHitGivesItsChargeBack(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("hitrefund", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1))
	req := promReq("up", testEpoch+1, ps[0])

	plain := f.engineWith(st, testLimits(), false)
	if _, err := plain.engine.Execute(f.ctx, scope, req); err != nil {
		t.Fatal(err)
	}
	cold := plain.engine.Usage().MemoryPeak

	e := f.engineWith(st, testLimits(), true)
	pad := make([]Diagnostic, 500)
	for i := range pad {
		pad[i] = Diagnostic{Severity: "warning", Code: "padding", SafeMessage: "a padding diagnostic that makes the stored entry large"}
	}
	raw, err := json.Marshal(Result{Projects: []ProjectResult{{ProjectID: ps[0], Completeness: CompletenessComplete, Diagnostics: pad, Watermarks: []model.Cursor{}}}})
	if err != nil {
		t.Fatal(err)
	}
	prof, err := e.registry.Resolve(prom310, baseFeatureSet)
	if err != nil {
		t.Fatal(err)
	}
	params := jsonKey(queryParams{Projects: ps, Eval: req.Evaluation})
	_, ticket, err := e.engine.cacheLookup(f.ctx, scope, prof.Identity, req.Expression, params)
	if err != nil || !ticket.enabled {
		t.Fatalf("no cache ticket: %v", err)
	}
	e.engine.cacheStore(f.ctx, scope, ticket, raw)

	// Room for the hit's charge (2 x raw) alone, and for the cold run alone, but not
	// for both at once.
	req.Budget.MemoryBytes = model.Uint64(cold + int64(len(raw))/2)
	if int64(req.Budget.MemoryBytes) < 2*int64(len(raw)) {
		t.Fatalf("the fixture must let the entry be examined: budget %d, charge %d", req.Budget.MemoryBytes, 2*len(raw))
	}
	res, err := e.engine.Execute(f.ctx, scope, req)
	if err != nil {
		t.Fatalf("the cold run replaces the unusable entry within the same budget: %v", err)
	}
	if res.Projects[0].Stats.Cached || res.Projects[0].Value == nil {
		t.Fatalf("the unusable entry was served: %+v", res.Projects[0].Stats)
	}
	e.idle(t)
}
