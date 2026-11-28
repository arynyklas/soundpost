// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// saturatedEngine is an engine whose only scheduler slot is held by a query
// parked inside a scan, after every cacheable response was warmed.
type saturatedEngine struct {
	*env
	org    model.ID
	ps     []model.ID
	alice  person
	reader auth.Scope
	window TimeRange
	hold   <-chan error
	gate   chan struct{}
	once   sync.Once
}

func newSaturated(t *testing.T, queue int, wait time.Duration) *saturatedEngine {
	t.Helper()
	f := newFx(t)
	org, ps := f.newOrg("admission", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	s := &saturatedEngine{org: org, ps: ps, alice: alice, reader: f.scope(alice, org, ps...),
		window: TimeRange{Start: model.UnixNano(testEpoch), End: model.UnixNano(testEpoch + 100)}}
	st := newStore()
	st.add(exemplarRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1, model.NewID()))
	l := testLimits()
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg, l.MaxQueueWait = 1, 1, 1, queue, wait
	s.env = f.engineWith(st, l, true)
	// Warm every cacheable surface, and prove each second call is a hit.
	if _, err := s.engine.Execute(f.ctx, s.reader, s.query()); err != nil {
		t.Fatal(err)
	}
	if res, err := s.engine.Execute(f.ctx, s.reader, s.query()); err != nil || !res.Projects[0].Stats.Cached {
		t.Fatalf("the query must be warm: cached=%v err=%v", err == nil && res.Projects[0].Stats.Cached, err)
	}
	if _, err := s.engine.Discover(f.ctx, s.reader, s.discovery()); err != nil {
		t.Fatal(err)
	}
	if res, err := s.engine.Discover(f.ctx, s.reader, s.discovery()); err != nil || !res.Freshness.Cached {
		t.Fatalf("discovery must be warm: %v", err)
	}
	if _, err := s.engine.Exemplars(f.ctx, s.reader, s.exemplars()); err != nil {
		t.Fatal(err)
	}
	if res, err := s.engine.Exemplars(f.ctx, s.reader, s.exemplars()); err != nil || !res.Freshness.Cached {
		t.Fatalf("exemplars must be warm: %v", err)
	}
	s.hold, s.gate = holdScan(t, st, s.engine, s.reader, promReq("up + 1", testEpoch+10, ps[0]))
	// holdScan returns once any scan ever started, which the warm-up already did.
	for deadline := time.Now().Add(5 * time.Second); s.engine.Usage().ActiveQueries != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the parked query must hold the only slot: %+v", s.engine.Usage())
		}
	}
	t.Cleanup(s.release)
	return s
}

func (s *saturatedEngine) query() Request { return promReq("up", testEpoch+10, s.ps[0]) }
func (s *saturatedEngine) discovery() DiscoveryRequest {
	return DiscoveryRequest{Projects: s.ps, Signal: model.Metric, Kind: DiscoverMetricNames, Time: s.window, Limit: 10}
}
func (s *saturatedEngine) exemplars() ExemplarRequest {
	return ExemplarRequest{Projects: s.ps, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "up", Window: s.window, Limit: 10}
}
func (s *saturatedEngine) format() FormatRequest {
	return FormatRequest{Language: LanguagePromQL, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "sum(rate(x[5m])) by (job)"}
}

// surfaces runs every cache-served or non-scanning service call as scope.
func (s *saturatedEngine) surfaces(scope auth.Scope) map[string]func() error {
	ctx := s.ctx
	return map[string]func() error{
		"cold query": func() error {
			_, err := s.engine.Execute(ctx, scope, promReq("up + 2", testEpoch+10, s.ps[0]))
			return err
		},
		"query cache hit": func() error { _, err := s.engine.Execute(ctx, scope, s.query()); return err },
		"discovery hit":   func() error { _, err := s.engine.Discover(ctx, scope, s.discovery()); return err },
		"exemplars hit":   func() error { _, err := s.engine.Exemplars(ctx, scope, s.exemplars()); return err },
		"format":          func() error { _, err := s.engine.Format(ctx, scope, s.format()); return err },
	}
}

func (s *saturatedEngine) release() {
	s.once.Do(func() {
		close(s.gate)
		<-s.hold
		s.store.mu.Lock()
		s.store.scanGate = nil
		s.store.mu.Unlock()
	})
}

// TestCacheHitsAndFormatAreAdmittedLikeColdQueries: a response served from the
// result cache and a Format call do real work for the caller, so a saturated
// engine must refuse them with the same typed Quota or Timeout fault as a cold
// query, never serve them for free.
func TestCacheHitsAndFormatAreAdmittedLikeColdQueries(t *testing.T) {
	for name, tc := range map[string]struct {
		queue int
		wait  time.Duration
		want  model.Code
	}{
		"full queue":   {queue: 0, wait: 2 * time.Second, want: model.Quota},
		"queue expiry": {queue: 4, wait: 60 * time.Millisecond, want: model.Timeout},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSaturated(t, tc.queue, tc.wait)
			for surface, call := range s.surfaces(s.reader) {
				if err := call(); code(err) != tc.want {
					t.Errorf("%s on a saturated engine: want %s, got %v", surface, tc.want, err)
				}
			}
			s.release()
			for surface, call := range s.surfaces(s.reader) {
				if surface == "cold query" {
					continue
				}
				if err := call(); err != nil {
					t.Errorf("%s once the slot is free: %v", surface, err)
				}
			}
			s.idle(t)
		})
	}
}

// TestDeniedCallersAreRefusedBeforeAdmission: on a saturated engine a caller
// whose scope does not hold gets the same typed denial it would get on an idle
// one, and learns nothing about load, cache state or existence.
func TestDeniedCallersAreRefusedBeforeAdmission(t *testing.T) {
	s := newSaturated(t, 0, 2*time.Second)
	bob := s.user(s.org, "bob@example.test", s.ps, auth.Read)
	bobScope := s.fx.scope(bob, s.org, s.ps...)
	s.revoke(s.org, bob, s.ps[0], auth.Read)
	otherOrg, otherProjects := s.newOrg("outsider", 1)
	carol := s.user(otherOrg, "carol@example.test", otherProjects, auth.Read)
	carolScope := s.fx.scope(carol, otherOrg, otherProjects...)

	for who, scope := range map[string]auth.Scope{"revoked member": bobScope, "foreign organization": carolScope} {
		for surface, call := range s.surfaces(scope) {
			if surface == "format" && who == "foreign organization" {
				continue // formatting names no project: any valid reader may format
			}
			err := call()
			if code(err) != model.NotFound {
				t.Errorf("%s / %s on a saturated engine must be the indistinguishable denial, got %v", who, surface, err)
			}
		}
	}
	// The foreign caller names the other organization's project directly: the
	// refusal is the one a nonexistent project gets, not a load signal.
	ghost := model.NewID()
	_, errGhost := s.engine.Execute(s.ctx, carolScope, promReq("up", testEpoch+10, ghost))
	_, errForeign := s.engine.Execute(s.ctx, carolScope, promReq("up", testEpoch+10, s.ps[0]))
	if code(errGhost) != model.NotFound || code(errForeign) != code(errGhost) || errForeign.Error() != errGhost.Error() {
		t.Fatalf("wrong-scope and missing must stay indistinguishable under load: %v vs %v", errForeign, errGhost)
	}
}

// TestCacheHitIsChargedForItsPayload: serving a cached response holds at least
// the serialized size in the process-wide account while it is decoded, and gives
// every byte back.
func TestCacheHitIsChargedForItsPayload(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("hitcharge", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	for i := range 60 {
		st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api" + string(rune('a'+i%26)) + string(rune('a'+i/26))}}, testEpoch, 1))
	}
	cold := f.engineWith(st, testLimits(), true)
	res, err := cold.engine.Execute(f.ctx, scope, promReq("up", testEpoch+10, ps[0]))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	// A second engine that shares only the warmed cache starts with an empty pool,
	// so its peak is exactly what serving the hit held.
	other, err := New(st, f.svc, cold.registry, testLimits(), WithDeleteGenerations(f.deletes), WithResultCache(cold.cache), WithTickets(cold.cache),
		WithClock(func() time.Time { return time.Unix(0, f.now.Load()) }))
	if err != nil {
		t.Fatal(err)
	}
	hit, err := other.Execute(f.ctx, scope, promReq("up", testEpoch+10, ps[0]))
	if err != nil || !hit.Projects[0].Stats.Cached {
		t.Fatalf("the second engine must serve a hit: cached=%v err=%v", err == nil && hit.Projects[0].Stats.Cached, err)
	}
	u := other.Usage()
	if u.MemoryPeak < int64(len(raw)) {
		t.Fatalf("a hit must be charged at least its serialized size %d, peak was %d", len(raw), u.MemoryPeak)
	}
	if u.MemoryUsed != 0 || u.LeakedBytes != 0 || u.OverReleasedBytes != 0 || u.ActiveQueries != 0 {
		t.Fatalf("a hit must release everything it charged: %+v", u)
	}
}

// formatBomb is the largest nesting the expression limit allows.
func formatBomb() string { return strings.Repeat("(", 16000) + "up" + strings.Repeat(")", 16000) }

// TestFormatIsChargedAndBoundedByTheAccount: Format parses, checks, prints,
// re-parses and compares trees of an expression of up to 32 KiB, so it holds
// accounted memory under its own deadline, is refused with a typed Quota when the
// account cannot hold it, and releases every byte on every path.
func TestFormatIsChargedAndBoundedByTheAccount(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("formatcharge", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	expr := formatBomb()
	one := 2 * planCharge(expr)
	l := testLimits()
	l.DefaultMemory, l.MaxMemory, l.GlobalMemory = one, one, one
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg = 4, 4, 4, 64
	e := f.engineWith(newStore(), l, false)
	req := FormatRequest{Language: LanguagePromQL, Profile: prom310, FeatureSet: baseFeatureSet, Expression: expr}

	// Deterministic: leave the process-wide account less than one plan's worth.
	if err := e.engine.pool.reserve(one - planCharge(expr)/2); err != nil {
		t.Fatal(err)
	}
	if res, err := e.engine.Format(f.ctx, scope, req); code(err) != model.Quota {
		t.Fatalf("Format must be charged and refused with Quota when the account is exhausted, got %v (%d bytes)", err, len(res.Formatted))
	}
	e.engine.pool.release(one - planCharge(expr)/2)
	e.idle(t)

	// 32 parallel requests: bounded concurrency, bounded bytes, nothing left behind.
	before := runtime.NumGoroutine()
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		maxLive  int
		stopPoll = make(chan struct{})
		pollDone = make(chan struct{})
	)
	go func() {
		defer close(pollDone)
		for {
			select {
			case <-stopPoll:
				return
			default:
			}
			if a := e.engine.Usage().ActiveQueries; a > maxLive {
				mu.Lock()
				maxLive = a
				mu.Unlock()
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()
	errs := make([]error, 32)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.engine.Format(f.ctx, scope, req)
		}()
	}
	wg.Wait()
	close(stopPoll)
	<-pollDone
	for i, err := range errs {
		switch code(err) {
		case model.Quota, model.Timeout, "":
			if code(err) == "" && err != nil && !isLanguageError(err) {
				t.Errorf("request %d: untyped failure %v", i, err)
			}
		default:
			t.Errorf("request %d: unexpected fault %v", i, err)
		}
	}
	u := e.engine.Usage()
	if u.MemoryPeak < planCharge(expr) {
		t.Errorf("Format never charged the account (peak %d, plan %d)", u.MemoryPeak, planCharge(expr))
	}
	if u.MemoryPeak > one {
		t.Errorf("parallel Format exceeded the account: peak %d > cap %d", u.MemoryPeak, one)
	}
	if maxLive > l.MaxConcurrent {
		t.Errorf("more Format calls ran at once (%d) than the scheduler admits (%d)", maxLive, l.MaxConcurrent)
	}
	e.idle(t)
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines grew from %d to %d after the burst", before, after)
	}
}

func isLanguageError(err error) bool {
	var language *syntax.LanguageError
	return errors.As(err, &language)
}

// TestDiscoveryAndExemplarHitsAreChargedForTheirPayload: like a query response, a
// discovery or exemplar page served from the cache is charged to the account at
// least at its serialized size and released afterwards.
func TestDiscoveryAndExemplarHitsAreChargedForTheirPayload(t *testing.T) {
	d := newDiscovery(t, true)
	for i := range 30 {
		d.store.add(exemplarRow(d.project, "http_total", model.Labels{{Name: "route", Value: fmt.Sprint("r", i)}}, testEpoch+int64(i), float64(i), model.NewID()))
	}
	discover := DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverMetricNames, Time: d.window, Limit: 10}
	exemplars := ExemplarRequest{Projects: []model.ID{d.project}, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "http_total", Window: d.window, Limit: 20}
	coldDiscovery, err := d.engine.Discover(d.ctx, d.scope, discover)
	if err != nil {
		t.Fatal(err)
	}
	coldExemplars, err := d.engine.Exemplars(d.ctx, d.scope, exemplars)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cold any
		base int64 // charged before the cache is consulted (the exemplar expression's tree)
		run  func(*Engine) (bool, error)
	}{
		"discovery": {coldDiscovery, 0, func(e *Engine) (bool, error) {
			res, err := e.Discover(d.ctx, d.scope, discover)
			return res.Freshness.Cached, err
		}},
		"exemplars": {coldExemplars, planCharge(exemplars.Expression), func(e *Engine) (bool, error) {
			res, err := e.Exemplars(d.ctx, d.scope, exemplars)
			return res.Freshness.Cached, err
		}},
	} {
		raw, err := json.Marshal(tc.cold)
		if err != nil {
			t.Fatal(err)
		}
		// A second engine sharing only the warmed cache starts with an empty pool.
		other, err := New(d.store, d.svc, d.registry, testLimits(), WithDeleteGenerations(d.deletes), WithResultCache(d.cache), WithTickets(d.cache),
			WithClock(func() time.Time { return time.Unix(0, d.now.Load()) }))
		if err != nil {
			t.Fatal(err)
		}
		if cached, err := tc.run(other); err != nil || !cached {
			t.Fatalf("%s: the second engine must serve a hit: cached=%v err=%v", name, cached, err)
		}
		u := other.Usage()
		if u.MemoryPeak < tc.base+int64(len(raw)) {
			t.Errorf("%s: a hit must be charged at least its serialized size %d on top of %d, peak was %d", name, len(raw), tc.base, u.MemoryPeak)
		}
		if u.MemoryUsed != 0 || u.LeakedBytes != 0 || u.OverReleasedBytes != 0 || u.ActiveQueries != 0 {
			t.Errorf("%s: a hit must release everything it charged: %+v", name, u)
		}
	}
}
