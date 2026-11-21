// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// countingStore counts the linearizable control reads an auth.Service makes.
type countingStore struct {
	*control.Store
	views *atomic.Int64
}

func (c countingStore) View(ctx context.Context, fn func(model.ControlState) error) error {
	c.views.Add(1)
	return c.Store.View(ctx, fn)
}

// countingGenerations counts the DeleteGeneration calls a cache binding makes of the retention service
// (each one is further control reads); the state-derived path is promoted from the service untouched.
type countingGenerations struct {
	*retention.Service
	calls *atomic.Int64
}

func (c countingGenerations) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	c.calls.Add(1)
	return c.Service.DeleteGeneration(ctx, org, projects)
}

// One cached read binds a scope to the delete generation with ONE control read (01.08-W5, I4): the
// revalidation and the generation (the source-lifecycle base plus the per-org deletion counter) come
// from the same snapshot, where they used to cost an authentication read, a revalidation read, a base
// read and a counter read. The generation it binds is the one DeleteGeneration reports, and it moves
// with a deletion exactly as before.
func TestCacheBindingReadsTheControlStateOnceAndBindsTheSameGeneration(t *testing.T) {
	f := newFx(t, options{})
	var views, calls atomic.Int64
	svc, err := auth.NewService(auth.AuthDependencies{Control: countingStore{f.store, &views}, Now: func() time.Time { return f.at() }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := svc.Authorize(f.ctx, cred, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := auth.NewCache(svc, countingGenerations{f.svc, &calls}, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func() auth.CacheResult {
		t.Helper()
		views.Store(0)
		calls.Store(0)
		r, err := cache.Lookup(f.ctx, scope, "profile", "query", "params")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	miss := lookup()
	if v, c := views.Load(), calls.Load(); v != 1 || c != 0 {
		t.Fatalf("a cache binding made %d scope reads and %d DeleteGeneration calls, want 1 and 0", v, c)
	}
	if err = cache.Store(f.ctx, scope, miss.Fill, []byte("v"), false); err != nil {
		t.Fatal(err)
	}
	if hit := lookup(); !hit.Hit {
		t.Fatal("the stored entry is not found under the generation the binding derived")
	}
	// The derived generation is DeleteGeneration's: a deletion moves it and kills the warm entry.
	if _, _, err = f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	before, err := f.svc.DeleteGeneration(f.ctx, f.org, []model.ID{f.project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	}); err != nil {
		t.Fatal(err)
	}
	after, err := f.svc.DeleteGeneration(f.ctx, f.org, []model.ID{f.project})
	if err != nil || after <= before {
		t.Fatalf("a deletion did not advance the generation: %d -> %d (%v)", before, after, err)
	}
	if r := lookup(); r.Hit {
		t.Fatal("a cache entry bound to the generation before the deletion survived it")
	}
	var derived uint64
	var ok bool
	if err = f.store.View(f.ctx, func(st control.State) (err error) {
		derived, ok, err = f.svc.DeleteGenerationFromState(st, f.org, []model.ID{f.project})
		return err
	}); err != nil || !ok || derived != after {
		t.Fatalf("the generation derived from a state is %d (derived=%v, %v), DeleteGeneration says %d", derived, ok, err, after)
	}
}
