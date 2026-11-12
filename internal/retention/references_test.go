// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/storage"
)

type lateRefs struct {
	mu    sync.Mutex
	until model.UnixNano
	err   error
	calls int
}

func (r *lateRefs) LatestReference(context.Context, storage.EraseCandidate) (model.UnixNano, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.until, r.err
}
func (r *lateRefs) set(until model.UnixNano, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.until, r.err = until, err
}
func (r *lateRefs) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// UseReferences binds the reference source once, after New (the application builds
// the service before the object that answers it can exist). The expiry pass then
// consults it for every candidate; a second binding is a Conflict and changes
// nothing; a source error vetoes the erasure and fails the pass.
func TestUseReferencesBindsOnceAndExpiryConsultsIt(t *testing.T) {
	f := newFx(t, options{})
	candidate := storage.EraseCandidate{Org: f.org, Project: f.project, Blob: &model.BlobManifest{Org: f.org, Project: f.project, Root: model.NewID()}}
	var allowed bool
	f.plane.expired = func(ctx context.Context, _ model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		var err error
		allowed, err = g(ctx, candidate)
		return storage.EraseReport{}, err
	}
	pass := func() error {
		f.advance(2 * time.Hour) // the expiry interval has elapsed
		return f.svc.RunOnce(f.ctx)
	}

	// Unbound: an artifact root is never erased, because nothing can prove it is fenced.
	if err := pass(); err != nil || allowed || f.svc.Status().UnfencedBlobs != 1 {
		t.Fatalf("an unbound service erased (or did not report) an artifact root: allowed=%v unfenced=%d err=%v", allowed, f.svc.Status().UnfencedBlobs, err)
	}
	if code(f.svc.UseReferences(nil)) != model.Invalid {
		t.Fatal("a nil source was accepted")
	}
	first := &lateRefs{}
	first.set(model.UnixNano(f.at().Add(3*time.Hour).UnixNano()), nil)
	if err := f.svc.UseReferences(first); err != nil {
		t.Fatal(err)
	}
	if err := pass(); err != nil || allowed || first.count() == 0 {
		t.Fatalf("a reference live past now must hold the candidate: allowed=%v consulted=%d err=%v", allowed, first.count(), err)
	}

	second := &lateRefs{}
	if code(f.svc.UseReferences(second)) != model.Conflict || code(f.svc.UseReferences(first)) != model.Conflict {
		t.Fatal("a second binding was accepted")
	}
	first.set(model.UnixNano(f.at().Add(5*time.Hour).UnixNano()), nil) // still ahead after the pass's own 2h
	if err := pass(); err != nil || allowed || second.count() != 0 {
		t.Fatalf("the refused source replaced the first (allowed=%v, refused source consulted %d times): %v", allowed, second.count(), err)
	}

	first.set(0, model.Fail(model.Corrupt))
	err := pass()
	if code(err) != model.Corrupt || allowed {
		t.Fatalf("a source that cannot answer must fail the pass and veto: allowed=%v err=%v", allowed, err)
	}
	if f.svc.Status().LastError != string(model.Corrupt) {
		t.Fatalf("the refusal is not reported: %q", f.svc.Status().LastError)
	}

	first.set(0, nil)
	if err = pass(); err != nil || !allowed {
		t.Fatalf("an unreferenced candidate must be released: allowed=%v err=%v", allowed, err)
	}
}

// With no References source a record candidate (a metric, an error) expires as always: the
// refusal is about artifact roots only, and it is not a pass failure.
func TestUnboundRetentionStillExpiresRecords(t *testing.T) {
	f := newFx(t, options{})
	record := storage.EraseCandidate{Org: f.org, Project: f.project, Kind: model.Metric, Record: &model.Record{ID: model.NewID(), Kind: model.Metric}}
	var allowed bool
	f.plane.expired = func(ctx context.Context, _ model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		var err error
		allowed, err = g(ctx, record)
		return storage.EraseReport{}, err
	}
	f.advance(2 * time.Hour)
	if err := f.svc.RunOnce(f.ctx); err != nil || !allowed || f.svc.Status().UnfencedBlobs != 0 {
		t.Fatalf("allowed=%v unfenced=%d err=%v", allowed, f.svc.Status().UnfencedBlobs, err)
	}
}
