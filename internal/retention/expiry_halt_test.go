// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// An expiry pass that fails closed (one source cannot answer for one candidate, so nothing of
// the pass is erased) is visible: Status().ExpiryHalt names the typed reason and the source
// that could not answer, counts the consecutive halted passes, and clears on the first expiry
// pass that completes. Before this the worker discarded the error and the only trace was a
// generic LastError no production reader consumed (review 10.09-F3 = 10.12-F1).
func TestAFailClosedExpiryPassIsVisibleAsATypedHalt(t *testing.T) {
	f := newFx(t, options{})
	candidate := storage.EraseCandidate{Org: f.org, Project: f.project, Blob: &model.BlobManifest{Org: f.org, Project: f.project, Root: model.NewID()}}
	var allowed bool
	f.plane.expired = func(ctx context.Context, _ model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		var err error
		allowed, err = g(ctx, candidate)
		return storage.EraseReport{}, err
	}
	pass := func() error {
		f.advance(2 * time.Hour)
		return f.svc.RunOnce(f.ctx)
	}
	src := &lateRefs{}
	if err := f.svc.UseReferences(src); err != nil {
		t.Fatal(err)
	}
	if err := pass(); err != nil || f.svc.Status().ExpiryHalt.Halted {
		t.Fatalf("a healthy pass reports a halt: %+v err=%v", f.svc.Status().ExpiryHalt, err)
	}
	src.set(0, model.Fail(model.Corrupt))
	if err := pass(); code(err) != model.Corrupt || allowed {
		t.Fatalf("the pass must still fail closed: allowed=%v err=%v", allowed, err)
	}
	h := f.svc.Status().ExpiryHalt
	if !h.Halted || h.Reason != string(model.Corrupt) || h.Source != "references" || h.Passes != 1 || h.Since == 0 {
		t.Fatalf("the halt is not typed: %+v", h)
	}
	if err := pass(); code(err) != model.Corrupt {
		t.Fatal(err)
	}
	if h2 := f.svc.Status().ExpiryHalt; h2.Passes != 2 || h2.Since != h.Since {
		t.Fatalf("consecutive halted passes are not counted from the first: %+v then %+v", h, h2)
	}
	src.set(0, model.Fail(model.Unavailable))
	if err := pass(); code(err) != model.Unavailable {
		t.Fatal(err)
	}
	if h3 := f.svc.Status().ExpiryHalt; h3.Reason != string(model.Unavailable) || h3.Passes != 3 {
		t.Fatalf("a changed reason is not reported: %+v", h3)
	}
	src.set(0, nil)
	if err := pass(); err != nil || !allowed {
		t.Fatalf("the pass must recover: allowed=%v err=%v", allowed, err)
	}
	if h4 := f.svc.Status().ExpiryHalt; h4.Halted || h4.Passes != 0 {
		t.Fatalf("the halt did not clear: %+v", h4)
	}
}
