// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// voterHook turns a fixture's plane into the data plane of a voter that did NOT run the erasure
// itself: the control state already says physical done (another voter recorded it), but this
// voter has no local marker, and the group has not acknowledged the operation yet. Planes
// without a hook behave exactly as the real engine does (the methods below delegate).
type voterHook struct {
	mu       sync.Mutex
	marked   map[model.ID]bool
	acks     int
	residual []string
}

var voterHooks sync.Map // *plane -> *voterHook

func hookOf(p *plane) *voterHook {
	if h, ok := voterHooks.Load(p); ok {
		return h.(*voterHook)
	}
	return nil
}

func (p *plane) ErasedLocally(op model.ID) bool {
	if h := hookOf(p); h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.marked[op]
	}
	return p.Engine.ErasedLocally(op)
}
func (p *plane) MarkErased(ops []model.ID) error {
	if h := hookOf(p); h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, op := range ops {
			h.marked[op] = true
		}
		return nil
	}
	return p.Engine.MarkErased(ops)
}
func (p *plane) AckErasure(ctx context.Context) error {
	if h := hookOf(p); h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.acks++
		return nil
	}
	return p.Engine.AckErasure(ctx)
}
func (p *plane) ErasureResidual(op model.ID) []string {
	if h := hookOf(p); h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.residual
	}
	return p.Engine.ErasureResidual(op)
}

// PhysicalAt is a cluster-wide fact: once another voter recorded it, this voter's worker must
// still erase from its own stores (it has no marker), mark it, and acknowledge; and its receipt
// names the data store until the group acknowledged.
func TestWorkerErasesOnAVoterThatDidNotRunTheErasureEvenWhenPhysicalIsRecorded(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	f.run() // this is "the voter that ran the saga": fence, complete, erase, record physical
	if done := f.poll(receipt.OperationID); done.Physical != retention.PhysicalDone {
		t.Fatalf("setup: %+v", done)
	}
	var erasedCalls int
	f.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		erasedCalls++
		return f.plane.Engine.EraseDeleted(ctx, preds, g)
	}
	other := &voterHook{marked: map[model.ID]bool{}, residual: []string{storage.ResidualApplyDB}}
	voterHooks.Store(f.plane, other)
	t.Cleanup(func() { voterHooks.Delete(f.plane) })
	svc := f.svc
	if err = svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if erasedCalls == 0 || !other.marked[receipt.OperationID] {
		t.Fatalf("a voter with no local marker did not erase (calls=%d marked=%v)", erasedCalls, other.marked)
	}
	if other.acks == 0 {
		t.Fatal("the voter did not acknowledge its erasure")
	}
	// Marked: the next pass does not erase it again.
	before := erasedCalls
	if err = svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if erasedCalls != before {
		t.Fatalf("a marked operation was erased again: %d -> %d", before, erasedCalls)
	}
	// The receipt keeps naming the data store until the group acknowledged.
	got, err := svc.PollDelete(f.ctx, f.adminScope(), receipt.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Physical != retention.PhysicalDone || !reflect.DeepEqual(got.Residual, []string{storage.ResidualApplyDB}) {
		t.Fatalf("receipt must name the data store until every voter acknowledged: %+v", got)
	}
	other.mu.Lock()
	other.residual = nil
	other.mu.Unlock()
	if got, err = svc.PollDelete(f.ctx, f.adminScope(), receipt.OperationID); err != nil || len(got.Residual) != 0 {
		t.Fatalf("after every acknowledgement: %+v %v", got, err)
	}
}
