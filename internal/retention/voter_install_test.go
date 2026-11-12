// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// A snapshot install can put erased rows back into a voter's live buckets, and the storage layer
// then clears that voter's erase marker (and withdraws its acknowledgement). The control record
// still says the physical cleanup is done, so the voter's worker must select the operation on the
// missing marker alone, erase again, mark again and acknowledge again.
func TestWorkerErasesAgainWhenAnInstallClearedTheVotersMarker(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	if done := f.poll(receipt.OperationID); done.Physical != retention.PhysicalDone {
		t.Fatalf("setup: %+v", done)
	}
	var erasedCalls int
	f.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		erasedCalls++
		return f.plane.Engine.EraseDeleted(ctx, preds, g)
	}
	voter := &voterHook{marked: map[model.ID]bool{}, residual: []string{storage.ResidualApplyDB}}
	voterHooks.Store(f.plane, voter)
	t.Cleanup(func() { voterHooks.Delete(f.plane) })
	op := receipt.OperationID

	if err = f.svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	voter.mu.Lock()
	marked, acks := voter.marked[op], voter.acks
	voter.mu.Unlock()
	if erasedCalls != 1 || !marked || acks == 0 {
		t.Fatalf("setup: the first pass erased %d times, marked %v, acknowledged %d times", erasedCalls, marked, acks)
	}
	if err = f.svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if erasedCalls != 1 {
		t.Fatalf("a marked operation was erased again with no install: %d calls", erasedCalls)
	}

	// The install: the storage layer deletes the marker.
	voter.mu.Lock()
	delete(voter.marked, op)
	before := voter.acks
	voter.mu.Unlock()
	if err = f.svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	voter.mu.Lock()
	defer voter.mu.Unlock()
	if erasedCalls != 2 {
		t.Fatalf("the voter lost its marker (an install put rows back) and its worker did not erase again: %d calls", erasedCalls)
	}
	if !voter.marked[op] {
		t.Fatal("the voter did not mark the operation again after erasing again")
	}
	if voter.acks <= before {
		t.Fatalf("the voter did not acknowledge again after erasing again: %d acknowledgements, %d before", voter.acks, before)
	}
}
