// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	"testing"
)

// holdOverProject places a legal hold over the fixture project and fails the test if it cannot.
func (f *fx) holdOverProject() model.ID {
	f.t.Helper()
	id, err := f.svc.PlaceHold(f.ctx, f.adminScope(), retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), ProjectIDs: []model.ID{f.project}, Reason: "litigation"})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// C11: a legal hold makes physical-erasure SUCCESS impossible. A hold that commits after the
// physical pass built its guard but before the erasing transaction must stop the erasure: the
// guard is a durable-state check at erase time, not a snapshot taken once per pass.
func TestHoldPlacedDuringAPhysicalPassStopsTheErasure(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	var hold model.ID
	var first *storage.EraseReport
	f.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		if hold == (model.ID{}) { // the guard was already built from a hold-free state
			hold = f.holdOverProject()
		}
		report, err := f.engine.EraseDeleted(ctx, preds, g)
		if first == nil {
			first = &report
		}
		return report, err
	}
	f.run()
	if first == nil {
		t.Fatal("the physical pass never ran")
	}
	if first.Records != 0 || first.Blobs != 0 || first.Held == 0 {
		t.Fatalf("a hold that committed before the erasing transaction lost its bytes: %+v", *first)
	}
	if got := f.poll(receipt.OperationID); got.Physical != retention.PhysicalHeld {
		t.Fatalf("physical-erasure success reported while a hold overlaps: %+v", got)
	}
	if st := f.svc.Status(); st.ErasedRecords != 0 || st.HeldByLegal == 0 {
		t.Fatalf("worker status after a vetoed erasure: %+v", st)
	}
	// The bytes were still there: releasing the hold lets the next pass erase them.
	if err = f.svc.ReleaseHold(f.ctx, f.adminScope(), model.NewID(), f.revision(), hold, "settled"); err != nil {
		t.Fatal(err)
	}
	f.plane.erased = nil
	f.run()
	if got := f.poll(receipt.OperationID); got.Physical != retention.PhysicalDone {
		t.Fatalf("release followed by erasure: %+v", got)
	}
	if st := f.svc.Status(); st.ErasedRecords != 1 {
		t.Fatalf("the released erasure did not remove the held record: %+v", st)
	}
}

// The window is not only between building the guard and starting the pass: the candidate scan
// itself runs before the erasing transaction. A hold that commits right after the scan allowed
// the record (the guard is asked, answers yes, and the hold lands before the transaction) must
// still win: the erasing transaction asks again, against current state.
func TestHoldPlacedBetweenTheScanAndTheErasingTransactionStopsTheErasure(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	var hold model.ID
	var first *storage.EraseReport
	f.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		report, err := f.engine.EraseDeleted(ctx, preds, func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
			allow, err := g(ctx, c)
			if allow && !c.Final && hold == (model.ID{}) {
				hold = f.holdOverProject() // lands after the scan said yes, before the transaction
			}
			return allow, err
		})
		if first == nil {
			first = &report
		}
		return report, err
	}
	f.run()
	if first == nil || hold == (model.ID{}) {
		t.Fatal("the scan never allowed the record, so the hold was never placed after it")
	}
	if first.Records != 0 || first.Blobs != 0 || first.Held == 0 {
		t.Fatalf("a hold committed between the scan and the erasing transaction lost its bytes: %+v", *first)
	}
	if got := f.poll(receipt.OperationID); got.Physical != retention.PhysicalHeld {
		t.Fatalf("physical-erasure success reported while a hold overlaps: %+v", got)
	}
}

// A hold that commits after the bytes were erased but before the cleanup is recorded cannot be
// honoured retroactively, and must not be hidden: the cleanup is NOT recorded (the receipt says
// held, never done), and the status counts what was erased before the hold committed. Once the
// hold is released the cleanup records.
func TestHoldPlacedAfterErasureBlocksThePhysicalDoneRecord(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	var hold model.ID
	f.plane.trace = func(step string) error { // first post-erasure maintenance step
		if step == "checkpoint" && hold == (model.ID{}) {
			hold = f.holdOverProject()
		}
		return nil
	}
	f.run()
	if hold == (model.ID{}) {
		t.Fatal("the post-erasure step never ran")
	}
	got := f.poll(receipt.OperationID)
	if got.Physical == retention.PhysicalDone {
		t.Fatalf("physical:done reported while a legal hold overlaps the operation: %+v", got)
	}
	if got.Physical != retention.PhysicalHeld {
		t.Fatalf("receipt does not say a hold blocks the cleanup: %+v", got)
	}
	if st := f.svc.Status(); st.ErasedBeforeHold != 1 {
		t.Fatalf("bytes erased before the hold committed are not reported: %+v", st)
	}
	if err = f.svc.ReleaseHold(f.ctx, f.adminScope(), model.NewID(), f.revision(), hold, "settled"); err != nil {
		t.Fatal(err)
	}
	f.run()
	if done := f.poll(receipt.OperationID); done.Physical != retention.PhysicalDone {
		t.Fatalf("cleanup never recorded after the hold was released: %+v", done)
	}
}
