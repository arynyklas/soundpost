// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"testing"
)

// An erasure pass that still owes the scrub of bbolt free pages has not physically erased the
// bytes: apply.db can still hold them. The receipt must say physical cleanup is pending until a
// pass finishes the scrub, never "done" on the strength of a pass that could not.
func TestPhysicalCleanupIsNeverDoneWhileAScrubIsOwed(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	owed := true
	f.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		report, err := f.engine.EraseDeleted(ctx, preds, g)
		report.ScrubPending = owed
		return report, err
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	pending := f.poll(receipt.OperationID)
	if pending.Phase != model.DeletePhaseComplete || pending.Physical != retention.PhysicalPending {
		t.Fatalf("a pass that still owes its scrub was reported as physically done: %+v", pending)
	}
	if n, _ := f.rows(); n != 0 {
		t.Fatal("rows of a logically complete deletion are readable while physical cleanup is pending")
	}
	if !f.svc.Status().ScrubPending {
		t.Fatal("the worker status does not say a scrub is owed")
	}
	owed = false
	f.run()
	if f.svc.Status().ScrubPending {
		t.Fatal("the worker status still says a scrub is owed")
	}
	if done := f.poll(receipt.OperationID); done.Physical != retention.PhysicalDone {
		t.Fatalf("physical cleanup never completed after the scrub finished: %+v", done)
	}
}

// The copies of deleted bytes in snapshots and the journal are cleaned by a fixed sequence after
// the erasure: advance every group's applied index (so the cut is new, not a no-op), cut and
// verify a snapshot, drop the superseded ones, compact the journal onto the new snapshot. The
// receipt may say physical cleanup is done only after ALL of it succeeded, in that order: a crash
// or failure in between leaves it pending and the next pass retries.
func TestPhysicalCleanupIsRecordedOnlyAfterSnapshotsAndJournalAreCleaned(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	var order []string
	failCompact := true
	f.plane.trace = func(step string) error {
		order = append(order, step)
		if step == "compact" && failCompact {
			failCompact = false
			return model.Fail(model.Unavailable)
		}
		return nil
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.RunOnce(f.ctx); err == nil {
		t.Fatal("a failed journal compaction was not reported")
	}
	if got := f.poll(receipt.OperationID); got.Physical != retention.PhysicalPending {
		t.Fatalf("physical cleanup was recorded although the journal was not cleaned: %+v", got)
	}
	order = nil
	f.run()
	want := []string{"checkpoint", "snapshot", "drop", "compact"}
	if len(order) < len(want) || order[0] != "checkpoint" || order[len(order)-1] != "compact" {
		t.Fatalf("maintenance order %v, want %v (snapshots between)", order, want)
	}
	drop, snap := -1, -1
	for i, s := range order {
		switch s {
		case "snapshot":
			snap = i
		case "drop":
			drop = i
		}
	}
	if snap < 0 || drop < snap {
		t.Fatalf("superseded snapshots dropped before the new one was cut: %v", order)
	}
	if got := f.poll(receipt.OperationID); got.Physical != retention.PhysicalDone {
		t.Fatalf("physical cleanup never completed: %+v", got)
	}
}

// A "done" receipt names a store only while it can still hold a copy of the deleted bytes. The
// cleanup redacts the replication layer's retry table and journal and replaces the snapshots, so
// after a completed cleanup the engine measures nothing and the receipt declares nothing; it says
// nothing of the kind before the cleanup is done, when the bytes are simply still everywhere. What
// the engine does declare is what the receipt shows.
func TestDoneReceiptDeclaresOnlyWhatTheEngineMeasuresAsStillHoldingDeletedBytes(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Residual) != 0 {
		t.Fatalf("a deletion that has only begun cannot declare residual stores: %+v", receipt)
	}
	f.run()
	done := f.poll(receipt.OperationID)
	if done.Physical != retention.PhysicalDone {
		t.Fatalf("setup: %+v", done)
	}
	if len(done.Residual) != 0 {
		t.Fatalf("a completed cleanup left the receipt declaring residual stores: %+v", done)
	}
	if got := f.engine.ResidualStores(); len(got) != 0 {
		t.Fatalf("the engine still measures copies after a completed cleanup: %v", got)
	}
	f.plane.residual = func() []string { return []string{"raft_journal"} }
	if again := f.poll(receipt.OperationID); len(again.Residual) != 1 || again.Residual[0] != "raft_journal" {
		t.Fatalf("the receipt does not show what the engine declares: %+v", again)
	}
}
