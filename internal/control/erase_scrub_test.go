// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// A failed deletion erases the covered control payloads (it keeps its predicate
// active) and owes the control.db scrub, but its physical step is never recorded
// (the data groups never erased it). The scrub must still be reachable and, once
// it ran, the residual must clear: nothing may stay owed forever for a scrub that
// cannot be run. (01.08 review CD-3.)
func TestFailedDeletionScrubIsReachableAndClearsItsResidual(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYFAILSCRUB7c41e90d2b86"
	for range 12 {
		f.seedAll(f.newSeed(f.project, gone), 50)
	}
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if _, err := f.store.FailDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}
	if f.stateHolds(gone) {
		t.Fatal("fixture: the failed deletion left the payload in the state")
	}
	if len(controlDBHits(t, f.dir, gone)) == 0 {
		t.Fatal("fixture: bbolt kept no copy of the replaced state in control.db")
	}
	if !contains(f.store.ResidualStores(), control.ResidualControlState) {
		t.Fatalf("a failed erasing deletion does not name control.db as owed: %v", f.store.ResidualStores())
	}
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, f.dir, gone); len(hits) != 0 {
		t.Fatalf("control.db still holds the erased payloads after the scrub: %v", hits)
	}
	if got := f.store.ResidualStores(); len(got) != 1 || got[0] != control.ResidualControlJournal {
		t.Fatalf("after the scrub only the journal residue is owed, got %v", got)
	}
	// Nothing is owed any more, so a second scrub is a no-op and stays clean.
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.store.ResidualStores(); len(got) != 1 || got[0] != control.ResidualControlJournal {
		t.Fatalf("residual stores after a second scrub: %v", got)
	}
	// The failed operation never claims a physical step it did not take.
	if op, _, _ := f.store.DeletionOperation(f.ctx, id); op.PhysicalAt != 0 || op.Phase != model.DeletePhaseFailed {
		t.Fatalf("the scrub rewrote the failed operation: %+v", op)
	}
}

// An erasure committed after a scrub owes a new one: a scrub clears what it
// covered, never what a later transition erased.
func TestScrubClearsOnlyTheErasuresItCovered(t *testing.T) {
	f := newEraseFx(t)
	f.seedAll(f.newSeed(f.project, "CANARYONE7c41e90d2b86a0f"), 50)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if contains(f.store.ResidualStores(), control.ResidualControlState) {
		t.Fatalf("setup: control.db still owed after the physical step: %v", f.store.ResidualStores())
	}
	f.seedAll(f.newSeed(f.otherProject, "CANARYTWO7c41e90d2b86a0f"), 50)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.otherProject}})
	if contains(f.store.ResidualStores(), control.ResidualControlState) {
		t.Fatalf("the second deletion's scrub did not clear its own residual: %v", f.store.ResidualStores())
	}
	// Erase again without scrubbing: a late effect of a range deletion.
	g := newEraseFx(t)
	g.saga(g.lateRange())
	g.commitRule(g.newSeed(g.project, "CANARYTHREE7c41e90d2b86a"), 60, model.Metric)
	if !contains(g.store.ResidualStores(), control.ResidualControlState) {
		t.Fatalf("a late erasure after the physical step owes nothing: %v", g.store.ResidualStores())
	}
}

// A backup cut between begin and completion restores the operation fencing: the
// restore authority's re-import finds it and applies nothing, and the payloads
// that came back with the restored state (or committed since) are erased when the
// resumed operation completes. (01.08 review CD-12.)
func TestRestoredFencingDeletionErasesRestoredPayloadsAtCompletion(t *testing.T) {
	f := newEraseFx(t)
	id := f.begin(f.lateRange())
	const restored = "CANARYRESTORED7c41e90d2b86"
	f.commitRule(f.newSeed(f.project, restored), 60, model.Metric)
	f.commitCondition(f.newSeed(f.project, restored), 60)
	op, found, err := f.store.DeletionOperation(f.ctx, id)
	if err != nil || !found {
		t.Fatalf("operation: %v %v", found, err)
	}
	if err = f.store.ImportDeletions(f.ctx, []model.DeletePredicate{op.Predicate}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := f.store.DeletionOperation(f.ctx, id); after.Phase != model.DeletePhaseFencing {
		t.Fatalf("the import changed an operation the restored state already has: %+v", after)
	}
	if !f.stateHolds(restored) {
		t.Fatal("fixture: the restored payload is not in the state")
	}
	f.complete(id)
	if f.stateHolds(restored) || f.snapshotHolds(restored) {
		t.Fatal("completing the restored operation left the restored payloads")
	}
	if _, err = f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, f.dir, restored); len(hits) != 0 {
		t.Fatalf("the restored payloads are still in %v", hits)
	}
}
