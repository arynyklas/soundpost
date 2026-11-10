// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"soundpost/internal/control"
	"soundpost/internal/model"
	"strings"
	"testing"
)

// completeRange begins a historical-range deletion of metric rows of the fixture project (or of
// project, when given) and drives it to completion with all 64 barriers.
func (f *fenceFx) completeRange(project model.ID) model.ID {
	f.t.Helper()
	id, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), nil); err != nil {
		f.t.Fatal(err)
	}
	return id
}
func (f *fenceFx) placeHold(project model.ID) model.ID {
	f.t.Helper()
	id := model.NewID()
	hold := control.PlaceHold{Projects: []model.ID{project}, Reason: "litigation", At: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, id, control.PolicyChange{Kind: "hold_place", Hold: &hold})); err != nil {
		f.t.Fatal(err)
	}
	return id
}
func (f *fenceFx) releaseHold(hold model.ID) {
	f.t.Helper()
	rel := control.ReleaseHold{Hold: hold, Reason: "settled", At: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "hold_release", Release: &rel})); err != nil {
		f.t.Fatal(err)
	}
}

// C12: completion needs a barrier in EVERY one of the 64 slots, whether or not an off-host
// authority is required. The authority branch also answers Unavailable, so the gate is only proved
// by an operation that needs no authority.
func TestCompletionNeedsAllBarriersEvenWhenNoAuthorityIsRequired(t *testing.T) {
	f := newFenceFx(t)
	id, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, AuthorityRequired: false})
	if err != nil {
		t.Fatal(err)
	}
	all := cursors(model.DeleteSlots)
	at := model.UnixNano(f.now.UnixNano())
	if _, err = f.store.RecordBarriers(f.ctx, id, all[:model.DeleteSlots-1]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); code(err) != model.Unavailable {
		t.Fatalf("63 of 64 barriers completed an operation that needs no authority: %v", err)
	}
	// The same through the organization-administrator command a caller can issue.
	step := control.FenceStep{Step: "complete", Operation: id, At: at}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindCompleteFence, model.NewID(), step)); code(err) != model.Unavailable {
		t.Fatalf("an administrator completed a deletion with 63 of 64 barriers: %v", err)
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, id); op.Phase != model.DeletePhaseFencing {
		t.Fatalf("phase %s after refused completions", op.Phase)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, all[model.DeleteSlots-1:]); err != nil {
		t.Fatal(err)
	}
	if op, err := f.store.CompleteDeletion(f.ctx, id, at, nil); err != nil || op.Phase != model.DeletePhaseComplete {
		t.Fatalf("64 of 64 barriers refused: %+v %v", op, err)
	}
}

// C11: physical cleanup cannot be recorded for an operation a legal hold overlaps, decided in
// the same control update that would stamp it. Operations no hold overlaps in the same call
// are still recorded, and the refused ones are named.
func TestRecordPhysicalCleanupRefusesAnOperationAHoldOverlaps(t *testing.T) {
	f := newFenceFx(t)
	covered, free := f.completeRange(f.project), f.completeRange(f.otherProject)
	hold := f.placeHold(f.project) // committed after completion, before the cleanup is recorded
	at := model.UnixNano(f.now.UnixNano()) + 5
	held, err := f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{covered, free}, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0] != covered {
		t.Fatalf("refused operations %v, want only the covered one", held)
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, covered); op.PhysicalAt != 0 {
		t.Fatal("physical cleanup stamped for an operation a legal hold overlaps")
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, free); op.PhysicalAt != at {
		t.Fatal("an operation no hold overlaps was not recorded")
	}
	f.releaseHold(hold)
	held, err = f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{covered, free}, at+7)
	if err != nil || len(held) != 0 {
		t.Fatalf("after release: held %v err %v", held, err)
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, covered); op.PhysicalAt != at+7 {
		t.Fatal("cleanup not recorded after the hold was released")
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, free); op.PhysicalAt != at {
		t.Fatal("an already recorded cleanup time moved")
	}
}

// AppliedHolds is the cheap in-process read the erasing transaction uses: it follows the
// control state this node has applied, without a consensus round trip, and a refresh that finds
// nothing new returns the same snapshot.
func TestAppliedHoldsFollowPlacementAndRelease(t *testing.T) {
	f := newFenceFx(t)
	snap, err := f.store.AppliedHolds(control.HoldSnapshot{})
	if err != nil || len(snap.Holds) != 0 {
		t.Fatalf("empty state: %+v %v", snap, err)
	}
	again, err := f.store.AppliedHolds(snap)
	if err != nil || len(again.Holds) != 0 || again.Applied != snap.Applied {
		t.Fatalf("unchanged refresh: %+v %v", again, err)
	}
	hold := f.placeHold(f.project)
	placed, err := f.store.AppliedHolds(again)
	if err != nil || len(placed.Holds) != 1 || placed.Holds[0].ID != hold || placed.Applied == snap.Applied {
		t.Fatalf("placed hold not visible: %+v %v", placed, err)
	}
	f.releaseHold(hold)
	released, err := f.store.AppliedHolds(placed)
	if err != nil || len(released.Holds) != 0 {
		t.Fatalf("a released hold still blocks: %+v %v", released, err)
	}
}

func (f *fenceFx) audits(action string) []model.ControlAudit {
	f.t.Helper()
	var out []model.ControlAudit
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				out = append(out, a)
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *fenceFx) installation() model.ID {
	f.t.Helper()
	var id model.ID
	if err := f.store.View(f.ctx, func(st control.State) error { id = st.Installation; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// I6: every gap is audited (who, interval, count) and records its declarant, and the declarant is
// decided by control from the path the gap arrived on, never by the request body.
func TestEvidenceGapsAreAuditedAndRecordTheirDeclarant(t *testing.T) {
	f := newFenceFx(t)
	group := model.NewID()
	worker := model.EvidenceGap{Org: f.org, Project: f.project, Group: group, After: 3, Through: 9, Count: 6, Start: 100, End: 200, Signals: []model.Kind{model.ErrorKind}, Reason: "unprocessed_expiry", RecordedAt: model.UnixNano(f.now.UnixNano())}
	declared, err := f.store.RecordEvidenceGap(f.ctx, worker)
	if err != nil {
		t.Fatal(err)
	}
	if declared.DeclaredBy != "worker" || declared.Actor == nil || *declared.Actor != f.installation() {
		t.Fatalf("worker gap declarant %q actor %v", declared.DeclaredBy, declared.Actor)
	}
	if _, err = f.store.RecordEvidenceGap(f.ctx, worker); err != nil { // idempotent retry: no second audit
		t.Fatal(err)
	}
	audits := f.audits("evidence.gap")
	if len(audits) != 1 {
		t.Fatalf("%d audits for one worker gap (retry included)", len(audits))
	}
	a := audits[0]
	if a.Principal != f.installation() || a.Org != f.org.String() || len(a.Targets) == 0 || a.Targets[0] != declared.ID {
		t.Fatalf("audit %+v", a)
	}
	for _, want := range []string{"declared_by=worker", "after=3", "through=9", "count=6"} {
		if !strings.Contains(a.Reason, want) {
			t.Fatalf("audit reason %q lacks %q", a.Reason, want)
		}
	}

	// The same interval declared by an administrator, who also claims to be the worker, is a
	// different, admin-declared fact: it neither replaces nor impersonates the worker's.
	forged := worker
	inst := f.installation()
	forged.ID, forged.DeclaredBy, forged.Actor = model.NewID(), "worker", &inst
	res, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindRecordEvidenceGap, model.NewID(), forged))
	if err != nil {
		t.Fatal(err)
	}
	var admin model.EvidenceGap
	for _, g := range mustGaps(t, f) {
		if g.ID == res.AffectedIDs[0] {
			admin = g
		}
	}
	if admin.ID == (model.ID{}) || admin.ID == declared.ID || admin.DeclaredBy != "admin" || admin.Actor == nil || *admin.Actor == f.installation() {
		t.Fatalf("admin gap %+v (worker gap %s)", admin, declared.ID)
	}
	if got := f.audits("evidence.gap"); len(got) != 2 || got[1].Principal != *admin.Actor || !strings.Contains(got[1].Reason, "declared_by=admin") {
		t.Fatalf("admin gap audits %+v", got)
	}
}

func mustGaps(t *testing.T, f *fenceFx) []model.EvidenceGap {
	t.Helper()
	gaps, err := f.store.EvidenceGaps(f.ctx, f.org, f.project)
	if err != nil {
		t.Fatal(err)
	}
	return gaps
}

// I6: the worker enumerates what it declares: its interval holds exactly Count entries, so a
// worker gap can never swallow entries between candidates. An administrator's gap is a statement
// nothing enumerates; it may be loose and is recorded, but it is not the worker's.
func TestWorkerGapMustEnumerateEveryEntryOfItsInterval(t *testing.T) {
	f := newFenceFx(t)
	loose := model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: model.NewID(), After: 3, Through: 9, Count: 3, Start: 100, End: 200, Signals: []model.Kind{model.ErrorKind}, Reason: "unprocessed_expiry", RecordedAt: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.RecordEvidenceGap(f.ctx, loose); code(err) != model.Invalid {
		t.Fatalf("a worker gap covering 6 indexes but counting 3 was accepted: %v", err)
	}
	if got := mustGaps(t, f); len(got) != 0 {
		t.Fatalf("rejected gap recorded: %+v", got)
	}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindRecordEvidenceGap, model.NewID(), loose)); err != nil {
		t.Fatalf("an administrator's loose gap must still be recorded: %v", err)
	}
	if got := mustGaps(t, f); len(got) != 1 || got[0].DeclaredBy != "admin" {
		t.Fatalf("%+v", got)
	}
}
