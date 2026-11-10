// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// An effect that commits AFTER a deletion completed (a worker that read its
// telemetry before the barrier and applies afterwards, which the barrier saga
// allows) must not leave telemetry-derived payload of the erased range behind:
// the erasure of the committed deletions that cover the affected project runs
// inside the effect-commit transition itself, so the payload never reaches the
// control state, the control snapshot or control.db. (01.08 review CD-1.)

// sagaOf drives one deletion through every control step a worker takes, for any
// fixture built on fenceFx.
func sagaOf(f *fenceFx, req control.DeleteScope) model.ID {
	f.t.Helper()
	id, _, err := f.del(req)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		f.t.Fatal(err)
	}
	at := model.UnixNano(f.now.UnixNano())
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, at); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *eraseFx) lateRange() control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}
}

// lateCase commits one effect of a writer for the seed at the given evidence
// time (the time the writer would be attributed to a range by).
type lateCase struct {
	name   string
	commit func(f *eraseFx, s eraseSeed, at int64)
}

var lateCases = []lateCase{
	{"rule evaluation", func(f *eraseFx, s eraseSeed, at int64) { f.commitRule(s, uint64(at), model.Metric) }},
	{"incident action", func(f *eraseFx, s eraseSeed, at int64) { f.commitIncident(s, at) }},
	{"condition", func(f *eraseFx, s eraseSeed, at int64) { f.commitCondition(s, at) }},
	{"delivery enqueue", func(f *eraseFx, s eraseSeed, at int64) {
		f.commitDelivery(s, model.UnixNano(at), model.UnixNano(at+10))
	}},
}

func TestEffectCommittedAfterCompletionIsErasedInTheSameApply(t *testing.T) {
	for _, c := range lateCases {
		t.Run(c.name, func(t *testing.T) {
			f := newEraseFx(t)
			// One in-range payload before the deletion, so the operation erased
			// something and its normal post-erasure accounting exists.
			f.commitRule(f.newSeed(f.project, "CANARYBEFORE7c41e90d2b86a"), 60, model.Metric)
			id := f.saga(f.lateRange())
			if op, _, _ := f.store.DeletionOperation(f.ctx, id); op.Phase != model.DeletePhaseComplete || op.PhysicalAt == 0 {
				t.Fatalf("fixture: the deletion is %+v, want complete and physically recorded", op)
			}

			const late, outside = "CANARYLATEc7de151f0aa93b86a", "CANARYOUTSIDE51f0aa93c7de1"
			c.commit(f, f.newSeed(f.project, late), 60)    // inside [40,100): covered
			c.commit(f, f.newSeed(f.project, outside), 10) // before the range: not covered (an opaque state past End would be covered, see retention.md)

			if f.stateHolds(late) {
				t.Fatal("an effect that committed after the deletion completed left its covered payload in the control state")
			}
			if f.snapshotHolds(late) {
				t.Fatal("the covered payload is in the control snapshot")
			}
			if !f.stateHolds(outside) {
				t.Fatal("the late effect outside the range was erased: nothing but the covered scope may go")
			}
			// What was erased in the apply is owed a scrub of control.db until
			// the scrub has run; afterwards only the journal residue is named.
			if !contains(f.store.ResidualStores(), control.ResidualControlState) {
				t.Fatalf("a late erasure is not named as owing the control.db scrub: %v", f.store.ResidualStores())
			}
			if err := f.store.ScrubErased(f.ctx); err != nil {
				t.Fatal(err)
			}
			if hits := controlDBHits(t, f.dir, late); len(hits) != 0 {
				t.Fatalf("the covered payload is in %v", hits)
			}
			if got := f.store.ResidualStores(); len(got) != 1 || got[0] != control.ResidualControlJournal {
				t.Fatalf("residual stores after the scrub: %v, want only %s", got, control.ResidualControlJournal)
			}
		})
	}
}

// A deletion that failed keeps its predicate active, so a late effect inside it
// is erased too.
func TestEffectCommittedAfterAFailedDeletionIsErased(t *testing.T) {
	f := newEraseFx(t)
	id := f.begin(f.lateRange())
	if _, err := f.store.FailDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}
	const late = "CANARYFAILEDLATE7c41e90d2b"
	f.commitRule(f.newSeed(f.project, late), 60, model.Metric)
	f.commitIncident(f.newSeed(f.project, late), 60)
	if f.stateHolds(late) {
		t.Fatal("an effect that committed after a failed deletion left its covered payload behind")
	}
}

// A deletion that is still fencing erases a late effect at its completion (the
// existing window rule), not at the effect: the barrier saga relies on it.
func TestEffectCommittedWhileFencingIsLeftForCompletion(t *testing.T) {
	f := newEraseFx(t)
	id := f.begin(f.lateRange())
	const late = "CANARYFENCING7c41e90d2b86"
	f.commitRule(f.newSeed(f.project, late), 60, model.Metric)
	if !f.stateHolds(late) {
		t.Fatal("a fencing deletion erased at the effect: completion owns that")
	}
	f.complete(id)
	if f.stateHolds(late) {
		t.Fatal("completion left the payload that committed while fencing")
	}
}

// An effect of another project than the deletion's is not touched.
func TestLateEffectOfAnotherProjectIsKept(t *testing.T) {
	f := newEraseFx(t)
	f.saga(f.lateRange())
	const other = "CANARYOTHERPROJECT7c41e90d"
	f.commitRule(f.newSeed(f.otherProject, other), 60, model.Metric)
	if !f.stateHolds(other) {
		t.Fatal("a deletion of one project erased a late effect of another")
	}
}

func TestIssueEvidenceCommittedAfterCompletionIsErased(t *testing.T) {
	f := newIssEraseFx(t)
	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req) // [50,300) of the error signal
	covered, outside := newMarker(7, 1), newMarker(7, 2)
	f.must(control.IssueCommand{
		Records: []control.IssueRecordChange{
			{Issue: f.issue(1, 1, f.ev(1, covered, 100, 1)), Explanations: json.RawMessage("[" + explanation(covered.occurrence, 100) + "]")},
			{Issue: f.issue(2, 1, f.ev(2, outside, 1000, 2)), Explanations: json.RawMessage("[" + explanation(outside.occurrence, 1000) + "]")},
		},
		Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 3},
	})
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range covered.all() {
		f.gone(c)
	}
	for _, c := range outside.all() {
		f.kept(c)
	}
}

func TestJobUpdateCommittedAfterCompletionIsErased(t *testing.T) {
	f := newJobFx(t)
	sagaOf(f.fenceFx, control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})
	const late = "CANARYJOBLATE7c41e90d2b86a"
	u := f.upd(f.job(1), 0, 1)
	u.State = f.state(f.job(1), 1, map[string]any{"latest_schedule_key": late})
	f.must(1, u)
	if bytes.Contains(mustJSON(t, f.books()), []byte(late)) {
		t.Fatal("a job update that committed after the deletion completed left its state in the control books")
	}
	if snap, ok := f.book(f.job(1)); !ok || !snap.Erased || snap.Version != 1 {
		t.Fatalf("the job must stay as an erased record at its committed version: %+v %v", snap, ok)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
