// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// A command whose evidence lands inside a range a completed deletion already erased commits (the
// control version moves) and the deletion's late pass erases the state it produced in the same
// transition. The service must not answer that as an applied change with the payload it submitted:
// the payload is gone, and the caller has to be able to tell that from success and from corruption
// (09.08x-W3). The typed answer is model.NotFound with the SafeDetail "condition_erased", the same
// shape an action on an erased incident has.

// completeRange runs a historical range deletion of the given signals through begin, barriers and
// completion, the way the saga does (sfx.completedRange fixes the signal to metrics).
func completeRange(n *node, signals []model.Kind, start, end model.UnixNano) {
	n.t.Helper()
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{n.project}, Signals: signals,
		Start: start, End: end, At: 10 * sec, Reason: "fixture", PhysicalDeadline: 11 * sec, BackupDeadline: 12 * sec})
	if err != nil {
		n.t.Fatal(err)
	}
	op := model.NewID()
	if _, err = n.app.Control.Transact(n.ctx, n.orgScope(), control.Command{CommandID: op, ExpectedRevision: n.revision(), Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		n.t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = n.app.Control.RecordBarriers(n.ctx, op, barriers); err != nil {
		n.t.Fatal(err)
	}
	if _, err = n.app.Control.CompleteDeletion(n.ctx, op, 10*sec, nil); err != nil {
		n.t.Fatal(err)
	}
}

func isErasedFault(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.NotFound && f.SafeDetail == "condition_erased"
}

func TestEventInsideACompletedRangeIsReportedErasedNotApplied(t *testing.T) {
	f := newSfx(t)
	f.completedRange(50*sec, 150*sec)
	erasing := f.audits("delete.control_erased")

	got, err := f.apply(event(epoch1, 1, int64(100*sec), "firing"))
	if !isErasedFault(err) {
		t.Fatalf("an event inside an erased range answered %+v, %v; want not_found/condition_erased", got, err)
	}
	if recs := f.conditionRecords(); len(recs) != 1 || recs[0].Version != 1 || !recs[0].Erased() {
		t.Fatalf("the command did not commit as a tombstone at version 1: %+v", recs)
	}
	if n := f.audits("delete.control_erased"); n != erasing+1 {
		t.Fatalf("%d erasing audits for the commit, want exactly one", n-erasing)
	}
	// It is not storage damage and not a refusal of the event: the condition reads as erased.
	st, found, gerr := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if gerr != nil || !found || !st.Erased || st.Version != 1 {
		t.Fatalf("the condition reads as %+v found=%v err=%v", st, found, gerr)
	}
}

// A consumed rule output whose condition state the deletion erases as it commits is finalized (a
// retry could only rebuild the same tombstone, and each rebuild would add an erasing audit) and
// reported as Erased, never as Applied.
func TestConsumedOutputWhoseStateIsErasedAtOnceIsReportedErased(t *testing.T) {
	f := newRuleFx(t)
	f.evaluate(65, f.lease)
	pending := f.outputs(control.RulePhasePending)
	if len(pending) != 1 {
		t.Fatalf("pending outputs: %+v", pending)
	}
	// The deletion names logs only: the metric output is not obsolete, but an opaque condition
	// state is erased by the window rule whatever the signal list says (retention.md, CD-9).
	completeRange(f.node, []model.Kind{model.Log}, 0, 100*sec)
	if got := f.outputs(control.RulePhasePending); len(got) != 1 || got[0].Obsolete {
		t.Fatalf("fixture: the output must stay consumable: %+v", got)
	}
	erasing := f.audits("delete.control_erased")

	rep := f.consume(f.lease)
	if len(rep.Applied) != 0 || len(rep.Erased) != 1 || rep.Erased[0] != pending[0].ID {
		t.Fatalf("report %+v, want the output erased and not applied", rep)
	}
	if left := f.outputs(control.RulePhasePending); len(left) != 0 {
		t.Fatalf("the erased output stayed pending and would be retried forever: %+v", left)
	}
	if done := f.outputs(control.RulePhaseFinalized); len(done) != 1 || done[0].ID != pending[0].ID {
		t.Fatalf("the erased output was not finalized: %+v", done)
	}
	if recs := f.conditionRecords(); len(recs) != 1 || !recs[0].Erased() {
		t.Fatalf("condition records: %+v", recs)
	}
	if n := f.audits("delete.control_erased"); n != erasing+1 {
		t.Fatalf("%d erasing audits for the commit, want exactly one", n-erasing)
	}
	again := f.consume(f.lease)
	if len(again.Applied)+len(again.Erased)+len(again.Suppressed) != 0 || f.audits("delete.control_erased") != erasing+1 {
		t.Fatalf("a second consume churned: %+v", again)
	}
}
