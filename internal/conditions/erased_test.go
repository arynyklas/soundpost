// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

// A deletion that covers a condition's evidence replaces its state by a
// tombstone. That is not storage damage: the service reads it as erased, the
// rule consumer is not wedged by it, and the next evidence starts a new history
// on the preserved version. A condition that a completed range deletion does not
// cover is never touched by the deletion's late re-erasure. (09.06 review C-1.)

// completedRange runs a historical range deletion of one metric window of the
// project through begin, barriers and completion, the way the saga does.
func (f *sfx) completedRange(start, end model.UnixNano) {
	f.t.Helper()
	scope := f.orgScope()
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric},
		Start: start, End: end, At: 10 * sec, Reason: "fixture", PhysicalDeadline: 11 * sec, BackupDeadline: 12 * sec})
	if err != nil {
		f.t.Fatal(err)
	}
	op := model.NewID()
	if _, err = f.app.Control.Transact(f.ctx, scope, control.Command{CommandID: op, ExpectedRevision: f.revision(), Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		f.t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = f.app.Control.RecordBarriers(f.ctx, op, barriers); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.app.Control.CompleteDeletion(f.ctx, op, 10*sec, nil); err != nil {
		f.t.Fatal(err)
	}
}

// A condition whose evidence is after a completed range deletion's end keeps its
// state through the transition that commits it and the ones after it, with no
// erasing audit.
func TestConditionOfDataAfterACompletedRangeDeletionSurvives(t *testing.T) {
	f := newSfx(t)
	f.completedRange(10*sec, 20*sec)
	erasing := f.audits("delete.control_erased")

	first := f.mustApply(event(epoch2, 1, int64(2000*sec), "firing"))
	if first.Erased || first.Version != 1 || len(first.Recent) != 1 || first.Phase == "" {
		t.Fatalf("the committed condition lost its state: %+v", first)
	}
	next := f.mustApply(event(epoch2, 2, int64(2001*sec), "recovered"))
	if !next.Recovered() || next.Version != 2 || next.Erased {
		t.Fatalf("the condition cannot move on: %+v", next)
	}
	got, found, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if err != nil || !found || got.Erased || got.Version != 2 || len(got.Recent) != 2 {
		t.Fatalf("the condition reads back as %+v found=%v err=%v", got, found, err)
	}
	if n := f.audits("delete.control_erased"); n != erasing {
		t.Fatalf("%d spurious erasing audit(s) for commits that erased nothing", n-erasing)
	}
}

// An erased condition reads as erased, not corrupt; listing and the rule
// consumer keep working; the next event starts a new history on the version the
// record kept.
func TestErasedConditionReadsAsErasedAndTheNextEventRebuildsIt(t *testing.T) {
	f := newSfx(t)
	f.mustApply(event(epoch1, 1, int64(100*sec), "firing"))
	f.completedRange(50*sec, 150*sec)

	got, found, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if err != nil || !found || !got.Erased || got.Condition != cond || got.Version != 1 || len(got.Recent) != 0 {
		t.Fatalf("the erased condition reads as %+v found=%v err=%v", got, found, err)
	}
	list, err := f.svc.List(f.ctx, f.scope(auth.Read))
	if err != nil || len(list) != 1 || !list[0].Erased {
		t.Fatalf("listing with an erased condition: %+v %v", list, err)
	}
	if _, err = f.svc.Consume(f.ctx, f.scope(auth.OrgAdmin), f.lease(), 10); err != nil {
		t.Fatalf("an erased condition wedged the rule consumer: %v", err)
	}

	rebuilt := f.mustApply(event(epoch2, 5, int64(3000*sec), "firing"))
	if rebuilt.Erased || rebuilt.Version != 2 || rebuilt.Phase != "firing" || len(rebuilt.Recent) != 1 || rebuilt.Sequence != 5 {
		t.Fatalf("the next event did not rebuild the condition on its kept version: %+v", rebuilt)
	}
	if rec := f.conditionRecords(); len(rec) != 1 || rec[0].Version != 2 || rec[0].Erased() {
		t.Fatalf("committed record %+v", rec)
	}
}

// staticCondition answers every condition read with one stored record.
type staticCondition struct {
	*control.Store
	rec control.ConditionRecord
}

func (s staticCondition) Condition(context.Context, auth.Scope, model.ID, model.ID) (control.ConditionRecord, bool, error) {
	return s.rec, true, nil
}

// A record that is neither a live state nor a tombstone of that record is
// storage damage, and still reads as corrupt.
func TestMalformedConditionRecordStillReadsAsCorrupt(t *testing.T) {
	f := newSfx(t)
	tomb := func(id, project model.ID, version string) json.RawMessage {
		return json.RawMessage(`{"condition_id":"` + id.String() + `","org_id":"` + f.org.String() + `","project_id":"` + project.String() + `","version":"` + version + `","erased":"` + model.ID{0xdd}.String() + `"}`)
	}
	live := json.RawMessage(`{"condition_id":"` + cond.String() + `","org_id":"` + f.org.String() + `","project_id":"` + f.project.String() + `","version":"1","recent":[]}`)
	for name, rec := range map[string]control.ConditionRecord{
		"live state without history":   {Org: f.org, Project: f.project, ID: cond, Version: 1, State: live},
		"not json":                     {Org: f.org, Project: f.project, ID: cond, Version: 1, State: json.RawMessage(`{`)},
		"tombstone of another cond":    {Org: f.org, Project: f.project, ID: cond, Version: 1, State: tomb(model.ID{0xc9}, f.project, "1")},
		"tombstone at another version": {Org: f.org, Project: f.project, ID: cond, Version: 2, State: tomb(cond, f.project, "1")},
		"tombstone of another project": {Org: f.org, Project: f.project, ID: cond, Version: 1, State: tomb(cond, model.ID{0x55}, "1")},
	} {
		svc, err := conditions.New(staticCondition{Store: f.app.Control, rec: rec}, f.app.Control.ReplicaGroup(), rules.NewOutboxStore(f.app.Control), f.clock)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = svc.Get(f.ctx, f.scope(auth.Read), cond); code(err) != model.Corrupt {
			t.Errorf("%s: Get = %v, want corrupt", name, err)
		}
	}
}
