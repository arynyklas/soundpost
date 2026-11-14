// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// A deletion that covers an incident's evidence replaces its state by a
// tombstone. That is not storage damage: the service reads it as erased, an
// action on it is a not-found, and an incident that a completed range deletion
// does not cover is never touched by the deletion's late re-erasure. (09.06
// review C-1.)

// completedRange runs a historical range deletion of one metric window of the
// project through begin, barriers and completion, the way the saga does.
func (f *fx) completedRange(start, end model.UnixNano) model.ID {
	f.t.Helper()
	if err := f.store.BindRetention(); err != nil {
		f.t.Fatal(err)
	}
	var revision model.Revision
	if err := f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		f.t.Fatal(err)
	}
	now := model.UnixNano(f.now.UnixNano())
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric},
		Start: start, End: end, At: now, Reason: "fixture", PhysicalDeadline: now + 1, BackupDeadline: now + 2})
	if err != nil {
		f.t.Fatal(err)
	}
	op := model.NewID()
	if _, err = f.store.Transact(f.ctx, f.scope(f.a), control.Command{CommandID: op, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		f.t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = f.store.RecordBarriers(f.ctx, op, barriers); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, op, now, nil); err != nil {
		f.t.Fatal(err)
	}
	return op
}

func (f *fx) erasingAudits() int {
	f.t.Helper()
	n := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "delete.control_erased" {
				n++
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// An incident opened AFTER a completed range deletion's end, from evidence the
// deletion did not cover, survives, reads back and can be acknowledged and
// resolved; the late pass adds no erasing audit.
func TestIncidentOpenedAfterACompletedRangeDeletionSurvivesAndCanBeActedOn(t *testing.T) {
	f := newFx(t)
	now := model.UnixNano(f.now.UnixNano())
	f.completedRange(now-model.UnixNano(24*time.Hour), now-model.UnixNano(23*time.Hour))
	erasing := f.erasingAudits()

	id := model.ID{0x77}
	opened, err := f.act(f.a, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: f.target(id),
		Impact: impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)})
	if err != nil {
		t.Fatalf("opening an incident after a completed range deletion: %v", err)
	}
	if opened.Erased || len(opened.Timeline) != 1 {
		t.Fatalf("the committed incident lost its state: %+v", opened)
	}
	got := f.get(id)
	if got.Erased || got.Version != 1 || len(got.Timeline) != 1 || got.Status != incidents.StatusOpen {
		t.Fatalf("the incident reads back as %+v", got)
	}
	f.mustAct(f.a, f.human(f.a, id, 1, incidents.TypeAck, ""))
	if st := f.mustAct(f.a, f.human(f.a, id, 2, incidents.TypeResolve, "fixed")); st.Status != incidents.StatusResolved || st.Version != 3 {
		t.Fatalf("the incident cannot be resolved: %+v", st)
	}
	if n := f.erasingAudits(); n != erasing {
		t.Fatalf("%d spurious erasing audit(s) for commits that erased nothing", n-erasing)
	}
}

// An incident whose evidence the deletion covers reads as erased, never as
// corrupt, and no action on it commits.
func TestErasedIncidentReadsAsErasedNotCorrupt(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x78}
	f.openIncident(id)
	now := model.UnixNano(f.now.UnixNano())
	f.completedRange(now-model.UnixNano(time.Hour), now+model.UnixNano(time.Hour))

	got, err := f.svc.Get(f.ctx, f.scope(f.a), f.project, id)
	if err != nil {
		t.Fatalf("an erased incident reads as an error: %v", err)
	}
	if !got.Erased || got.ID != id || got.Org != f.org || got.Project != f.project || got.Version != 1 || len(got.Timeline) != 0 {
		t.Fatalf("the erased incident reads as %+v", got)
	}
	revision := f.record(id).Version
	for name, a := range map[string]incidents.Action{
		"ack":   f.human(f.a, id, revision, incidents.TypeAck, ""),
		"open":  {CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: f.target(id), Impact: impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)},
		"worse": f.worse(id, revision),
	} {
		_, err := f.act(f.a, a)
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.NotFound || fault.SafeDetail != incidents.DetailErased {
			t.Errorf("%s on an erased incident: %v, want not_found/%s", name, err, incidents.DetailErased)
		}
	}
	if after := f.record(id); after.Version != revision || !after.Erased() {
		t.Fatalf("a refused action changed the record: %+v", after)
	}
}

// staticControl answers every read with one stored record.
type staticControl struct {
	*control.Store
	rec control.IncidentRecord
}

func (s staticControl) Incident(context.Context, auth.Scope, model.ID, model.ID) (control.IncidentRecord, bool, error) {
	return s.rec, true, nil
}

// A record that is neither a live state nor a tombstone of that record is
// storage damage, and still reads as corrupt.
func TestMalformedIncidentRecordStillReadsAsCorrupt(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x79}
	tomb := func(header string) json.RawMessage {
		return json.RawMessage(`{"incident_id":"` + header + `","org_id":"` + f.org.String() + `","project_id":"` + f.project.String() + `","version":"1","erased":"` + model.ID{0xdd}.String() + `"}`)
	}
	for name, rec := range map[string]control.IncidentRecord{
		"timeline does not match the version": {Org: f.org, Project: f.project, ID: id, Version: 2, State: json.RawMessage(`{"incident_id":"` + id.String() + `","version":"2","timeline":[]}`)},
		"not json":                            {Org: f.org, Project: f.project, ID: id, Version: 1, State: json.RawMessage(`{`)},
		"tombstone of another incident":       {Org: f.org, Project: f.project, ID: id, Version: 1, State: tomb(model.ID{0x7a}.String())},
		"tombstone at another version":        {Org: f.org, Project: f.project, ID: id, Version: 2, State: tomb(id.String())},
	} {
		svc, err := incidents.New(staticControl{Store: f.store, rec: rec}, fixedClock{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.Get(f.ctx, f.scope(f.a), f.project, id); !isCode(err, model.Corrupt) {
			t.Errorf("%s: Get = %v, want corrupt", name, err)
		}
	}
}

func isCode(err error, code model.Code) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == code
}

// An incident whose evidence is INSIDE a completed range, committed after the
// deletion completed (a worker that read it before the barrier), is erased as it
// commits: the action reports it as erased (not found, not corrupt), and the
// record reads as erased at the version it committed.
func TestIncidentCommittedInsideACompletedRangeIsErasedAndActAnswersNotFound(t *testing.T) {
	f := newFx(t)
	now := model.UnixNano(f.now.UnixNano())
	f.completedRange(now-model.UnixNano(time.Hour), now+model.UnixNano(time.Hour))
	id := model.ID{0x7b}
	_, err := f.act(f.a, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: f.target(id),
		Impact: impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)})
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.NotFound || fault.SafeDetail != incidents.DetailErased {
		t.Fatalf("opening an incident whose evidence the range covers: %v, want not_found/%s", err, incidents.DetailErased)
	}
	if rec := f.record(id); rec.Version != 1 || !rec.Erased() {
		t.Fatalf("the committed record must be the tombstone at its version: %+v", rec)
	}
	if got := f.get(id); !got.Erased || got.Version != 1 {
		t.Fatalf("the incident reads as %+v", got)
	}
}
