// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// The erasure runs in the transition that begins the deletion, not at its
// completion: the moment a deletion is fencing, its covered payloads are gone,
// and its unsent deliveries stay paused (not settled) until it completes.
func TestBeginningADeletionErasesBeforeItCompletes(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYBEGIN7c41e90d2b86a"
	s := f.newSeed(f.project, gone)
	s.note = true
	output, delivery := f.seedAll(s, 50)
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if op, _, _ := f.store.DeletionOperation(f.ctx, id); op.Phase != model.DeletePhaseFencing {
		t.Fatalf("fixture: the deletion is %s, want fencing", op.Phase)
	}
	if f.stateHolds(gone) {
		t.Fatal("a fencing deletion left covered payloads in the control state")
	}
	if o := f.output(s, output); o.Phase != control.RulePhasePending || !o.Obsolete || !dropped(o.Payload) {
		t.Errorf("the unreleased output must be obsolete and payload-free after the beginning transition: %+v", o)
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		var d control.DeliveryRecord
		if err := json.Unmarshal(st.DeliveryBooks["delivery:"+delivery.String()], &d); err != nil || !dropped(d.Body) || d.Phase != control.DeliveryPending {
			t.Errorf("a fencing deletion drops the body and leaves the delivery paused, not settled: %+v %v", d, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// An effect that commits between the beginning and the completion of a range
// deletion (nothing stops a rule evaluation of the project meanwhile) is erased
// when the deletion completes.
func TestCompletionErasesWhatCommittedWhileFencing(t *testing.T) {
	f := newEraseFx(t)
	const late = "CANARYLATEWINDOW7c41e90d2"
	id := f.begin(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})
	s := f.newSeed(f.project, late)
	f.commitRule(s, 60, model.Metric)
	f.commitCondition(s, 60)
	if !f.stateHolds(late) {
		t.Fatal("fixture: the late effect is not in the control state")
	}
	f.complete(id)
	if f.stateHolds(late) {
		t.Fatal("completing the deletion left a payload that committed while it was fencing")
	}
}

// A state that names no evidence time (or whose time cannot be read) cannot be
// attributed to a range: it is dropped whole, never kept.
func TestRangeErasesStatesItCannotAttribute(t *testing.T) {
	f := newEraseFx(t)
	const bare, unreadable, dated = "CANARYBARE7c41e90d2b86a", "CANARYUNREAD51f0aa93c7d", "CANARYDATED9c7de151f0aa"
	incident := func(s eraseSeed, extra string) {
		t.Helper()
		state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","evidence":%q%s}`, s.inc.String(), f.org.String(), s.project.String(), s.canary, extra))
		c := control.IncidentCommand{Project: s.project, Incident: s.inc, Action: "open", Origin: "human", Actor: f.user, At: 100, NewVersion: 1, State: state, Digest: digest(state)}
		if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindIncidentAction, model.NewID(), c)); err != nil {
			t.Fatal(err)
		}
	}
	incident(f.newSeed(f.project, bare), "")
	incident(f.newSeed(f.project, unreadable), `,"at":{"nested":true}`)
	incident(f.newSeed(f.project, dated), `,"at":"5"`) // before the range: attributed, kept
	f.saga(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})
	if f.stateHolds(bare) || f.stateHolds(unreadable) {
		t.Fatal("a state that cannot be attributed to the range was kept")
	}
	if !f.stateHolds(dated) {
		t.Fatal("a state attributed to a time before the range was erased")
	}
}
