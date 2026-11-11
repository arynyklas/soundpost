// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
)

// An incident whose state a deletion erased is not storage damage: the queue
// leaves it out instead of failing for the whole project, and a read of it is a
// not-found. A live incident beside it is unaffected. (09.06 review C-1.)
func TestErasedIncidentIsNotCorruptInTheQueueOrGet(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("erased org", p1)
	alice := e.user(org, "alice-erased@example.test")
	e.admin(org, alice)
	erased, _, _ := e.open(org, p1, incidents.SeverityMajor)

	// Erase it with a real completed range deletion that ends before the next one opens.
	scope, err := e.app.Auth.Authorize(e.ctx, alice.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	orgScope, err := e.app.Auth.Authorize(e.ctx, alice.Cred, org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	now := model.UnixNano(time.Now().UnixNano())
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{p1}, Signals: []model.Kind{model.Metric},
		Start: now - model.UnixNano(time.Hour), End: now, At: now, Reason: "fixture", PhysicalDeadline: now + 1, BackupDeadline: now + 2})
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = e.app.Control.View(e.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	op := model.NewID()
	if _, err = e.app.Control.Transact(e.ctx, orgScope, control.Command{CommandID: op, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = e.app.Control.RecordBarriers(e.ctx, op, barriers); err != nil {
		t.Fatal(err)
	}
	if _, err = e.app.Control.CompleteDeletion(e.ctx, op, now, nil); err != nil {
		t.Fatal(err)
	}
	live, _, _ := e.open(org, p1, incidents.SeverityCritical) // evidence after the range's end

	if rec, found, err := e.app.Control.Incident(e.ctx, scope, p1, erased); err != nil || !found || !rec.Erased() {
		t.Fatalf("fixture: the first incident is not erased: %+v found=%v err=%v", rec, found, err)
	}
	view, err := e.actions.Queue(e.ctx, scope, httpapi.QueueRequest{Projects: []model.ID{p1}, Limit: 10})
	if err != nil {
		t.Fatalf("an erased incident failed the queue: %v", err)
	}
	if len(view.Entries) != 1 || view.Entries[0].ID != live {
		t.Fatalf("the queue must list only the live incident: %+v", view.Entries)
	}
	_, err = e.actions.GetIncident(e.ctx, scope, p1, erased)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.NotFound || fault.SafeDetail != incidents.DetailErased {
		t.Fatalf("a read of an erased incident: %v, want not_found/%s", err, incidents.DetailErased)
	}
	if got, err := e.actions.GetIncident(e.ctx, scope, p1, live); err != nil || got.ID != live {
		t.Fatalf("the live incident: %+v %v", got, err)
	}
}
