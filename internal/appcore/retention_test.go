// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// Open hands the retention service the composite residual plane, so a receipt
// names what the control store still owes (its Raft journal cannot yet be
// redacted) and not only what the storage engine measures. Without it a
// "physical: done" receipt of an empty deletion lists no residual store at all.
func TestOpenReportsControlResidualsInDeletionReceipts(t *testing.T) {
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "retention@example.test", "retention wiring password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "retention wiring"
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "retention wiring"})
	command("create_project", auth.AdminPayload{ID: project, Name: "retention wiring"})
	admin := func() auth.Scope {
		t.Helper()
		scope, err := app.Auth.Authorize(ctx, actor, org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		return scope
	}
	// Seed one incident book (the shape the incident writer commits) whose state
	// carries telemetry-derived text, so the deletion erases control payload and the
	// control store owes a residual copy. A deletion that erases nothing owes none.
	incident := model.NewID()
	state := json.RawMessage(`{"incident_id":"` + incident.String() + `","org_id":"` + org.String() + `","project_id":"` + project.String() + `","version":"1","evidence":"CANARYWIRING7c41e90d","at":"5"}`)
	record, err := json.Marshal(control.IncidentRecord{Org: org, Project: project, ID: incident, Version: 1, Digest: model.Hash{7}, State: state})
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Control.Update(ctx, func(st *control.State) error {
		if st.IncidentBooks == nil {
			st.IncidentBooks = map[string]json.RawMessage{}
		}
		st.IncidentBooks[org.String()+":"+project.String()+":"+incident.String()] = record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	receipt, err := app.Retention.Delete(ctx, admin(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireProject, OrgID: org, ProjectIDs: []model.ID{project}, Reason: "retention wiring"})
	if err != nil {
		t.Fatal(err)
	}
	var done retention.DeleteReceipt
	for range 20 {
		if err = app.Retention.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if done, err = app.Retention.PollDelete(ctx, admin(), receipt.OperationID); err != nil {
			t.Fatal(err)
		}
		if done.Physical == retention.PhysicalDone {
			break
		}
	}
	if done.Physical != retention.PhysicalDone {
		t.Fatalf("the deletion did not finish physically: %+v", done)
	}
	if !slices.Contains(app.Control.ResidualStores(), control.ResidualControlJournal) {
		t.Fatalf("setup: the control store does not owe its journal copy: %v", app.Control.ResidualStores())
	}
	if !slices.Contains(done.Residual, control.ResidualControlJournal) {
		t.Fatalf("a done receipt hides the control raft journal residue: %+v", done)
	}
}
