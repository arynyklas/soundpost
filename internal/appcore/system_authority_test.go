// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"soundpost/internal/retention"
)

func faultOf(t *testing.T, what string, err error) model.Code {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) {
		t.Fatalf("%s: got %v, want a refusal", what, err)
	}
	return f.Code
}

// The runner's organization-administrator scope has no administrator record, so every
// authority that is not the runner's own stays closed to it: deletion, legal holds,
// release registration, ownership cutover and human incident actions are all refused
// and commit nothing.
func TestSystemScopeHoldsOnlyTheRunnersAuthority(t *testing.T) {
	n := newWorkerNode(t)
	admin, err := n.app.Auth.AuthorizeSystem(n.ctx, n.org, []model.ID{n.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = n.app.Control.View(n.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	notFound := func(what string, err error) {
		t.Helper()
		if code := faultOf(t, what, err); code != model.NotFound && code != model.Forbidden {
			t.Fatalf("%s: code %s", what, code)
		}
	}
	_, err = n.app.Retention.Delete(n.ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireProject, OrgID: n.org, ProjectIDs: []model.ID{n.project}, Reason: "a system scope must not delete"})
	notFound("deletion", err)
	_, err = n.app.Retention.PlaceHold(n.ctx, admin, retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: revision, ProjectIDs: []model.ID{n.project}, Reason: "a system scope must not hold"})
	notFound("legal hold", err)
	_, err = n.app.Releases.Register(n.ctx, admin, releases.Release{ID: model.NewID(), Org: n.org, Project: n.project, BuildID: model.NewID(), BuildTime: 1, Parents: []model.ID{}}, revision, model.NewID())
	notFound("release registration", err)
	_, err = n.app.Control.TransactCutover(n.ctx, admin, model.NewID(), control.CutoverTransition{Project: n.project, Old: model.NewID(), New: model.NewID(), Phase: "shadow", At: 1, Reason: "a system scope must not cut over",
		Frontier: []control.CutoverFrontier{{Source: model.NewID(), Version: 1, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}}})
	if code := faultOf(t, "ownership cutover", err); code != model.Forbidden {
		t.Fatalf("ownership cutover: code %s, want forbidden", code)
	}
	_, err = n.app.Incidents.Act(n.ctx, admin, incidents.Action{CommandID: model.NewID(), ExpectedVersion: 1, Type: incidents.TypeAck, Target: incidents.Target{Project: n.project, Incident: model.NewID()}}, 0)
	notFound("human incident action", err)
	var after model.Revision
	if err = n.app.Control.View(n.ctx, func(st model.ControlState) error { after = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	if after != revision {
		t.Fatalf("a refused system command moved the control revision %d -> %d", revision, after)
	}
}
