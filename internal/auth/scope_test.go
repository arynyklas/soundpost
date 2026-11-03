// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

func TestProjectGrantNotOrgMembership(t *testing.T) { testGrant(t, false) }
func TestRevocationStopsLiveResult(t *testing.T)    { testGrant(t, true) }
func testGrant(t *testing.T, revoke bool) {
	t.Helper()
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	token, _ := store.BootstrapToken()
	admin, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	c, e := service.Authenticate(ctx, admin.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project, user := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var rev model.Revision
		_ = store.View(ctx, func(st control.State) error { rev = st.Revision; return nil })
		p.Reason = "isolation behavior test"
		raw, _ := json.Marshal(p)
		_, e := service.AdminCommand(ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw})
		if e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "org"})
	command("create_project", auth.AdminPayload{ID: project, Name: "project"})
	command("create_user", auth.AdminPayload{ID: user, Email: "member@example.test", Password: "member password long enough"})
	command("membership", auth.AdminPayload{UserID: user, Enabled: true})
	login, e := service.Login(ctx, "member@example.test", "member password long enough", "")
	if e != nil {
		t.Fatal(e)
	}
	member, e := service.Authenticate(ctx, login.Token)
	if e != nil {
		t.Fatal(e)
	}
	_, e = service.Authorize(ctx, member, org, []model.ID{project}, auth.Read)
	assertCode(t, e, model.NotFound)
	command("grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}})
	scope, e := service.Authorize(ctx, member, org, []model.ID{project}, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	if e = service.Revalidate(ctx, scope); e != nil {
		t.Fatal(e)
	}
	if revoke {
		command("grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: false})
		assertCode(t, service.Revalidate(ctx, scope), model.NotFound)
	}
}
