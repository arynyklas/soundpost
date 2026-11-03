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
	"time"
)

func TestServerTokenCannotBroadenOrSurviveRevocation(t *testing.T) {
	ctx := context.Background()
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	boot, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, boot, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, first, second, user := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "machine scope test"
		raw, _ := json.Marshal(p)
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "org"})
	for _, project := range []model.ID{first, second} {
		command("create_project", auth.AdminPayload{ID: project, Name: "project"})
	}
	command("create_user", auth.AdminPayload{ID: user, Email: "worker@example.test", Password: "worker password long enough"})
	command("membership", auth.AdminPayload{UserID: user, Enabled: true})
	for _, project := range []model.ID{first, second} {
		command("grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{"telemetry.read", "raw.read"}})
	}
	issued, err := service.IssueServerToken(ctx, actor, org, user, []model.ID{first}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "machine read grant")
	if err != nil {
		t.Fatal(err)
	}
	machine, err := service.Authenticate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := service.Authorize(ctx, machine, org, []model.ID{first}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Authorize(ctx, machine, org, []model.ID{second}, auth.Read)
	assertCode(t, err, model.NotFound)
	_, err = service.Authorize(ctx, machine, org, []model.ID{first}, auth.RawRead)
	assertCode(t, err, model.NotFound)
	if err = service.RevokeServerToken(ctx, actor, org, issued.ID, "machine grant revoked"); err != nil {
		t.Fatal(err)
	}
	assertCode(t, service.Revalidate(ctx, scope), model.Unauthenticated)
}
