// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

func TestTransactReplayIsBoundToPrincipalOrgAndKind(t *testing.T) {
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
	bootstrap, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, bootstrap, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	orgs := []model.ID{model.NewID(), model.NewID()}
	other := model.NewID()
	revision := func() model.Revision {
		t.Helper()
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		return revision
	}
	admin := func(org model.ID, kind string, p auth.AdminPayload) {
		t.Helper()
		p.Reason = "command owner regression"
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision(), OrgID: org, Kind: kind, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range orgs {
		admin(org, "create_org", auth.AdminPayload{Name: "original"})
	}
	admin(orgs[0], "create_user", auth.AdminPayload{ID: other, Email: "other-admin@example.test", Password: "other administrator password"})
	admin(orgs[0], "org_admin", auth.AdminPayload{UserID: other, Enabled: true})
	first, err := service.Authorize(ctx, actor, orgs[0], nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := service.Authorize(ctx, actor, orgs[1], nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, "other-admin@example.test", "other administrator password", "")
	if err != nil {
		t.Fatal(err)
	}
	otherCredential, err := service.Authenticate(ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := service.Authorize(ctx, otherCredential, orgs[0], nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := func(scope auth.Scope, st *control.State, cmd control.Command) (control.Effect, error) {
		calls++
		org := st.Orgs[scope.OrgID().String()]
		org.Name = "committed effect"
		st.Orgs[scope.OrgID().String()] = org
		return control.Effect{AffectedIDs: []model.ID{scope.OrgID()}}, nil
	}
	if err := store.RegisterHandler(control.KindPolicyChange, handler); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterHandler(control.KindGrant, handler); err != nil {
		t.Fatal(err)
	}
	command := control.Command{CommandID: model.NewID(), ExpectedRevision: revision(), Kind: string(control.KindPolicyChange)}
	original, err := store.Transact(ctx, first, command)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.Transact(ctx, first, command)
	if err != nil || !reflect.DeepEqual(original, replay) {
		t.Fatalf("owner replay changed receipt: %v", err)
	}
	denied := func(scope auth.Scope, kind string) {
		t.Helper()
		attempt := command
		attempt.Kind = kind
		attempt.ExpectedRevision = revision()
		result, err := store.Transact(ctx, scope, attempt)
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.NotFound {
			t.Fatalf("mismatched replay got %v", err)
		}
		if !reflect.DeepEqual(result, control.Result{}) {
			t.Fatal("mismatched owner received result metadata")
		}
	}
	denied(foreign, string(control.KindPolicyChange))
	denied(otherScope, string(control.KindPolicyChange))
	denied(first, string(control.KindGrant))
	if calls != 1 {
		t.Fatalf("replayed or mismatched command executed %d effects", calls)
	}
	if err := store.View(ctx, func(st control.State) error {
		if st.Orgs[orgs[1].String()].Name != "original" {
			t.Fatal("foreign replay changed organization")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	auditPayload, err := json.Marshal(control.Audit{ID: model.NewID(), Principal: first.PrincipalID(), Action: "owned control operation", Reason: "safe command-boundary regression", Time: 1800000000000000000, RequestID: model.NewID(), Outcome: model.AuditFailed})
	if err != nil {
		t.Fatal(err)
	}
	auditCommand := control.Command{CommandID: model.NewID(), ExpectedRevision: revision(), Kind: string(control.KindAudit), Payload: auditPayload}
	if _, err := store.Transact(ctx, first, auditCommand); err != nil {
		t.Fatal(err)
	}
	if err := store.View(ctx, func(st control.State) error {
		audit := st.Audits[len(st.Audits)-1]
		if audit.RequestID != auditCommand.CommandID || audit.Outcome != model.AuditAllowed {
			t.Fatal("Audit command retained payload-supplied observation instead of admitted command correlation/outcome")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
