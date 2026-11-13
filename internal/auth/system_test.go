// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

type systemRig struct {
	store   *control.Store
	service *auth.Service
	admin   auth.Credential
	org     model.ID
	project model.ID
}

func newSystemRig(t *testing.T) *systemRig {
	t.Helper()
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	admin, e := service.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	r := &systemRig{store: store, service: service, admin: admin, org: model.NewID(), project: model.NewID()}
	r.command(t, "create_org", auth.AdminPayload{Name: "org"})
	r.command(t, "create_project", auth.AdminPayload{ID: r.project, Name: "project"})
	return r
}

func (r *systemRig) command(t *testing.T, kind string, p auth.AdminPayload) error {
	t.Helper()
	return r.commandIn(t, r.org, kind, p)
}

func (r *systemRig) commandIn(t *testing.T, org model.ID, kind string, p auth.AdminPayload) error {
	t.Helper()
	ctx := context.Background()
	var rev model.Revision
	_ = r.store.View(ctx, func(st control.State) error { rev = st.Revision; return nil })
	p.Reason = "system scope test"
	raw, _ := json.Marshal(p)
	_, e := r.service.AdminCommand(ctx, r.admin, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw})
	return e
}

// The runner has a scope for exactly the roles it needs: project read, organization
// administration, issue writes and policy writes. Every other permission is refused,
// and the principal is the readable system:runner principal of that organization.
func TestSystemScopeCarriesExactlyTheRunnerRoles(t *testing.T) {
	r := newSystemRig(t)
	ctx := context.Background()
	for _, p := range []auth.Permission{auth.Read, auth.IssuesWrite, auth.PolicyWrite} {
		scope, e := r.service.AuthorizeSystem(ctx, r.org, []model.ID{r.project}, p)
		if e != nil {
			t.Fatalf("%s: %v", p, e)
		}
		if scope.Permission() != p || !scope.AllowsProject(r.project) || !scope.IsSystem() || scope.OrgID() != r.org {
			t.Fatalf("%s: wrong scope %+v", p, scope)
		}
		if scope.PrincipalID() != auth.SystemPrincipal(r.org) || !auth.IsSystemPrincipal(scope.PrincipalID()) {
			t.Fatalf("%s: principal is not the system principal", p)
		}
		if e = r.service.Revalidate(ctx, scope); e != nil {
			t.Fatalf("%s: revalidate: %v", p, e)
		}
		if scope.LeaseDeadline().IsZero() {
			t.Fatalf("%s: no lease", p)
		}
	}
	admin, e := r.service.AuthorizeSystem(ctx, r.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	if e = admin.ControlAuthorize(ctx, "ApplyCondition"); e != nil {
		t.Fatalf("system org.admin scope refused by the control gate: %v", e)
	}
	for _, p := range []auth.Permission{auth.RawRead, auth.InstanceAdmin, auth.ArtifactRead, auth.ArtifactWrite, "replay.read", "profiles.read", "incidents.write", "rules.write", "telemetry.ingest", ""} {
		_, e = r.service.AuthorizeSystem(ctx, r.org, []model.ID{r.project}, p)
		assertCode(t, e, model.Forbidden)
	}
	// A read scope names projects; an unknown or foreign project is a NotFound.
	_, e = r.service.AuthorizeSystem(ctx, r.org, nil, auth.Read)
	assertCode(t, e, model.Invalid)
	_, e = r.service.AuthorizeSystem(ctx, r.org, []model.ID{model.NewID()}, auth.Read)
	assertCode(t, e, model.NotFound)
	_, e = r.service.AuthorizeSystem(ctx, model.NewID(), nil, auth.OrgAdmin)
	assertCode(t, e, model.NotFound)
	if auth.SystemPrincipal(r.org) == auth.SystemPrincipal(model.NewID()) {
		t.Fatal("two organizations share a system principal")
	}
}

// Nothing a client can present is a system credential: no token string, session or
// user ID authenticates as the runner, and an administrator cannot create a user
// that carries a system principal ID.
func TestSystemScopeCannotBeObtainedFromACredential(t *testing.T) {
	r := newSystemRig(t)
	ctx := context.Background()
	principal := auth.SystemPrincipal(r.org)
	for _, token := range []string{"", auth.SystemRunner, principal.String(), hex.EncodeToString(principal[:]), "Bearer " + auth.SystemRunner} {
		_, e := r.service.Authenticate(ctx, token)
		assertCode(t, e, model.Unauthenticated)
	}
	e := r.command(t, "create_user", auth.AdminPayload{ID: principal, Email: "runner@example.test", Password: "runner password long enough"})
	assertCode(t, e, model.Invalid)
	other := auth.SystemPrincipal(model.NewID())
	e = r.command(t, "create_user", auth.AdminPayload{ID: other, Email: "runner2@example.test", Password: "runner password long enough"})
	assertCode(t, e, model.Invalid)
	_ = r.store.View(ctx, func(st control.State) error {
		if _, ok := st.Users[principal.String()]; ok {
			t.Fatal("a user with the system principal ID exists")
		}
		return nil
	})
	// A human scope never claims to be the runner.
	human, e := r.service.Authorize(ctx, r.admin, r.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	if human.IsSystem() || auth.IsSystemPrincipal(human.PrincipalID()) {
		t.Fatal("human scope is a system scope")
	}
	// A system scope cannot be decoded from a request body.
	var decoded auth.Scope
	if json.Unmarshal([]byte(`{"service":{},"system":true}`), &decoded) == nil {
		t.Fatal("a scope decoded from JSON")
	}
}

// The scope is re-derived every pass: a project or an organization that has ended
// yields no scope at the next pass and ends the scopes already in hand; a policy
// change of the organization ends a scope derived under the old policy.
func TestSystemScopeEndsWithTheOrganizationAndItsPolicy(t *testing.T) {
	r := newSystemRig(t)
	ctx := context.Background()
	read, e := r.service.AuthorizeSystem(ctx, r.org, []model.ID{r.project}, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := r.service.AuthorizeSystem(ctx, r.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	// A policy change of the organization (a new user's membership) moves the epoch.
	user := model.NewID()
	if e = r.command(t, "create_user", auth.AdminPayload{ID: user, Email: "member@example.test", Password: "member password long enough"}); e != nil {
		t.Fatal(e)
	}
	if e = r.command(t, "membership", auth.AdminPayload{UserID: user, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	assertCode(t, r.service.Revalidate(ctx, read), model.NotFound)
	assertCode(t, r.service.Revalidate(ctx, admin), model.NotFound)
	assertCode(t, admin.ControlAuthorize(ctx, "ApplyCondition"), model.NotFound)
	read, e = r.service.AuthorizeSystem(ctx, r.org, []model.ID{r.project}, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	// The project is retired: no scope for it next pass, and the one in hand ends.
	if e = r.store.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[r.org.String()]
		delete(o.Projects, r.project.String())
		st.Orgs[r.org.String()] = o
		if st.RetiredProjects == nil {
			st.RetiredProjects = map[string]model.ID{}
		}
		st.RetiredProjects[r.org.String()+":"+r.project.String()] = model.NewID()
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	assertCode(t, r.service.Revalidate(ctx, read), model.NotFound)
	_, e = r.service.AuthorizeSystem(ctx, r.org, []model.ID{r.project}, auth.Read)
	assertCode(t, e, model.NotFound)
	admin, e = r.service.AuthorizeSystem(ctx, r.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal("organization scope must survive the end of one project:", e)
	}
	// The organization is deleted (retired): no scope at all at the next pass.
	if e = r.store.Update(ctx, func(st *model.ControlState) error {
		delete(st.Orgs, r.org.String())
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[r.org.String()] = model.NewID()
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	assertCode(t, r.service.Revalidate(ctx, admin), model.NotFound)
	_, e = r.service.AuthorizeSystem(ctx, r.org, nil, auth.OrgAdmin)
	assertCode(t, e, model.NotFound)
	// An organization retired while its record is still present is refused too.
	other := model.NewID()
	if e = r.commandIn(t, other, "create_org", auth.AdminPayload{Name: "other"}); e != nil {
		t.Fatal(e)
	}
	if _, e = r.service.AuthorizeSystem(ctx, other, nil, auth.OrgAdmin); e != nil {
		t.Fatal(e)
	}
	if e = r.store.Update(ctx, func(st *model.ControlState) error {
		st.RetiredOrgs[other.String()] = model.NewID()
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	_, e = r.service.AuthorizeSystem(ctx, other, nil, auth.OrgAdmin)
	assertCode(t, e, model.NotFound)
}
