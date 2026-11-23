// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// rwFixture: an organization with two projects, an administrator who is also a member, a plain member holding
// artifacts.write on the first project and a plain member holding nothing.
type rwFixture struct {
	*cacheFixture
	other        model.ID
	admin        model.ID
	writer, bare model.ID
}

func newRWFixture(t *testing.T) *rwFixture {
	t.Helper()
	f := &rwFixture{cacheFixture: newCacheFixture(t), other: model.NewID(), admin: model.ID{}}
	f.admin = f.session.User
	f.cmd("create_project", auth.AdminPayload{ID: f.other, Name: "other"})
	f.cmd("membership", auth.AdminPayload{UserID: f.admin, Enabled: true})
	_, f.writer = f.reader("rw-writer@example.test", auth.ArtifactWrite)
	_, f.bare = f.reader("rw-bare@example.test", auth.Read)
	return f
}

func (f *rwFixture) token(principal model.ID, projects []model.ID, perms ...auth.Permission) (auth.Credential, auth.IssuedServerToken) {
	f.t.Helper()
	issued, err := f.service.IssueServerToken(f.ctx, f.actor, f.org, principal, projects, perms, f.at().Add(3600e9).Unix(), "release pipeline")
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.service.Authenticate(f.ctx, issued.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return c, issued
}

func TestAuthorizeReleaseGrantsOnlyTheNarrowScope(t *testing.T) {
	f := newRWFixture(t)
	admin, _ := f.token(f.admin, []model.ID{f.project}, auth.ReleaseWrite)
	scope, err := f.service.AuthorizeRelease(f.ctx, admin, f.org, f.project, auth.OrgAdmin)
	if err != nil {
		t.Fatalf("the release scope of an administrator's token: %v", err)
	}
	if scope.Permission() != auth.OrgAdmin || scope.OrgID() != f.org || len(scope.ProjectIDs()) != 1 || scope.ProjectIDs()[0] != f.project {
		t.Fatalf("scope: %+v", scope)
	}
	if err := f.service.Revalidate(f.ctx, scope); err != nil {
		t.Fatalf("revalidate: %v", err)
	}
	if err := scope.ControlAuthorize(f.ctx, "RegisterRelease"); err != nil {
		t.Fatalf("registration: %v", err)
	}
	for _, kind := range []string{"Audit", "Grant", "CreateOrg", "PolicyChange", "IncidentAction"} {
		if err := scope.ControlAuthorize(f.ctx, kind); code(err) != model.Forbidden {
			t.Errorf("%s: %v", kind, err)
		}
	}
	// Project confinement: the token names one project; the other project and organization are the same not-found.
	if _, err := f.service.AuthorizeRelease(f.ctx, admin, f.org, f.other, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("another project of the organization: %v", err)
	}
	if _, err := f.service.AuthorizeRelease(f.ctx, admin, f.otherOrg(), f.project, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("another organization: %v", err)
	}
	// Only the two scopes exist.
	for _, a := range []auth.Permission{auth.Read, auth.OrgAdmin + "x", auth.InstanceAdmin, auth.RawRead} {
		if _, err := f.service.AuthorizeRelease(f.ctx, admin, f.org, f.project, a); err == nil {
			t.Errorf("a release scope with action %s", a)
		}
	}
}

func TestAuthorizeReleaseIsForServerTokensOnly(t *testing.T) {
	f := newRWFixture(t)
	// The administrator's own session, and a member's session, derive nothing through this door.
	for name, c := range map[string]auth.Credential{"administrator session": f.actor} {
		for _, a := range []auth.Permission{auth.OrgAdmin, auth.ArtifactWrite} {
			if _, err := f.service.AuthorizeRelease(f.ctx, c, f.org, f.project, a); err == nil {
				t.Errorf("%s derived a release scope for %s", name, a)
			}
		}
	}
}

func TestAuthorizeReleaseNeedsTheGrantAndThePrincipalsRole(t *testing.T) {
	f := newRWFixture(t)
	// A token without release.write.
	for _, p := range []auth.Permission{auth.ArtifactWrite, auth.Read, "telemetry.ingest"} {
		c, _ := f.token(f.admin, []model.ID{f.project}, p)
		if _, err := f.service.AuthorizeRelease(f.ctx, c, f.org, f.project, auth.OrgAdmin); code(err) != model.NotFound {
			t.Errorf("a %s token: %v", p, err)
		}
	}
	// A principal that does not administer the organization gets no registry scope...
	member, _ := f.token(f.writer, []model.ID{f.project}, auth.ReleaseWrite)
	if _, err := f.service.AuthorizeRelease(f.ctx, member, f.org, f.project, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("a plain member's token got the registry scope: %v", err)
	}
	// ...a principal with artifacts.write gets the upload scope, one without it does not.
	if _, err := f.service.AuthorizeRelease(f.ctx, member, f.org, f.project, auth.ArtifactWrite); err != nil {
		t.Fatalf("a writer's token: %v", err)
	}
	bare, _ := f.token(f.bare, []model.ID{f.project}, auth.ReleaseWrite)
	if _, err := f.service.AuthorizeRelease(f.ctx, bare, f.org, f.project, auth.ArtifactWrite); code(err) != model.NotFound {
		t.Fatalf("a principal without artifacts.write: %v", err)
	}
}

func TestAuthorizeReleaseRefusesRevokedAndExpiredTokens(t *testing.T) {
	f := newRWFixture(t)
	c, issued := f.token(f.admin, []model.ID{f.project}, auth.ReleaseWrite)
	if _, err := f.service.AuthorizeRelease(f.ctx, c, f.org, f.project, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	live, _ := f.token(f.admin, []model.ID{f.project}, auth.ReleaseWrite)
	// Expired: the clock passes the token's expiry.
	f.advance(2 * 3600e9)
	if _, err := f.service.AuthorizeRelease(f.ctx, live, f.org, f.project, auth.OrgAdmin); err == nil {
		t.Fatal("an expired token derived a release scope")
	}
	f.advance(-2 * 3600e9)
	if _, err := f.service.AuthorizeRelease(f.ctx, live, f.org, f.project, auth.OrgAdmin); err != nil {
		t.Fatalf("back in time: %v", err)
	}
	// Revoked.
	if err := f.service.RevokeServerToken(f.ctx, f.actor, f.org, issued.ID, "pipeline retired"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.AuthorizeRelease(f.ctx, c, f.org, f.project, auth.OrgAdmin); err == nil {
		t.Fatal("a revoked token derived a release scope")
	}
	// A scope derived before the revocation is refused by its own revalidation.
	c2, issued2 := f.token(f.admin, []model.ID{f.project}, auth.ReleaseWrite)
	scope, err := f.service.AuthorizeRelease(f.ctx, c2, f.org, f.project, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.service.RevokeServerToken(f.ctx, f.actor, f.org, issued2.ID, "retired too"); err != nil {
		t.Fatal(err)
	}
	if err = f.service.Revalidate(f.ctx, scope); err == nil {
		t.Fatal("a scope of a revoked token revalidated")
	}
	// The scope of an administrator that lost the role: refused at derivation.
	c3, _ := f.token(f.admin, []model.ID{f.project}, auth.ReleaseWrite)
	f.cmd("org_admin", auth.AdminPayload{UserID: f.admin, Enabled: false})
	if _, err = f.service.AuthorizeRelease(f.ctx, c3, f.org, f.project, auth.OrgAdmin); err == nil {
		t.Fatal("a demoted principal's token derived the registry scope")
	}
}

func TestIssueServerTokenNeverGrantsOrgAdmin(t *testing.T) {
	f := newRWFixture(t)
	for _, p := range []auth.Permission{auth.OrgAdmin, auth.InstanceAdmin, "release.admin", ""} {
		if _, err := f.service.IssueServerToken(f.ctx, f.actor, f.org, f.admin, []model.ID{f.project}, []auth.Permission{auth.ReleaseWrite, p}, f.at().Add(3600e9).Unix(), "x"); code(err) != model.Invalid {
			t.Errorf("a token with %q: %v", p, err)
		}
	}
	// release.write is a token permission only: a person cannot be granted it.
	body, _ := json.Marshal(auth.AdminPayload{UserID: f.writer, ProjectID: f.project, Enabled: true, Permissions: []string{"release.write"}, Reason: "x"})
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	if _, err := f.service.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: "grant", Payload: body}); err == nil {
		t.Fatal("release.write was granted to a person")
	}
}
