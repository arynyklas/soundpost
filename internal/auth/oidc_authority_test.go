// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"net/url"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The start of an OIDC login adds a pending record and its callback consumes it. A pending record
// authenticates nobody (the callback still needs the provider's verified id token and a mapped,
// enabled user, and the session it ends in is a separate write), so neither commit moves
// AuthorityRevision; each is still exactly one control transition, and the record really is there
// after the start and gone after the callback.
func TestOIDCStartAndCallbackKeepAuthorityRevision(t *testing.T) {
	f := newSweepFixture(t)
	revisions := func() (revision, authority model.Revision) {
		t.Helper()
		if err := f.store.View(f.ctx, func(st control.State) error {
			revision, authority = st.Revision, st.AuthorityRevision
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	pending0, _ := f.oidcRecords(t)
	rev0, auth0 := revisions()
	start, err := f.service.OIDCStart(f.ctx, f.cfg, "binding")
	if err != nil {
		t.Fatal(err)
	}
	rev1, auth1 := revisions()
	if pending, _ := f.oidcRecords(t); pending != pending0+1 {
		t.Fatalf("the start left %d pending records, want %d", pending, pending0+1)
	}
	if rev1 != rev0+1 || auth1 != auth0 {
		t.Fatalf("OIDCStart: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev0, rev1, auth0, auth1)
	}
	u, err := url.Parse(start)
	if err != nil {
		t.Fatal(err)
	}
	// The provider has no token endpoint, so the callback fails after its first step: the pending
	// record is consumed (committed) and no session is created.
	if _, err = f.service.OIDCCallback(f.ctx, f.cfg, "binding", u.Query().Get("state"), "code"); err == nil {
		t.Fatal("a callback without a working provider created a session")
	}
	rev2, auth2 := revisions()
	if pending, _ := f.oidcRecords(t); pending != pending0 {
		t.Fatalf("the callback left %d pending records, want %d", pending, pending0)
	}
	if rev2 != rev1+1 || auth2 != auth1 {
		t.Fatalf("OIDCCallback: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev1, rev2, auth1, auth2)
	}
	// The guard is not a blanket exemption for the auth package: an ordinary Update still bumps.
	if err = f.store.Update(f.ctx, func(*control.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if rev3, auth3 := revisions(); auth3 != rev3 {
		t.Fatalf("Update after the logins: authority %d at revision %d (want a bump)", auth3, rev3)
	}
}
