// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The administrators of an organization read its sources and their admitted
// policy (what POST /api/v1/sources/policy changes by revision); another
// organization's administrator, a plain member and a source's own credential see
// none of it, and no credential or credential ID is ever in the answer.
func TestAdminReadSourcesIsScopedAndCarriesNoCredential(t *testing.T) {
	e := newIsoEnv(t)
	pA, pB := model.NewID(), model.NewID()
	orgA, orgB := e.org("sources A", pA), e.org("sources B", pB)
	ids := sharedIDs{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	a := e.source(orgA, pA, ids, []model.Kind{model.Metric, model.Log})
	b := e.source(orgB, pB, ids, []model.Kind{model.Metric})
	member := e.user(orgA, "member-src@example.test")
	otherAdmin := e.user(orgB, "admin-src-b@example.test")
	e.cmd(orgB, "org_admin", auth.AdminPayload{UserID: otherAdmin.ID, Enabled: true})

	view, err := e.app.Auth.AdminRead(e.ctx, e.actor.Cred, auth.AdminReadRequest{OrgID: orgA, Kind: "source"})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Sources) != 1 || view.Sources[0].ID != a.ID || view.Sources[0].Project != pA || !view.Sources[0].Policy.Enabled || view.Sources[0].Policy.Revision != 1 || len(view.Sources[0].Policy.Kinds) != 2 {
		t.Fatalf("organization A's sources: %+v", view.Sources)
	}
	raw, _ := json.Marshal(view)
	for _, leaked := range []string{a.Credential, b.ID.String(), "credential"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("the source read carries %q: %s", leaked, raw)
		}
	}
	if _, err = e.app.Auth.AdminRead(e.ctx, otherAdmin.Cred, auth.AdminReadRequest{OrgID: orgA, Kind: "source"}); faultCode(err) != model.NotFound {
		t.Fatalf("another organization's administrator: %v", err)
	}
	if _, err = e.app.Auth.AdminRead(e.ctx, member.Cred, auth.AdminReadRequest{OrgID: orgA, Kind: "source"}); faultCode(err) != model.NotFound {
		t.Fatalf("a member: %v", err)
	}
	viewB, err := e.app.Auth.AdminRead(e.ctx, otherAdmin.Cred, auth.AdminReadRequest{OrgID: orgB, Kind: "source"})
	if err != nil || len(viewB.Sources) != 1 || viewB.Sources[0].ID != b.ID {
		t.Fatalf("organization B's sources: %v %+v", err, viewB.Sources)
	}
}
