// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func TestElevationAuditsBeforeRead(t *testing.T) {
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	now := time.Now()
	service, e := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	c, e := service.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org := model.NewID()
	var rev model.Revision
	_ = store.View(ctx, func(st control.State) error { rev = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "org", Reason: "audit test"})
	if _, e = service.AdminCommand(ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: payload}); e != nil {
		t.Fatal(e)
	}
	elev, e := service.Elevate(ctx, session, "investigate selected organization", []model.ID{org})
	if e != nil {
		t.Fatal(e)
	}
	scope, e := service.ElevatedScope(ctx, elev, org, nil, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	_ = store.View(ctx, func(st control.State) error {
		n := len(st.Audits)
		if n < 3 || st.Audits[n-2].Action != "elevate" || st.Audits[n-1].Action != "elevated_read" {
			t.Fatal("missing durable ordered elevation/read audit")
		}
		return nil
	})
	now = now.Add(16 * time.Minute)
	assertCode(t, service.Revalidate(ctx, scope), model.Forbidden)
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = service.ElevatedScope(ctx, elev, org, nil, auth.Read); e == nil {
		t.Fatal("closed audit authority released scope")
	}
}

// Only an instance administrator elevates. An organization administrator and a project
// administrator holding every project permission are refused with one Forbidden that is
// identical for a real organization and for one that does not exist, and the refusal
// writes no elevation audit, so nothing about an organization's existence is learned.
func TestNonInstanceAdminsCannotElevateAndLearnNothingAboutOrgs(t *testing.T) {
	f := newCacheFixture(t)
	elevations := func() int {
		n := 0
		_ = f.store.View(f.ctx, func(st control.State) error {
			for _, a := range st.Audits {
				if a.Action == "elevate" {
					n++
				}
			}
			return nil
		})
		return n
	}
	// Control: the instance administrator's fresh session does elevate, so the
	// refusals below are about the principal, not freshness or the request shape.
	if _, err := f.service.Elevate(f.ctx, f.session, "control elevation", []model.ID{f.org}); err != nil {
		t.Fatalf("instance administrator refused: %v", err)
	}
	base := elevations()

	_, orgAdminID := f.reader("org-admin-user@example.test", auth.Read)
	f.cmd("org_admin", auth.AdminPayload{UserID: orgAdminID, Enabled: true})
	orgAdminLogin, err := f.service.Login(f.ctx, "org-admin-user@example.test", "cache reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	_, projectAdminSession := f.readerSession("project-admin-no-elevate@example.test", auth.Read, auth.RawRead, auth.ArtifactRead, auth.ArtifactWrite, auth.PolicyWrite, auth.IssuesWrite)

	missing := model.NewID()
	var want error
	for name, session := range map[string]auth.Session{"organization administrator": orgAdminLogin, "project administrator": projectAdminSession} {
		_, real := f.service.Elevate(f.ctx, session, "must not elevate", []model.ID{f.org})
		_, none := f.service.Elevate(f.ctx, session, "must not elevate", []model.ID{missing})
		if code(real) != model.Forbidden || code(none) != model.Forbidden {
			t.Fatalf("%s: real %v, missing %v; both must be Forbidden", name, real, none)
		}
		if !sameDenial(real, none) {
			t.Fatalf("%s: refusal differs between a real and a missing organization: %v vs %v", name, real, none)
		}
		if want == nil {
			want = real
		} else if !sameDenial(real, want) {
			t.Fatalf("%s: refusal is distinguishable from the other principal's: %v vs %v", name, real, want)
		}
	}
	if got := elevations(); got != base {
		t.Fatalf("a refused elevation wrote %d audit rows", got-base)
	}
}
