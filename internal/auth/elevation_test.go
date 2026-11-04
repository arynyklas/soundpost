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
