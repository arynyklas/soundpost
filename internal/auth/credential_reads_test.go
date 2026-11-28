// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Every request of the API authenticates. The control state is decoded per member and shared, but the
// authentication read every member, so a commit of any of them (the rule books, the organizations: at the
// gate they change all the time) made the next request decode it: 20 CPU-seconds of 463 in the mix. It reads
// the three members it looks at, so a commit of the others costs it nothing; a commit of those three is seen by
// the very next request.
func TestAuthenticationDecodesOnlyTheMembersItReads(t *testing.T) {
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
	activateAuthControl(t, store, t.TempDir())
	boot, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, boot, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(ctx, session.Token) // warms the decode
	if err != nil {
		t.Fatal(err)
	}
	org := model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "credential read test"
		raw, _ := json.Marshal(p)
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "org"})
	for i := range 4 {
		command("create_project", auth.AdminPayload{ID: model.NewID(), Name: "project"}) // changes the organizations, not the credentials
		// the first read after the commit is counted
		before := store.DecodeStats()
		for range 5 {
			if _, err = service.Authenticate(ctx, session.Token); err != nil {
				t.Fatal(err)
			}
			if _, err = service.Session(ctx, session.Token); err != nil {
				t.Fatal(err)
			}
		}
		after := store.DecodeStats()
		if after.Members != before.Members || after.Whole != before.Whole || after.Blobs != before.Blobs {
			t.Fatalf("commit %d: 10 authentications decoded %d members, %d whole states, %d blobs, want none", i, after.Members-before.Members, after.Whole-before.Whole, after.Blobs-before.Blobs)
		}
	}
	// Authority is not weakened: a session that is logged out is refused by the very next request.
	if err = service.Logout(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Authenticate(ctx, session.Token); err == nil {
		t.Fatal("a logged-out session was served by the next request")
	}
	if _, err = service.Session(ctx, session.Token); err == nil {
		t.Fatal("a logged-out session was read by the next request")
	}
}
