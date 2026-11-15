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
)

// An admin command on an existing organization may carry the organization's policy
// epoch it read (AdminView.Epoch) instead of the global control revision, as a policy
// write does: a login or a background commit elsewhere moves the revision and is no
// reason to refuse a save, while a change to the organization since the page read it
// (a lost update) is refused and changes nothing.
func TestAdminCommandCarriesOrganizationEpochPrecondition(t *testing.T) {
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
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	boot, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	c, e := service.Authenticate(ctx, boot.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, user, other := model.NewID(), model.NewID(), model.NewID()
	revision := func() model.Revision {
		var rev model.Revision
		_ = store.View(ctx, func(st control.State) error { rev = st.Revision; return nil })
		return rev
	}
	send := func(kind string, p auth.AdminPayload, rev model.Revision, epoch *model.Uint64) error {
		t.Helper()
		p.Reason = "epoch precondition test"
		raw, _ := json.Marshal(p)
		_, err := service.AdminCommand(ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, ExpectedEpoch: epoch, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	run := func(kind string, p auth.AdminPayload, epoch *model.Uint64) error {
		t.Helper()
		return send(kind, p, revision(), epoch)
	}
	must := func(kind string, p auth.AdminPayload) {
		t.Helper()
		if err := run(kind, p, nil); err != nil {
			t.Fatal(kind, err)
		}
	}
	read := func() auth.AdminView {
		t.Helper()
		v, err := service.AdminRead(ctx, c, auth.AdminReadRequest{OrgID: org, Kind: "organization"})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	must("create_org", auth.AdminPayload{Name: "epoch org"})
	must("create_user", auth.AdminPayload{ID: user, Email: "member@example.test", Password: "member password long enough"})
	must("create_user", auth.AdminPayload{ID: other, Email: "other@example.test", Password: "other password long enough"})

	// The read names the organization's epoch, and every organization command advances it by one.
	seen := read().Epoch
	if seen == 0 {
		t.Fatal("an organization read carries no epoch")
	}
	must("membership", auth.AdminPayload{UserID: user, Enabled: true})
	if got := read().Epoch; got != seen+1 {
		t.Fatalf("epoch after one command: %d, want %d", got, seen+1)
	}

	// The global revision moves without touching the organization: a command on the epoch it read still commits, whatever
	// control revision the page held (the revision it read is no longer current, and no longer matters).
	epoch, readAt := read().Epoch, revision()
	must("create_user", auth.AdminPayload{ID: model.NewID(), Email: "elsewhere@example.test", Password: "elsewhere password long enough"})
	before := revision()
	if readAt == before {
		t.Fatal("a change elsewhere did not move the control revision")
	}
	if err := send("membership", auth.AdminPayload{UserID: other, Enabled: true}, readAt, &epoch); err != nil {
		t.Fatalf("a save based on the current epoch was refused after a change elsewhere: %v", err)
	}
	if revision() == before {
		t.Fatal("the committed command did not advance the control revision")
	}
	if !read().Organizations[0].Members[other.String()] {
		t.Fatal("the committed membership is not in the organization")
	}

	// A change to the organization since the read is a lost update: refused, nothing changes.
	stale := read().Epoch
	must("org_admin", auth.AdminPayload{UserID: user, Enabled: true})
	frozen := read()
	if err := run("create_project", auth.AdminPayload{ID: model.NewID(), Name: "late project"}, &stale); faultCode(err) != model.Conflict {
		t.Fatalf("a save on a stale epoch: %v, want conflict", err)
	}
	after := read()
	if after.Epoch != frozen.Epoch || len(after.Organizations[0].Projects) != 0 {
		t.Fatalf("a refused stale save changed the organization: epoch %d -> %d, projects %v", frozen.Epoch, after.Epoch, after.Organizations[0].Projects)
	}

	// An epoch names an organization: commands that create one (or a user) have none to compare.
	one := model.Uint64(1)
	if err := run("create_user", auth.AdminPayload{ID: model.NewID(), Email: "x@example.test", Password: "password long enough"}, &one); faultCode(err) != model.Invalid {
		t.Fatalf("create_user with an epoch: %v, want invalid", err)
	}
}
