// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

func TestScanFixtureRequiresCommittedMembershipAndScopedGrants(t *testing.T) {
	store, a, c, d := fixture(t)
	write, batch := normalized(t, store, a, c, d)
	var before uint64
	if err := store.View(context.Background(), func(st control.State) error { before = st.Orgs[d.Org.String()].Epoch; return nil }); err != nil {
		t.Fatal(err)
	}
	read := scanPermission(t, store, a, d, auth.Read)
	profile := scanPermission(t, store, a, d, profilesRead)
	if read.Permission() != auth.Read || profile.Permission() != profilesRead {
		t.Fatal("requested scope action was broadened")
	}
	if err := store.View(context.Background(), func(st control.State) error {
		if st.Orgs[d.Org.String()].Epoch != before {
			t.Fatal("read scope helper mutated tenant grant epoch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	// Provisioning belongs before normalization; obtaining read scopes must not
	// invalidate this already-reserved, real source-authorized write.
	if _, err = engine.Append(context.Background(), write, batch); err != nil {
		t.Fatal("scope helper invalidated source authority", err)
	}
	session, err := a.Login(context.Background(), "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := a.Authenticate(context.Background(), session.Token)
	if err != nil {
		t.Fatal(err)
	}
	command := func(kind string, payload auth.AdminPayload) error {
		var revision model.Revision
		if err := store.View(context.Background(), func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		payload.Reason = "storage fixture authority regression"
		_, err := a.AdminCommand(context.Background(), credential, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: d.Org, Kind: kind, Payload: mustJSON(t, payload)})
		return err
	}
	if err = command("membership", auth.AdminPayload{UserID: session.User, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	assertDenied := func(err error) {
		t.Helper()
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.NotFound {
			t.Fatal("membership denial was weakened", err)
		}
	}
	_, err = a.Authorize(context.Background(), credential, d.Org, []model.ID{d.Project}, auth.Read)
	assertDenied(err)
	// Organization administration is deliberately independent of membership;
	// even the admin cannot grant telemetry access to this nonmember.
	assertDenied(command("grant", auth.AdminPayload{UserID: session.User, ProjectID: d.Project, Enabled: true, Permissions: []string{string(auth.Read)}}))
	lookups := engine.Stats().IndexLookups
	_, err = engine.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2})
	assertDenied(err)
	if engine.Stats().IndexLookups != lookups {
		t.Fatal("revoked membership touched the index")
	}
}
