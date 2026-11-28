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

func TestSameOrgDisjointNamedRawSourceGrants(t *testing.T) {
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
	bootstrap, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Bootstrap(ctx, bootstrap, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	users := []model.ID{model.NewID(), model.NewID()}
	sources := []model.ID{model.NewID(), model.NewID()}
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "named source isolation regression"
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "same organization"})
	command("create_project", auth.AdminPayload{ID: project, Name: "shared project"})
	emails := []string{"first-reader@example.test", "second-reader@example.test"}
	for i, user := range users {
		command("create_user", auth.AdminPayload{ID: user, Email: emails[i], Password: "reader password long enough"})
		command("membership", auth.AdminPayload{UserID: user, Enabled: true})
		command("grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{string(auth.RawRead)}})
		config, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{user}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		command("source_policy", auth.AdminPayload{ID: sources[i], Config: config})
	}
	scopes := make([]auth.Scope, 2)
	for i := range users {
		login, err := service.Login(ctx, emails[i], "reader password long enough", "")
		if err != nil {
			t.Fatal(err)
		}
		credential, err := service.Authenticate(ctx, login.Token)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := service.AuthorizeRestrictedSource(ctx, credential, org, project, sources[i])
		if err != nil {
			t.Fatal(err)
		}
		if !scope.AllowsSource(sources[i]) || scope.AllowsSource(sources[1-i]) {
			t.Fatal("scope widened named-source access")
		}
		if err := service.Revalidate(ctx, scope); err != nil {
			t.Fatal(err)
		}
		_, err = service.AuthorizeRestrictedSource(ctx, credential, org, project, sources[1-i])
		assertCode(t, err, model.NotFound)
		scopes[i] = scope
	}
	if scopes[0].PolicyEpoch() != scopes[1].PolicyEpoch() {
		t.Fatal("fixture must compare the same policy epoch")
	}
	if scopes[0].VisibilityFingerprint() == scopes[1].VisibilityFingerprint() {
		t.Fatal("disjoint source readers shared a cache visibility fingerprint")
	}
	// Read the real persisted settings, not a test-only policy substitute.
	if err := store.View(ctx, func(st control.State) error {
		for i, source := range sources {
			var policy auth.SourcePolicyConfig
			if err := json.Unmarshal(st.Orgs[org.String()].Settings["source_policy:"+source.String()], &policy); err != nil {
				return err
			}
			if len(policy.Readers) != 1 || policy.Readers[0] != users[i] {
				t.Fatal("persisted named-reader assignment differs")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
