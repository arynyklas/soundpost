// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func TestBearerHashesAreKeyedPurposeSeparatedAndInstallationOwned(t *testing.T) {
	ctx := context.Background()
	stores := make([]*control.Store, 2)
	services := make([]*auth.Service, 2)
	for i := range stores {
		store, err := control.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		service, err := auth.NewService(auth.AuthDependencies{Control: store})
		if err != nil {
			t.Fatal(err)
		}
		stores[i], services[i] = store, service
	}
	const token = "same high-entropy fixture bearer value"
	first, err := services[0].BearerDigest(auth.ServerAPIBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	second, err := services[1].BearerDigest(auth.ServerAPIBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	source, err := services[0].BearerDigest(auth.SourceBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("separate installations shared bearer authority hashes")
	}
	if first == source {
		t.Fatal("API and source bearers lack purpose separation")
	}
	if _, err := services[0].BearerDigest(auth.BearerPurpose("unregistered-purpose"), token); err == nil {
		t.Fatal("unregistered bearer purpose accepted")
	}
	bare := sha256.Sum256([]byte(token))
	if first == hex.EncodeToString(bare[:]) {
		t.Fatal("API authority is still bare SHA256")
	}
	if err := stores[0].View(ctx, func(st control.State) error {
		if st.BearerHashKey == "" {
			t.Fatal("installation hash key was not persisted")
		}
		encoded, err := stores[0].OpenSecret(st.BearerHashKey)
		if err != nil {
			return err
		}
		if encoded == st.BearerHashKey {
			t.Fatal("hash key stored as plaintext")
		}
		key, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return err
		}
		if len(key) != 32 {
			t.Fatal("hash key is not 256 bits")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("soundpost/bearer-authority/v1\x00server-api\x00"))
		mac.Write([]byte(token))
		want := "hmac-sha256:v1:" + hex.EncodeToString(mac.Sum(nil))
		if first != want {
			t.Fatal("stored authority digest is not the purpose-separated HMAC")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServerBearerAuthoritySurvivesRestartAndEnvelopeRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, dir)
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
	org, project, worker := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "keyed bearer regression"
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "organization"})
	command("create_project", auth.AdminPayload{ID: project, Name: "project"})
	command("create_user", auth.AdminPayload{ID: worker, Email: "worker@example.test", Password: "worker password long enough"})
	command("membership", auth.AdminPayload{UserID: worker, Enabled: true})
	command("grant", auth.AdminPayload{UserID: worker, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}})
	issued, err := service.IssueServerToken(ctx, actor, org, worker, []model.ID{project}, []auth.Permission{auth.Read}, time.Now().Add(365*24*time.Hour).Unix(), "operator chosen expiry")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := service.BearerDigest(auth.ServerAPIBearer, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	var sealedKey string
	if err := store.View(ctx, func(st control.State) error {
		sealedKey = st.BearerHashKey
		if _, ok := st.ServerTokens[digest]; !ok {
			t.Fatal("issued authority did not use keyed digest")
		}
		bare := sha256.Sum256([]byte(issued.Token))
		if _, ok := st.ServerTokens[hex.EncodeToString(bare[:])]; ok {
			t.Fatal("bare SHA256 authority record remained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	credential, err := service.Authenticate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := service.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := scope.VisibilityFingerprint()
	if _, err := store.RotateSecretKey(); err != nil {
		t.Fatal(err)
	}
	if err := service.Revalidate(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	service, err = auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, dir)
	again, err := service.BearerDigest(auth.ServerAPIBearer, issued.Token)
	if err != nil || again != digest {
		t.Fatal("envelope rotation/restart changed bearer hash authority")
	}
	if err := store.View(ctx, func(st control.State) error {
		if st.BearerHashKey != sealedKey {
			t.Fatal("restart replaced immutable hash key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	credential, err = service.Authenticate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err = service.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if scope.VisibilityFingerprint() != fingerprint {
		t.Fatal("rotation/restart changed token visibility ownership")
	}
	actor, err = service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeServerToken(ctx, actor, org, issued.ID, "revoke after restart"); err != nil {
		t.Fatal(err)
	}
	assertCode(t, service.Revalidate(ctx, scope), model.Unauthenticated)
	// Deliberately insert the old unreleased SHA256 format: there is no lookup shim.
	const obsolete = "obsolete server bearer fixture"
	sum := sha256.Sum256([]byte(obsolete))
	obsoleteRecord := model.ControlServerToken{ID: model.NewID(), Principal: worker, Org: org, Projects: []model.ID{project}, Permissions: []string{string(auth.Read)}, Expires: time.Now().Add(time.Hour).Unix()}
	if err := store.Update(ctx, func(st *control.State) error {
		st.ServerTokens[hex.EncodeToString(sum[:])] = obsoleteRecord
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = service.Authenticate(ctx, obsolete)
	assertCode(t, err, model.Unauthenticated)
}
