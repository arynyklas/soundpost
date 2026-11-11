// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sweepFixture struct {
	ctx     context.Context
	store   *control.Store
	service *auth.Service
	now     *time.Time
	cfg     auth.OIDCConfig
	fetches *atomic.Int64
	session auth.Session
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()
	f := &sweepFixture{fetches: &atomic.Int64{}}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuer = server.URL
	f.ctx = context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = store
	now := time.Now()
	f.now = &now
	f.service, err = auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return *f.now }})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	f.session, err = f.service.Bootstrap(f.ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = auth.OIDCConfig{Issuer: issuer, ClientID: "client", RedirectURL: "https://soundpost.example.test/api/v1/oidc/callback", Subjects: map[string]model.ID{"s": f.session.User}}
	return f
}
func (f *sweepFixture) oidcRecords(t *testing.T) (pending, elevations int) {
	t.Helper()
	_ = f.store.View(f.ctx, func(st control.State) error {
		for k := range st.OIDC {
			if strings.HasPrefix(k, "elevation:") {
				elevations++
			} else {
				pending++
			}
		}
		return nil
	})
	return
}

// I-1: abandoned starts must not stay in replicated state after expiry.
func TestSweepRemovesExpiredAbandonedOIDCStarts(t *testing.T) {
	f := newSweepFixture(t)
	base, _ := f.oidcRecords(t)
	const n = 12
	for i := 0; i < n; i++ {
		if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := f.oidcRecords(t); p-base != n {
		t.Fatalf("setup: %d pending", p-base)
	}
	if removed, err := f.service.SweepExpired(f.ctx); err != nil || removed != 0 {
		t.Fatalf("live records swept: %d %v", removed, err)
	}
	if p, _ := f.oidcRecords(t); p-base != n {
		t.Fatal("sweep removed unexpired pending state")
	}
	*f.now = f.now.Add(6 * time.Minute)
	removed, err := f.service.SweepExpired(f.ctx)
	if err != nil || removed != n {
		t.Fatalf("removed %d err %v, want %d", removed, err, n)
	}
	if p, _ := f.oidcRecords(t); p != base {
		t.Fatalf("%d abandoned records survive expiry", p-base)
	}
}

// A live pending record is still consumed by its callback; an expired one is refused.
func TestSweepKeepsLiveStateAndExpiredCallbackRefused(t *testing.T) {
	f := newSweepFixture(t)
	start, err := f.service.OIDCStart(f.ctx, f.cfg, "binding")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start)
	state := u.Query().Get("state")
	*f.now = f.now.Add(4 * time.Minute)
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 0 {
		t.Fatalf("swept live: %d %v", n, err)
	}
	*f.now = f.now.Add(2 * time.Minute)
	if _, err := f.service.SweepExpired(f.ctx); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.OIDCCallback(f.ctx, f.cfg, "binding", state, "code")
	assertCode(t, err, model.Unauthenticated)
}

// I-1(b): the number of live pending records is capped; at the cap no outbound
// discovery fetch and no state write happen, and the error is typed retryable.
func TestOIDCStartCapsLivePendingRecords(t *testing.T) {
	f := newSweepFixture(t)
	const limit = 8
	t.Cleanup(auth.SetPendingOIDCCap(limit))
	for i := 0; i < limit; i++ {
		if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	fetches := f.fetches.Load()
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	_, err := f.service.OIDCStart(f.ctx, f.cfg, "binding")
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("want retryable unavailable, got %v", err)
	}
	if f.fetches.Load() != fetches {
		t.Fatal("outbound discovery fetch at cap")
	}
	var after model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { after = st.Revision; return nil })
	if after != rev {
		t.Fatal("state written at cap")
	}
	if err := f.service.OIDCCapacity(f.ctx); err == nil {
		t.Fatal("capacity probe passes at cap")
	}
	*f.now = f.now.Add(5 * time.Minute)
	if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
		t.Fatalf("expired records still count against cap: %v", err)
	}
}

// M-3: elevation records are collected after expiry; audits are retained.
func TestSweepRemovesExpiredElevationRecordsKeepsAudits(t *testing.T) {
	f := newSweepFixture(t)
	c, err := f.service.Authenticate(f.ctx, f.session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org := model.NewID()
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "org", Reason: "sweep test"})
	if _, err = f.service.AdminCommand(f.ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	var live auth.Elevation
	for i := 0; i < 5; i++ {
		el, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.ElevatedScope(f.ctx, el, org, nil, auth.Read); err != nil {
			t.Fatal(err)
		}
		live = el
	}
	audits := func() (n int) {
		_ = f.store.View(f.ctx, func(st control.State) error { n = len(st.Audits); return nil })
		return
	}
	before := audits()
	if _, e := f.oidcRecords(t); e != 5 {
		t.Fatalf("setup: %d elevation records", e)
	}
	*f.now = f.now.Add(16 * time.Minute)
	if _, err := f.service.SweepExpired(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, e := f.oidcRecords(t); e != 0 {
		t.Fatalf("%d expired elevation records survive", e)
	}
	if audits() != before {
		t.Fatal("sweep deleted audit rows")
	}
	_, err = f.service.ResolveElevation(f.ctx, c, live.ID())
	assertCode(t, err, model.NotFound)
}

// A live elevation survives the sweep and still resolves.
func TestSweepKeepsLiveElevation(t *testing.T) {
	f := newSweepFixture(t)
	c, _ := f.service.Authenticate(f.ctx, f.session.Token)
	org := model.NewID()
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "org", Reason: "sweep test"})
	if _, err := f.service.AdminCommand(f.ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	el, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
	if err != nil {
		t.Fatal(err)
	}
	*f.now = f.now.Add(5 * time.Minute)
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 0 {
		t.Fatalf("swept live elevation %d %v", n, err)
	}
	if _, err := f.service.ResolveElevation(f.ctx, c, el.ID()); err != nil {
		t.Fatal(err)
	}
}

// The sweep expires at the same boundary the callback refuses at, and never
// touches other residents of the OIDC map (restore stash, unrecognized entries).
func TestSweepBoundaryAndForeignResidents(t *testing.T) {
	f := newSweepFixture(t)
	if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
		t.Fatal(err)
	}
	foreign := json.RawMessage(`{"State":"x","Expires":1}`)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.OIDC["restore:quarantine"] = foreign
		st.OIDC["unrelated"] = foreign
		st.OIDC["elevation:garbage"] = json.RawMessage(`"not a record"`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	*f.now = f.now.Add(5*time.Minute - time.Second)
	if n, _ := f.service.SweepExpired(f.ctx); n != 0 {
		t.Fatalf("swept %d before expiry", n)
	}
	*f.now = f.now.Add(time.Second)
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 1 {
		t.Fatalf("swept %d err %v at exact expiry, want 1", n, err)
	}
	_ = f.store.View(f.ctx, func(st control.State) error {
		for _, k := range []string{"restore:quarantine", "unrelated", "elevation:garbage"} {
			if _, ok := st.OIDC[k]; !ok {
				t.Fatalf("foreign resident %q deleted", k)
			}
		}
		return nil
	})
}

// Elevation records expire at the instant resolution refuses (15 minutes exactly).
func TestSweepElevationBoundary(t *testing.T) {
	f := newSweepFixture(t)
	c, _ := f.service.Authenticate(f.ctx, f.session.Token)
	org := model.NewID()
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "org", Reason: "sweep test"})
	if _, err := f.service.AdminCommand(f.ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	el, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
	if err != nil {
		t.Fatal(err)
	}
	*f.now = time.Unix(el.ExpiresAt(), 0).Add(-time.Second)
	if n, _ := f.service.SweepExpired(f.ctx); n != 0 {
		t.Fatalf("swept %d before expiry", n)
	}
	*f.now = time.Unix(el.ExpiresAt(), 0)
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 1 {
		t.Fatalf("swept %d err %v at exact expiry, want 1", n, err)
	}
}

// OIDCStart itself collects expired pending state, so growth is bounded even
// if the periodic sweep is not wired.
func TestOIDCStartCollectsExpiredPending(t *testing.T) {
	f := newSweepFixture(t)
	base, _ := f.oidcRecords(t)
	for i := 0; i < 5; i++ {
		if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
			t.Fatal(err)
		}
	}
	*f.now = f.now.Add(6 * time.Minute)
	if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.oidcRecords(t); p-base != 1 {
		t.Fatalf("%d pending after start past expiry, want 1", p-base)
	}
}
