// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Every authenticated request reads the control state several times before it does any work: the credential
// (Authenticate), the session (CSRF), the scope (Authorize), the cache binding (Revalidate with the delete
// generation), and the periodic sweep and capacity check. Each of those decoded the whole control blob for a State of
// its own, once per request, at 1.8 MB of JSON. They read the decode every reader of the revision shares, which a
// commit makes the members it changed decode again and no more.
func TestQueryPathReadsOfTheAuthServiceDoNotDecodeTheBlob(t *testing.T) {
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	admin, e := service.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org := model.NewID()
	command := func(kind string, p auth.AdminPayload, at model.ID) {
		t.Helper()
		rev, e := store.Revision(ctx)
		if e != nil {
			t.Fatal(e)
		}
		p.Reason = "query path decode test"
		raw, _ := json.Marshal(p)
		if _, e := service.AdminCommand(ctx, admin, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: at, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "org"}, org)
	scope, e := service.Authorize(ctx, admin, org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	cache, e := auth.NewCache(service, service.SourceLifecycleGenerations(), 16, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	request := func() {
		t.Helper()
		if _, e := service.Authenticate(ctx, session.Token); e != nil {
			t.Fatalf("Authenticate: %v", e)
		}
		if _, e := service.Session(ctx, session.Token); e != nil {
			t.Fatalf("Session: %v", e)
		}
		if _, e := service.Authorize(ctx, admin, org, nil, auth.OrgAdmin); e != nil {
			t.Fatalf("Authorize: %v", e)
		}
		if _, e := cache.Lookup(ctx, scope, "profile", "query", "params"); e != nil {
			t.Fatalf("cache binding: %v", e)
		}
		if e := service.OIDCCapacity(ctx); e != nil {
			t.Fatalf("OIDCCapacity: %v", e)
		}
		if _, e := service.SweepExpired(ctx); e != nil {
			t.Fatalf("SweepExpired: %v", e)
		}
	}
	request() // what the first request decodes is shared by the rest
	before := store.DecodeStats()
	for range 10 {
		request()
	}
	got := store.DecodeStats()
	if n := got.Blobs - before.Blobs; n != 0 {
		t.Errorf("10 requests decoded the whole blob %d times in the reads of the auth service, want never", n)
	}
	if n := got.Members - before.Members; n != 0 {
		t.Errorf("10 requests of one revision decoded %d members, want none", n)
	}
	// A commit costs the requests after it the members it changed, once, and never the whole state.
	command("create_project", auth.AdminPayload{ID: model.NewID(), Name: "project"}, org)
	if scope, e = service.Authorize(ctx, admin, org, nil, auth.OrgAdmin); e != nil {
		t.Fatal(e)
	}
	before = store.DecodeStats()
	for range 10 {
		request()
	}
	got = store.DecodeStats()
	if n := got.Blobs - before.Blobs; n != 0 {
		t.Errorf("after a commit, 10 requests decoded the whole blob %d times, want never", n)
	}
	if n := got.Whole - before.Whole; n != 0 {
		t.Errorf("after a commit, 10 requests decoded the whole state %d times, want the members it changed only", n)
	}
}
