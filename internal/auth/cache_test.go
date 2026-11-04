// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"sync/atomic"
	"testing"
	"time"
)

type cacheFixture struct {
	t       *testing.T
	ctx     context.Context
	store   *control.Store
	service *auth.Service
	actor   auth.Credential
	org     model.ID
	project model.ID
	now     atomic.Int64
}

type bumpDeletes struct {
	base auth.DeleteGenerations
	n    atomic.Uint64
}

func (b *bumpDeletes) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	v, err := b.base.DeleteGeneration(ctx, org, projects)
	return v + b.n.Load(), err
}
func newCacheFixture(t *testing.T) *cacheFixture {
	t.Helper()
	f := &cacheFixture{t: t, ctx: context.Background()}
	f.now.Store(time.Now().UnixNano())
	var err error
	if f.store, err = control.Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.service, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return time.Unix(0, f.now.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, f.store, t.TempDir())
	boot, _ := f.store.BootstrapToken()
	session, err := f.service.Bootstrap(f.ctx, boot, "cache-owner@example.test", "cache owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	if f.actor, err = f.service.Authenticate(f.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	f.org, f.project = model.NewID(), model.NewID()
	f.cmd("create_org", auth.AdminPayload{Name: "cache org"})
	f.cmd("create_project", auth.AdminPayload{ID: f.project, Name: "p"})
	return f
}
func (f *cacheFixture) cmd(kind string, p auth.AdminPayload) {
	f.t.Helper()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	p.Reason = "cache regression"
	raw, _ := json.Marshal(p)
	if _, err := f.service.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: f.org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}
func (f *cacheFixture) reader(email string, permissions ...auth.Permission) (auth.Credential, model.ID) {
	f.t.Helper()
	id := model.NewID()
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	f.cmd("create_user", auth.AdminPayload{ID: id, Email: email, Password: "cache reader password"})
	f.cmd("membership", auth.AdminPayload{UserID: id, Enabled: true})
	f.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: f.project, Enabled: true, Permissions: ps})
	login, err := f.service.Login(f.ctx, email, "cache reader password", "")
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.service.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return c, id
}
func (f *cacheFixture) cache(deletes auth.DeleteGenerations) *auth.Cache {
	c, err := auth.NewCache(f.service, deletes, 8, time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}
func (f *cacheFixture) scope(c auth.Credential, p auth.Permission) auth.Scope {
	f.t.Helper()
	s, err := f.service.Authorize(f.ctx, c, f.org, []model.ID{f.project}, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func code(err error) model.Code {
	if f, ok := err.(*model.Fault); ok {
		return f.Code
	}
	return ""
}

func TestCacheKeysBindPrincipalEpochAndDeleteGeneration(t *testing.T) {
	f := newCacheFixture(t)
	a, _ := f.reader("a@example.test", auth.Read)
	b, _ := f.reader("b@example.test", auth.Read)
	deletes := &bumpDeletes{base: f.service.SourceLifecycleGenerations()}
	cache := f.cache(deletes)
	as, bs := f.scope(a, auth.Read), f.scope(b, auth.Read)
	if as.PolicyEpoch() != bs.PolicyEpoch() || as.VisibilityFingerprint() == bs.VisibilityFingerprint() {
		t.Fatal("equal org/epoch/project/action readers must still have distinct fingerprints")
	}
	store := func(s auth.Scope, query, value string, negative bool) {
		t.Helper()
		res, err := cache.Lookup(f.ctx, s, "p", query, "t")
		if err != nil || res.Hit {
			t.Fatal("expected a cold miss", err)
		}
		v := []byte(value)
		if negative {
			v = nil
		}
		if err = cache.Store(f.ctx, s, res.Fill, v, negative); err != nil {
			t.Fatal(err)
		}
	}
	store(as, "q", "alice-positive", false)
	store(as, "missing", "", true)
	if res, err := cache.Lookup(f.ctx, as, "p", "q", "t"); err != nil || !res.Hit || res.Negative || string(res.Value) != "alice-positive" {
		t.Fatal("owner lost its warm positive entry", err)
	}
	if res, err := cache.Lookup(f.ctx, as, "p", "missing", "t"); err != nil || !res.Hit || !res.Negative {
		t.Fatal("owner lost its warm negative entry", err)
	}
	for _, q := range []string{"q", "missing"} {
		if res, err := cache.Lookup(f.ctx, bs, "p", q, "t"); err != nil || res.Hit {
			t.Fatalf("second principal hit the first principal's %q entry", q)
		}
	}
	// A different profile or time params never share an entry either.
	if res, _ := cache.Lookup(f.ctx, as, "other", "q", "t"); res.Hit {
		t.Fatal("profile not part of key")
	}
	if res, _ := cache.Lookup(f.ctx, as, "p", "q", "t2"); res.Hit {
		t.Fatal("time params not part of key")
	}
	// A fill computed before a deletion cannot be stored after it.
	miss, err := cache.Lookup(f.ctx, bs, "p", "late", "t")
	if err != nil {
		t.Fatal(err)
	}
	deletes.n.Add(1)
	if err = cache.Store(f.ctx, bs, miss.Fill, []byte("stale"), false); code(err) != model.Stale {
		t.Fatalf("pre-deletion fill stored after deletion: %v", err)
	}
	if res, err := cache.Lookup(f.ctx, as, "p", "q", "t"); err != nil || res.Hit {
		t.Fatal("entry survived a delete generation advance", err)
	}
}

func TestCacheLookupRevalidatesScopeBeforeAnyEntry(t *testing.T) {
	f := newCacheFixture(t)
	a, id := f.reader("revoked@example.test", auth.Read)
	cache := f.cache(f.service.SourceLifecycleGenerations())
	s := f.scope(a, auth.Read)
	res, err := cache.Lookup(f.ctx, s, "p", "q", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Store(f.ctx, s, res.Fill, []byte("warm"), false); err != nil {
		t.Fatal(err)
	}
	f.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: f.project, Enabled: false})
	if _, err = cache.Lookup(f.ctx, s, "p", "q", "t"); code(err) != model.NotFound {
		t.Fatalf("revoked scope reached a warm entry: %v", err)
	}
	if _, err = cache.IssueTicket(f.ctx, s, "cursor", model.NewID(), nil, time.Minute); code(err) != model.NotFound {
		t.Fatalf("revoked scope minted a ticket: %v", err)
	}
	if err = cache.Store(f.ctx, s, res.Fill, []byte("x"), false); code(err) != model.NotFound {
		t.Fatalf("revoked scope stored an entry: %v", err)
	}
}

func TestTicketsAreBoundExpireAndRejectForgery(t *testing.T) {
	f := newCacheFixture(t)
	a, _ := f.reader("t-a@example.test", auth.Read)
	b, _ := f.reader("t-b@example.test", auth.Read)
	deletes := &bumpDeletes{base: f.service.SourceLifecycleGenerations()}
	cache := f.cache(deletes)
	as, bs := f.scope(a, auth.Read), f.scope(b, auth.Read)
	subject := model.NewID()
	token, err := cache.IssueTicket(f.ctx, as, "cursor", subject, []byte("pos-7"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, state, err := cache.OpenTicket(f.ctx, as, "cursor", token); err != nil || got != subject || string(state) != "pos-7" {
		t.Fatal("owner ticket rejected", err)
	}
	for name, try := range map[string]func() error{
		"other principal": func() error { _, _, e := cache.OpenTicket(f.ctx, bs, "cursor", token); return e },
		"other kind":      func() error { _, _, e := cache.OpenTicket(f.ctx, as, "live", token); return e },
		"truncated":       func() error { _, _, e := cache.OpenTicket(f.ctx, as, "cursor", token[:len(token)-2]); return e },
		"flipped":         func() error { _, _, e := cache.OpenTicket(f.ctx, as, "cursor", "A"+token[1:]); return e },
		"garbage":         func() error { _, _, e := cache.OpenTicket(f.ctx, as, "cursor", "!!!"); return e },
	} {
		if code(try()) != model.NotFound {
			t.Fatalf("%s ticket was not a plain NotFound", name)
		}
	}
	if _, err = cache.IssueTicket(f.ctx, as, "cursor", subject, nil, time.Hour); code(err) != model.Invalid {
		t.Fatal("ticket lifetime is not bounded", err)
	}
	f.now.Add(int64(2 * time.Minute))
	// Re-authorize at the advanced clock so only the ticket itself is expired.
	as = f.scope(a, auth.Read)
	if _, _, err = cache.OpenTicket(f.ctx, as, "cursor", token); code(err) != model.NotFound {
		t.Fatal("expired ticket opened", err)
	}
	fresh, err := cache.IssueTicket(f.ctx, as, "cursor", subject, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deletes.n.Add(1)
	if _, _, err = cache.OpenTicket(f.ctx, as, "cursor", fresh); code(err) != model.NotFound {
		t.Fatal("ticket survived a delete generation advance", err)
	}
}

func TestSelectedNamedSourceIsPartOfTheFingerprint(t *testing.T) {
	f := newCacheFixture(t)
	reader, id := f.reader("two-sources@example.test", auth.RawRead)
	sources := []model.ID{model.NewID(), model.NewID()}
	for _, s := range sources {
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Restricted: true, Readers: []model.ID{id}, Enabled: true})
		f.cmd("source_policy", auth.AdminPayload{ID: s, Config: cfg})
	}
	var fingerprints [2]string
	for i, s := range sources {
		sc, err := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, s)
		if err != nil {
			t.Fatal(err)
		}
		fingerprints[i] = sc.VisibilityFingerprint()
	}
	if fingerprints[0] == fingerprints[1] {
		t.Fatal("one reader's two selected sources share a cache fingerprint")
	}
	cache := f.cache(f.service.SourceLifecycleGenerations())
	first, _ := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, sources[0])
	second, _ := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, sources[1])
	res, err := cache.Lookup(f.ctx, first, "p", "q", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Store(f.ctx, first, res.Fill, []byte("source-one"), false); err != nil {
		t.Fatal(err)
	}
	if again, err := cache.Lookup(f.ctx, second, "p", "q", "t"); err != nil || again.Hit {
		t.Fatal("selected source two reused source one's warm entry", err)
	}
	token, _ := cache.IssueTicket(f.ctx, first, "cursor", sources[0], nil, time.Minute)
	if _, _, err = cache.OpenTicket(f.ctx, second, "cursor", token); code(err) != model.NotFound {
		t.Fatal("cursor of source one resumed under source two", err)
	}
}
