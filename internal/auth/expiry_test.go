// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func (f *cacheFixture) at() time.Time { return time.Unix(0, f.now.Load()) }
func (f *cacheFixture) advance(d time.Duration) {
	f.now.Add(int64(d))
}
func (f *cacheFixture) setClock(t time.Time) { f.now.Store(t.UnixNano()) }

// rawSource onboards a real restricted-raw source whose single named reader is
// reader. policyTTL is the source policy's expiration, sourceTTL the source's
// own lifetime (policy expiry may not exceed it).
func (f *cacheFixture) rawSource(reader model.ID, policyTTL, sourceTTL time.Duration) model.ID {
	f.t.Helper()
	source := model.NewID()
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Restricted: true, Readers: []model.ID{reader}, Enabled: true})
	f.cmd("source_policy", auth.AdminPayload{ID: source, Config: cfg})
	owner := f.session.User
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{{ID: "raw", Revision: 1, Line: "{msg}", Severity: "error", Fields: []model.TemplateField{{Name: "msg", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"}}}}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Expires: model.UnixNano(f.at().Add(policyTTL).UnixNano()), RawOwner: &owner, RawRationale: "expiry regression", RawMaxBytes: 128}
	if _, err := f.service.OnboardSource(f.ctx, f.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: source, Expires: model.UnixNano(f.at().Add(sourceTTL).UnixNano()), Policy: policy, Reason: "expiry regression"}); err != nil {
		f.t.Fatal(err)
	}
	return source
}
func (f *cacheFixture) relogin(email string) (auth.Credential, auth.Session) {
	f.t.Helper()
	login, err := f.service.Login(f.ctx, email, "cache reader password", "")
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.service.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return c, login
}
func visible(t *testing.T, f *cacheFixture, c auth.Credential, p auth.Permission, source model.ID) bool {
	t.Helper()
	scope, err := f.service.Authorize(f.ctx, c, f.org, []model.ID{f.project}, p)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := f.service.VisibleSources(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sources {
		if s.ID == source {
			return true
		}
	}
	return false
}

// Expiry is a pure clock event: nothing in the control state changes when a
// restricted-raw window closes. Every read path must still die at that instant,
// including a scope, ticket and cache entry minted one second earlier.
func TestRestrictedRawExpiryEndsEveryReadPathAtTheBoundary(t *testing.T) {
	f := newCacheFixture(t)
	reader, id := f.reader("expiring-reader@example.test", auth.RawRead)
	start := f.at()
	source := f.rawSource(id, 10*time.Minute, time.Hour)
	expiry := start.Add(10 * time.Minute)
	cache := f.cache(f.service.SourceLifecycleGenerations())
	f.setClock(expiry.Add(-time.Second))
	scope, err := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, source)
	if err != nil {
		t.Fatalf("source one second before expiry: %v", err)
	}
	if !visible(t, f, reader, auth.RawRead, source) {
		t.Fatal("source not discoverable before its window closes")
	}
	ticket, err := cache.IssueTicket(f.ctx, scope, "cursor", source, []byte("pos"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := cache.Lookup(f.ctx, scope, "raw", "q", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Store(f.ctx, scope, warm.Fill, []byte("raw-bytes"), false); err != nil {
		t.Fatal(err)
	}
	if got := cache.LatestEntryExpiry(); got.After(expiry) {
		t.Fatalf("cache entry outlives the source window by %v", got.Sub(expiry))
	}
	if _, _, err = cache.OpenTicket(f.ctx, scope, "cursor", ticket); err != nil {
		t.Fatalf("grant rejected before expiry: %v", err)
	}
	if res, err := cache.Lookup(f.ctx, scope, "raw", "q", "t"); err != nil || !res.Hit {
		t.Fatalf("warm entry lost before expiry: %v", err)
	}
	// One second past the boundary: epoch, fingerprint and delete generation are
	// unchanged, yet nothing minted earlier may work.
	f.setClock(expiry.Add(time.Second))
	if code(f.service.Revalidate(f.ctx, scope)) != model.NotFound {
		t.Fatalf("expired scope revalidated: %v", f.service.Revalidate(f.ctx, scope))
	}
	if _, _, err = cache.OpenTicket(f.ctx, scope, "cursor", ticket); code(err) != model.NotFound {
		t.Fatalf("grant minted before expiry opened after it: %v", err)
	}
	if _, err = cache.Lookup(f.ctx, scope, "raw", "q", "t"); code(err) != model.NotFound {
		t.Fatalf("warm entry served after expiry: %v", err)
	}
	if _, err = f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, source); code(err) != model.NotFound {
		t.Fatalf("expired source authorized afresh: %v", err)
	}
	if _, err = f.service.VisibleSources(f.ctx, scope); code(err) != model.NotFound {
		t.Fatalf("expired scope listed sources: %v", err)
	}
	if visible(t, f, reader, auth.RawRead, source) {
		t.Fatal("capabilities still list a source whose raw window closed")
	}
	// Indistinguishable from a guessed source.
	_, guessed := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, model.NewID())
	_, expired := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, source)
	if !sameDenial(guessed, expired) {
		t.Fatalf("expired source distinguishable from a guess: %v / %v", guessed, expired)
	}
}

// The source's own lifetime also ends raw read eligibility, even when its
// policy carries no expiration of its own.
func TestRestrictedRawSourceLifetimeAloneEndsReads(t *testing.T) {
	f := newCacheFixture(t)
	reader, id := f.reader("lifetime-reader@example.test", auth.RawRead)
	source := f.rawSource(id, 20*time.Minute, time.Hour)
	sourceEnds := f.at().Add(5 * time.Minute)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		src := st.Sources[source.String()]
		src.Policy.Expires = 0
		src.Expires = model.UnixNano(sourceEnds.UnixNano())
		st.Sources[source.String()] = src
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(sourceEnds.Add(-time.Second))
	scope, err := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, source)
	if err != nil || !visible(t, f, reader, auth.RawRead, source) {
		t.Fatalf("source unreadable before its lifetime ends: %v", err)
	}
	f.setClock(sourceEnds.Add(time.Second))
	if code(f.service.Revalidate(f.ctx, scope)) != model.NotFound {
		t.Fatal("scope outlived the source lifetime")
	}
	if _, err = f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, source); code(err) != model.NotFound {
		t.Fatalf("source past its lifetime authorized: %v", err)
	}
	if visible(t, f, reader, auth.RawRead, source) {
		t.Fatal("capabilities list a source past its lifetime")
	}
}

// Expiry of one source never touches another reader's source, and scopes
// without an expiring source (structured reads) are unaffected.
func TestNonExpiringAndLaterSourcesSurviveAnotherSourcesExpiry(t *testing.T) {
	f := newCacheFixture(t)
	reader, id := f.reader("mixed-reader@example.test", auth.RawRead)
	structured, _ := f.reader("structured-reader@example.test", auth.Read)
	cache := f.cache(f.service.SourceLifecycleGenerations())
	start := f.at()
	early := f.rawSource(id, 10*time.Minute, time.Hour)
	late := f.rawSource(id, 40*time.Minute, time.Hour)
	lateScope, err := f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, late)
	if err != nil {
		t.Fatal(err)
	}
	readScope := f.scope(structured, auth.Read)
	if !readScope.ExpiresAt().IsZero() {
		t.Fatal("a scope with no expiring source carries an expiry")
	}
	if got, want := lateScope.ExpiresAt(), start.Add(40*time.Minute); got.Sub(want).Abs() > time.Second {
		t.Fatalf("late scope expires at %v, want about %v", got, want)
	}
	lateTicket, err := cache.IssueTicket(f.ctx, lateScope, "cursor", late, nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	readTicket, err := cache.IssueTicket(f.ctx, readScope, "cursor", f.project, nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.setClock(start.Add(11 * time.Minute))
	if _, err = f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, early); code(err) != model.NotFound {
		t.Fatalf("early source still readable: %v", err)
	}
	if err = f.service.Revalidate(f.ctx, lateScope); err != nil {
		t.Fatalf("a later source was killed by an earlier source's expiry: %v", err)
	}
	if _, _, err = cache.OpenTicket(f.ctx, lateScope, "cursor", lateTicket); err != nil {
		t.Fatalf("later source's grant died early: %v", err)
	}
	if _, _, err = cache.OpenTicket(f.ctx, readScope, "cursor", readTicket); err != nil {
		t.Fatalf("structured grant died at an unrelated expiry: %v", err)
	}
	if !visible(t, f, reader, auth.RawRead, late) || visible(t, f, reader, auth.RawRead, early) {
		t.Fatal("capabilities disagree with authorization at the boundary")
	}
	// A grant cannot be minted to outlive its source window.
	f.setClock(start.Add(39*time.Minute + 30*time.Second))
	lateScope, err = f.service.AuthorizeRestrictedSource(f.ctx, reader, f.org, f.project, late)
	if err != nil {
		t.Fatal(err)
	}
	last, err := cache.IssueTicket(f.ctx, lateScope, "cursor", late, nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.setClock(start.Add(40*time.Minute + time.Second))
	if _, _, err = cache.OpenTicket(f.ctx, lateScope, "cursor", last); code(err) != model.NotFound {
		t.Fatalf("15 minute grant minted 30 s before expiry survived it: %v", err)
	}
}

func elevationID(t *testing.T, e auth.Elevation) model.ID {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ ID model.ID }
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

// Every target-dependent elevation denial is one NotFound, so a caller cannot
// learn whether an elevation ID exists, belongs to someone else, or expired.
func TestElevationDenialsAreOneIndistinguishableNotFound(t *testing.T) {
	f := newCacheFixture(t)
	other := f.otherOrg()
	reader, _ := f.reader("elevation-prober@example.test", auth.Read)
	elevation, err := f.service.Elevate(f.ctx, f.session, "elevation oracle regression", []model.ID{f.org})
	if err != nil {
		t.Fatal(err)
	}
	id := elevationID(t, elevation)
	if _, err = f.service.ResolveElevation(f.ctx, f.actor, id); err != nil {
		t.Fatalf("own valid elevation rejected: %v", err)
	}
	foreign := func() error { _, e := f.service.ResolveElevation(f.ctx, reader, id); return e }
	guessed := func() error { _, e := f.service.ResolveElevation(f.ctx, reader, model.NewID()); return e }
	owned, err := f.service.ResolveElevation(f.ctx, f.actor, id)
	if err != nil {
		t.Fatal(err)
	}
	uncovered := func() error {
		_, e := f.service.ElevatedScope(f.ctx, owned, other, []model.ID{f.project}, auth.Read)
		return e
	}
	want := guessed()
	if code(want) != model.NotFound {
		t.Fatalf("guessed elevation: %v", want)
	}
	for name, got := range map[string]error{"foreign existing": foreign(), "own on an uncovered org": uncovered()} {
		if !sameDenial(got, want) {
			t.Fatalf("%s elevation denial %v differs from a guess %v", name, got, want)
		}
	}
	f.advance(16 * time.Minute)
	_, expired := f.service.ResolveElevation(f.ctx, f.actor, id)
	if !sameDenial(expired, want) {
		t.Fatalf("expired elevation denial %v differs from a guess %v", expired, want)
	}
	// A real credential failure does not depend on the target and stays distinct.
	if err = f.service.Logout(f.ctx, f.session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ResolveElevation(f.ctx, f.actor, id); code(err) != model.Unauthenticated {
		t.Fatalf("dead session: %v", err)
	}
}

// Logout + Login must kill every outstanding ticket and warm entry even though
// the principal, grants, epoch and delete generation are unchanged.
func TestSessionRotationKillsTicketsAndWarmEntries(t *testing.T) {
	f := newCacheFixture(t)
	first, session := f.readerSession("rotating@example.test", auth.Read)
	cache := f.cache(f.service.SourceLifecycleGenerations())
	before := f.scope(first, auth.Read)
	ticket, err := cache.IssueTicket(f.ctx, before, "export", model.NewID(), nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := cache.Lookup(f.ctx, before, "p", "q", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Store(f.ctx, before, warm.Fill, []byte("warm"), false); err != nil {
		t.Fatal(err)
	}
	// Same session, fresh scope: tickets and entries remain usable.
	again := f.scope(first, auth.Read)
	if _, _, err = cache.OpenTicket(f.ctx, again, "export", ticket); err != nil {
		t.Fatalf("same session's own ticket rejected: %v", err)
	}
	if res, err := cache.Lookup(f.ctx, again, "p", "q", "t"); err != nil || !res.Hit {
		t.Fatal("same session lost its warm entry", err)
	}
	// Rotate: logout then login again.
	email := "rotating@example.test"
	if err = f.service.Logout(f.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	second, _ := f.relogin(email)
	after := f.scope(second, auth.Read)
	if before.PolicyEpoch() != after.PolicyEpoch() {
		t.Fatal("fixture must keep the policy epoch")
	}
	if before.VisibilityFingerprint() == after.VisibilityFingerprint() {
		t.Fatal("a rotated session shares the previous session's fingerprint")
	}
	if _, _, err = cache.OpenTicket(f.ctx, after, "export", ticket); code(err) != model.NotFound {
		t.Fatalf("ticket minted before logout opened after login: %v", err)
	}
	if res, err := cache.Lookup(f.ctx, after, "p", "q", "t"); err != nil || res.Hit {
		t.Fatal("warm entry survived session rotation", err)
	}
	// A session that never logged out is a separate session too.
	third, _ := f.relogin(email)
	if f.scope(third, auth.Read).VisibilityFingerprint() == after.VisibilityFingerprint() {
		t.Fatal("two concurrent sessions share a fingerprint")
	}
}

// readerSession is reader() that also returns the live session, for tests that
// rotate it.
func (f *cacheFixture) readerSession(email string, permissions ...auth.Permission) (auth.Credential, auth.Session) {
	f.t.Helper()
	id := model.NewID()
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	f.cmd("create_user", auth.AdminPayload{ID: id, Email: email, Password: "cache reader password"})
	f.cmd("membership", auth.AdminPayload{UserID: id, Enabled: true})
	f.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: f.project, Enabled: true, Permissions: ps})
	return f.relogin(email)
}

// otherOrg creates a second organization the fixture's reader knows nothing of.
func (f *cacheFixture) otherOrg() model.ID {
	f.t.Helper()
	org := model.NewID()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	raw, _ := json.Marshal(auth.AdminPayload{Name: "other org", Reason: "cache regression"})
	if _, err := f.service.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: "create_org", Payload: raw}); err != nil {
		f.t.Fatal(err)
	}
	return org
}

// sameDenial compares what a client can observe of two denials: the code,
// retry hint and public detail. The per-request correlation ID is by design
// unique to each request.
func sameDenial(a, b error) bool {
	var x, y *model.Fault
	if !errors.As(a, &x) || !errors.As(b, &y) {
		return false
	}
	return x.Code == y.Code && x.Retryable == y.Retryable && x.SafeDetail == y.SafeDetail
}
