// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// structuredSource onboards a real structured source in the fixture's project.
func (f *cacheFixture) structuredSource() model.ID {
	f.t.Helper()
	source := model.NewID()
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100}
	if _, err := f.service.OnboardSource(f.ctx, f.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: source, Expires: model.UnixNano(f.at().Add(time.Hour).UnixNano()), Policy: policy, Reason: "lifecycle read regression"}); err != nil {
		f.t.Fatal(err)
	}
	return source
}

// sourceState is the state the capability listing reports for source, "" when it is not listed.
func sourceState(t *testing.T, f *cacheFixture, c auth.Credential, p auth.Permission, source model.ID) string {
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
			return s.State
		}
	}
	return ""
}

// TestRevokedRetiredAndClosingSourcesStayReadable pins decision D11: revoking, retiring or
// closing a source stops its ingest, not the readability of what it already delivered. Readers
// keep the same scope (named-reader rule for restricted raw, project grant for structured), the
// source stays listed with its state, and a reader who was never granted still learns nothing.
func TestRevokedRetiredAndClosingSourcesStayReadable(t *testing.T) {
	f := newCacheFixture(t)
	raw, rawID := f.reader("raw-reader@example.test", auth.RawRead)
	stranger, _ := f.reader("raw-stranger@example.test", auth.RawRead)
	telemetry, _ := f.reader("telemetry-reader@example.test", auth.Read)
	rawSource := f.rawSource(rawID, time.Hour, 2*time.Hour)
	structured := f.structuredSource()
	cache := f.cache(f.service.SourceLifecycleGenerations())

	if got := sourceState(t, f, raw, auth.RawRead, rawSource); got != "active" {
		t.Fatalf("raw source before any change: state %q", got)
	}
	if got := sourceState(t, f, telemetry, auth.Read, structured); got != "active" {
		t.Fatalf("structured source before any change: state %q", got)
	}
	before, err := f.service.AuthorizeRestrictedSource(f.ctx, raw, f.org, f.project, rawSource)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := cache.Lookup(f.ctx, before, "raw", "q", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Store(f.ctx, before, filled.Fill, []byte("raw-bytes"), false); err != nil {
		t.Fatal(err)
	}

	// Revocation closes the source (Revoked and Closing); it must stay readable and listed.
	if err = f.service.RevokeSource(f.ctx, f.actor, rawSource, "credential leaked"); err != nil {
		t.Fatal(err)
	}
	if err = f.service.RevokeSource(f.ctx, f.actor, structured, "credential leaked"); err != nil {
		t.Fatal(err)
	}
	// A scope minted before the revocation belongs to an older policy epoch and is dead, as for
	// any policy change; the delete generation moved too, so no cached result outlives it.
	if code(f.service.Revalidate(f.ctx, before)) != model.NotFound {
		t.Fatal("a scope minted before the revocation kept working")
	}
	after, err := f.service.AuthorizeRestrictedSource(f.ctx, raw, f.org, f.project, rawSource)
	if err != nil {
		t.Fatalf("revoked restricted source is no longer readable by its named reader: %v", err)
	}
	if got := sourceState(t, f, raw, auth.RawRead, rawSource); got != "revoked" {
		t.Fatalf("revoked raw source listed with state %q, want revoked", got)
	}
	if got := sourceState(t, f, telemetry, auth.Read, structured); got != "revoked" {
		t.Fatalf("revoked structured source listed with state %q, want revoked", got)
	}
	// The same scoping as a live source: an ungranted principal learns nothing and the denial
	// is the guessed-source denial.
	_, guessed := f.service.AuthorizeRestrictedSource(f.ctx, stranger, f.org, f.project, model.NewID())
	_, denied := f.service.AuthorizeRestrictedSource(f.ctx, stranger, f.org, f.project, rawSource)
	if !sameDenial(guessed, denied) {
		t.Fatalf("revoked source distinguishable from a guess: %v / %v", guessed, denied)
	}
	if got := sourceState(t, f, telemetry, auth.Read, rawSource); got != "" {
		t.Fatalf("telemetry reader sees the restricted source (state %q)", got)
	}
	if got := sourceState(t, f, stranger, auth.RawRead, rawSource); got != "" {
		t.Fatalf("an unnamed raw reader sees the restricted source (state %q)", got)
	}
	// The raw window clock still ends read eligibility (decision D6), revoked or not.
	if end := after.ExpiresAt(); end.IsZero() || end.After(f.at().Add(time.Hour+time.Second)) {
		t.Fatalf("revoked source lost its policy-expiry clamp: %v", end)
	}

	// Retired and closing states, set the way the deletion saga and a policy change set them.
	retire := func(state func(*model.SourceAuthority), id model.ID) {
		t.Helper()
		if err := f.store.Update(f.ctx, func(st *model.ControlState) error {
			src := st.Sources[id.String()]
			state(&src)
			st.Sources[id.String()] = src
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	closing, retired := f.structuredSource(), f.structuredSource()
	retire(func(s *model.SourceAuthority) { s.Closing = true }, closing)
	retire(func(s *model.SourceAuthority) { s.Retired = true }, retired)
	if got := sourceState(t, f, telemetry, auth.Read, closing); got != "closing" {
		t.Fatalf("closing source listed with state %q, want closing", got)
	}
	if got := sourceState(t, f, telemetry, auth.Read, retired); got != "retired" {
		t.Fatalf("retired source listed with state %q, want retired", got)
	}
}
