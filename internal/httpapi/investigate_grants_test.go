// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// The replay and profile investigations are navigation to a target that needs its OWN grant (replay.read / profiles.read), asked per requested
// project through the caller's own credential by the route itself. This drives POST /api/v1/investigate with real sessions and real grants.
func TestInvestigateRouteAsksForTheSeparateGrantOfTheTargetKindOnEveryProject(t *testing.T) {
	e := newIsoEnv(t)
	pA, pB := model.NewID(), model.NewID()
	org := e.org("investigate grants", pA, pB)
	target := model.NewID()
	links := &fakeLinks{available: map[model.ID]bool{target: true}}
	inv, err := httpapi.NewInvestigator(e.app.Auth, &fakeDiscovery{}, links)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterInvestigateRoutes(mux, e.app.Auth, inv) }).Handler)
	t.Cleanup(srv.Close)
	ev := &evEnv{isoEnv: e, srv: srv}

	telemetryOnly := e.user(org, "inv-telemetry@example.test")
	e.grant(org, telemetryOnly, pA, true, auth.Read)
	e.grant(org, telemetryOnly, pB, true, auth.Read)
	replayOnA := e.user(org, "inv-replay-a@example.test")
	e.grant(org, replayOnA, pA, true, auth.Read, httpapi.ReplayRead)
	e.grant(org, replayOnA, pB, true, auth.Read)
	profilesOnBoth := e.user(org, "inv-profiles@example.test")
	e.grant(org, profilesOnBoth, pA, true, auth.Read, httpapi.ProfilesRead)
	e.grant(org, profilesOnBoth, pB, true, auth.Read, httpapi.ProfilesRead)

	post := func(who person, kind string, tgt model.ID, projects ...model.ID) (int, httpapi.InvestigationView) {
		t.Helper()
		ids := make([]string, len(projects))
		for i, p := range projects {
			ids[i] = p.String()
		}
		status, raw := ev.post(who, "/api/v1/investigate", map[string]any{"org": org.String(), "kind": kind, "projects": ids, "target": tgt.String(), "window": map[string]any{"start": "10", "end": "20"}, "limit": 10}, nil)
		if status != 200 {
			return status, httpapi.InvestigationView{}
		}
		return status, decodeView(t, raw)
	}
	grantRequired := func(name string, status int, v httpapi.InvestigationView) {
		t.Helper()
		if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonGrantRequired || v.Link != nil {
			t.Fatalf("%s: want the one typed grant-required answer, got %d %+v", name, status, v)
		}
	}
	linked := func(name string, kind string, status int, v httpapi.InvestigationView) {
		t.Helper()
		if status != 200 || v.State != httpapi.StateReady || v.Link == nil || !v.Link.Available || v.Link.Kind != kind || v.Link.ID != target {
			t.Fatalf("%s: want a ready %s link, got %d %+v", name, kind, status, v)
		}
	}

	// Without the separate grant the target is never probed, whatever telemetry.read says.
	status, v := post(telemetryOnly, "replay", target, pA)
	grantRequired("telemetry.read only, replay", status, v)
	status, v = post(telemetryOnly, "profile", target, pA)
	grantRequired("telemetry.read only, profile", status, v)
	if links.calls != 0 {
		t.Fatalf("the target was probed %d time(s) for callers without the separate grant", links.calls)
	}
	// The grant of the other kind is no grant for this one.
	status, v = post(replayOnA, "profile", target, pA)
	grantRequired("replay.read asked for a profile", status, v)
	status, v = post(profilesOnBoth, "replay", target, pA, pB)
	grantRequired("profiles.read asked for a replay", status, v)
	if links.calls != 0 {
		t.Fatalf("the target was probed %d time(s) under the other kind's grant", links.calls)
	}
	// One grant on one of two requested projects is no grant for the request.
	status, v = post(replayOnA, "replay", target, pA, pB)
	grantRequired("replay.read on one of two projects", status, v)
	if links.calls != 0 {
		t.Fatalf("the target was probed %d time(s) with the grant held on only one project", links.calls)
	}
	// The grant on every requested project opens the way to the target, resolved as the requested kind.
	status, v = post(replayOnA, "replay", target, pA)
	linked("replay.read on its project", "replay", status, v)
	if links.lastKind != "replay" {
		t.Fatalf("the target was resolved as %q", links.lastKind)
	}
	status, v = post(profilesOnBoth, "profile", target, pA, pB)
	linked("profiles.read on both projects", "profile", status, v)
	if links.lastKind != "profile" {
		t.Fatalf("the target was resolved as %q", links.lastKind)
	}
	// A target nothing resolves is the one not-found, never a link.
	if status, _ = post(replayOnA, "replay", model.NewID(), pA); status != 404 {
		t.Fatalf("an unresolvable replay target answered %d", status)
	}
}

// resolverFunc is a labelled test double of the C04 resolver: it answers every call with whatever the test says.
type resolverFunc func(refs []link.Reference) []link.ResolvedReference

func (r resolverFunc) Resolve(_ context.Context, _ auth.Scope, refs []link.Reference) ([]link.ResolvedReference, error) {
	return r(refs), nil
}

// A resolver that answers with a reference other than the one asked for (another record, another project, no reference at all, or a
// reference marked unavailable) never yields a link: the investigation accepts exactly the requested project and ID.
func TestInvestigateTargetLinkRefusesAReferenceThatIsNotTheRequestedOne(t *testing.T) {
	e := newIsoEnv(t)
	p := model.NewID()
	org := e.org("investigate decoys", p)
	alice := e.user(org, "inv-decoy@example.test")
	e.grant(org, alice, p, true, auth.Read)
	scope, err := e.scope(alice, org, p, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	target, foreign, otherProject := model.NewID(), model.NewID(), model.NewID()
	win := query.TimeRange{Start: 10, End: 20}
	ask := func(r resolverFunc, kind httpapi.InvestigationKind) (httpapi.InvestigationView, error) {
		inv, err := httpapi.NewInvestigator(e.app.Auth, &fakeDiscovery{}, r)
		if err != nil {
			t.Fatal(err)
		}
		holds := func(context.Context, model.ID, string) bool { return true }
		return inv.InvestigateGranted(e.ctx, scope, httpapi.InvestigationRequest{Kind: kind, Projects: []model.ID{p}, Target: &target, Window: win, Limit: 10}, holds)
	}
	answer := func(mutate func(ref link.Reference) (*link.Reference, bool)) resolverFunc {
		return func(refs []link.Reference) []link.ResolvedReference {
			out := make([]link.ResolvedReference, len(refs))
			for i, r := range refs {
				ref, ok := mutate(r)
				out[i] = link.ResolvedReference{Reference: ref, Available: ok}
			}
			return out
		}
	}
	exact := answer(func(r link.Reference) (*link.Reference, bool) { return &r, true })
	decoys := []struct {
		name   string
		answer resolverFunc
	}{
		{"another record", answer(func(r link.Reference) (*link.Reference, bool) { r.ID = foreign; return &r, true })},
		{"another project", answer(func(r link.Reference) (*link.Reference, bool) { r.Project = otherProject; return &r, true })},
		{"available, no record", answer(func(link.Reference) (*link.Reference, bool) { return nil, true })},
		{"a record, unavailable", answer(func(r link.Reference) (*link.Reference, bool) { return &r, false })},
		{"nothing", func([]link.Reference) []link.ResolvedReference { return nil }},
	}
	for _, kind := range []httpapi.InvestigationKind{httpapi.KindTrace, httpapi.KindReplay, httpapi.KindProfile} {
		v, err := ask(exact, kind)
		if err != nil || v.Link == nil || v.Link.ID != target || v.Link.ProjectID != p {
			t.Fatalf("%s: the exact reference must link: %+v %v", kind, v, err)
		}
		for _, d := range decoys {
			v, err := ask(d.answer, kind)
			if faultCode(err) != model.NotFound || v.Link != nil {
				t.Fatalf("%s, %s: a reference that is not the requested one must be the one not-found, got %+v %v", kind, d.name, v, err)
			}
		}
	}
}
