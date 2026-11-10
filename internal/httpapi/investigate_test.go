// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/link"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"strings"
	"testing"
)

// invEnv serves the owned investigate route over the real control store, real
// ingestion, real storage and the owned query engine.
type invEnv struct {
	*queryEnv
	inv    *httpapi.Investigator
	server *httptest.Server
}

func newInvEnv(t *testing.T) *invEnv {
	t.Helper()
	q := newQueryEnv(t, queryLimits())
	inv, err := httpapi.NewInvestigator(q.app.Auth, q.engine, q.resolver)
	if err != nil {
		t.Fatal(err)
	}
	e := &invEnv{queryEnv: q, inv: inv}
	e.server = httptest.NewTLSServer(httpapi.NewServer("", q.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterInvestigateRoutes(mux, q.app.Auth, inv)
	}).Handler)
	t.Cleanup(e.server.Close)
	return e
}

func (e *invEnv) investigate(who person, body queryBody) (int, []byte, http.Header) {
	e.t.Helper()
	saved := e.queryEnv.server
	e.queryEnv.server = e.server
	defer func() { e.queryEnv.server = saved }()
	return e.queryEnv.post(who, "/api/v1/investigate", body)
}

func window() queryBody {
	return queryBody{"start": decimal(sampleTime - 1000), "end": decimal(sampleTime + 1000)}
}
func request(org model.ID, kind string, projects ...model.ID) queryBody {
	ps := make([]string, len(projects))
	for i, p := range projects {
		ps[i] = p.String()
	}
	return queryBody{"org": org.String(), "kind": kind, "projects": ps, "window": window(), "limit": 100}
}
func decodeView(t *testing.T, raw []byte) httpapi.InvestigationView {
	t.Helper()
	var v httpapi.InvestigationView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a view: %v\n%s", err, raw)
	}
	return v
}
func sectionStates(v httpapi.InvestigationView) map[string]httpapi.ViewState {
	out := map[string]httpapi.ViewState{}
	for _, s := range v.Sections {
		out[s.Name] = s.State
	}
	return out
}

func TestInvestigateScopeAndFreshness(t *testing.T) {
	e := newInvEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p1, p2, p3 := model.NewID(), model.NewID(), model.NewID()
	org := e.org("investigate org", p1, p2, p3)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p1, true, auth.Read)
	e.grant(org, alice, p2, true, auth.Read)
	s1 := e.metricSource(org, p1, ids)
	api := model.Labels{{Name: "job", Value: "api"}}
	e.metricPoint(s1, "up", api, sampleTime, 1, nil)
	e.metricPoint(s1, "build_info", model.Labels{{Name: "version", Value: "1.2"}}, sampleTime, 1, nil)

	status, raw, header := e.investigate(alice, request(org, "service", p1))
	if status != 200 || header.Get("Cache-Control") != "no-store" {
		t.Fatalf("service: %d %s", status, raw)
	}
	v := decodeView(t, raw)
	if v.Org != org || v.Kind != httpapi.KindService || len(v.Projects) != 1 || v.Projects[0].ProjectID != p1 || len(v.Projects[0].Sources) != 1 || v.Projects[0].Sources[0].ID != s1.ID {
		t.Fatalf("view is not scoped to the request: %s", raw)
	}
	if strings.Join(v.MetricNames, ",") != "build_info,up" || v.Freshness == nil || v.Freshness.Completeness != "complete" || len(v.Freshness.Watermarks) == 0 {
		t.Fatalf("telemetry evidence/freshness: %s", raw)
	}
	// A page that is not the whole answer is truthful: more with a cursor, and the
	// cursor is only good for the same projects.
	paged := request(org, "service", p1)
	paged["limit"] = 1
	status, raw, _ = e.investigate(alice, paged)
	first := decodeView(t, raw)
	if status != 200 || !first.More || first.NextCursor == "" || len(first.MetricNames) != 1 {
		t.Fatalf("page one: %d %s", status, raw)
	}
	paged["cursor"] = first.NextCursor
	status, raw, _ = e.investigate(alice, paged)
	second := decodeView(t, raw)
	if status != 200 || second.More || strings.Join(append(first.MetricNames, second.MetricNames...), ",") != "build_info,up" {
		t.Fatalf("page two: %d %s", status, raw)
	}
	for name, mutate := range map[string]func(queryBody){
		"other project": func(b queryBody) { b["projects"] = []string{p2.String()} },
		"garbage":       func(b queryBody) { b["cursor"] = "AAAA" },
		"other kind":    func(b queryBody) { b["kind"] = "queue" },
	} {
		bad := request(org, "service", p1)
		bad["limit"] = 1
		bad["cursor"] = first.NextCursor
		mutate(bad)
		status, raw, _ = e.investigate(alice, bad)
		if status == 200 || strings.Contains(string(raw), "build_info") {
			t.Fatalf("%s cursor resumed: %d %s", name, status, raw)
		}
	}

	// Wrong org member, unauthorized sibling, other org's project and a guess are
	// one indistinguishable answer.
	var first404 string
	for name, projects := range map[string][]model.ID{"ungranted sibling": {p3}, "guess": {model.NewID()}, "mixed": {p1, p3}} {
		status, raw, _ := e.investigate(alice, request(org, "service", projects...))
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		_, detail := faultBody(t, raw)
		if first404 == "" {
			first404 = detail
		} else if detail != first404 {
			t.Fatalf("%s: denial differs", name)
		}
		if strings.Contains(string(raw), "build_info") || strings.Contains(string(raw), p1.String()) {
			t.Fatalf("%s: denial leaks: %s", name, raw)
		}
	}
	// A body cannot name another principal's scope.
	smuggled := request(org, "service", p1)
	smuggled["scope"] = queryBody{"principal": "x"}
	if status, _, _ := e.investigate(alice, smuggled); status != 400 {
		t.Fatalf("closed body: %d", status)
	}
	if status, _, _ := e.investigate(person{}, request(org, "service", p1)); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", status)
	}
	resp, err := e.client.Get(e.server.URL + "/api/v1/investigate")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("investigate is POST-only: %d", resp.StatusCode)
	}

	// Revocation is a fresh derivation: the old answer cannot be re-read.
	e.grant(org, alice, p1, false, auth.Read)
	if status, raw, _ = e.investigate(alice, request(org, "service", p1)); status != 404 || strings.Contains(string(raw), "build_info") {
		t.Fatalf("revoked read: %d %s", status, raw)
	}
}

func TestInvestigateRestrictedSourceNeverLeaksToTelemetryOnlyReader(t *testing.T) {
	e := newInvEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	project := model.NewID()
	org := e.org("restricted org", project)
	reader := e.user(org, "raw-reader@example.test")
	plain := e.user(org, "plain@example.test")
	e.grant(org, reader, project, true, auth.RawRead, auth.Read)
	e.grant(org, plain, project, true, auth.Read)
	structured := e.metricSource(org, project, ids)
	restricted := e.onboard(org, project, model.NewID(), ids, e.rawPolicy(e.actor.ID), auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{reader.ID}, Enabled: true})
	e.rawLog(restricted, "canary-restricted")

	named := request(org, "service", project)
	named["permission"] = "raw.read"
	named["source"] = restricted.ID.String()
	status, raw, _ := e.investigate(reader, named)
	v := decodeView(t, raw)
	if status != 200 || len(v.Projects) != 1 || len(v.Projects[0].Sources) != 1 || v.Projects[0].Sources[0].ID != restricted.ID {
		t.Fatalf("named reader: %d %s", status, raw)
	}
	if states := sectionStates(v); states["telemetry"] != httpapi.StateNotAvailable || len(v.MetricNames) != 0 {
		t.Fatalf("restricted scope must not pretend structured discovery ran: %s", raw)
	}
	// The same project, warmed by the named reader, as a telemetry-only principal.
	status, raw, _ = e.investigate(plain, request(org, "service", project))
	v = decodeView(t, raw)
	if status != 200 || len(v.Projects) != 1 || len(v.Projects[0].Sources) != 1 || v.Projects[0].Sources[0].ID != structured.ID {
		t.Fatalf("telemetry-only reader sees the wrong source set: %d %s", status, raw)
	}
	if strings.Contains(string(raw), restricted.ID.String()) || strings.Contains(string(raw), "canary") || strings.Contains(string(raw), "log") {
		t.Fatalf("restricted source leaked: %s", raw)
	}
	// Naming the restricted source without being its reader is plain not-found.
	named["permission"] = "raw.read"
	if status, raw, _ = e.investigate(plain, named); status != 404 {
		t.Fatalf("non-reader named restricted source: %d %s", status, raw)
	}
	// Losing the grant ends the old projection.
	e.grant(org, reader, project, false, auth.RawRead)
	if status, raw, _ = e.investigate(reader, named); status != 404 || strings.Contains(string(raw), restricted.ID.String()) {
		t.Fatalf("revoked raw reader: %d %s", status, raw)
	}
}

type fakeLinks struct {
	available map[model.ID]bool
	calls     int
}

func (f *fakeLinks) Resolve(_ context.Context, _ auth.Scope, refs []link.Reference) ([]link.ResolvedReference, error) {
	f.calls++
	out := make([]link.ResolvedReference, len(refs))
	for i, r := range refs {
		if f.available[r.ID] {
			owned := r
			out[i] = link.ResolvedReference{Reference: &owned, Available: true}
		}
	}
	return out, nil
}

type fakeDiscovery struct {
	result query.DiscoveryResult
	err    error
	calls  int
	last   query.DiscoveryRequest
}

func (f *fakeDiscovery) Discover(_ context.Context, _ auth.Scope, r query.DiscoveryRequest) (query.DiscoveryResult, error) {
	f.calls++
	f.last = r
	return f.result, f.err
}

func TestInvestigateKindsReportTruthfulStates(t *testing.T) {
	e := newIsoEnv(t)
	p := model.NewID()
	org := e.org("kinds org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	scope, err := e.scope(alice, org, p, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	trace := model.NewID()
	links := &fakeLinks{available: map[model.ID]bool{trace: true}}
	discovery := &fakeDiscovery{result: query.DiscoveryResult{Items: []string{"up"}, Freshness: query.Freshness{Completeness: "complete", Watermarks: []model.Cursor{{Group: model.NewID(), Index: 1}}}}}
	inv, err := httpapi.NewInvestigator(e.app.Auth, discovery, links)
	if err != nil {
		t.Fatal(err)
	}
	win := query.TimeRange{Start: 10, End: 20}
	read := func(kind httpapi.InvestigationKind, target *model.ID) (httpapi.InvestigationView, error) {
		return inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: kind, Projects: []model.ID{p}, Target: target, Window: win, Limit: 10})
	}
	// Nothing for these kinds is built: never an empty success.
	for _, kind := range []httpapi.InvestigationKind{httpapi.KindQueue, httpapi.KindIncident, httpapi.KindIssue, httpapi.KindRelease, httpapi.KindJob, httpapi.KindReplay, httpapi.KindProfile} {
		v, err := read(kind, nil)
		if err != nil || v.State != httpapi.StateNotAvailable || v.Reason == "" || v.Kind != kind || v.Org != org || len(v.MetricNames) != 0 || v.Freshness != nil {
			t.Fatalf("%s: %+v %v", kind, v, err)
		}
		if v.State == httpapi.StateEmpty || v.State == httpapi.StateReady {
			t.Fatalf("%s: unbuilt kind answered as success", kind)
		}
	}
	// Replay/profile need their own grant, which does not exist: they must not
	// even probe for the target through the telemetry.read scope.
	for _, kind := range []httpapi.InvestigationKind{httpapi.KindReplay, httpapi.KindProfile} {
		if _, err := read(kind, &trace); err != nil {
			t.Fatal(err)
		}
	}
	if links.calls != 0 {
		t.Fatal("replay/profile resolved a target under telemetry.read")
	}
	// Trace: link only when this scope resolves it; content is a separate not-built section.
	v, err := read(httpapi.KindTrace, &trace)
	if err != nil || v.State != httpapi.StateIncomplete || v.Link == nil || !v.Link.Available || v.Link.ID != trace || v.Link.ProjectID != p || v.Link.Kind != "trace" {
		t.Fatalf("trace: %+v %v", v, err)
	}
	if st := sectionStates(v); st["link"] != httpapi.StateReady || st["content"] != httpapi.StateNotAvailable {
		t.Fatalf("trace sections: %+v", v.Sections)
	}
	missing := model.NewID()
	if _, err := read(httpapi.KindTrace, &missing); faultCode(err) != model.NotFound {
		t.Fatalf("unresolvable trace must be not-found: %v", err)
	}
	if _, err := read(httpapi.KindTrace, nil); faultCode(err) != model.Invalid {
		t.Fatalf("trace without target: %v", err)
	}
	// Service: separately qualified sections, none invented.
	v, err = read(httpapi.KindService, nil)
	if err != nil || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonSectionsAbsent {
		t.Fatalf("service: %+v %v", v, err)
	}
	st := sectionStates(v)
	if st["telemetry"] != httpapi.StateReady || st["health"] != httpapi.StateNotAvailable || st["dependencies"] != httpapi.StateNotAvailable || st["releases"] != httpapi.StateNotAvailable {
		t.Fatalf("service sections: %+v", v.Sections)
	}
	if v.Window != win || discovery.last.Time != win || discovery.last.Signal != model.Metric || discovery.last.Limit != 10 {
		t.Fatalf("discovery not bound to the request window: %+v", discovery.last)
	}

	// Freshness is never inferred from rows: partial and stale are labelled, and
	// zero rows from a complete answer is empty only when nothing is missing.
	cases := []struct {
		name         string
		items        []string
		completeness string
		want         httpapi.ViewState
		reason       string
	}{
		{"complete without rows", nil, "complete", httpapi.StateEmpty, ""},
		{"partial without rows is not empty", nil, "partial", httpapi.StateIncomplete, httpapi.ReasonShardsMissing},
		{"partial with rows", []string{"up"}, "partial", httpapi.StateIncomplete, httpapi.ReasonShardsMissing},
		{"stale with rows", []string{"up"}, "stale", httpapi.StateStale, httpapi.ReasonFreshnessStale},
		{"stale without rows", nil, "stale", httpapi.StateStale, httpapi.ReasonFreshnessStale},
	}
	for _, c := range cases {
		discovery.result = query.DiscoveryResult{Items: c.items, Freshness: query.Freshness{Completeness: c.completeness}}
		v, err := read(httpapi.KindService, nil)
		if err != nil || v.State != c.want || (c.reason != "" && v.Reason != c.reason) || sectionStates(v)["telemetry"] == httpapi.StateReady && c.completeness != "complete" {
			t.Fatalf("%s: %+v %v", c.name, v, err)
		}
	}
	discovery.result = query.DiscoveryResult{Freshness: query.Freshness{Completeness: "unknown-future-value"}}
	if _, err := read(httpapi.KindService, nil); err == nil {
		t.Fatal("an unrecognized completeness must fail, not read as complete")
	}
	discovery.err = model.Fail(model.Quota)
	if _, err := read(httpapi.KindService, nil); faultCode(err) != model.Quota {
		t.Fatalf("engine failure must stay typed: %v", err)
	}

	// Request validation: closed kinds, bounded windows/limits/projects.
	bad := []httpapi.InvestigationRequest{
		{Kind: "nope", Projects: []model.ID{p}, Window: win, Limit: 10},
		{Kind: httpapi.KindService, Projects: nil, Window: win, Limit: 10},
		{Kind: httpapi.KindService, Projects: []model.ID{p, p}, Window: win, Limit: 10},
		{Kind: httpapi.KindService, Projects: []model.ID{p}, Window: query.TimeRange{Start: 20, End: 20}, Limit: 10},
		{Kind: httpapi.KindService, Projects: []model.ID{p}, Window: query.TimeRange{Start: 30, End: 20}, Limit: 10},
		{Kind: httpapi.KindService, Projects: []model.ID{p}, Window: win, Limit: 0},
		{Kind: httpapi.KindService, Projects: []model.ID{p}, Window: win, Limit: httpapi.MaxInvestigationLimit + 1},
		{Kind: httpapi.KindQueue, Projects: []model.ID{p}, Window: win, Limit: 10, Cursor: "x"},
		{Kind: httpapi.KindService, Projects: []model.ID{p, model.NewID()}, Window: win, Limit: 10},
	}
	discovery.err = nil
	discovery.result = query.DiscoveryResult{Freshness: query.Freshness{Completeness: "complete"}}
	for i, r := range bad {
		if _, err := inv.Investigate(e.ctx, scope, r); err == nil {
			t.Fatalf("bad request %d accepted: %+v", i, r)
		}
	}
}
