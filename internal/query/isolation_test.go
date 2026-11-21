// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"math"
	"testing"
	"time"
)

func faultOf(t *testing.T, err error) *model.Fault {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) {
		t.Fatalf("not a typed fault: %v", err)
	}
	return f
}

// scannedProjects lists every project any scan of the store asked for.
func (s *tstore) scannedProjects() map[model.ID]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[model.ID]bool{}
	for _, r := range s.requests {
		for _, p := range r.Projects {
			out[p] = true
		}
	}
	return out
}
func (s *tstore) resetRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
	s.scans.Store(0)
}

// TestScopeIsolationMatrix runs one adversarial matrix of principals against
// two organizations and three projects: every query, discovery and exemplar
// request outside the caller's scope fails with the one indistinguishable
// NotFound, before any scan, and nothing of another project's data (names,
// values, counts, exemplars) is ever visible.
func TestScopeIsolationMatrix(t *testing.T) {
	f := newFx(t)
	orgA, psA := f.newOrg("org A", 2)
	orgB, psB := f.newOrg("org B", 1)
	p1, p2, p3 := psA[0], psA[1], psB[0]
	alice := f.user(orgA, "alice@example.test", []model.ID{p1}, auth.Read)
	bob := f.user(orgA, "bob@example.test", []model.ID{p2}, auth.Read)
	carol := f.user(orgB, "carol@example.test", []model.ID{p3}, auth.Read)
	dave := f.user(orgA, "dave@example.test", nil, auth.Read)
	st := newStore()
	same := model.Labels{{Name: "job", Value: "api"}}
	trace := model.NewID()
	st.add(
		metricRow(p1, "up", same, testEpoch, 1), metricRow(p1, "p1_only", same, testEpoch, 1),
		metricRow(p2, "up", same, testEpoch, 2), metricRow(p2, "p2_secret", model.Labels{{Name: "tenant", Value: "p2-value"}}, testEpoch, 2),
		metricRow(p3, "up", same, testEpoch, 3), metricRow(p3, "p3_secret", model.Labels{{Name: "tenant", Value: "p3-value"}}, testEpoch, 3),
		exemplarRow(p1, "up", same, testEpoch, 1, trace), exemplarRow(p2, "up", model.Labels{{Name: "job", Value: "other"}}, testEpoch, 2, model.NewID()),
	)
	e := f.engineWith(st, testLimits(), true)
	window := TimeRange{Start: model.UnixNano(testEpoch - 10), End: model.UnixNano(testEpoch + 10)}
	fs := baseFeatureSet

	if _, err := f.svc.Authorize(f.ctx, dave.cred, orgA, []model.ID{p1}, auth.Read); err == nil {
		t.Fatal("a member with no grant must not get a scope")
	}
	if _, err := f.svc.Authorize(f.ctx, alice.cred, orgA, []model.ID{p2}, auth.Read); err == nil {
		t.Fatal("a scope over a project without a grant must not exist")
	}
	if _, err := f.svc.Authorize(f.ctx, alice.cred, orgB, []model.ID{p3}, auth.Read); err == nil {
		t.Fatal("a scope in another organization must not exist")
	}

	scopeA := f.scope(alice, orgA, p1)
	scopeC := f.scope(carol, orgB, p3)
	denied := func(name string, err error) *model.Fault {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: crossed the scope", name)
		}
		fault := faultOf(t, err)
		if fault.Code != model.NotFound {
			t.Fatalf("%s: want NotFound, got %v", name, err)
		}
		return fault
	}
	guess := model.NewID()
	var reference *model.Fault
	check := func(name string, err error) {
		t.Helper()
		fault := denied(name, err)
		if reference == nil {
			reference = fault
		} else if fault.Code != reference.Code || fault.SafeDetail != reference.SafeDetail || fault.Retryable != reference.Retryable {
			t.Fatalf("%s: denial differs from the guessed-ID denial (%v vs %v)", name, fault, reference)
		}
	}
	st.resetRequests()
	for _, target := range []struct {
		name  string
		scope auth.Scope
		ps    []model.ID
	}{
		{"alice to a sibling project", scopeA, []model.ID{p2}},
		{"alice to another organization's project", scopeA, []model.ID{p3}},
		{"alice to a guessed project", scopeA, []model.ID{guess}},
		{"alice to a granted and a foreign project", scopeA, []model.ID{p1, p2}},
		{"carol to organization A", scopeC, []model.ID{p1}},
		{"carol to a guessed project", scopeC, []model.ID{guess}},
	} {
		_, err := e.engine.Execute(f.ctx, target.scope, promReq("up", testEpoch+1, target.ps...))
		check("query: "+target.name, err)
		_, err = e.engine.Discover(f.ctx, target.scope, DiscoveryRequest{Projects: target.ps, Signal: model.Metric, Kind: DiscoverMetricNames, Time: window, Limit: 10})
		check("discover: "+target.name, err)
		_, err = e.engine.Exemplars(f.ctx, target.scope, ExemplarRequest{Projects: target.ps, Profile: prom310, FeatureSet: fs, Expression: "up", Window: window, Limit: 10})
		check("exemplars: "+target.name, err)
		_, err = e.engine.Execute(f.ctx, target.scope, logReq(`{app="web"}`, testEpoch, testEpoch+10, target.ps...))
		check("logs: "+target.name, err)
	}
	if st.scans.Load() != 0 || len(st.scannedProjects()) != 0 {
		t.Fatalf("a denied request reached the index: %d scans", st.scans.Load())
	}

	// What each principal may see is exactly its own project, in every surface.
	for _, who := range []struct {
		name    string
		scope   auth.Scope
		project model.ID
		value   float64
		hidden  []string
	}{
		{"alice", scopeA, p1, 1, []string{"p2_secret", "p3_secret", "p2-value", "p3-value"}},
		{"carol", scopeC, p3, 3, []string{"p1_only", "p2_secret", "p2-value"}},
	} {
		res, err := e.engine.Execute(f.ctx, who.scope, promReq("up", testEpoch+1, who.project))
		if err != nil || len(res.Projects) != 1 || len(res.Projects[0].Value.Vector) != 1 || math.Float64frombits(sampleBits(t, res.Projects[0].Value.Vector[0].Sample)) != who.value {
			t.Fatalf("%s sees only her project's series: %v %+v", who.name, err, res)
		}
		names, err := e.engine.Discover(f.ctx, who.scope, DiscoveryRequest{Projects: []model.ID{who.project}, Signal: model.Metric, Kind: DiscoverMetricNames, Time: window, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		values, err := e.engine.Discover(f.ctx, who.scope, DiscoveryRequest{Projects: []model.ID{who.project}, Signal: model.Metric, Kind: DiscoverLabelValues, Field: "tenant", Time: window, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		ex, err := e.engine.Exemplars(f.ctx, who.scope, ExemplarRequest{Projects: []model.ID{who.project}, Profile: prom310, FeatureSet: fs, Expression: "up", Window: window, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range append(names.Items, values.Items...) {
			for _, hidden := range who.hidden {
				if item == hidden {
					t.Fatalf("%s learned %q from another project", who.name, hidden)
				}
			}
		}
		for _, x := range ex.Exemplars {
			if x.Project != who.project {
				t.Fatalf("%s received another project's exemplar", who.name)
			}
		}
	}
	for project := range st.scannedProjects() {
		if project == p2 {
			t.Fatal("a project outside every granted scope was scanned")
		}
	}

	// bob owns p2 only: his view is symmetrical.
	scopeB := f.scope(bob, orgA, p2)
	res, err := e.engine.Execute(f.ctx, scopeB, promReq("up", testEpoch+1, p2))
	if err != nil || math.Float64frombits(sampleBits(t, res.Projects[0].Value.Vector[0].Sample)) != 2 {
		t.Fatalf("%v", err)
	}
	if _, err = e.engine.Execute(f.ctx, scopeB, promReq("up", testEpoch+1, p1)); code(err) != model.NotFound {
		t.Fatalf("%v", err)
	}
	e.idle(t)
}

// TestEffectiveSourceReaderCacheIsolation: two principals of one org and project
// hold the same broad telemetry.read and raw.read grants and the same policy
// epoch, but principal A may read restricted source X and B only Y. Every cache
// and cursor warmed by A is unreachable to B.
func TestEffectiveSourceReaderCacheIsolation(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("sources", 1)
	project := ps[0]
	a := f.user(org, "a@example.test", ps, auth.Read, auth.RawRead)
	b := f.user(org, "b@example.test", ps, auth.Read, auth.RawRead)
	x := f.restricted(org, project, a.id)
	y := f.restricted(org, project, b.id)
	st := newStore()
	trace := model.NewID()
	st.add(
		metricRow(project, "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1),
		exemplarRow(project, "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1, trace),
		logRow(t, project, testEpoch+1, "structured line", model.Labels{{Name: "app", Value: "web"}}),
		rawLogRow(t, project, x, testEpoch+2, "secret for X only", model.Labels{{Name: "app", Value: "x-app"}, {Name: "xonly", Value: "x-value"}}),
		rawLogRow(t, project, y, testEpoch+3, "secret for Y only", model.Labels{{Name: "app", Value: "y-app"}}),
	)
	e := f.engineWith(st, testLimits(), true)
	window := TimeRange{Start: model.UnixNano(testEpoch - 10), End: model.UnixNano(testEpoch + 10)}
	fs := baseFeatureSet

	readA, readB := f.scope(a, org, project), f.scope(b, org, project)
	rawA, err := f.rawScope(a, org, project, x)
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := f.rawScope(b, org, project, y)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.rawScope(b, org, project, x); err == nil {
		t.Fatal("B must not obtain a scope for A's source")
	}
	if readA.VisibilityFingerprint() == readB.VisibilityFingerprint() || readA.PolicyEpoch() != readB.PolicyEpoch() {
		t.Fatal("fixture: equal broad grants and epoch must still differ in effective visibility")
	}

	var warm struct{ query, discover, exemplars, cursor string }
	runQuery := func(s auth.Scope) (ProjectResult, int64) {
		before := st.scans.Load()
		res, err := e.engine.Execute(f.ctx, s, promReq("up", testEpoch+1, project))
		if err != nil {
			t.Fatal(err)
		}
		return res.Projects[0], st.scans.Load() - before
	}
	discover := func(s auth.Scope) (DiscoveryResult, int64) {
		before := st.scans.Load()
		res, err := e.engine.Discover(f.ctx, s, DiscoveryRequest{Projects: ps, Signal: model.Metric, Kind: DiscoverLabelNames, Time: window, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return res, st.scans.Load() - before
	}
	exemplars := func(s auth.Scope) (ExemplarResult, int64) {
		before := st.scans.Load()
		res, err := e.engine.Exemplars(f.ctx, s, ExemplarRequest{Projects: ps, Profile: prom310, FeatureSet: fs, Expression: "up", Window: window, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return res, st.scans.Load() - before
	}
	// Warm every cache as A, then prove each is warm.
	runQuery(readA)
	discover(readA)
	exemplars(readA)
	if pr, scans := runQuery(readA); scans != 0 || !pr.Stats.Cached {
		t.Fatalf("A's query cache is not warm (%d scans)", scans)
	}
	if res, scans := discover(readA); scans != 0 || !res.Freshness.Cached {
		t.Fatalf("A's discovery cache is not warm (%d scans)", scans)
	}
	if res, scans := exemplars(readA); scans != 0 || !res.Freshness.Cached {
		t.Fatalf("A's exemplar cache is not warm (%d scans)", scans)
	}
	rawDiscover := func(s auth.Scope, source model.ID, cursor string, limit uint32) (DiscoveryResult, error) {
		return e.engine.Discover(f.ctx, s, DiscoveryRequest{Projects: ps, Signal: model.Log, Kind: DiscoverLabelValues, Field: "app", Time: window, Limit: limit, Source: &source, Cursor: cursor})
	}
	first, err := rawDiscover(rawA, x, "", 1)
	if err != nil || len(first.Items) != 1 || first.Items[0] != "x-app" || first.More {
		t.Fatalf("A reads source X: %v %+v", err, first)
	}
	names, err := e.engine.Discover(f.ctx, rawA, DiscoveryRequest{Projects: ps, Signal: model.Log, Kind: DiscoverLabelNames, Time: window, Limit: 1, Source: &x})
	if err != nil || !names.More || names.NextCursor == "" {
		t.Fatalf("A's page of X label names: %v %+v", err, names)
	}
	warm.cursor = names.NextCursor
	rawLogs, err := e.engine.Execute(f.ctx, rawA, func() Request {
		r := logReq(`{app="x-app"}`, testEpoch, testEpoch+10, project)
		r.Source = &x
		return r
	}())
	if err != nil || rawLogs.Projects[0].Stats.LogsReturned != 1 || rawLogs.Projects[0].Value.Streams[0].Entries[0].Line != "secret for X only" {
		t.Fatalf("A's raw read of X: %v", err)
	}
	_ = warm

	// B, same org, project, epoch and broad grants, sees none of it.
	if pr, scans := runQuery(readB); scans == 0 || pr.Stats.Cached {
		t.Fatal("B reused A's query cache entry")
	}
	if res, scans := discover(readB); scans == 0 || res.Freshness.Cached {
		t.Fatal("B reused A's discovery cache entry")
	}
	if res, scans := exemplars(readB); scans == 0 || res.Freshness.Cached {
		t.Fatal("B reused A's exemplar cache entry")
	}
	before := st.scans.Load()
	if _, err = rawDiscover(rawB, x, "", 10); code(err) != model.NotFound {
		t.Fatalf("B's scope must not name source X: %v", err)
	}
	if _, err = e.engine.Execute(f.ctx, rawB, func() Request {
		r := logReq(`{app="x-app"}`, testEpoch, testEpoch+10, project)
		r.Source = &x
		return r
	}()); code(err) != model.NotFound {
		t.Fatalf("B's query of X: %v", err)
	}
	if _, err = e.engine.Discover(f.ctx, rawB, DiscoveryRequest{Projects: ps, Signal: model.Log, Kind: DiscoverLabelNames, Time: window, Limit: 1, Source: &x, Cursor: warm.cursor}); code(err) != model.NotFound {
		t.Fatalf("B's use of A's cursor on X: %v", err)
	}
	if st.scans.Load() != before {
		t.Fatal("a denied source reached the index")
	}
	own, err := rawDiscover(rawB, y, "", 10)
	if err != nil || len(own.Items) != 1 || own.Items[0] != "y-app" {
		t.Fatalf("B reads only Y's values: %v %+v", err, own)
	}
	ownNames, err := e.engine.Discover(f.ctx, rawB, DiscoveryRequest{Projects: ps, Signal: model.Log, Kind: DiscoverLabelNames, Time: window, Limit: 10, Source: &y})
	if err != nil || len(ownNames.Items) != 1 || ownNames.Items[0] != "app" {
		t.Fatalf("B's label names of Y must not include X's label: %v %+v", err, ownNames)
	}
	if _, err = e.engine.Discover(f.ctx, rawB, DiscoveryRequest{Projects: ps, Signal: model.Log, Kind: DiscoverLabelNames, Time: window, Limit: 1, Source: &y, Cursor: warm.cursor}); err == nil {
		t.Fatal("A's cursor continued B's request")
	}
	ownLogs, err := e.engine.Execute(f.ctx, rawB, func() Request { r := logReq(`{app=~".+"}`, testEpoch, testEpoch+10, project); r.Source = &y; return r }())
	if err != nil || ownLogs.Projects[0].Stats.LogsReturned != 1 || ownLogs.Projects[0].Value.Streams[0].Entries[0].Line != "secret for Y only" {
		t.Fatalf("B's raw read of Y: %v", err)
	}
	// Structured reads never include restricted raw rows, for either principal.
	for _, s := range []auth.Scope{readA, readB} {
		res, err := e.engine.Execute(f.ctx, s, logReq(`{app=~".+"}`, testEpoch, testEpoch+10, project))
		if err != nil || res.Projects[0].Stats.LogsReturned != 1 || res.Projects[0].Value.Streams[0].Entries[0].Line != "structured line" {
			t.Fatalf("a telemetry.read scope leaked restricted raw logs: %v %+v", err, res.Projects[0].Stats)
		}
		hidden, err := e.engine.Execute(f.ctx, s, logReq(`{app="x-app"}`, testEpoch, testEpoch+10, project))
		if err != nil || len(hidden.Projects[0].Value.Streams) != 0 {
			t.Fatalf("restricted-source existence leaked through a structured read: %v", err)
		}
	}
	e.idle(t)
}

// TestProjectFailureIsIsolated: one project's failure never changes another's
// values, and is never presented as data. Without the opt-in the request fails
// with the typed error; with it the failed project is a typed partial; request-
// level failures stay fatal.
func TestProjectFailureIsIsolated(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("failure", 2)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	same := model.Labels{{Name: "job", Value: "api"}}
	st.add(metricRow(ps[0], "up", same, testEpoch, 1), metricRow(ps[1], "up", same, testEpoch, 2))
	sorted := sortedIDs(ps...)
	low, high := sorted[0], sorted[1]
	e := f.engineWith(st, testLimits(), false)
	fail := func(project model.ID, err error) {
		st.scanErr = func(p model.ID) error {
			if p == project {
				return err
			}
			return nil
		}
	}
	req := promReq("up", testEpoch+1, ps...)

	fail(low, model.Fail(model.Unavailable))
	res, err := e.engine.Execute(f.ctx, scope, req)
	requireCode(t, err, model.Unavailable)
	if len(res.Projects) != 0 {
		t.Fatal("a failed project released values without the opt-in")
	}
	req.AllowPartial = true
	res, err = e.engine.Execute(f.ctx, scope, req)
	if err != nil || len(res.Projects) != 2 {
		t.Fatalf("%v", err)
	}
	failed, healthy := res.Projects[0], res.Projects[1]
	if failed.ProjectID != low || failed.Value != nil || failed.Failure == nil || failed.Failure.Code != string(model.Unavailable) || failed.Completeness != CompletenessPartial {
		t.Fatalf("the failed project must be a typed partial with no value: %+v", failed)
	}
	wantHealthy := 2.0
	if high == ps[0] {
		wantHealthy = 1
	}
	if healthy.ProjectID != high || healthy.Failure != nil || healthy.Completeness != CompletenessComplete || len(healthy.Value.Vector) != 1 || math.Float64frombits(sampleBits(t, healthy.Value.Vector[0].Sample)) != wantHealthy {
		t.Fatalf("the healthy project is unaffected: %+v", healthy)
	}
	for _, fatal := range []model.Code{model.NotFound, model.Forbidden, model.Stale, model.Timeout} {
		fail(low, model.Fail(fatal))
		if _, err = e.engine.Execute(f.ctx, scope, req); code(err) != fatal {
			t.Fatalf("a %s failure is a request-level failure even with partial allowed: %v", fatal, err)
		}
	}
	// With two failing projects the reported error is deterministic: the lowest
	// project ID's, never whichever finished first.
	st.scanErr = func(p model.ID) error {
		if p == low {
			return model.Fail(model.Corrupt)
		}
		time.Sleep(20 * time.Millisecond)
		return model.Fail(model.Unavailable)
	}
	req.AllowPartial = false
	for range 5 {
		if _, err = e.engine.Execute(f.ctx, scope, req); code(err) != model.Corrupt {
			t.Fatalf("error choice must be deterministic: %v", err)
		}
	}
	// Cancellation of the caller is fatal and typed.
	st.scanErr = nil
	ctx, cancel := context.WithCancel(f.ctx)
	st.nextHook = func(context.Context, int) error { cancel(); return nil }
	req.AllowPartial = true
	if _, err = e.engine.Execute(ctx, scope, req); code(err) != model.Cancelled {
		t.Fatalf("%v", err)
	}
	st.nextHook = nil
	e.idle(t)
	// A worker's panic is contained and typed.
	st.nextHook = func(context.Context, int) error { panic("hostile storage") }
	req.AllowPartial = false
	if _, err = e.engine.Execute(f.ctx, scope, req); code(err) != model.Unavailable {
		t.Fatalf("a panic in one project must not take the process down: %v", err)
	}
	st.nextHook = nil
}
