// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// conditionHealth is a labelled double: incidents are the real committed
// records of the real control store; conditions come from a fixed list because
// committing one needs the leader lease of the workers runner.
type conditionHealth struct {
	httpapi.HealthSource
	conds map[model.ID][]control.ConditionRecord
	deny  error
}

func (c *conditionHealth) Incidents(ctx context.Context, scope auth.Scope, project model.ID) ([]control.IncidentRecord, error) {
	if c.deny != nil {
		return nil, c.deny
	}
	return c.HealthSource.Incidents(ctx, scope, project)
}
func (c *conditionHealth) Conditions(_ context.Context, _ auth.Scope, project model.ID) ([]control.ConditionRecord, error) {
	return c.conds[project], nil
}

func conditionRecord(t *testing.T, org, project model.ID, phase conditions.Phase, links ...model.ID) control.ConditionRecord {
	t.Helper()
	id := model.NewID()
	state := conditions.State{Condition: id, Version: 1, Epoch: model.NewID(), Phase: phase, Severity: "critical", Freshness: conditions.FreshnessFresh, Links: links, Labels: model.Labels{}, Recent: []conditions.EventRef{}}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return control.ConditionRecord{Org: org, Project: project, ID: id, Version: 1, State: raw}
}

// TestServiceViewDerivesServicesAndHealthFromStoredEvidence is D9: services and
// environments are the resources the active source policies admit; health is
// failing with an open incident linked to the service, degraded with only
// active conditions naming it, healthy with neither, and never inferred.
func TestServiceViewDerivesServicesAndHealthFromStoredEvidence(t *testing.T) {
	e := newIsoEnv(t)
	p := model.NewID()
	org := e.org("service org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	s1, s2 := model.NewID(), model.NewID()
	e1, e2 := model.NewID(), model.NewID()
	b1, b2 := model.NewID(), model.NewID()
	src1 := e.source(org, p, sharedIDs{s1, e1, b1}, []model.Kind{model.Metric})
	src2 := e.source(org, p, sharedIDs{s2, e2, b2}, []model.Kind{model.Metric})
	scope, err := e.scope(alice, org, p, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	discovery := &fakeDiscovery{result: query.DiscoveryResult{Items: []string{"up"}, Freshness: query.Freshness{Completeness: "complete"}}}
	inv, err := httpapi.NewInvestigator(e.app.Auth, discovery, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	health := &conditionHealth{HealthSource: e.app.Control, conds: map[model.ID][]control.ConditionRecord{}}
	win := query.TimeRange{Start: 10, End: 20}
	read := func(target, environment *model.ID) (httpapi.InvestigationView, error) {
		return inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p}, Target: target, Environment: environment, Window: win, Limit: 10})
	}

	// The catalogue is exactly the two admitted services, each with its own sources.
	v, err := read(nil, nil)
	if err != nil || len(v.Services) != 2 || v.Health != nil {
		t.Fatalf("catalogue: %+v %v", v, err)
	}
	by := map[model.ID]auth.VisibleService{}
	for _, s := range v.Services {
		by[s.ID] = s
	}
	if !slices.Equal(by[s1].Sources, []model.ID{src1.ID}) || !slices.Equal(by[s1].Environments, []model.ID{e1}) || !slices.Equal(by[s1].Builds, []model.ID{b1}) || !slices.Equal(by[s2].Sources, []model.ID{src2.ID}) {
		t.Fatalf("services are not derived from the source policies: %+v", v.Services)
	}
	discovery.calls = 0 // the list view above reads telemetry; narrowed views below must not
	for _, name := range []string{"health", "dependencies", "releases"} {
		if sectionStates(v)[name] != httpapi.StateNotAvailable {
			t.Fatalf("a list view states %s: %+v", name, v.Sections)
		}
	}

	// Without a health source the service is never reported healthy.
	v, err = read(&s1, nil)
	if err != nil || v.Health != nil || sectionStates(v)["health"] != httpapi.StateNotAvailable || v.Sections[len(v.Sections)-3].Reason != httpapi.ReasonHealthNotWired {
		t.Fatalf("unwired health: %+v %v", v, err)
	}
	inv.WithHealth(health)

	// Identity is confirmed from the policies; telemetry is not claimed per service.
	v, err = read(&s1, nil)
	st := sectionStates(v)
	if err != nil || v.Health == nil || v.Health.Status != httpapi.HealthHealthy || len(v.Health.Incidents) != 0 || len(v.Health.Conditions) != 0 || st["identity"] != httpapi.StateReady || st["health"] != httpapi.StateReady || st["telemetry"] != httpapi.StateNotAvailable {
		t.Fatalf("healthy service: %+v %v", v, err)
	}
	if discovery.calls != 0 {
		t.Fatal("a service-narrowed view answered with project-wide telemetry")
	}
	if len(v.Services) != 1 || len(v.Projects[0].Sources) != 1 || v.Projects[0].Sources[0].ID != src1.ID {
		t.Fatalf("evidence of another service listed: %+v", v)
	}
	if st["releases"] != httpapi.StateIncomplete || st["dependencies"] != httpapi.StateEmpty {
		t.Fatalf("declared sections: %+v", v.Sections)
	}

	// An open incident linked to s1 makes s1 failing and no other service.
	admin, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{p}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	incident, condition, episode := model.NewID(), model.NewID(), model.NewID()
	target := incidents.Target{Org: org, Project: p, Incident: incident}
	if _, err = e.app.Incidents.Act(e.ctx, admin, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: target,
		Impact: &incidents.Impact{Condition: condition, Episode: episode, Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}}, 0); err != nil {
		t.Fatal(err)
	}
	if v, err = read(&s1, nil); err != nil || v.Health.Status != httpapi.HealthHealthy {
		t.Fatalf("an incident with no service link changed health: %+v %v", v.Health, err)
	}
	if _, err = e.app.Incidents.Act(e.ctx, admin, incidents.Action{CommandID: model.NewID(), ExpectedVersion: 1, Type: incidents.TypeLink, Origin: incidents.OriginSystem, Target: target, Link: &incidents.Link{Kind: incidents.LinkService, ID: s1}}, 0); err != nil {
		t.Fatal(err)
	}
	v, err = read(&s1, nil)
	if err != nil || v.Health.Status != httpapi.HealthFailing || len(v.Health.Incidents) != 1 || v.Health.Incidents[0].ID != incident || v.Health.Incidents[0].Project != p || v.Health.Incidents[0].Severity != "major" {
		t.Fatalf("failing service: %+v %v", v.Health, err)
	}
	if v, err = read(&s2, nil); err != nil || v.Health.Status != httpapi.HealthHealthy {
		t.Fatalf("another service's incident leaked into s2: %+v %v", v.Health, err)
	}

	// Resolving the incident ends failing; only conditions that name the service degrade it.
	if _, err = e.app.Incidents.Act(e.ctx, admin, incidents.Action{CommandID: model.NewID(), ExpectedVersion: 2, Type: incidents.TypeResolve, Origin: incidents.OriginHuman, Target: target, Reason: "fixed"}, 0); err != nil {
		t.Fatal(err)
	}
	if v, err = read(&s1, nil); err != nil || v.Health.Status != httpapi.HealthHealthy {
		t.Fatalf("resolved incident still fails the service: %+v %v", v.Health, err)
	}
	firing := conditionRecord(t, org, p, conditions.PhaseFiring, s2)
	recovered := conditionRecord(t, org, p, conditions.PhaseRecovered, s2)
	pending := conditionRecord(t, org, p, conditions.PhasePending, s2)
	elsewhere := conditionRecord(t, org, p, conditions.PhaseFiring, model.NewID())
	health.conds[p] = []control.ConditionRecord{firing, recovered, pending, elsewhere}
	v, err = read(&s2, nil)
	if err != nil || v.Health.Status != httpapi.HealthDegraded || len(v.Health.Conditions) != 1 || v.Health.Conditions[0].ID != firing.ID || v.Health.Conditions[0].Phase != "firing" || v.Health.Conditions[0].Freshness != "fresh" {
		t.Fatalf("degraded service: %+v %v", v.Health, err)
	}
	if v, err = read(&s1, nil); err != nil || v.Health.Status != httpapi.HealthHealthy {
		t.Fatalf("a condition naming s2 degraded s1: %+v %v", v.Health, err)
	}

	// A refused or unreadable health read is its own section; the view stays and is never healthy.
	health.deny = model.Fail(model.Forbidden)
	v, err = read(&s2, nil)
	if err != nil || v.Health != nil || sectionStates(v)["health"] != httpapi.StateNotAvailable || sectionStates(v)["identity"] != httpapi.StateReady {
		t.Fatalf("denied health: %+v %v", v, err)
	}
	health.deny = nil
	health.conds[p] = []control.ConditionRecord{{Org: org, Project: p, ID: model.NewID(), Version: 1, State: json.RawMessage(`{"condition_id":"nope"}`)}}
	if v, err = read(&s2, nil); err != nil || v.Health != nil || v.Sections[len(v.Sections)-3].Reason != httpapi.ReasonHealthUnreadable {
		t.Fatalf("unreadable condition read as health: %+v %v", v, err)
	}
	health.conds[p] = nil

	// A target no policy admits, in any form, is one NotFound.
	unknown := model.NewID()
	if _, err = read(&unknown, nil); faultCode(err) != model.NotFound {
		t.Fatalf("unknown service: %v", err)
	}
	// The environment filter is server side: it narrows the catalogue, an
	// unlisted environment is empty, and a target outside it is not found.
	if v, err = read(nil, &e1); err != nil || len(v.Services) != 1 || v.Services[0].ID != s1 || len(v.Projects[0].Sources) != 1 || v.Projects[0].Sources[0].ID != src1.ID {
		t.Fatalf("environment filter: %+v %v", v, err)
	}
	if sectionStates(v)["telemetry"] != httpapi.StateNotAvailable || discovery.calls != 0 {
		t.Fatalf("environment-narrowed view answered project-wide telemetry: %+v", v.Sections)
	}
	if v, err = read(nil, &unknown); err != nil || len(v.Services) != 0 || v.State != httpapi.StateEmpty {
		t.Fatalf("unlisted environment: %+v %v", v, err)
	}
	if _, err = read(&s2, &e1); faultCode(err) != model.NotFound {
		t.Fatalf("service outside the environment: %v", err)
	}
	if v, err = read(&s2, &e2); err != nil || len(v.Services) != 1 {
		t.Fatalf("service inside its environment: %+v %v", v, err)
	}
	zero := model.ID{}
	if _, err = read(nil, &zero); faultCode(err) != model.Invalid {
		t.Fatalf("zero environment: %v", err)
	}
	if _, err = inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: httpapi.KindTrace, Projects: []model.ID{p}, Target: &s1, Environment: &e1, Window: win, Limit: 10}); faultCode(err) != model.Invalid {
		t.Fatalf("environment on a non-service kind: %v", err)
	}
}

// TestServiceCatalogueNeverLeaksAnotherScope: a reader sees only the services of
// the projects it may read; the same service ID in a project it may not read
// (or another organization) is not found, with no sign it exists.
func TestServiceCatalogueNeverLeaksAnotherScope(t *testing.T) {
	e := newIsoEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("catalogue org", p1, p2)
	other := e.org("other org", model.NewID())
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p1, true, auth.Read)
	shared := model.NewID()
	e.source(org, p1, sharedIDs{shared, model.NewID(), model.NewID()}, []model.Kind{model.Metric})
	hidden := model.NewID()
	e.source(org, p2, sharedIDs{hidden, model.NewID(), model.NewID()}, []model.Kind{model.Metric})
	e.source(other, mustProject(t, e, other), sharedIDs{model.NewID(), model.NewID(), model.NewID()}, []model.Kind{model.Metric})
	scope, err := e.scope(alice, org, p1, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := httpapi.NewInvestigator(e.app.Auth, &fakeDiscovery{result: query.DiscoveryResult{Freshness: query.Freshness{Completeness: "complete"}}}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	win := query.TimeRange{Start: 10, End: 20}
	v, err := inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p1}, Window: win, Limit: 10})
	if err != nil || len(v.Services) != 1 || v.Services[0].ID != shared {
		t.Fatalf("catalogue of p1: %+v %v", v.Services, err)
	}
	if _, err = inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p1}, Target: &hidden, Window: win, Limit: 10}); faultCode(err) != model.NotFound {
		t.Fatalf("service of an unreadable project: %v", err)
	}
	if _, err = inv.Investigate(e.ctx, scope, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p2}, Window: win, Limit: 10}); faultCode(err) != model.NotFound {
		t.Fatalf("unreadable project: %v", err)
	}
	// A request narrower than the grant lists only the requested project's services.
	e.grant(org, alice, p2, true, auth.Read)
	both, err := e.app.Auth.Authorize(e.ctx, alice.Cred, org, []model.ID{p1, p2}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = inv.Investigate(e.ctx, both, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p1}, Window: win, Limit: 10}); err != nil || len(v.Services) != 1 || v.Services[0].ID != shared {
		t.Fatalf("services of an unrequested project listed: %+v %v", v.Services, err)
	}
	if _, err = inv.Investigate(e.ctx, both, httpapi.InvestigationRequest{Kind: httpapi.KindService, Projects: []model.ID{p1}, Target: &hidden, Window: win, Limit: 10}); faultCode(err) != model.NotFound {
		t.Fatalf("service of an unrequested project: %v", err)
	}
}

func mustProject(t *testing.T, e *isoEnv, org model.ID) model.ID {
	t.Helper()
	p := model.NewID()
	e.cmd(org, "create_project", auth.AdminPayload{ID: p, Name: "project"})
	return p
}
