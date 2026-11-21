// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

func issueAct(org, project, target model.ID, kind string) actBody {
	return actBody{"org": org.String(), "command_id": model.NewID().String(), "expected_version": "1", "project_id": project.String(), "target_id": target.String(),
		"entity_kind": "issue", "kind": kind, "payload": map[string]any{"reason": "permission model"}}
}

// Decision D19: a human action needs the project grant that names it, and
// organization administration implies all of them.
func TestActionPermissionModel(t *testing.T) {
	e := newActEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("permission org", p1, p2)
	admin := e.user(org, "admin-perm@example.test")
	erin := e.user(org, "erin-perm@example.test")   // incidents.write on p1
	frank := e.user(org, "frank-perm@example.test") // telemetry.read on p1
	gina := e.user(org, "gina-perm@example.test")   // issues.write on p1
	hank := e.user(org, "hank-perm@example.test")   // policy.write on p1
	ivan := e.user(org, "ivan-perm@example.test")   // rules.write on p1
	june := e.user(org, "june-perm@example.test")   // issues.write + policy.write on p1
	e.admin(org, admin)
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(org, hank, p1, true, auth.PolicyWrite)
	e.grant(org, ivan, p1, true, auth.RulesWrite)
	e.grant(org, june, p1, true, auth.IssuesWrite, auth.PolicyWrite)
	one, condition, episode := e.open(org, p1, incidents.SeverityMajor)
	other, _, _ := e.open(org, p2, incidents.SeverityMajor)

	// incidents.write alone acts as a person on its own project: the actor is the
	// caller, the origin is human, and the committed view is readable by the caller.
	r := e.respond(e.post(erin, "/api/v1/actions", act(org, p1, one, "assign", 1, map[string]any{"owner": erin.ID.String()})))
	if r.Incident == nil || r.Incident.Owner == nil || *r.Incident.Owner != erin.ID || r.Incident.Timeline[1].Actor != erin.ID || r.Incident.Timeline[1].Origin != "human" {
		t.Fatalf("incidents.write must act as the person: %+v", r.Incident)
	}
	if got := e.incident(erin, org, p1, one); got.Version != 2 {
		t.Fatalf("incidents.write must read the incident it acts on: %+v", got)
	}
	if v := e.queueView(erin, org, p1); len(v.Entries) != 1 {
		t.Fatalf("incidents.write must read its project queue: %+v", v)
	}

	// A caller without the grant, with another grant, or on another project gets
	// the one denial a missing project gets: the missing grant is never named.
	var baseline string
	for name, call := range map[string]func() (int, []byte){
		"read only":     func() (int, []byte) { return e.post(frank, "/api/v1/actions", act(org, p1, one, "ack", 2, nil)) },
		"issues.write":  func() (int, []byte) { return e.post(gina, "/api/v1/actions", act(org, p1, one, "ack", 2, nil)) },
		"policy.write":  func() (int, []byte) { return e.post(hank, "/api/v1/actions", act(org, p1, one, "ack", 2, nil)) },
		"rules.write":   func() (int, []byte) { return e.post(ivan, "/api/v1/actions", act(org, p1, one, "ack", 2, nil)) },
		"other project": func() (int, []byte) { return e.post(erin, "/api/v1/actions", act(org, p2, other, "ack", 1, nil)) },
		"missing project": func() (int, []byte) {
			return e.post(erin, "/api/v1/actions", act(org, model.NewID(), one, "ack", 2, nil))
		},
	} {
		status, raw := call()
		if status != http.StatusNotFound {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable from the other denials: %s vs %s", name, got, baseline)
		}
	}
	// rules.write and issues.write authorize no read of an incident either.
	for name, who := range map[string]person{"rules.write": ivan, "issues.write": gina, "policy.write": hank} {
		if status, raw := e.post(who, "/api/v1/incidents/get", map[string]any{"org": org.String(), "project_id": p1.String(), "target_id": one.String()}); status != http.StatusNotFound {
			t.Fatalf("%s must not read an incident: %d %s", name, status, raw)
		}
	}

	// Organization administration implies every grant, with no grant of its own.
	e.respond(e.post(admin, "/api/v1/actions", act(org, p2, other, "ack", 1, nil)))
	if s, raw := e.post(admin, "/api/v1/actions", issueAct(org, p1, model.NewID(), "resolve")); s != http.StatusNotImplemented {
		t.Fatalf("an administrator reaches the issue action: %d %s", s, raw)
	}

	// Issue actions need issues.write; the grouping migration needs issues.write
	// AND policy.write. Permission is decided before the owner answers, so a
	// caller without the grant never learns whether an owner exists.
	issue := model.NewID()
	for name, tc := range map[string]struct {
		who    person
		kind   string
		status int
	}{
		"issues.write resolves":                {gina, "resolve", http.StatusNotImplemented},
		"incidents.write cannot resolve issue": {erin, "resolve", http.StatusNotFound},
		"read cannot resolve issue":            {frank, "resolve", http.StatusNotFound},
		"policy.write cannot resolve issue":    {hank, "resolve", http.StatusNotFound},
		"issues.write cannot migrate":          {gina, "grouping_migration", http.StatusNotFound},
		"policy.write cannot migrate":          {hank, "grouping_migration", http.StatusNotFound},
		"both grants migrate":                  {june, "grouping_migration", http.StatusNotImplemented},
		"administrator migrates":               {admin, "grouping_migration", http.StatusNotImplemented},
	} {
		if status, raw := e.post(tc.who, "/api/v1/actions", issueAct(org, p1, issue, tc.kind)); status != tc.status {
			t.Fatalf("%s: %d want %d: %s", name, status, tc.status, raw)
		}
	}

	// Impact over HTTP: the person with incidents.write reports it; it is an
	// observation of the alert condition (origin system) attributed to that person.
	r = e.respond(e.post(erin, "/api/v1/actions", act(org, p1, one, "impact", 2, map[string]any{"impact": map[string]any{"condition": condition.String(), "episode": episode.String(), "severity": "critical", "state": "firing", "freshness": "fresh"}})))
	if last := r.Incident.Timeline[len(r.Incident.Timeline)-1]; last.Type != "impact" || last.Origin != "system" || last.Actor != erin.ID {
		t.Fatalf("impact over HTTP: %+v", last)
	}

	// Revocation applies at once: the next action is the same denial.
	e.grant(org, erin, p1, false)
	if status, raw := e.post(erin, "/api/v1/actions", act(org, p1, one, "ack", 3, nil)); status != http.StatusNotFound {
		t.Fatalf("a revoked grant must not act: %d %s", status, raw)
	}
	if status, raw := e.post(erin, "/api/v1/incidents/get", map[string]any{"org": org.String(), "project_id": p1.String(), "target_id": one.String()}); status != http.StatusNotFound {
		t.Fatalf("a revoked grant must not read: %d %s", status, raw)
	}
}

// The incidents.write scope reaches the control store for the incident action and
// nothing else, and Act refuses a scope that holds some other grant.
func TestIncidentsWriteScopeIsConfinedToTheIncidentAction(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("confined org", p1)
	erin := e.user(org, "erin-confined@example.test")
	frank := e.user(org, "frank-confined@example.test")
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read, auth.IssuesWrite)
	one, _, _ := e.open(org, p1, incidents.SeverityMinor)

	if auth.IncidentActionKind != string(control.KindIncidentAction) {
		t.Fatalf("auth.IncidentActionKind %q must equal control.KindIncidentAction %q", auth.IncidentActionKind, control.KindIncidentAction)
	}
	scope, err := e.scope(erin, org, p1, auth.IncidentsWrite)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"name": "grab"})
	for _, kind := range []control.CommandKind{control.KindCreateOrg, control.KindGrant, control.KindPolicyChange, control.KindDeleteScope, control.KindRegisterRelease, control.KindClaimDelivery, control.KindApplyCondition} {
		if _, err := e.app.Control.Transact(e.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(kind), Payload: payload}); faultCode(err) != model.Forbidden {
			t.Fatalf("an incidents.write scope must not commit %s: %v", kind, err)
		}
	}

	// Act itself is scope-first: a scope that holds another grant is Forbidden
	// before the incident is looked up.
	for name, grant := range map[string]auth.Permission{"telemetry.read": auth.Read, "issues.write": auth.IssuesWrite} {
		held, err := e.scope(frank, org, p1, grant)
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := e.actions.Act(e.ctx, held, httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: 1, ProjectID: p1, TargetID: one, EntityKind: httpapi.EntityIncident, Kind: httpapi.ActionAck}); faultCode(err) != model.Forbidden {
			t.Fatalf("%s scope acted on an incident: %v", name, err)
		}
	}
	// And the other way: the incidents.write scope reaches no issue action, before
	// the owner of issue actions is consulted.
	if _, err := e.actions.Act(e.ctx, scope, httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: 1, ProjectID: p1, TargetID: model.NewID(), EntityKind: httpapi.EntityIssue, Kind: httpapi.ActionResolve}); faultCode(err) != model.Forbidden {
		t.Fatalf("an incidents.write scope reached an issue action: %v", err)
	}
}
