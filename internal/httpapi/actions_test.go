// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

type wallClock struct{}

func (wallClock) Now() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

// fakePoller is a labelled test double for the deletion poller (C11 PollDelete):
// it answers a fixed receipt for one organization and NotFound for any other
// org or operation, the way the real service does.
type fakePoller struct {
	org      model.ID
	receipts map[model.ID]retention.DeleteReceipt
}

func (f *fakePoller) PollDelete(_ context.Context, scope auth.Scope, op model.ID) (retention.DeleteReceipt, error) {
	r, ok := f.receipts[op]
	if !ok || scope.OrgID() != f.org || scope.Permission() != auth.OrgAdmin {
		return retention.DeleteReceipt{}, model.Fail(model.NotFound)
	}
	return r, nil
}

// actEnv serves the human-action routes over the real control store, real auth
// and the REAL committed incidents service (app.Incidents). Only the deletion
// poller is a double.
type actEnv struct {
	*isoEnv
	srv     *httptest.Server
	actions *httpapi.Actions
	poller  *fakePoller
}

func newActEnv(t *testing.T) *actEnv {
	t.Helper()
	e := &actEnv{isoEnv: newIsoEnv(t), poller: &fakePoller{receipts: map[model.ID]retention.DeleteReceipt{}}}
	var err error
	if e.actions, err = httpapi.NewActions(e.app.Incidents, e.app.Control, e.app.Control, e.poller, wallClock{}); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterActionRoutes(mux, e.app.Auth, e.actions)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *actEnv) do(who person, method, path string, body any, mutate func(*http.Request)) (int, []byte) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, reader)
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *actEnv) post(who person, path string, body any) (int, []byte) {
	return e.do(who, "POST", path, body, nil)
}

func (e *actEnv) admin(org model.ID, who person) {
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: who.ID, Enabled: true})
}

// open commits version 1 of a real incident through the real incidents service,
// exactly as the condition engine would.
func (e *actEnv) open(org, project model.ID, severity incidents.Severity) (incident, condition, episode model.ID) {
	e.t.Helper()
	incident, condition, episode = model.NewID(), model.NewID(), model.NewID()
	scope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		e.t.Fatal(err)
	}
	st, err := e.app.Incidents.Act(e.ctx, scope, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Org: org, Project: project, Incident: incident},
		Impact: &incidents.Impact{Condition: condition, Episode: episode, Severity: severity, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}}, 0)
	if err != nil || st.Version != 1 {
		e.t.Fatal("open", st.Version, err)
	}
	return
}

type actBody map[string]any

func act(org, project, incident model.ID, kind string, expected uint64, payload map[string]any) actBody {
	if payload == nil {
		payload = map[string]any{}
	}
	return actBody{"org": org.String(), "command_id": model.NewID().String(), "expected_version": strconv.FormatUint(expected, 10), "project_id": project.String(), "target_id": incident.String(),
		"entity_kind": "incident", "kind": kind, "payload": payload}
}

func (e *actEnv) respond(status int, raw []byte) httpapi.ActionResponse {
	e.t.Helper()
	return e.respondWant(200, status, raw)
}

func (e *actEnv) respondWant(want, status int, raw []byte) httpapi.ActionResponse {
	e.t.Helper()
	if status != want {
		e.t.Fatalf("status %d want %d: %s", status, want, raw)
	}
	var r httpapi.ActionResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		e.t.Fatalf("not an action response: %v %s", err, raw)
	}
	return r
}

func (e *actEnv) incident(who person, org, project, incident model.ID) httpapi.IncidentView {
	e.t.Helper()
	status, raw := e.post(who, "/api/v1/incidents/get", map[string]any{"org": org.String(), "project_id": project.String(), "target_id": incident.String()})
	if status != 200 {
		e.t.Fatalf("get: %d %s", status, raw)
	}
	var v httpapi.IncidentView
	if err := json.Unmarshal(raw, &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func TestActionVersionAndPermission(t *testing.T) {
	e := newActEnv(t)
	p1, p2, q1 := model.NewID(), model.NewID(), model.NewID()
	org := e.org("actions org", p1, p2)
	other := e.org("other org", q1)
	alice := e.user(org, "alice-actions@example.test")
	bob := e.user(org, "bob-actions@example.test")
	carol := e.user(org, "carol-actions@example.test")
	e.admin(org, alice)
	e.admin(org, bob)
	e.grant(org, carol, p1, true, auth.Read)
	incident, _, _ := e.open(org, p1, incidents.SeverityMajor)
	foreign, _, _ := e.open(other, q1, incidents.SeverityMajor)

	// A and B both load revision 1. A assigns; B's ACK with expected 1 loses.
	loaded := e.incident(bob, org, p1, incident)
	if loaded.Version != 1 || loaded.Status != "open" || !loaded.SourceFiring {
		t.Fatalf("loaded: %+v", loaded)
	}
	assign := act(org, p1, incident, "assign", 1, map[string]any{"owner": alice.ID.String()})
	r := e.respond(e.post(alice, "/api/v1/actions", assign))
	if r.State != httpapi.ActionCommitted || r.Revision == nil || *r.Revision != 2 || r.Incident == nil || r.Incident.Owner == nil || *r.Incident.Owner != alice.ID {
		t.Fatalf("assign: %+v", r)
	}
	status, raw := e.post(bob, "/api/v1/actions", act(org, p1, incident, "ack", 1, map[string]any{"reason": "taking a look"}))
	if status != 409 {
		t.Fatalf("stale ACK: %d %s", status, raw)
	}
	var conflict httpapi.ActionConflict
	if err := json.Unmarshal(raw, &conflict); err != nil || conflict.Code != "conflict" || conflict.Detail != "incident_version_conflict" || conflict.CurrentVersion != 2 {
		t.Fatalf("conflict body must carry the current revision: %s", raw)
	}
	// Exactly one commit: nothing of B's action is applied, no hidden retry.
	now := e.incident(bob, org, p1, incident)
	if now.Version != 2 || now.Ack != nil || len(now.Timeline) != 2 {
		t.Fatalf("lost race changed state: %+v", now)
	}
	// B retries explicitly against the current revision. ACK does not change the
	// source: it is still firing, and the ACK is attributed to the session actor.
	ack := act(org, p1, incident, "ack", 2, map[string]any{"reason": "taking a look"})
	r = e.respond(e.post(bob, "/api/v1/actions", ack))
	v := *r.Incident
	if v.Version != 3 || v.Ack == nil || !v.Ack.Current || v.Ack.Actor != bob.ID || !v.SourceFiring || v.Condition.State != "firing" || v.Status != "open" {
		t.Fatalf("ack: %+v", v)
	}
	last := v.Timeline[len(v.Timeline)-1]
	if last.Type != "ack" || last.Actor != bob.ID || last.Origin != "human" {
		t.Fatalf("ack timeline entry: %+v", last)
	}

	// Reusing a command ID returns the ORIGINAL result and commits nothing.
	r = e.respond(e.post(alice, "/api/v1/actions", assign))
	if r.Revision == nil || *r.Revision != 2 || r.Incident.Version != 2 || r.Incident.Ack != nil {
		t.Fatalf("replay must return the original result: %+v", r)
	}
	if cur := e.incident(bob, org, p1, incident); cur.Version != 3 || len(cur.Timeline) != 3 {
		t.Fatalf("replay committed a duplicate: %+v", cur)
	}
	// Another principal's command ID is not-found; the same ID with other content
	// is a distinct conflict that carries no revision.
	if s, raw := e.post(bob, "/api/v1/actions", assign); s != 404 {
		t.Fatalf("foreign command ID: %d %s", s, raw)
	}
	changed := act(org, p1, incident, "assign", 1, map[string]any{"owner": alice.ID.String(), "reason": "different"})
	changed["command_id"] = assign["command_id"]
	status, raw = e.post(alice, "/api/v1/actions", changed)
	if code, detail := faultBody(t, raw); status != 409 || code != "conflict" || detail != "incident_command_reused" {
		t.Fatalf("reused command ID with other content: %d %s", status, raw)
	}

	// Wrong-scope targets are indistinguishable from a missing one.
	attempts := map[string]struct {
		who  person
		body actBody
	}{
		"missing incident":          {alice, act(org, p1, model.NewID(), "ack", 3, nil)},
		"other org's incident":      {alice, act(org, p1, foreign, "ack", 1, nil)},
		"other org named":           {alice, act(other, q1, foreign, "ack", 1, nil)},
		"non admin member":          {carol, act(org, p1, incident, "ack", 3, nil)},
		"sibling project":           {alice, act(org, p2, incident, "ack", 3, nil)},
		"other org's project named": {alice, act(org, q1, foreign, "ack", 1, nil)},
		"guessed project":           {alice, act(org, model.NewID(), incident, "ack", 3, nil)},
	}
	var baseline string
	for name, a := range attempts {
		status, raw := e.post(a.who, "/api/v1/actions", a.body)
		got := denial(t, status, raw)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if baseline == "" {
			baseline = got
		}
		if got != baseline {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, baseline)
		}
	}
	if status, _ := e.post(person{}, "/api/v1/actions", act(org, p1, incident, "ack", 3, nil)); status != 401 {
		t.Fatalf("no credential: %d", status)
	}
	// A link would commit at revision 3; without the CSRF token a session must be refused and nothing may change.
	linkBody := act(org, p1, incident, "link", 3, map[string]any{"link": map[string]any{"kind": "release", "id": model.NewID().String()}})
	if status, raw := e.do(alice, "POST", "/api/v1/actions", linkBody, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }); status != 403 {
		t.Fatalf("a session action without the CSRF token: %d %s", status, raw)
	}

	// No body field widens the scope or names the actor.
	for name, extra := range map[string]map[string]any{"actor": {"actor": bob.ID.String()}, "origin": {"origin": "system"}, "org_id": {"org_id": other.String()}, "permission": {"permission": "instance.admin"}, "elevation": {"elevation": model.NewID().String()}} {
		body := act(org, p1, incident, "ack", 3, nil)
		for k, v := range extra {
			body[k] = v
		}
		if status, raw := e.post(alice, "/api/v1/actions", body); status != 400 {
			t.Fatalf("%s accepted from the body: %d %s", name, status, raw)
		}
	}
	nested := act(org, p1, incident, "ack", 3, map[string]any{"actor": bob.ID.String()})
	if status, raw := e.post(alice, "/api/v1/actions", nested); status != 400 {
		t.Fatalf("actor accepted in the payload: %d %s", status, raw)
	}
	if cur := e.incident(alice, org, p1, incident); cur.Version != 3 {
		t.Fatalf("a refused action committed: %+v", cur)
	}

	// The action kinds and entities are closed; open is never a human action.
	for name, mutate := range map[string]func(actBody){
		"unknown kind":           func(b actBody) { b["kind"] = "delete" },
		"open":                   func(b actBody) { b["kind"] = "open" },
		"unknown entity":         func(b actBody) { b["entity_kind"] = "release" },
		"issue kind on incident": func(b actBody) { b["kind"] = "ignore" },
		"owner on an ack":        func(b actBody) { b["payload"] = map[string]any{"owner": alice.ID.String()} },
		"until on an ack":        func(b actBody) { b["payload"] = map[string]any{"until": "1"} },
		"zero command":           func(b actBody) { b["command_id"] = model.ID{}.String() },
		"unknown owner":          func(b actBody) { b["kind"] = "assign"; b["payload"] = map[string]any{"owner": model.NewID().String()} },
	} {
		body := act(org, p1, incident, "ack", 3, nil)
		mutate(body)
		if status, raw := e.post(alice, "/api/v1/actions", body); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}

	// Issue actions have no owner: an explicit not_available, never a success,
	// and never before the scope check.
	issue := act(org, p1, model.NewID(), "resolve", 1, map[string]any{"reason": "fixed"})
	issue["entity_kind"] = "issue"
	issueStatus, issueRaw := e.post(alice, "/api/v1/actions", issue)
	r = e.respondWant(501, issueStatus, issueRaw)
	if r.State != httpapi.ActionNotAvailable || r.Reason != httpapi.ReasonIssueActionsNotBuilt || r.Revision != nil || r.Incident != nil {
		t.Fatalf("issue action: %+v", r)
	}
	if status, raw := e.post(carol, "/api/v1/actions", issue); status != 404 {
		t.Fatalf("a non-admin learned the issue service state: %d %s", status, raw)
	}
}

func TestActionResolveImpactAndWindows(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("windows org", p1)
	alice := e.user(org, "alice-windows@example.test")
	e.admin(org, alice)

	// Resolve while the source is firing needs a reason; resolving does not make
	// the source recovered.
	resolving, condition, episode := e.open(org, p1, incidents.SeverityMajor)
	if status, raw := e.post(alice, "/api/v1/actions", act(org, p1, resolving, "resolve", 1, nil)); status != 400 {
		t.Fatalf("resolve without a reason: %d %s", status, raw)
	} else if _, detail := faultBody(t, raw); detail != "incident_reason_invalid" {
		t.Fatalf("detail %q", detail)
	}
	r := e.respond(e.post(alice, "/api/v1/actions", act(org, p1, resolving, "resolve", 1, map[string]any{"reason": "mitigated by rollback"})))
	if v := *r.Incident; v.Status != "resolved" || !v.SourceFiring || v.Condition.State != "firing" || v.ResolvedAt == nil || v.Notification.SuppressedBy != "resolved" || v.Notification.WorseImpactEligible {
		t.Fatalf("resolved while firing: %+v", v)
	}
	if status, raw := e.post(alice, "/api/v1/actions", act(org, p1, resolving, "ack", 2, nil)); status != 409 {
		t.Fatalf("ACK after resolve: %d %s", status, raw)
	} else if _, detail := faultBody(t, raw); detail != "incident_resolved" {
		t.Fatalf("detail %q", detail)
	}

	// ACK pauses reminders but a worse impact stays eligible and voids the ACK.
	acked, condition, episode := e.open(org, p1, incidents.SeverityMajor)
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, acked, "ack", 1, nil)))
	if v := *r.Incident; !v.Notification.RemindersPaused || v.Notification.PausedBy != "ack" || !v.Notification.WorseImpactEligible || v.Notification.Delivery.State != httpapi.StateNotAvailable {
		t.Fatalf("acked: %+v", v.Notification)
	}
	worse := map[string]any{"impact": map[string]any{"condition": condition.String(), "episode": episode.String(), "severity": "critical", "state": "firing", "freshness": "fresh"}}
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, acked, "impact", 2, worse)))
	if v := *r.Incident; v.ImpactRevision != 2 || v.Severity != "critical" || v.Ack == nil || v.Ack.Current || v.Notification.RemindersPaused || !v.Notification.WorseImpactEligible {
		t.Fatalf("worse impact: ack current=%v %+v", v.Ack, v.Notification)
	}
	for name, impact := range map[string]map[string]any{
		"recovered but stale": {"condition": condition.String(), "episode": episode.String(), "severity": "critical", "state": "recovered", "freshness": "stale"},
		"other condition":     {"condition": model.NewID().String(), "episode": episode.String(), "severity": "critical", "state": "firing", "freshness": "fresh"},
		"unknown severity":    {"condition": condition.String(), "episode": episode.String(), "severity": "catastrophic", "state": "firing", "freshness": "fresh"},
	} {
		if status, raw := e.post(alice, "/api/v1/actions", act(org, p1, acked, "impact", 3, map[string]any{"impact": impact})); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}

	// Snooze and maintenance are separate, expiring, reasoned scopes. Only an
	// active maintenance window makes a worse impact ineligible.
	windowed, condition, episode := e.open(org, p1, incidents.SeverityMinor)
	until := strconv.FormatInt(time.Now().Add(time.Hour).UnixNano(), 10)
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, windowed, "snooze", 1, map[string]any{"reason": "known flapping", "until": until})))
	if v := *r.Incident; v.Snooze == nil || !v.Snooze.Active || v.Snooze.Reason != "known flapping" || v.Snooze.Actor != alice.ID || string(strconv.AppendInt(nil, int64(v.Snooze.Until), 10)) != until || !v.Notification.RemindersPaused || v.Notification.PausedBy != "snooze" || !v.Notification.WorseImpactEligible || v.Maintenance != nil {
		t.Fatalf("snooze: %+v", v)
	}
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, windowed, "maintenance", 2, map[string]any{"reason": "planned upgrade", "until": until})))
	if v := *r.Incident; v.Maintenance == nil || !v.Maintenance.Active || v.Notification.WorseImpactEligible || v.Notification.SuppressedBy != "maintenance" || !v.SourceFiring {
		t.Fatalf("maintenance: %+v", v)
	}
	if status, raw := e.post(alice, "/api/v1/actions", act(org, p1, windowed, "maintenance_end", 3, nil)); status != 400 {
		t.Fatalf("ending maintenance without a reason: %d %s", status, raw)
	}
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, windowed, "maintenance_end", 3, map[string]any{"reason": "upgrade finished"})))
	if v := *r.Incident; v.Maintenance == nil || v.Maintenance.Active || v.Maintenance.Ended == nil || !v.Notification.WorseImpactEligible {
		t.Fatalf("maintenance end: %+v", v)
	}
	past := strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10)
	if status, raw := e.post(alice, "/api/v1/actions", act(org, p1, windowed, "snooze", 4, map[string]any{"reason": "x", "until": past})); status != 400 {
		t.Fatalf("snooze into the past: %d %s", status, raw)
	}
	link := map[string]any{"link": map[string]any{"kind": "issue", "id": model.NewID().String()}}
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, windowed, "link", 4, link)))
	if v := *r.Incident; len(v.Links) != 2 || v.Links[1].Kind != incidents.LinkIssue {
		t.Fatalf("link: %+v", v.Links)
	}
	_ = condition
	_ = episode
}

func TestActionQueueIsScopedAndTruthfulAboutMissingOwners(t *testing.T) {
	e := newActEnv(t)
	p1, p2, q1 := model.NewID(), model.NewID(), model.NewID()
	org := e.org("queue org", p1, p2)
	other := e.org("queue other", q1)
	alice := e.user(org, "alice-queue@example.test")
	carol := e.user(org, "carol-queue@example.test")
	e.admin(org, alice)
	e.grant(org, carol, p1, true, auth.Read)
	minor, _, _ := e.open(org, p1, incidents.SeverityMinor)
	critical, _, _ := e.open(org, p1, incidents.SeverityCritical)
	done, _, _ := e.open(org, p1, incidents.SeverityCritical)
	e.respond(e.post(alice, "/api/v1/actions", act(org, p1, done, "resolve", 1, map[string]any{"reason": "done"})))
	hidden, _, _ := e.open(org, p2, incidents.SeverityCritical)
	e.open(other, q1, incidents.SeverityCritical)

	queue := func(who person, projects ...model.ID) (int, []byte) {
		ids := make([]string, len(projects))
		for i, p := range projects {
			ids[i] = p.String()
		}
		return e.post(who, "/api/v1/queue", map[string]any{"org": org.String(), "projects": ids, "limit": 50})
	}
	status, raw := queue(carol, p1)
	if status != 200 {
		t.Fatalf("queue: %d %s", status, raw)
	}
	var v httpapi.QueueView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var order []model.ID
	for _, entry := range v.Entries {
		order = append(order, entry.ID)
		if len(entry.Timeline) != 0 {
			t.Fatal("a queue row carried a whole timeline")
		}
	}
	if len(order) != 3 || order[0] != critical || order[1] != minor || order[2] != done {
		t.Fatalf("order must be open first then severity: %v", order)
	}
	// Delivery, digest, urgency and unread state have no owner yet: each is its
	// own not_available section and the view is never ready.
	states := map[string]httpapi.ViewState{}
	for _, s := range v.Sections {
		states[s.Name] = s.State
	}
	if v.State != httpapi.StateIncomplete || states["incidents"] != httpapi.StateReady || states["delivery"] != httpapi.StateNotAvailable || states["digest"] != httpapi.StateNotAvailable || states["urgency"] != httpapi.StateNotAvailable || states["unread_change"] != httpapi.StateNotAvailable {
		t.Fatalf("sections: %+v state %s", v.Sections, v.State)
	}
	// A page smaller than the answer says so.
	status, raw = e.post(carol, "/api/v1/queue", map[string]any{"org": org.String(), "projects": []string{p1.String()}, "limit": 1})
	var small httpapi.QueueView
	if err := json.Unmarshal(raw, &small); err != nil || status != 200 || len(small.Entries) != 1 || !small.Truncated {
		t.Fatalf("limit: %d %s", status, raw)
	}
	// Ungranted sibling, other org's project, a guess and a mixed set are one answer.
	var baseline string
	for name, projects := range map[string][]model.ID{"ungranted sibling": {p2}, "other org": {q1}, "guess": {model.NewID()}, "mixed": {p1, p2}} {
		s, r := queue(carol, projects...)
		if s != 404 {
			t.Fatalf("%s: %d %s", name, s, r)
		}
		if got := denial(t, s, r); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable", name)
		}
	}
	// An admin without a telemetry grant reads the incidents they can act on; a
	// non-member reads nothing and cannot tell a missing incident from a foreign one.
	if s, r := queue(alice, p1, p2); s != 200 {
		t.Fatalf("admin queue: %d %s", s, r)
	}
	if got := e.incident(alice, org, p2, hidden); got.ID != hidden {
		t.Fatal("admin could not read their incident")
	}
	status, raw = e.post(carol, "/api/v1/incidents/get", map[string]any{"org": org.String(), "project_id": p2.String(), "target_id": hidden.String()})
	status2, raw2 := e.post(carol, "/api/v1/incidents/get", map[string]any{"org": org.String(), "project_id": p1.String(), "target_id": model.NewID().String()})
	if status != 404 || status2 != 404 || denial(t, status, raw) != denial(t, status2, raw2) {
		t.Fatalf("incident read denial: %d %s / %d %s", status, raw, status2, raw2)
	}
}

func TestActionLifecycleOperationPhases(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("operations org", p1)
	other := e.org("operations other", model.NewID())
	alice := e.user(org, "alice-ops@example.test")
	carol := e.user(org, "carol-ops@example.test")
	e.admin(org, alice)
	e.poller.org = org
	physical := model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano())
	backup := model.UnixNano(time.Now().Add(30 * 24 * time.Hour).UnixNano())
	receipt := func(phase, progress, phys string, holds ...model.ID) model.ID {
		id := model.NewID()
		e.poller.receipts[id] = retention.DeleteReceipt{OperationID: id, Phase: phase, Generation: 9, Progress: progress, Physical: phys, PhysicalDeadline: physical, BackupDeadline: backup, Holds: holds, SafeReason: map[string]string{model.DeletePhaseFailed: "barrier_failed"}[phase]}
		return id
	}
	poll := func(who person, org, id model.ID) (int, []byte) {
		return e.do(who, "GET", "/api/v1/lifecycle/operations/"+id.String()+"?org="+org.String(), nil, nil)
	}
	get := func(id model.ID) httpapi.LifecycleOperation {
		status, raw := poll(alice, org, id)
		if status != 200 {
			t.Fatalf("poll: %d %s", status, raw)
		}
		var op httpapi.LifecycleOperation
		if err := json.Unmarshal(raw, &op); err != nil {
			t.Fatal(err)
		}
		return op
	}
	fencing := get(receipt(model.DeletePhaseFencing, "63/64", "pending"))
	if fencing.Phase != "fencing" || fencing.AppliedBarriers != 63 || fencing.PendingGroups != 1 || fencing.Generation != 9 || int64(fencing.PhysicalDeadline) != int64(physical) || int64(fencing.BackupDeadline) != int64(backup) {
		t.Fatalf("one unavailable group must stay fencing with one pending: %+v", fencing)
	}
	logical := get(receipt(model.DeletePhaseComplete, "64/64", "pending"))
	if logical.Phase != "complete" || logical.Physical != "pending" || logical.PendingGroups != 0 {
		t.Fatalf("logical completion is not physical erasure: %+v", logical)
	}
	held := get(receipt(model.DeletePhaseHeld, "0/64", "held", model.NewID()))
	if held.Phase != "held" || held.Holds != 1 || held.Physical != "held" || int64(held.BackupDeadline) != int64(backup) {
		t.Fatalf("held: %+v", held)
	}
	failed := get(receipt(model.DeletePhaseFailed, "10/64", "pending"))
	if failed.Phase != "failed" || failed.SafeFault != "barrier_failed" {
		t.Fatalf("failed: %+v", failed)
	}
	// A progress or phase the engine cannot state is not guessed.
	if status, raw := poll(alice, org, receipt(model.DeletePhaseFencing, "65/64", "pending")); status != 503 {
		t.Fatalf("impossible progress: %d %s", status, raw)
	}
	if status, raw := poll(alice, org, receipt("exploded", "1/64", "pending")); status != 503 {
		t.Fatalf("unknown phase: %d %s", status, raw)
	}
	// Missing, another organization's, a non-admin's and a malformed ID are one answer.
	known := receipt(model.DeletePhaseFencing, "1/64", "pending")
	var baseline string
	for name, c := range map[string]func() (int, []byte){
		"missing":   func() (int, []byte) { return poll(alice, org, model.NewID()) },
		"foreign":   func() (int, []byte) { return poll(alice, other, known) },
		"non admin": func() (int, []byte) { return poll(carol, org, known) },
		"malformed": func() (int, []byte) {
			return e.do(alice, "GET", "/api/v1/lifecycle/operations/zz?org="+org.String(), nil, nil)
		},
	} {
		s, r := c()
		if s != 404 {
			t.Fatalf("%s: %d %s", name, s, r)
		}
		if got := denial(t, s, r); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable", name)
		}
	}
	// Without a poller wired the answer is an explicit not_available operation.
	bare, err := httpapi.NewActions(e.app.Incidents, e.app.Control, e.app.Control, nil, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := e.app.Auth.Authorize(e.ctx, alice.Cred, org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	op, err := bare.GetOperation(e.ctx, scope, known)
	if err != nil || op.State != httpapi.StateNotAvailable || op.Reason != httpapi.ReasonLifecycleNotWired || op.Phase != "" {
		t.Fatalf("unwired: %+v %v", op, err)
	}
}

// The typed over_erased count of a receipt (CD-9) reaches the LifecycleOperation
// body as it is: book names and decimal-string counts, omitted when empty.
func TestActionLifecycleOperationCarriesOverErased(t *testing.T) {
	e := newActEnv(t)
	org := e.org("operations over-erased", model.NewID())
	alice := e.user(org, "alice-over@example.test")
	e.admin(org, alice)
	e.poller.org = org
	physical := model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano())
	put := func(over []model.OverErased) model.ID {
		id := model.NewID()
		e.poller.receipts[id] = retention.DeleteReceipt{OperationID: id, Phase: model.DeletePhaseComplete, Generation: 1, Progress: "64/64", Physical: "pending", PhysicalDeadline: physical, BackupDeadline: physical, OverErased: over}
		return id
	}
	poll := func(id model.ID) string {
		status, raw := e.do(alice, "GET", "/api/v1/lifecycle/operations/"+id.String()+"?org="+org.String(), nil, nil)
		if status != 200 {
			t.Fatalf("poll: %d %s", status, raw)
		}
		return string(raw)
	}
	with := poll(put([]model.OverErased{{Book: model.OverErasedIncident, Count: 2}, {Book: model.OverErasedJob, Count: 1}}))
	if !strings.Contains(with, `"over_erased":[{"book":"incident","count":"2"},{"book":"job","count":"1"}]`) {
		t.Fatalf("over_erased missing or reshaped: %s", with)
	}
	if without := poll(put(nil)); strings.Contains(without, "over_erased") {
		t.Fatalf("an exact erasure must not carry over_erased: %s", without)
	}
}

// seamIncidents and seamLister are labelled test doubles: they count how often the owned
// services are reached, to prove the handler answers a wrong-scope target before reaching them.
type seamIncidents struct{ calls int }

func (s *seamIncidents) Act(context.Context, auth.Scope, incidents.Action, model.UnixNano) (incidents.State, error) {
	s.calls++
	return incidents.State{}, model.Fail(model.Unavailable)
}
func (s *seamIncidents) Get(context.Context, auth.Scope, model.ID, model.ID) (incidents.State, error) {
	s.calls++
	return incidents.State{}, model.Fail(model.Unavailable)
}

type seamLister struct {
	calls   int
	records []control.IncidentRecord
}

func (l *seamLister) Incidents(context.Context, auth.Scope, model.ID) ([]control.IncidentRecord, error) {
	l.calls++
	return l.records, nil
}

func TestActionScopeIsCheckedBeforeAnyServiceIsReached(t *testing.T) {
	e := newActEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("seam org", p1, p2)
	alice := e.user(org, "alice-seam@example.test")
	e.admin(org, alice)
	incident, _, _ := e.open(org, p1, incidents.SeverityMajor)
	scope, err := e.app.Auth.Authorize(e.ctx, alice.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	svc, lister := &seamIncidents{}, &seamLister{}
	actions, err := httpapi.NewActions(svc, lister, e.app.Control, nil, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	foreign := httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: 1, ProjectID: p2, TargetID: incident, EntityKind: httpapi.EntityIncident, Kind: httpapi.ActionAck}
	if _, err = actions.Act(e.ctx, scope, foreign); faultCode(err) != model.NotFound || svc.calls != 0 {
		t.Fatalf("a project outside the scope reached the incident service (%d calls): %v", svc.calls, err)
	}
	if _, err = actions.Queue(e.ctx, scope, httpapi.QueueRequest{Projects: []model.ID{p2}, Limit: 10}); faultCode(err) != model.NotFound || lister.calls != 0 {
		t.Fatalf("a project outside the scope reached the lister (%d calls): %v", lister.calls, err)
	}
	// A committed record that contradicts its own header is a fault for the whole read, never skipped.
	records, err := e.app.Control.Incidents(e.ctx, scope, p1)
	if err != nil || len(records) != 1 {
		t.Fatal(err, len(records))
	}
	for name, mutate := range map[string]func(*control.IncidentRecord){
		"version": func(r *control.IncidentRecord) { r.Version++ },
		"id":      func(r *control.IncidentRecord) { r.ID = model.NewID() },
		"state version": func(r *control.IncidentRecord) {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(r.State, &m); err != nil {
				t.Fatal(err)
			}
			m["version"] = json.RawMessage(`"2"`)
			r.State, _ = json.Marshal(m)
		},
	} {
		bad := records[0]
		mutate(&bad)
		lister.records = []control.IncidentRecord{bad}
		if _, err = actions.Queue(e.ctx, scope, httpapi.QueueRequest{Projects: []model.ID{p1}, Limit: 10}); faultCode(err) != model.Corrupt {
			t.Fatalf("%s: corrupt record was served: %v", name, err)
		}
	}
	lister.records = records
	view, err := actions.Queue(e.ctx, scope, httpapi.QueueRequest{Projects: []model.ID{p1}, Limit: 10})
	if err != nil || len(view.Entries) != 1 {
		t.Fatalf("the intact record must be served: %v", err)
	}
}
