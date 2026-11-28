// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// These tests drive POST /api/v1/events/webhooks over the real control store, the real
// authority and the real durable outbox (deliveries are committed through
// notify.Outbox.CommitEvents exactly as the producer does; only the provider outcome of each
// attempt is chosen by the test).

const (
	evSecretOne = "ROUTE-SECRET-ONE-0123456789abcdef"
	evSecretTwo = "ROUTE-SECRET-TWO-0123456789abcdef"
	evPathToken = "PATH-TOKEN-9f3a7c11"
)

type hookEnv struct {
	*actEnv
	srv2 *httptest.Server
}

func newHookEnv(t *testing.T) *hookEnv {
	t.Helper()
	e := &hookEnv{actEnv: newActEnv(t)}
	webhooks, err := httpapi.NewEventWebhooks(e.app.Auth, e.app.Control, e.app.Control, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := httpapi.NewPolicies(e.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	e.srv2 = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterEventWebhookRoutes(mux, e.app.Auth, webhooks)
		httpapi.RegisterPolicyRoutes(mux, e.app.Auth, policies)
	}).Handler)
	t.Cleanup(e.srv2.Close)
	return e
}

func (e *hookEnv) call(who person, path string, body any) (int, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv2.URL+path, bytes.NewReader(raw))
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.srv2.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv2.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *hookEnv) hooks(who person, body map[string]any) (int, []byte) {
	return e.call(who, "/api/v1/events/webhooks", body)
}

func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return v
}

func saveEndpoint(org, id, command model.ID, expected string, change map[string]any) map[string]any {
	change["id"] = id.String()
	return map[string]any{"op": "save", "org": org.String(), "command_id": command.String(), "expected_version": expected, "reason": "receiver change", "endpoint": change}
}

func goodEndpoint(secret string) map[string]any {
	ep := map[string]any{"name": "ops receiver", "url": "https://events.example.test/hook/" + evPathToken, "events": []string{"incident.opened", "issue.new", "release.registered"}, "enabled": true}
	if secret != "" {
		ep["secret"] = secret
	}
	return ep
}

// hookFixture is an organization with two projects, an administrator and the people who must
// NOT be able to use the surface.
type hookFixture struct {
	org, p1, p2    model.ID
	admin          person
	reader, writer person
}

func (e *hookEnv) fixture(name string) hookFixture {
	p1, p2 := model.NewID(), model.NewID()
	f := hookFixture{p1: p1, p2: p2}
	f.org = e.org(name, p1, p2)
	f.admin = e.user(f.org, name+"-admin@example.test")
	e.admin(f.org, f.admin)
	f.reader = e.user(f.org, name+"-reader@example.test")
	e.grant(f.org, f.reader, p1, true, auth.Read)
	f.writer = e.user(f.org, name+"-writer@example.test")
	e.grant(f.org, f.writer, p1, true, auth.Read, auth.PolicyWrite)
	return f
}

func (e *hookEnv) auditText() string {
	var out string
	_ = e.app.Control.View(e.ctx, func(st model.ControlState) error {
		a, _ := json.Marshal(st.Audits)
		b, _ := json.Marshal(st.DeliveryBooks)
		out = string(a) + string(b)
		return nil
	})
	return out
}

// Save creates, edits and rotates an endpoint under the version precondition; the command ID
// makes a retry idempotent; a rotation shows the overlap window; and no response, audit entry
// or outbox record ever carries the secret or the path of the URL.
func TestEventWebhookRoutesSaveListAndRotate(t *testing.T) {
	e := newHookEnv(t)
	f := e.fixture("save")
	var responses []string
	keep := func(status int, raw []byte) (int, []byte) {
		responses = append(responses, string(raw))
		return status, raw
	}

	status, raw := keep(e.hooks(f.admin, map[string]any{"op": "list", "org": f.org.String()}))
	list := decodeInto[httpapi.EventWebhookListAnswer](t, raw)
	if status != 200 || list.State != httpapi.StateReady || len(list.Endpoints) != 0 || len(list.Events) != 8 || list.Events[0] != "incident.opened" {
		t.Fatalf("empty list: %d %s", status, raw)
	}
	for _, name := range list.Events {
		if name == "test.ping" {
			t.Fatal("test.ping is not a subscribable event")
		}
	}

	id, create := model.NewID(), model.NewID()
	before := time.Now()
	status, raw = keep(e.hooks(f.admin, saveEndpoint(f.org, id, create, "0", goodEndpoint(evSecretOne))))
	saved := decodeInto[httpapi.EventWebhookSaveAnswer](t, raw)
	v := saved.Endpoint
	if status != 200 || saved.State != httpapi.ActionCommitted || v.ID != id || v.Name != "ops receiver" || v.Host != "events.example.test" || !v.Enabled || !v.HasSecret || v.Version != 1 ||
		v.State != "no_deliveries" || len(v.Events) != 3 || v.PreviousSecretUntil != nil || v.SecretRotatedAt == nil || time.Duration(int64(*v.SecretRotatedAt)) < time.Duration(before.UnixNano())-time.Second {
		t.Fatalf("create: %d %s", status, raw)
	}
	// The same command again is the same answer and commits nothing more.
	status, raw = keep(e.hooks(f.admin, saveEndpoint(f.org, id, create, "0", goodEndpoint(evSecretOne))))
	if status != 200 || decodeInto[httpapi.EventWebhookSaveAnswer](t, raw).Endpoint.Version != 1 {
		t.Fatalf("replay: %d %s", status, raw)
	}
	// A stale version loses with a conflict.
	status, raw = keep(e.hooks(f.admin, saveEndpoint(f.org, id, model.NewID(), "0", goodEndpoint(""))))
	if status != 409 {
		t.Fatalf("stale version: %d %s", status, raw)
	}
	// An edit that leaves the URL out keeps it; the secret stays.
	edit := goodEndpoint("")
	delete(edit, "url")
	edit["events"] = []string{"incident.resolved"}
	edit["name"] = "renamed"
	status, raw = keep(e.hooks(f.admin, saveEndpoint(f.org, id, model.NewID(), "1", edit)))
	v = decodeInto[httpapi.EventWebhookSaveAnswer](t, raw).Endpoint
	if status != 200 || v.Version != 2 || v.Host != "events.example.test" || v.Name != "renamed" || len(v.Events) != 1 || v.Events[0] != "incident.resolved" || !v.HasSecret || v.PreviousSecretUntil != nil {
		t.Fatalf("edit: %d %s", status, raw)
	}
	// A new secret rotates: both keep signing for 24 hours.
	rotateAt := time.Now()
	status, raw = keep(e.hooks(f.admin, saveEndpoint(f.org, id, model.NewID(), "2", goodEndpoint(evSecretTwo))))
	v = decodeInto[httpapi.EventWebhookSaveAnswer](t, raw).Endpoint
	if status != 200 || v.Version != 3 || v.PreviousSecretUntil == nil {
		t.Fatalf("rotate: %d %s", status, raw)
	}
	until := time.Unix(0, int64(*v.PreviousSecretUntil))
	if d := until.Sub(rotateAt); d < 23*time.Hour+59*time.Minute || d > 24*time.Hour+time.Minute {
		t.Fatalf("the previous secret window is %s", d)
	}
	status, raw = keep(e.hooks(f.admin, map[string]any{"op": "list", "org": f.org.String()}))
	list = decodeInto[httpapi.EventWebhookListAnswer](t, raw)
	if len(list.Endpoints) != 1 || list.Endpoints[0].PreviousSecretUntil == nil || list.Endpoints[0].State != "no_deliveries" || list.Endpoints[0].Version != 3 {
		t.Fatalf("list after rotation: %s", raw)
	}
	for _, r := range responses {
		for _, secret := range []string{evSecretOne, evSecretTwo, evPathToken} {
			if strings.Contains(r, secret) {
				t.Fatalf("a response carries %q: %s", secret, r)
			}
		}
	}
	if audits := e.auditText(); strings.Contains(audits, evSecretOne) || strings.Contains(audits, evSecretTwo) {
		t.Fatal("a secret is in the audit log")
	}
	// The destination, policy and settings surfaces do not list event endpoints.
	status, raw = e.call(f.admin, "/api/v1/destinations", map[string]any{"org": f.org.String(), "project_id": f.p1.String(), "operation": "list"})
	if status != 200 || strings.Contains(string(raw), id.String()) || strings.Contains(string(raw), "event_webhook") {
		t.Fatalf("the destination list shows an event endpoint: %d %s", status, raw)
	}
	status, raw = e.call(f.admin, "/api/v1/policies", map[string]any{"org": f.org.String(), "project_id": f.p1.String(), "operation": "read"})
	if status != 200 || strings.Contains(string(raw), id.String()) {
		t.Fatalf("the policy view shows an event endpoint: %d %s", status, raw)
	}
	// The generic destination route cannot reshape one.
	status, raw = e.call(f.admin, "/api/v1/destinations", saveBody(f.org, f.p1, model.NewID(), 3, "reshape", map[string]any{"id": id.String(), "type": "webhook", "endpoint": "https://hooks.example.test/x", "enabled": true}))
	if status == 200 {
		t.Fatalf("an event endpoint became a webhook through /destinations: %s", raw)
	}
}

// Every invalid endpoint is refused with a closed code and commits nothing.
func TestEventWebhookRouteRefusesInvalidRequests(t *testing.T) {
	e := newHookEnv(t)
	f := e.fixture("invalid")
	snapshot := func() string {
		var out string
		_ = e.app.Control.View(e.ctx, func(st model.ControlState) error {
			o := st.Orgs[f.org.String()]
			a, _ := json.Marshal(o.Settings)
			b, _ := json.Marshal(o.Secrets)
			out = string(a) + string(b)
			return nil
		})
		return out
	}
	mutate := func(fn func(map[string]any)) map[string]any {
		ep := goodEndpoint(evSecretOne)
		fn(ep)
		return ep
	}
	existing := model.NewID()
	if status, raw := e.hooks(f.admin, saveEndpoint(f.org, existing, model.NewID(), "0", goodEndpoint(evSecretOne))); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	for name, body := range map[string]map[string]any{
		"plain http":          saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["url"] = "http://events.example.test/h" })),
		"query in the url":    saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["url"] = "https://events.example.test/h?token=x" })),
		"no events":           saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["events"] = []string{} })),
		"unknown event":       saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["events"] = []string{"incident.exploded"} })),
		"short secret":        saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["secret"] = "short" })),
		"no secret, enabled":  saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { delete(m, "secret") })),
		"no url, new":         saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { delete(m, "url") })),
		"unknown member":      saveEndpoint(f.org, model.NewID(), model.NewID(), "0", mutate(func(m map[string]any) { m["token"] = "x" })),
		"stale on a new id":   saveEndpoint(f.org, model.NewID(), model.NewID(), "5", goodEndpoint(evSecretOne)),
		"existing, version 0": saveEndpoint(f.org, existing, model.NewID(), "0", goodEndpoint("")),
		"no command":          {"op": "save", "org": f.org.String(), "expected_version": "0", "reason": "x", "endpoint": goodEndpoint(evSecretOne)},
		"no reason":           {"op": "save", "org": f.org.String(), "command_id": model.NewID().String(), "expected_version": "0", "endpoint": map[string]any{"id": model.NewID().String()}},
		"unknown op":          {"op": "delete", "org": f.org.String()},
		"no org":              {"op": "list"},
		"list with a command": {"op": "list", "org": f.org.String(), "command_id": model.NewID().String()},
		"test without id":     {"op": "test", "org": f.org.String(), "command_id": model.NewID().String()},
		"deliveries limit":    {"op": "deliveries", "org": f.org.String(), "endpoint": existing.String(), "limit": 5000},
	} {
		before := snapshot()
		status, raw := e.hooks(f.admin, body)
		if status < 400 || status >= 500 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
		if status == 200 {
			t.Errorf("%s was accepted", name)
		}
		if snapshot() != before {
			t.Errorf("%s: a refused request changed the organization", name)
		}
	}
	// An event endpoint cannot take the ID of a notification destination, nor the reverse.
	dest := model.NewID()
	e.cmd(f.org, "destination", auth.AdminPayload{ID: dest, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/n","enabled":true}`), Secret: evSecretOne})
	if status, raw := e.hooks(f.admin, saveEndpoint(f.org, dest, model.NewID(), "0", goodEndpoint(evSecretOne))); status != 400 || !strings.Contains(string(raw), "event_endpoint_id_taken") {
		t.Fatalf("a destination ID: %d %s", status, raw)
	}
}

// hookDriver commits event deliveries through the real outbox, as the producer does.
type hookDriver struct {
	e    *hookEnv
	next int64
}

func (e *hookEnv) driver() *hookDriver {
	return &hookDriver{e: e, next: time.Now().UnixNano() - int64(time.Hour)}
}

func (d *hookDriver) scope(org, project model.ID) auth.Scope {
	d.e.t.Helper()
	s, err := d.e.app.Auth.Authorize(d.e.ctx, d.e.actor.Cred, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		d.e.t.Fatal(err)
	}
	return s
}

func (d *hookDriver) outbox() *notify.Outbox {
	ob, err := notify.NewOutbox(d.e.app.Control, d.e.app.Control.ReplicaGroup(), wallClock{})
	if err != nil {
		d.e.t.Fatal(err)
	}
	return ob
}

// enqueue announces one event of one entity to one endpoint (baselining the feed first) and
// returns the delivery ID.
func (d *hookDriver) enqueue(org, project, endpoint model.ID, name notify.EventName, kind notify.EntityKind, entity model.ID, seq uint64) model.ID {
	d.e.t.Helper()
	ob, scope := d.outbox(), d.scope(org, project)
	lease, err := d.e.app.Control.ReplicaGroup().Fence(d.e.ctx)
	if err != nil {
		d.e.t.Fatal(err)
	}
	d.next += int64(time.Minute)
	at := model.UnixNano(d.next)
	feed, err := ob.EventFeed(d.e.ctx, scope)
	if err != nil {
		d.e.t.Fatal(err)
	}
	if feed.Version == 0 {
		plan, err := feed.State.Plan(org, project, nil, nil, at, true)
		if err != nil {
			d.e.t.Fatal(err)
		}
		if _, err = ob.CommitEvents(d.e.ctx, scope, lease, feed, plan, at); err != nil {
			d.e.t.Fatal("baseline:", err)
		}
		if feed, err = ob.EventFeed(d.e.ctx, scope); err != nil {
			d.e.t.Fatal(err)
		}
	}
	ev := notify.FeedEvent{Name: name, Entity: notify.Entity{Kind: kind, ID: entity}, Seq: seq, At: at, Severity: notify.SeverityMajor, Revision: seq,
		Update: notify.MarkUpdate{Key: notify.MarkKey(kind, entity), Mark: notify.FeedMark{Through: seq}}}
	plan, err := feed.State.Plan(org, project, []notify.FeedEvent{ev}, []notify.FeedEndpoint{{ID: endpoint, Events: []notify.EventName{name}}}, at, false)
	if err != nil || len(plan.Intents) != 1 {
		d.e.t.Fatalf("plan: %+v %v", plan.Intents, err)
	}
	if _, err = ob.CommitEvents(d.e.ctx, scope, lease, feed, plan, at); err != nil {
		d.e.t.Fatal("enqueue:", err)
	}
	return plan.Intents[0].ID
}

// attempt claims every due delivery of the project and closes each with outcome(id).
func (d *hookDriver) attempt(org, project model.ID, outcome func(model.ID) notify.Outcome) {
	d.e.t.Helper()
	ob, scope := d.outbox(), d.scope(org, project)
	lease, err := d.e.app.Control.ReplicaGroup().Fence(d.e.ctx)
	if err != nil {
		d.e.t.Fatal(err)
	}
	claimed, err := ob.Claim(d.e.ctx, scope, model.UnixNano(time.Now().UnixNano()), lease, notify.MaxClaim)
	if err != nil {
		d.e.t.Fatal("claim:", err)
	}
	for _, c := range claimed {
		if err = ob.Complete(d.e.ctx, scope, c.ID, c.Attempt, outcome(c.ID)); err != nil {
			d.e.t.Fatal("complete:", err)
		}
	}
}

var (
	accepted = notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "rcpt-1"}
	retrying = notify.Outcome{Kind: notify.OutcomeRetry, Code: "http_503"}
	failed   = notify.Outcome{Kind: notify.OutcomeTerminal, Code: "http_410"}
	unsure   = notify.Outcome{Kind: notify.OutcomeUnknown, Code: "timeout"}
)

func (e *hookEnv) endpointState(who person, org, id model.ID) httpapi.EventEndpointView {
	e.t.Helper()
	status, raw := e.hooks(who, map[string]any{"op": "list", "org": org.String()})
	if status != 200 {
		e.t.Fatalf("list: %d %s", status, raw)
	}
	for _, ep := range decodeInto[httpapi.EventWebhookListAnswer](e.t, raw).Endpoints {
		if ep.ID == id {
			return ep
		}
	}
	e.t.Fatalf("endpoint %s not listed", id)
	return httpapi.EventEndpointView{}
}

// The state of an endpoint is one word that follows the newest attempted delivery
// (working, retrying, failing), pending while nothing was attempted, no_deliveries before any;
// the deliveries list is the outbox's own records, newest first, across the organization's
// projects, with uncertain deliveries kept visible; it never mixes endpoints.
func TestEventWebhookStateAndDeliveries(t *testing.T) {
	e := newHookEnv(t)
	f := e.fixture("deliveries")
	id, other := model.NewID(), model.NewID()
	for _, ep := range []model.ID{id, other} {
		if status, raw := e.hooks(f.admin, saveEndpoint(f.org, ep, model.NewID(), "0", goodEndpoint(evSecretOne))); status != 200 {
			t.Fatalf("%d %s", status, raw)
		}
	}
	d := e.driver()
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "no_deliveries" || ep.LastDelivery != nil {
		t.Fatalf("before any delivery: %+v", ep)
	}
	status, raw := e.hooks(f.admin, map[string]any{"op": "deliveries", "org": f.org.String(), "endpoint": id.String()})
	empty := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, raw)
	if status != 200 || empty.State != httpapi.StateEmpty || len(empty.Deliveries) != 0 {
		t.Fatalf("empty deliveries: %d %s", status, raw)
	}

	incident, issue, release := model.NewID(), model.NewID(), model.NewID()
	d1 := d.enqueue(f.org, f.p1, id, notify.EventIncidentOpened, notify.EntityIncident, incident, 1)
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "pending" || ep.LastDelivery == nil || ep.LastDelivery.ID != d1 || ep.LastDelivery.Status != "pending" {
		t.Fatalf("a delivery nobody attempted: %+v", ep)
	}
	d.attempt(f.org, f.p1, func(model.ID) notify.Outcome { return accepted })
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "working" || ep.LastDelivery == nil || ep.LastDelivery.Status != "accepted" || ep.LastDelivery.Attempts != 1 {
		t.Fatalf("an accepted delivery: %+v", ep)
	}
	// Another project's delivery, retried, is the newest attempted one.
	d2 := d.enqueue(f.org, f.p2, id, notify.EventIssueNew, notify.EntityIssue, issue, 0)
	d.attempt(f.org, f.p2, func(model.ID) notify.Outcome { return retrying })
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "retrying" || ep.LastDelivery.ID != d2 || ep.LastDelivery.LastCode != "http_503" || ep.LastDelivery.NextAt == nil {
		t.Fatalf("a retrying delivery: %+v", ep)
	}
	// An unattempted newer delivery says nothing about the receiver; a failed one does.
	d3 := d.enqueue(f.org, f.p1, id, notify.EventReleaseRegistered, notify.EntityRelease, release, 0)
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "retrying" || ep.LastDelivery.ID != d2 {
		t.Fatalf("a pending delivery changed the state: %+v", ep)
	}
	d.attempt(f.org, f.p1, func(model.ID) notify.Outcome { return failed })
	if ep := e.endpointState(f.admin, f.org, id); ep.State != "failing" || ep.LastDelivery.ID != d3 || ep.LastDelivery.Status != "failed" {
		t.Fatalf("a failed delivery: %+v", ep)
	}
	// An uncertain delivery is failing and says so.
	d4 := d.enqueue(f.org, f.p1, id, notify.EventIncidentResolved, notify.EntityIncident, incident, 2)
	d.attempt(f.org, f.p1, func(x model.ID) notify.Outcome {
		if x == d4 {
			return unsure
		}
		return retrying
	})
	ep := e.endpointState(f.admin, f.org, id)
	if ep.State != "failing" || ep.LastDelivery.ID != d4 || !ep.LastDelivery.Uncertain || ep.LastDelivery.Status != "uncertain" {
		t.Fatalf("an uncertain delivery: %+v", ep)
	}
	// The other endpoint never saw any of it.
	if o := e.endpointState(f.admin, f.org, other); o.State != "no_deliveries" {
		t.Fatalf("another endpoint: %+v", o)
	}

	status, raw = e.hooks(f.admin, map[string]any{"op": "deliveries", "org": f.org.String(), "endpoint": id.String()})
	all := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, raw)
	if status != 200 || all.State != httpapi.StateReady || len(all.Deliveries) != 4 {
		t.Fatalf("deliveries: %d %s", status, raw)
	}
	want := []struct {
		id    model.ID
		event string
		kind  string
		proj  model.ID
	}{{d4, "incident.resolved", "incident", f.p1}, {d3, "release.registered", "release", f.p1}, {d2, "issue.new", "issue", f.p2}, {d1, "incident.opened", "incident", f.p1}}
	for i, w := range want {
		g := all.Deliveries[i]
		if g.ID != w.id || g.Event != w.event || g.EntityKind != w.kind || g.Project != w.proj {
			t.Fatalf("delivery %d: %+v, want %+v", i, g, w)
		}
	}
	if g := all.Deliveries[0]; g.Phase != "pending" && g.Phase != "claimed" || g.Status != "uncertain" || g.LastOutcome != "unknown" || g.LastCode != "timeout" {
		t.Fatalf("the uncertain delivery: %+v", g)
	}
	status, raw = e.hooks(f.admin, map[string]any{"op": "deliveries", "org": f.org.String(), "endpoint": id.String(), "limit": 2})
	if got := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, raw); status != 200 || len(got.Deliveries) != 2 || got.Deliveries[0].ID != d4 || got.Deliveries[1].ID != d3 {
		t.Fatalf("limit: %d %s", status, raw)
	}
	status, raw = e.hooks(f.admin, map[string]any{"op": "deliveries", "org": f.org.String(), "endpoint": other.String()})
	if got := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, raw); status != 200 || len(got.Deliveries) != 0 || got.State != httpapi.StateEmpty {
		t.Fatalf("the other endpoint's deliveries: %d %s", status, raw)
	}
	// No answer carries a secret, a URL path or a body.
	if strings.Contains(string(raw), evSecretOne) || strings.Contains(string(raw), evPathToken) {
		t.Fatal("a delivery answer carries a secret or a path")
	}
	// The incident queue still reads normally with a feed in the project.
	incidentID, _, _ := e.open(f.org, f.p1, incidents.SeverityMajor)
	view := e.queueView(f.admin, f.org, f.p1)
	if entryOf(t, view, incidentID).ID != incidentID || view.State != httpapi.StateReady {
		t.Fatalf("queue with an event feed: %+v", view.State)
	}
}

// A test request records one request per command and returns where it will appear; it needs
// an enabled endpoint; replaying the command is idempotent; the project is one of the
// organization's.
func TestEventWebhookTestRequest(t *testing.T) {
	e := newHookEnv(t)
	f := e.fixture("test")
	id, off := model.NewID(), model.NewID()
	if status, raw := e.hooks(f.admin, saveEndpoint(f.org, id, model.NewID(), "0", goodEndpoint(evSecretOne))); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	disabled := goodEndpoint(evSecretOne)
	disabled["enabled"] = false
	if status, raw := e.hooks(f.admin, saveEndpoint(f.org, off, model.NewID(), "0", disabled)); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	command := model.NewID()
	status, raw := e.hooks(f.admin, map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String(), "command_id": command.String()})
	answer := decodeInto[httpapi.EventWebhookTestAnswer](t, raw)
	first := f.p1
	if f.p2.String() < first.String() {
		first = f.p2
	}
	if status != 200 || answer.State != "requested" || answer.Endpoint != id || answer.Project != first {
		t.Fatalf("test: %d %s (the first project is %s)", status, raw, first)
	}
	stored := func() auth.EventTestConfig {
		var cfg auth.EventTestConfig
		_ = e.app.Control.View(e.ctx, func(st model.ControlState) error {
			_ = json.Unmarshal(st.Orgs[f.org.String()].Settings["event_test:"+id.String()], &cfg)
			return nil
		})
		return cfg
	}
	cfg := stored()
	if cfg.Command == nil || *cfg.Command != command || cfg.Project != first || cfg.At == 0 {
		t.Fatalf("stored request: %+v", cfg)
	}
	if status, _ = e.hooks(f.admin, map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String(), "command_id": command.String()}); status != 200 || stored().At != cfg.At {
		t.Fatalf("a replayed test command: %d", status)
	}
	// An explicit project; a project of nobody; an unknown endpoint; a disabled one.
	status, raw = e.hooks(f.admin, map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String(), "command_id": model.NewID().String(), "project": f.p2.String()})
	if got := decodeInto[httpapi.EventWebhookTestAnswer](t, raw); status != 200 || got.Project != f.p2 {
		t.Fatalf("explicit project: %d %s", status, raw)
	}
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
	}{
		"a project of nobody": {map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String(), "command_id": model.NewID().String(), "project": model.NewID().String()}, 404},
		"an unknown endpoint": {map[string]any{"op": "test", "org": f.org.String(), "endpoint": model.NewID().String(), "command_id": model.NewID().String()}, 404},
		"a disabled endpoint": {map[string]any{"op": "test", "org": f.org.String(), "endpoint": off.String(), "command_id": model.NewID().String()}, 400},
		"no command":          {map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String()}, 400},
		"with a version":      {map[string]any{"op": "test", "org": f.org.String(), "endpoint": id.String(), "command_id": model.NewID().String(), "expected_version": "1"}, 400},
	} {
		if status, raw = e.hooks(f.admin, tc.body); status != tc.status {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
}

// Only an organization administrator can use the surface; everyone else, another
// organization's administrator, a project writer and a stranger get the same not_found a
// missing organization gives, for every operation, and nothing is read or written.
func TestEventWebhookRouteIsOrganizationAdminOnly(t *testing.T) {
	e := newHookEnv(t)
	a := e.fixture("alpha")
	b := e.fixture("beta")
	id := model.NewID()
	if status, raw := e.hooks(a.admin, saveEndpoint(a.org, id, model.NewID(), "0", goodEndpoint(evSecretOne))); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	bEndpoint := model.NewID()
	if status, raw := e.hooks(b.admin, saveEndpoint(b.org, bEndpoint, model.NewID(), "0", goodEndpoint(evSecretTwo))); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	d := e.driver()
	d.enqueue(a.org, a.p1, id, notify.EventIncidentOpened, notify.EntityIncident, model.NewID(), 1)

	bodies := func(org model.ID, endpoint model.ID) map[string]map[string]any {
		return map[string]map[string]any{
			"list":       {"op": "list", "org": org.String()},
			"save":       saveEndpoint(org, model.NewID(), model.NewID(), "0", goodEndpoint(evSecretOne)),
			"test":       {"op": "test", "org": org.String(), "endpoint": endpoint.String(), "command_id": model.NewID().String()},
			"deliveries": {"op": "deliveries", "org": org.String(), "endpoint": endpoint.String()},
		}
	}
	snapshot := func() string {
		var out string
		_ = e.app.Control.View(e.ctx, func(st model.ControlState) error {
			o := st.Orgs[a.org.String()]
			x, _ := json.Marshal(o.Settings)
			y, _ := json.Marshal(o.Secrets)
			out = string(x) + string(y) + string(rune(len(st.Audits)))
			return nil
		})
		return out
	}
	missing := map[string]string{}
	for op, body := range bodies(model.NewID(), id) { // an organization that does not exist
		status, raw := e.hooks(a.admin, body)
		if status != 404 {
			t.Fatalf("%s on a missing organization: %d %s", op, status, raw)
		}
		missing[op] = errorShape(t, raw)
	}
	before := snapshot()
	for who, p := range map[string]person{"a project reader": a.reader, "a policy writer": a.writer, "another organization's administrator": b.admin, "a member of another organization": b.reader} {
		for op, body := range bodies(a.org, id) {
			status, raw := e.hooks(p, body)
			if status != 404 || errorShape(t, raw) != missing[op] {
				t.Errorf("%s, %s: %d %s (a missing organization answers %s)", who, op, status, raw, missing[op])
			}
		}
	}
	if snapshot() != before {
		t.Fatal("a refused caller changed the organization")
	}
	// No credential at all, and a session without the CSRF token.
	status, _ := e.call(person{}, "/api/v1/events/webhooks", map[string]any{"op": "list", "org": a.org.String()})
	if status != 401 {
		t.Fatalf("no credential: %d", status)
	}
	raw, _ := json.Marshal(map[string]any{"op": "list", "org": a.org.String()})
	req, _ := http.NewRequest("POST", e.srv2.URL+"/api/v1/events/webhooks", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+a.admin.Session.Token)
	req.Header.Set("Origin", e.srv2.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("a session without the CSRF token listed the endpoints")
	}

	// An administrator of organization B sees only B: A's endpoint ID is unknown to B for
	// test and deliveries, and A's deliveries never appear in B's list.
	for op, body := range map[string]map[string]any{
		"test":       {"op": "test", "org": b.org.String(), "endpoint": id.String(), "command_id": model.NewID().String()},
		"deliveries": {"op": "deliveries", "org": b.org.String(), "endpoint": id.String()},
	} {
		if status, raw := e.hooks(b.admin, body); status != 404 {
			t.Errorf("%s of another organization's endpoint: %d %s", op, status, raw)
		}
	}
	status, rawB := e.hooks(b.admin, map[string]any{"op": "list", "org": b.org.String()})
	listB := decodeInto[httpapi.EventWebhookListAnswer](t, rawB)
	if status != 200 || len(listB.Endpoints) != 1 || listB.Endpoints[0].ID != bEndpoint || listB.Endpoints[0].State != "no_deliveries" || strings.Contains(string(rawB), id.String()) {
		t.Fatalf("organization B's list: %d %s", status, rawB)
	}
	// B's administrator cannot reach A's projects' deliveries through B's endpoint either.
	status, rawD := e.hooks(b.admin, map[string]any{"op": "deliveries", "org": b.org.String(), "endpoint": bEndpoint.String()})
	if got := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, rawD); status != 200 || len(got.Deliveries) != 0 {
		t.Fatalf("organization B's deliveries: %d %s", status, rawD)
	}
	// The same endpoint ID can exist in two organizations without crossing: A's deliveries
	// of its endpoint stay A's.
	status, rawA := e.hooks(a.admin, map[string]any{"op": "deliveries", "org": a.org.String(), "endpoint": id.String()})
	if got := decodeInto[httpapi.EventWebhookDeliveriesAnswer](t, rawA); status != 200 || len(got.Deliveries) != 1 {
		t.Fatalf("organization A's deliveries: %d %s", status, rawA)
	}
}

// errorShape is the closed part of an error body: code and detail, never the request ID.
func errorShape(t *testing.T, raw []byte) string {
	t.Helper()
	var body struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return body.Code + "/" + body.Detail
}
