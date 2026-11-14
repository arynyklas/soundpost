// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// notifyFixture drives the REAL durable outbox (notify.Outbox over the real
// control store) for real committed incidents, exactly as the background worker
// does, so the queue is read back from committed state. Only the provider
// outcome of each attempt is chosen by the test.
type notifyFixture struct {
	e       *actEnv
	org     model.ID
	project model.ID
	policy  model.ID
	dest    model.ID
	outbox  *notify.Outbox
	seq     byte
}

func newNotifyFixture(t *testing.T, e *actEnv, org, project model.ID) *notifyFixture {
	t.Helper()
	ob, err := notify.NewOutbox(e.app.Control, e.app.Control.ReplicaGroup(), wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	f := &notifyFixture{e: e, org: org, project: project, policy: model.NewID(), dest: model.NewID(), outbox: ob}
	e.cmd(org, "destination", auth.AdminPayload{ID: f.dest, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "SECRET-DESTINATION-TEXT-71c2"})
	return f
}

func (f *notifyFixture) scope() auth.Scope {
	f.e.t.Helper()
	s, err := f.e.app.Auth.Authorize(f.e.ctx, f.e.actor.Cred, f.org, []model.ID{f.project}, auth.OrgAdmin)
	if err != nil {
		f.e.t.Fatal(err)
	}
	return s
}

func (f *notifyFixture) event(kind notify.EventKind, subject notify.Entity) notify.PolicyEvent {
	f.seq++
	cfg := notify.DefaultConfig()
	ev := notify.PolicyEvent{Kind: kind, Command: model.ID{0xc0, f.seq, byte(len(subject.ID))}, Org: f.org, Project: f.project, Policy: f.policy, PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfg}, OwnerRevision: 1}
	copy(ev.Command[3:], subject.ID[:12])
	return ev
}

// submit opens the notification for one committed incident: the recipient, then
// the incident snapshot, both through the real outbox.
func (f *notifyFixture) submit(incident model.ID, severity notify.Severity) {
	f.e.t.Helper()
	scope := f.scope()
	lease, err := f.e.app.Control.ReplicaGroup().Fence(f.e.ctx)
	if err != nil {
		f.e.t.Fatal(err)
	}
	subject := notify.Entity{Kind: notify.EntityIncident, ID: incident}
	at := model.UnixNano(time.Now().UnixNano())
	dest := f.event(notify.EventDestination, subject)
	dest.Destination = &notify.DestinationChange{Recipient: f.dest, Enabled: true}
	if _, err = f.outbox.Submit(f.e.ctx, scope, lease, subject, dest, at); err != nil {
		f.e.t.Fatal("destination event:", err)
	}
	ev := f.event(notify.EventIncident, subject)
	ev.Entity = &subject
	ev.Mode = notify.ModeLive
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: severity, ImpactRevision: 1, Episode: model.ID{0xe9}, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if _, err = f.outbox.Submit(f.e.ctx, scope, lease, subject, ev, at); err != nil {
		f.e.t.Fatal("incident event:", err)
	}
}

// claimAll leases every due delivery and closes each attempt with outcome.
func (f *notifyFixture) claimAll(outcome notify.Outcome) int {
	f.e.t.Helper()
	scope := f.scope()
	lease, err := f.e.app.Control.ReplicaGroup().Fence(f.e.ctx)
	if err != nil {
		f.e.t.Fatal(err)
	}
	claimed, err := f.outbox.Claim(f.e.ctx, scope, model.UnixNano(time.Now().UnixNano()), lease, notify.MaxClaim)
	if err != nil {
		f.e.t.Fatal("claim:", err)
	}
	for _, d := range claimed {
		if err = f.outbox.Complete(f.e.ctx, scope, d.ID, d.Attempt, outcome); err != nil {
			f.e.t.Fatal("complete:", err)
		}
	}
	return len(claimed)
}

func (e *actEnv) queueView(who person, org model.ID, projects ...model.ID) httpapi.QueueView {
	e.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	status, raw := e.post(who, "/api/v1/queue", map[string]any{"org": org.String(), "projects": ids, "limit": 50})
	if status != 200 {
		e.t.Fatalf("queue: %d %s", status, raw)
	}
	var v httpapi.QueueView
	if err := json.Unmarshal(raw, &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func entryOf(t *testing.T, v httpapi.QueueView, id model.ID) httpapi.IncidentView {
	t.Helper()
	for _, e := range v.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("incident %s not in the queue", id)
	return httpapi.IncidentView{}
}

// The queue and the incident read show what the committed outbox and policy
// state hold: a failed delivery and an uncertain one are visible and named, a
// delivery not yet claimed is pending (visible before any digest), an incident
// no policy evaluated says so instead of showing a tier, and the order follows
// the canonical urgency tier.
func TestQueueShowsUrgencyDeliveryDigestAndUnreadFromTheOutbox(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("queue delivery org", p1)
	alice := e.user(org, "alice-qd@example.test")
	e.admin(org, alice)
	f := newNotifyFixture(t, e, org, p1)

	failed, _, _ := e.open(org, p1, incidents.SeverityMajor)
	uncertain, _, _ := e.open(org, p1, incidents.SeverityMajor)
	pending, _, _ := e.open(org, p1, incidents.SeverityMajor)
	unevaluated, _, _ := e.open(org, p1, incidents.SeverityCritical)

	f.submit(failed, notify.SeverityMajor)
	if n := f.claimAll(notify.Outcome{Kind: notify.OutcomeTerminal, Code: "http_410"}); n == 0 {
		t.Fatal("nothing was claimed for the failing incident")
	}
	f.submit(uncertain, notify.SeverityMajor)
	if n := f.claimAll(notify.Outcome{Kind: notify.OutcomeUnknown, Code: "timeout"}); n == 0 {
		t.Fatal("nothing was claimed for the uncertain incident")
	}
	f.submit(pending, notify.SeverityMajor)

	v := e.queueView(alice, org, p1)
	states := map[string]httpapi.ViewState{}
	for _, s := range v.Sections {
		states[s.Name] = s.State
	}
	if v.State != httpapi.StateReady || states["urgency"] != httpapi.StateReady || states["delivery"] != httpapi.StateReady || states["digest"] != httpapi.StateReady || states["unread_change"] != httpapi.StateReady {
		t.Fatalf("sections must be ready when the outbox is wired: %+v state %s", v.Sections, v.State)
	}

	fv := entryOf(t, v, failed).Notification
	if fv.Delivery.State != httpapi.StateReady || fv.Delivery.Attention != "failed" || fv.Delivery.Counts["failed"] == 0 {
		t.Fatalf("failed delivery not visible: %+v", fv.Delivery)
	}
	var sawFailed bool
	for _, d := range fv.Delivery.Entries {
		if d.Status == "failed" && d.LastOutcome == "terminal" && d.LastCode == "http_410" && d.Attempts == 1 {
			sawFailed = true
		}
	}
	if !sawFailed {
		t.Fatalf("the failed entry must carry its attempt outcome and code: %+v", fv.Delivery.Entries)
	}

	uv := entryOf(t, v, uncertain).Notification
	if uv.Delivery.Attention != "uncertain" || uv.Delivery.Counts["uncertain"] == 0 {
		t.Fatalf("uncertain delivery not visible: %+v", uv.Delivery)
	}
	var sawUncertain bool
	for _, d := range uv.Delivery.Entries {
		if d.Status == "uncertain" && d.Uncertain && d.LastOutcome == "unknown" && d.Phase != "accepted" {
			sawUncertain = true
		}
	}
	if !sawUncertain {
		t.Fatalf("the uncertain entry must say the provider may have accepted it: %+v", uv.Delivery.Entries)
	}

	pv := entryOf(t, v, pending).Notification
	if pv.Delivery.Attention != "pending" || pv.Delivery.Counts["pending"] == 0 {
		t.Fatalf("an unclaimed delivery is pending: %+v", pv.Delivery)
	}
	for _, n := range []httpapi.NotificationView{fv, uv, pv} {
		if n.Urgency.State != httpapi.StateReady || n.Urgency.Tier != string(notify.TierUrgent) || n.Urgency.Mode != string(notify.ModeActive) {
			t.Fatalf("urgency must be the policy's tier: %+v", n.Urgency)
		}
		if n.Digest.State != httpapi.StateReady || n.Unread.State != httpapi.StateReady || !n.Unread.Changed || n.Unread.QueueRevision == 0 || n.Unread.SeenRevision >= n.Unread.QueueRevision {
			t.Fatalf("digest/unread must come from the policy state: digest %+v unread %+v", n.Digest, n.Unread)
		}
	}

	un := entryOf(t, v, unevaluated).Notification
	if un.Urgency.State != httpapi.StateEmpty || un.Urgency.Reason != httpapi.ReasonNoPolicyState || un.Urgency.Tier != "" ||
		un.Delivery.State != httpapi.StateEmpty || un.Delivery.Reason != httpapi.ReasonNoDeliveries || un.Delivery.Attention != "none" ||
		un.Unread.State != httpapi.StateEmpty || un.Digest.State != httpapi.StateEmpty {
		t.Fatalf("an incident no policy evaluated must say so and show no tier or delivery: %+v", un)
	}

	// Canonical urgency order: the unevaluated critical incident (tier none)
	// sorts after the three urgent major ones even though it is more severe.
	if last := v.Entries[len(v.Entries)-1]; last.ID != unevaluated {
		t.Fatalf("urgent tier must sort before an unevaluated incident: last is %s", last.ID)
	}

	// The incident read and a committed action answer the same notification state.
	got := e.incident(alice, org, p1, failed)
	if got.Notification.Delivery.Attention != "failed" || got.Notification.Urgency.Tier != string(notify.TierUrgent) {
		t.Fatalf("incident read: %+v", got.Notification)
	}
	resp := e.respond(e.post(alice, "/api/v1/actions", act(org, p1, failed, "ack", 1, map[string]any{"reason": "looking"})))
	if resp.Incident == nil || resp.Incident.Notification.Delivery.Attention != "failed" {
		t.Fatalf("a committed action must carry the delivery state: %+v", resp.Incident)
	}
}

// A queue whose project has no outbox entries and no wired reader are different
// answers: only the unwired reader is not_available.
func TestQueueNotificationSectionsAreNotAvailableOnlyWithoutAReader(t *testing.T) {
	e := newActEnv(t)
	p1 := model.NewID()
	org := e.org("queue unwired org", p1)
	alice := e.user(org, "alice-qu@example.test")
	e.admin(org, alice)
	id, _, _ := e.open(org, p1, incidents.SeverityMinor)

	wired := e.queueView(alice, org, p1)
	if n := entryOf(t, wired, id).Notification; n.Delivery.State != httpapi.StateEmpty || n.Delivery.Reason != httpapi.ReasonNoDeliveries {
		t.Fatalf("a wired reader with no delivery is empty with a reason: %+v", n.Delivery)
	}

	unwired, err := httpapi.NewActions(e.app.Incidents, bareLister{e.app.Control}, e.app.Control, nil, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	v, err := unwired.Queue(e.ctx, scope, httpapi.QueueRequest{Projects: []model.ID{p1}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	n := v.Entries[0].Notification
	if v.State != httpapi.StateIncomplete || n.Delivery.State != httpapi.StateNotAvailable || n.Delivery.Reason != httpapi.ReasonOutboxNotWired || n.Urgency.State != httpapi.StateNotAvailable {
		t.Fatalf("an unwired reader must be not_available: %s %+v", v.State, n)
	}
}

// bareLister hides everything but the incident list from NewActions.
type bareLister struct {
	inner httpapi.IncidentLister
}

func (b bareLister) Incidents(ctx context.Context, scope auth.Scope, project model.ID) ([]control.IncidentRecord, error) {
	return b.inner.Incidents(ctx, scope, project)
}
