// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// These tests cover the event webhook feed (events.go): the pure plan (identity,
// budget, bounds) and, over the real control store, the one-transaction commit of the
// feed state with its deliveries, replay, the lease fence, the deletion pause, and the
// coexistence with notification policy states.

var (
	epA         = model.ID{0xe1}
	epB         = model.ID{0xe2}
	eventSecret = "EVENT-SECRET-0123456789abcdef"
)

func (n *node) eventEndpoint(id model.ID, enabled bool, events ...string) {
	n.t.Helper()
	cfg, _ := json.Marshal(map[string]any{"type": "event_webhook", "endpoint": "https://events.example.test/hook", "enabled": enabled, "name": "hook", "events": events})
	n.admin("destination", auth.AdminPayload{ID: id, Config: cfg, Secret: eventSecret})
}

func incidentEntity(id model.ID) notify.Entity {
	return notify.Entity{Kind: notify.EntityIncident, ID: id}
}

// opened is an incident.opened event for timeline entry seq of the incident.
func opened(incident model.ID, seq uint64, at model.UnixNano) notify.FeedEvent {
	return notify.FeedEvent{Name: notify.EventIncidentOpened, Entity: incidentEntity(incident), Seq: seq, At: at, Severity: notify.SeverityMajor, Revision: seq,
		Update: notify.MarkUpdate{Key: notify.MarkKey(notify.EntityIncident, incident), Mark: notify.FeedMark{Through: seq}}}
}

// silentIncident is the baseline record of an incident: its mark, no event.
func silentIncident(incident model.ID, through uint64) notify.FeedEvent {
	return notify.FeedEvent{At: base, Update: notify.MarkUpdate{Key: notify.MarkKey(notify.EntityIncident, incident), Mark: notify.FeedMark{Through: through}}}
}

func subscribed(id model.ID, events ...notify.EventName) notify.FeedEndpoint {
	return notify.FeedEndpoint{ID: id, Events: events}
}

func (n *node) commitFeed(ob *notify.Outbox, events []notify.FeedEvent, eps []notify.FeedEndpoint, baseline bool) (notify.EventPlan, notify.Submission, error) {
	n.t.Helper()
	scope := n.scope()
	feed, err := ob.EventFeed(n.ctx, scope)
	if err != nil {
		n.t.Fatal(err)
	}
	plan, err := feed.State.Plan(n.org, n.project, events, eps, base, baseline)
	if err != nil {
		n.t.Fatal(err)
	}
	sub, err := ob.CommitEvents(n.ctx, scope, n.lease(), feed, plan, base)
	return plan, sub, err
}

func (n *node) eventRecords(ob *notify.Outbox) []notify.Record {
	n.t.Helper()
	var out []notify.Record
	for _, r := range n.records(ob, "") {
		if r.Subject == notify.EventSubject {
			out = append(out, r)
		}
	}
	return out
}

// The feed state and the deliveries commit in ONE transaction. The first pass is a
// silent baseline; one event creates one delivery per subscribed endpoint (and none for
// an endpoint that does not subscribe); the delivery is a pending, immediate KindEvent
// record for the endpoint with the event's own origin; a replay of the same commit (a
// lost response) and a recomputation from a stale feed create nothing twice.
func TestEventFeedCommitsMarksAndDeliveriesTogether(t *testing.T) {
	n := newNode(t)
	n.eventEndpoint(epA, true, "incident.opened", "incident.resolved")
	n.eventEndpoint(epB, true, "incident.resolved")
	ob := n.outbox()
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened, notify.EventIncidentResolved), subscribed(epB, notify.EventIncidentResolved)}
	known, fresh := model.ID{0x71}, model.ID{0x72}

	plan, sub, err := n.commitFeed(ob, []notify.FeedEvent{silentIncident(known, 4)}, eps, true)
	if err != nil || len(sub.Intents) != 0 || !plan.State.Baselined || sub.Version != 1 {
		t.Fatalf("baseline: %+v %v", sub, err)
	}
	if recs := n.eventRecords(ob); len(recs) != 0 {
		t.Fatalf("the baseline announced history: %+v", recs)
	}

	scope := n.scope()
	feed, err := ob.EventFeed(n.ctx, scope)
	if err != nil || feed.Version != 1 || !feed.State.Baselined || feed.State.Marks[notify.MarkKey(notify.EntityIncident, known)].Through != 4 {
		t.Fatalf("feed after the baseline: %+v %v", feed, err)
	}
	plan, err = feed.State.Plan(n.org, n.project, []notify.FeedEvent{opened(fresh, 1, base)}, eps, base, false)
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].Key.Recipient == nil || *plan.Intents[0].Key.Recipient != epA {
		t.Fatalf("plan: %+v %v", plan.Intents, err)
	}
	lease := n.lease()
	if sub, err = ob.CommitEvents(n.ctx, scope, lease, feed, plan, base); err != nil || sub.Version != 2 || len(sub.Intents) != 1 {
		t.Fatalf("commit: %+v %v", sub, err)
	}
	recs := n.eventRecords(ob)
	if len(recs) != 1 {
		t.Fatalf("deliveries: %d", len(recs))
	}
	r := recs[0]
	if r.ID != plan.Intents[0].ID || r.Kind != string(notify.KindEvent) || r.Route != control.DeliveryRouteImmediate || r.Phase != control.DeliveryPending ||
		r.Recipient == nil || *r.Recipient != epA || r.OriginFrom != base || r.OriginTo != base || r.Policy != notify.EventPolicy(n.org, n.project) {
		t.Fatalf("record: %+v", r)
	}
	var d notify.Delivery
	if err = json.Unmarshal(r.Body, &d); err != nil || d.Template.Event == nil || d.Template.Event.Event != "incident.opened" || d.Template.Entity != incidentEntity(fresh) ||
		d.Template.Project != n.project || d.Template.Severity != notify.SeverityMajor || d.Key.Kind != notify.KindEvent || d.Key.Org != n.org {
		t.Fatalf("body: %s %v", r.Body, err)
	}
	if strings.Contains(string(r.Body), eventSecret) || strings.Contains(n.stateText(), eventSecret) {
		t.Fatal("the endpoint secret reached the outbox or its audit")
	}

	// A lost response: the very same commit again changes nothing.
	if _, err = ob.CommitEvents(n.ctx, scope, lease, feed, plan, base); err != nil {
		if c, det := faultOf(err); c != model.Conflict || det != control.DeliveryPolicyConflict {
			t.Fatalf("replayed commit: %v", err)
		}
	}
	// A recomputation from the stale feed (the event was applied meanwhile) is a typed
	// conflict, and the next read has nothing left to announce.
	stale, err := feed.State.Plan(n.org, n.project, []notify.FeedEvent{opened(fresh, 1, base+sec)}, eps, base+sec, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ob.CommitEvents(n.ctx, scope, lease, feed, stale, base+sec); err == nil {
		t.Fatal("a commit from a stale feed was accepted")
	} else if c, det := faultOf(err); c != model.Conflict || det != control.DeliveryPolicyConflict {
		t.Fatalf("stale commit: %v", err)
	}
	if recs = n.eventRecords(ob); len(recs) != 1 {
		t.Fatalf("a replay or stale commit created deliveries: %d", len(recs))
	}
	now, err := ob.EventFeed(n.ctx, scope)
	if err != nil || now.Version != 2 || now.State.Marks[notify.MarkKey(notify.EntityIncident, fresh)].Through != 1 {
		t.Fatalf("feed after the event: %+v %v", now, err)
	}
	// An unchanged plan commits nothing.
	same, err := now.State.Plan(n.org, n.project, nil, eps, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if sub, err = ob.CommitEvents(n.ctx, scope, lease, now, same, base); err != nil || !sub.Unchanged || sub.Version != 2 {
		t.Fatalf("an idle pass committed: %+v %v", sub, err)
	}
}

// The identity of a delivery is the event and the endpoint, nothing else: the same event
// of the same entity for the same endpoint is the same ID and the same bytes whatever the
// pass time, a different endpoint, entry, event or entity is a different ID.
func TestEventPlanIdentityIsDeterministic(t *testing.T) {
	org, project := model.ID{0x0a}, model.ID{0x0b}
	state := notify.NewFeedState()
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened), subscribed(epB, notify.EventIncidentOpened)}
	i1 := model.ID{0x31}
	plan := func(ev notify.FeedEvent, at model.UnixNano) notify.EventPlan {
		p, err := state.Plan(org, project, []notify.FeedEvent{ev}, eps, at, false)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := plan(opened(i1, 1, base), base), plan(opened(i1, 1, base), base)
	if len(a.Intents) != 2 || a.Intents[0].ID == a.Intents[1].ID {
		t.Fatalf("one intent per endpoint: %+v", a.Intents)
	}
	for i := range a.Intents {
		x, _ := json.Marshal(notify.Delivery{ID: a.Intents[i].ID, Key: a.Intents[i].Key, Route: a.Intents[i].Route, Template: a.Intents[i].Template})
		y, _ := json.Marshal(notify.Delivery{ID: b.Intents[i].ID, Key: b.Intents[i].Key, Route: b.Intents[i].Route, Template: b.Intents[i].Template})
		if a.Intents[i].ID != b.Intents[i].ID || string(x) != string(y) {
			t.Fatal("the same event decided twice is not the same delivery")
		}
	}
	later := plan(opened(i1, 1, base), base+60*sec)
	if later.Intents[0].ID != a.Intents[0].ID {
		t.Fatal("the pass time is part of the delivery identity")
	}
	for name, other := range map[string]notify.FeedEvent{
		"another entry":  opened(i1, 2, base),
		"another entity": opened(model.ID{0x32}, 1, base),
		"another event":  func() notify.FeedEvent { e := opened(i1, 1, base); e.Name = notify.EventIncidentResolved; return e }(),
	} {
		eps2 := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened, notify.EventIncidentResolved)}
		p, err := state.Plan(org, project, []notify.FeedEvent{other}, eps2, base, false)
		if err != nil || len(p.Intents) != 1 || p.Intents[0].ID == a.Intents[0].ID {
			t.Fatalf("%s kept the identity: %+v %v", name, p.Intents, err)
		}
	}
	// Another project or organization never shares an ID.
	p2, err := state.Plan(org, model.ID{0x0c}, []notify.FeedEvent{opened(i1, 1, base)}, eps, base, false)
	if err != nil || p2.Intents[0].ID == a.Intents[0].ID {
		t.Fatalf("another project: %+v %v", p2.Intents, err)
	}
	if notify.EventPolicy(org, project) == notify.EventPolicy(org, model.ID{0x0c}) || notify.EventPolicy(org, project) == notify.EventPolicy(model.ID{0x0d}, project) {
		t.Fatal("the feed policy ID must be per organization and project")
	}
}

// A test ping goes to its one endpoint whatever that subscribes to; a baseline is silent
// and refuses an event; an unknown event is refused.
func TestEventPlanTestPingBaselineAndUnknownEvents(t *testing.T) {
	org, project := model.ID{0x0a}, model.ID{0x0b}
	state := notify.NewFeedState()
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIssueNew), subscribed(epB)}
	command := model.ID{0x99}
	only := epB
	ping := notify.FeedEvent{Name: notify.EventTestPing, Entity: notify.Entity{Kind: notify.EntityEndpoint, ID: epB}, Ref: command, At: base, Only: &only,
		Update: notify.MarkUpdate{TestEndpoint: epB, TestCommand: command}}
	p, err := state.Plan(org, project, []notify.FeedEvent{ping}, eps, base, false)
	if err != nil || len(p.Intents) != 1 || *p.Intents[0].Key.Recipient != epB || p.State.Tests[epB.String()] != command {
		t.Fatalf("ping: %+v %v", p, err)
	}
	if _, err = state.Plan(org, project, []notify.FeedEvent{ping}, eps, base, true); err == nil {
		t.Fatal("a baseline announced an event")
	}
	bad := ping
	bad.Name = "incident.exploded"
	if _, err = state.Plan(org, project, []notify.FeedEvent{bad}, eps, base, false); err == nil {
		t.Fatal("an unknown event was planned")
	}
	if notify.EventName("test.ping").Subscribable() || !notify.EventName("issue.new").Subscribable() || notify.EventName("x").Known() {
		t.Fatal("event vocabulary")
	}
}

// The subscribable vocabulary of the administration (auth) and of the feed are one.
func TestEventVocabularyMatchesTheAdministration(t *testing.T) {
	var names []string
	for _, e := range notify.SubscribableEvents() {
		names = append(names, string(e))
	}
	if !slices.Equal(names, auth.EventWebhookEvents) {
		t.Fatalf("notify %v, auth %v", names, auth.EventWebhookEvents)
	}
	if auth.EventEndpointsMax != notify.MaxFeedEndpoints {
		t.Fatal("endpoint bound differs")
	}
}

// One enqueue carries at most MaxFeedIntents deliveries: a larger burst is split over
// commits in order, each commit consumes a prefix of the events and its marks, and the
// total is exactly one delivery per (event, endpoint).
func TestEventPlanBudgetSplitsABurstAcrossCommits(t *testing.T) {
	n := newNode(t)
	n.eventEndpoint(epA, true, "incident.opened")
	n.eventEndpoint(epB, true, "incident.opened")
	ob := n.outbox()
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened), subscribed(epB, notify.EventIncidentOpened)}
	if _, _, err := n.commitFeed(ob, nil, eps, true); err != nil {
		t.Fatal(err)
	}
	var events []notify.FeedEvent
	for i := range 40 {
		var id model.ID
		binary.BigEndian.PutUint32(id[:], uint32(i+1))
		events = append(events, opened(id, 1, base+model.UnixNano(i)))
	}
	commits := 0
	for len(events) > 0 {
		plan, sub, err := n.commitFeed(ob, events, eps, false)
		if err != nil {
			t.Fatalf("commit %d: %v", commits, err)
		}
		if len(plan.Intents) > notify.MaxFeedIntents || plan.Applied == 0 || len(sub.Intents) != len(plan.Intents) {
			t.Fatalf("plan: applied %d intents %d", plan.Applied, len(plan.Intents))
		}
		if plan.Remaining != len(events)-plan.Applied {
			t.Fatalf("remaining %d, want %d", plan.Remaining, len(events)-plan.Applied)
		}
		events = events[plan.Applied:]
		commits++
	}
	if commits != 2 {
		t.Fatalf("80 intents took %d commits", commits)
	}
	recs := n.eventRecords(ob)
	seen := map[model.ID]bool{}
	for _, r := range recs {
		seen[r.ID] = true
	}
	if len(recs) != 80 || len(seen) != 80 {
		t.Fatalf("deliveries %d distinct %d", len(recs), len(seen))
	}
}

// The state is bounded in every class, the closed behaviour is documented and tested:
// incident and issue marks past their bound are refused (Full, the entity is not announced
// and not remembered); the release set evicts its lowest build time and remembers it as
// the floor; and the fullest possible state encodes well under the control state's cap.
func TestEventFeedStateIsBoundedInEveryClass(t *testing.T) {
	org, project := model.ID{0x0a}, model.ID{0x0b}
	id := func(i int) model.ID { var v model.ID; binary.BigEndian.PutUint32(v[:], uint32(i+1)); return v }
	state := notify.NewFeedState()
	var events []notify.FeedEvent
	for i := range notify.MaxIncidentMarks + 5 {
		events = append(events, silentIncident(id(i), 128))
	}
	last := id(7)
	for i := range notify.MaxIssueMarks + 5 {
		key := notify.MarkKey(notify.EntityIssue, id(i))
		events = append(events, notify.FeedEvent{Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Workflow: "resolved", Last: &last}}})
	}
	for i := range notify.MaxReleaseMarks + 10 {
		key := notify.MarkKey(notify.EntityRelease, id(i))
		events = append(events, notify.FeedEvent{Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Built: base + model.UnixNano(i)*sec}}})
	}
	for i := range notify.MaxTestMarks + 3 {
		events = append(events, notify.FeedEvent{Update: notify.MarkUpdate{TestEndpoint: id(i), TestCommand: model.ID{0xff}}})
	}
	plan, err := state.Plan(org, project, events, nil, base, true)
	if err != nil {
		t.Fatal(err)
	}
	count := func(prefix string) int {
		c := 0
		for k := range plan.State.Marks {
			if strings.HasPrefix(k, prefix) {
				c++
			}
		}
		return c
	}
	if !plan.Full || count("i:") != notify.MaxIncidentMarks || count("s:") != notify.MaxIssueMarks || count("r:") != notify.MaxReleaseMarks || len(plan.State.Tests) != notify.MaxTestMarks {
		t.Fatalf("bounds: full=%v i=%d s=%d r=%d t=%d", plan.Full, count("i:"), count("s:"), count("r:"), len(plan.State.Tests))
	}
	// The newest releases stay; the ten oldest were evicted and are under the floor.
	if plan.State.Floor != base+9*sec {
		t.Fatalf("floor %d, want the build time of the newest evicted release", plan.State.Floor-base)
	}
	if _, kept := plan.State.Marks[notify.MarkKey(notify.EntityRelease, id(9))]; kept {
		t.Fatal("an evicted release kept its mark")
	}
	if _, kept := plan.State.Marks[notify.MarkKey(notify.EntityRelease, id(10))]; !kept {
		t.Fatal("the lowest kept release lost its mark")
	}
	raw, err := plan.State.Encode()
	if err != nil || len(raw) > notify.MaxFeedStateBytes || len(raw) > 240<<10 {
		t.Fatalf("the fullest state encodes to %d bytes: %v", len(raw), err)
	}
	t.Logf("fullest state: %d bytes of %d", len(raw), notify.MaxFeedStateBytes)
	// An entity refused for a full class is not announced.
	more := notify.FeedEvent{Name: notify.EventIncidentOpened, Entity: incidentEntity(id(5000)), Seq: 1, At: base,
		Update: notify.MarkUpdate{Key: notify.MarkKey(notify.EntityIncident, id(5000)), Mark: notify.FeedMark{Through: 1}}}
	p2, err := plan.State.Plan(org, project, []notify.FeedEvent{more}, []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened)}, base, false)
	if err != nil || !p2.Full || len(p2.Intents) != 0 {
		t.Fatalf("a full class announced an unremembered entity: %+v %v", p2, err)
	}
	// Deleting a mark makes room again.
	del := notify.FeedEvent{Update: notify.MarkUpdate{Key: notify.MarkKey(notify.EntityIncident, id(0)), Delete: true}}
	p3, err := plan.State.Plan(org, project, []notify.FeedEvent{del, more}, []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened)}, base, false)
	if err != nil || p3.Full || len(p3.Intents) != 1 {
		t.Fatalf("after a prune: %+v %v", p3, err)
	}
}

// Policy records of the event feed are not PolicyStates: Due, SyncModes and the readers
// skip them, and notifications and events interleave in one outbox: a worker claims and
// completes both kinds, each to its own recipient.
func TestEventFeedCoexistsWithNotificationState(t *testing.T) {
	n := newNode(t)
	n.eventEndpoint(epA, true, "incident.opened")
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil { // a normal incident notification for the webhook destination
		t.Fatal(err)
	}
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened)}
	if _, _, err := n.commitFeed(ob, nil, eps, true); err != nil {
		t.Fatal(err)
	}
	if _, sub, err := n.commitFeed(ob, []notify.FeedEvent{opened(model.ID{0x53}, 1, base)}, eps, false); err != nil || len(sub.Intents) != 1 {
		t.Fatalf("event commit: %+v %v", sub, err)
	}
	recs, err := n.store.PolicyRecords(n.ctx, n.scope(), n.project)
	if err != nil || len(recs) != 2 {
		t.Fatalf("policy records: %d %v", len(recs), err)
	}
	var feedVersion model.Revision
	for _, r := range recs {
		if notify.IsEventSubject(r.Subject) {
			feedVersion = r.Version
		}
	}
	p := &provider{}
	kinds := map[model.ID]notify.Kind{}
	w := n.worker(ob, &kindProbe{inner: p, kinds: kinds})
	rep := n.mustRun(w, base+sec)
	if len(rep.Claimed) != 2 || len(rep.Accepted) != 2 || len(rep.Errors) != 0 {
		t.Fatalf("worker: %+v", rep)
	}
	got := map[notify.Kind]int{}
	for _, k := range kinds {
		got[k]++
	}
	if got[notify.KindOpen] != 1 || got[notify.KindEvent] != 1 {
		t.Fatalf("kinds sent: %v", got)
	}
	// SyncModes moves the incident's PolicyState and leaves the feed alone.
	moved, err := ob.SyncModes(n.ctx, n.scope(), n.lease(), notify.CutoverShadow, model.ID{0xcc}, 1, base+2*sec)
	if err != nil || moved != 1 {
		t.Fatalf("SyncModes: %d %v", moved, err)
	}
	if fired, err := ob.Due(n.ctx, n.scope(), n.lease(), base+10*60*sec, 10); err != nil {
		t.Fatalf("Due over a feed record: %d %v", fired, err)
	}
	after, err := ob.EventFeed(n.ctx, n.scope())
	if err != nil || after.Version != feedVersion {
		t.Fatalf("the feed was touched by a notification pass: %+v %v", after, err)
	}
	raw, _ := json.Marshal(notify.Template{})
	if strings.Contains(string(raw), `"event"`) {
		t.Fatalf("a notification template carries an event member: %s", raw)
	}
	var old notify.Template
	if err = json.Unmarshal([]byte(`{"entity":{"kind":"incident","id":"`+strings.Repeat("0", 31)+`1"},"tier":"urgent","severity":2}`), &old); err != nil || old.Event != nil {
		t.Fatalf("an old body: %+v %v", old, err)
	}
}

// kindProbe records the kind of every delivery a sender is asked to send.
type kindProbe struct {
	inner *provider
	kinds map[model.ID]notify.Kind
}

func (k *kindProbe) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	k.kinds[d.ID] = d.Key.Kind
	return k.inner.Send(ctx, scope, d)
}

// Only the current leader commits a feed: a lease of an earlier term is stale at the
// adapter and nothing is committed; the new leader's commit lands.
func TestEventFeedLeaderFence(t *testing.T) {
	n := newNode(t)
	n.eventEndpoint(epA, true, "incident.opened")
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened)}
	_ = n.outbox() // the first term's outbox dies with its store
	old := n.lease()
	n.restart()
	ob2 := n.outbox()
	fresh := n.lease()
	if fresh.Term <= old.Term {
		t.Fatalf("leadership did not move: %d -> %d", old.Term, fresh.Term)
	}
	scope := n.scope()
	feed, err := ob2.EventFeed(n.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := feed.State.Plan(n.org, n.project, nil, eps, base, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ob2.CommitEvents(n.ctx, scope, old, feed, plan, base); err == nil {
		t.Fatal("a deposed leader committed a feed")
	} else if c, det := faultOf(err); c != model.Stale || det != control.DeliveryLeaseStale {
		t.Fatalf("deposed commit: %v", err)
	}
	if got, err := ob2.EventFeed(n.ctx, scope); err != nil || got.Version != 0 {
		t.Fatalf("a fenced commit left a mark: %+v %v", got, err)
	}
	if _, err = ob2.CommitEvents(n.ctx, scope, fresh, feed, plan, base); err != nil {
		t.Fatalf("the current leader: %v", err)
	}
	// A raw enqueue under the old lease, after the new leader committed, is stale at apply.
	state := json.RawMessage(`{"v":1}`)
	raw, _ := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &old, Enqueue: &control.DeliveryEnqueue{Project: n.project, Policy: notify.EventPolicy(n.org, n.project),
		Subject: notify.EventSubject, ExpectedVersion: 1, NewVersion: 2, At: base, State: state, Digest: model.Hash(sha256.Sum256(state))}})
	_, err = n.store.Transact(n.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: n.revision(), Kind: string(control.KindClaimDelivery), Payload: raw})
	if c, det := faultOf(err); c != model.Stale || det != control.DeliveryLeaseStale {
		t.Fatalf("a raw enqueue under a deposed lease: %v", err)
	}
}

// An event delivery is derived from the data it is about: a closing deletion that covers
// its origin pauses the send (the claim is released unsent), and the completed deletion
// cancels it as deleted; an event outside the deleted range is untouched.
func TestEventDeliveryFollowsTheDeletionPause(t *testing.T) {
	n := newNode(t)
	n.eventEndpoint(epA, true, "incident.opened")
	ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	eps := []notify.FeedEndpoint{subscribed(epA, notify.EventIncidentOpened)}
	if _, _, err := n.commitFeed(ob, nil, eps, true); err != nil {
		t.Fatal(err)
	}
	inside, outside := model.ID{0x61}, model.ID{0x62}
	if _, _, err := n.commitFeed(ob, []notify.FeedEvent{opened(inside, 1, base), opened(outside, 1, 3*base)}, eps, false); err != nil {
		t.Fatal(err)
	}
	var covered, kept notify.Record
	for _, r := range n.eventRecords(ob) {
		if r.OriginFrom == base {
			covered = r
		} else {
			kept = r
		}
	}
	p := &provider{}
	w := n.worker(ob, p)
	n.clock.set(base + sec)
	deletion := n.beginDeletion(0, 2*base)
	rep := n.mustRun(w, base+2*sec)
	if has(rep.Claimed, covered.ID) || !has(rep.Claimed, kept.ID) {
		t.Fatalf("claimed: %+v", rep.Claimed)
	}
	if rec := n.record(ob, covered.ID); rec.Phase != control.DeliveryPending || rec.Hold != control.DeliveryHoldPaused {
		t.Fatalf("a covered event delivery: %+v", rec)
	}
	n.completeDeletion(deletion)
	n.mustRun(w, base+3*sec)
	if rec := n.record(ob, covered.ID); rec.Phase != control.DeliveryCancelled || rec.Code != "deleted" || p.count(covered.ID) != 0 {
		t.Fatalf("after the deletion: %+v sends %d", rec, p.count(covered.ID))
	}
	if rec := n.record(ob, kept.ID); rec.Phase != control.DeliveryAccepted {
		t.Fatalf("an event outside the range: %+v", rec)
	}
}
