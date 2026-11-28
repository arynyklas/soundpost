// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// These tests drive the real pipeline: ingested errors become issues and incidents under
// the leader-only workers, the event producer diffs them against its durable feed, and the
// notification outbox delivers to a recording sender. See docs/operations/event-webhooks.md.

const eventEndpointSecret = "EVENT-ENDPOINT-SECRET-0123456789"

var allEvents = []string{"incident.opened", "incident.acknowledged", "incident.resolved", "issue.new", "issue.regressed", "issue.resolved", "release.registered", "issue.reopened"}

// eventRecorder is the sender behind the workers: it records every delivery it is asked to
// send and accepts it.
type eventRecorder struct {
	mu   sync.Mutex
	sent []notify.Delivery
}

func (s *eventRecorder) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, d)
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "rcpt-" + d.ID.String()[:8]}, nil
}

func (s *eventRecorder) all() []notify.Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]notify.Delivery(nil), s.sent...)
}

// events counts the event deliveries a recipient received, by event name.
func (s *eventRecorder) events(recipient model.ID) map[string]int {
	out := map[string]int{}
	for _, d := range s.all() {
		if d.Key.Kind == notify.KindEvent && d.Key.Recipient != nil && *d.Key.Recipient == recipient {
			out[string(d.Template.Event.Event)]++
		}
	}
	return out
}

func (s *eventRecorder) ofEvent(recipient model.ID, name string) []notify.Delivery {
	var out []notify.Delivery
	for _, d := range s.all() {
		if d.Key.Kind == notify.KindEvent && d.Key.Recipient != nil && *d.Key.Recipient == recipient && string(d.Template.Event.Event) == name {
			out = append(out, d)
		}
	}
	return out
}

func sameCounts(got map[string]int, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

type eventRig struct {
	*issueRig
	rec *eventRecorder
}

func newEventRig(t *testing.T) *eventRig {
	t.Helper()
	return &eventRig{issueRig: newIssueRig(t), rec: &eventRecorder{}}
}

// producers is the issue, incident and event producers in the order a served node runs them.
func (r *eventRig) producers() func(*appcore.WorkerConfig) {
	return func(c *appcore.WorkerConfig) {
		c.Producers = []appcore.Producer{r.app.IssueProducer(), r.app.IncidentProducer(), r.app.EventProducer()}
		c.Sender = r.rec
	}
}

func (r *eventRig) workers(extra ...func(*appcore.WorkerConfig)) *appcore.Workers {
	r.t.Helper()
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
		r.producers()(c)
		for _, e := range extra {
			e(c)
		}
	}))
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

func (r *eventRig) endpoint(events ...string) model.ID {
	r.t.Helper()
	id := model.NewID()
	cfg, _ := json.Marshal(map[string]any{"type": "event_webhook", "endpoint": "https://events.example.test/hook", "enabled": true, "name": "hook", "events": events})
	r.command("destination", auth.AdminPayload{ID: id, Config: cfg, Secret: eventEndpointSecret})
	return id
}

// eventRecords are the event deliveries of the project in the outbox.
func (r *eventRig) eventRecords() []control.DeliveryRecord {
	r.t.Helper()
	var out []control.DeliveryRecord
	for _, rec := range r.deliveries("") {
		if rec.Subject == notify.EventSubject {
			out = append(out, rec)
		}
	}
	return out
}

func (r *eventRig) feed() notify.EventFeedState {
	r.t.Helper()
	rec, found, err := r.app.Control.PolicyRecord(r.ctx, r.admin(), r.project, notify.EventPolicy(r.org, r.project), notify.EventSubject)
	if err != nil || !found {
		r.t.Fatalf("event feed: %v %v", found, err)
	}
	state, err := notify.ParseFeedState(rec.State)
	if err != nil {
		r.t.Fatal(err)
	}
	return state
}

func (r *eventRig) issueIDs() map[model.ID]bool {
	out := map[model.ID]bool{}
	for _, i := range r.snapshot().Issues {
		out[i.ID] = true
	}
	return out
}

func (r *eventRig) incidentIDs() map[model.ID]bool {
	out := map[model.ID]bool{}
	for _, i := range r.incidentRecords() {
		out[i.ID] = true
	}
	return out
}

func added(before, after map[model.ID]bool) []model.ID {
	var out []model.ID
	for id := range after {
		if !before[id] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (r *eventRig) incidentVersion(id model.ID) model.Revision {
	r.t.Helper()
	for _, rec := range r.incidentRecords() {
		if rec.ID == id {
			return rec.Version
		}
	}
	r.t.Fatalf("incident %s", id)
	return 0
}

func (r *eventRig) act(id model.ID, kind incidents.Type) {
	r.t.Helper()
	version := r.incidentVersion(id)
	if _, err := r.app.Incidents.Act(r.ctx, r.admin(), incidents.Action{CommandID: model.NewID(), ExpectedVersion: version, Type: kind, Reason: "event fixture", Target: incidents.Target{Project: r.project, Incident: id}}, workerNow+model.UnixNano(version)); err != nil {
		r.t.Fatal(kind, err)
	}
}

func (r *eventRig) registerRelease(id model.ID) {
	r.t.Helper()
	var revision model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.app.Releases.Register(r.ctx, r.admin(), model.Release{ID: id, Org: r.org, Project: r.project, BuildID: model.NewID(), BuildTime: 10, Parents: []model.ID{}}, revision, model.NewID()); err != nil {
		r.t.Fatal(err)
	}
}

// The whole life of the feed: the first pass baselines history silently; one event per
// transition, to exactly the endpoints that subscribe (and the marks advance for the ones
// that do not); an idle pass and a restarted process announce nothing again; an endpoint
// added later gets no history; a test request is one ping to one endpoint.
func TestEventProducerAnnouncesEachTransitionOnce(t *testing.T) {
	r := newEventRig(t)
	all := r.endpoint(allEvents...)
	releasesOnly := r.endpoint("release.registered")

	// History that exists before the first pass is never announced.
	r.ingest("TypeError", 5, true, false)
	w := r.workers()
	r.tick(w)
	if len(r.snapshot().Issues) != 1 || len(r.incidentRecords()) != 1 {
		t.Fatalf("the fixture did not produce an issue and an incident")
	}
	if recs := r.eventRecords(); len(recs) != 0 || len(r.rec.all()) != 0 {
		t.Fatalf("the baseline announced history: %d deliveries", len(recs))
	}
	if st := r.feed(); !st.Baselined || len(st.Marks) != 2 {
		t.Fatalf("baseline state: %+v", st)
	}

	// A new error class: issue.new and incident.opened, once, to the endpoint that subscribes.
	issuesBefore, incidentsBefore := r.issueIDs(), r.incidentIDs()
	r.ingest("RangeError", 6, true, false)
	r.tick(w)
	newIssue, newIncident := added(issuesBefore, r.issueIDs()), added(incidentsBefore, r.incidentIDs())
	if len(newIssue) != 1 || len(newIncident) != 1 {
		t.Fatalf("new entities: %v %v", newIssue, newIncident)
	}
	if got := r.rec.events(all); !sameCounts(got, map[string]int{"issue.new": 1, "incident.opened": 1}) {
		t.Fatalf("events to the endpoint: %v", got)
	}
	if got := r.rec.events(releasesOnly); len(got) != 0 {
		t.Fatalf("an endpoint received events it does not subscribe to: %v", got)
	}
	issueNew := r.rec.ofEvent(all, "issue.new")[0]
	opened := r.rec.ofEvent(all, "incident.opened")[0]
	if issueNew.Template.Entity != (notify.Entity{Kind: notify.EntityIssue, ID: newIssue[0]}) || issueNew.Template.Project != r.project || issueNew.Key.Org != r.org {
		t.Fatalf("issue.new delivery: %+v", issueNew)
	}
	if opened.Template.Entity != (notify.Entity{Kind: notify.EntityIncident, ID: newIncident[0]}) || opened.Template.Severity == 0 || opened.Template.Event.OccurredAt != model.UnixNano(workerNow) || opened.Template.Event.Revision != 1 {
		t.Fatalf("incident.opened delivery: %+v", opened)
	}

	// An idle pass and a restarted process (a new Workers over the same state) announce nothing.
	count := len(r.rec.all())
	r.tick(w)
	r.tick(r.workers())
	if len(r.rec.all()) != count || len(r.eventRecords()) != count {
		t.Fatalf("an idle or restarted pass announced again: %d -> %d", count, len(r.rec.all()))
	}

	// Acknowledge, then resolve, the incident.
	r.act(newIncident[0], incidents.TypeAck)
	r.tick(w)
	r.act(newIncident[0], incidents.TypeResolve)
	r.tick(w)
	if got := r.rec.events(all); !sameCounts(got, map[string]int{"issue.new": 1, "incident.opened": 1, "incident.acknowledged": 1, "incident.resolved": 1}) {
		t.Fatalf("after ack and resolve: %v", got)
	}
	ack := r.rec.ofEvent(all, "incident.acknowledged")[0]
	if ack.Template.Event.Revision != 2 || ack.Template.Entity.ID != newIncident[0] {
		t.Fatalf("ack delivery: %+v", ack)
	}
	if resolved := r.rec.ofEvent(all, "incident.resolved")[0]; resolved.Template.Event.Revision != 3 {
		t.Fatalf("resolve delivery: %+v", resolved)
	}

	// A release: both endpoints subscribe.
	release := model.NewID()
	r.registerRelease(release)
	r.tick(w)
	if got := r.rec.events(releasesOnly); !sameCounts(got, map[string]int{"release.registered": 1}) || r.rec.events(all)["release.registered"] != 1 {
		t.Fatalf("release.registered: %v / %v", got, r.rec.events(all))
	}
	if d := r.rec.ofEvent(releasesOnly, "release.registered")[0]; d.Template.Entity != (notify.Entity{Kind: notify.EntityRelease, ID: release}) {
		t.Fatalf("release delivery: %+v", d)
	}

	// Resolve the first issue and see it again after the boundary: issue.resolved, then
	// issue.regressed (and the incident of the new episode).
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := issues.New(issues.Deps{Store: store, Authorizer: r.app.Auth, Graphs: adminGraphs{r.issueRig}, Fence: allowFence{}, Policy: allowPolicy{}, Clock: constClock(1000), Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	if err != nil {
		t.Fatal(err)
	}
	var first model.ID
	for _, i := range r.snapshot().Issues {
		if i.ID != newIssue[0] {
			first = i.ID
		}
	}
	issue := r.snapshot().Issues
	var revision model.Revision
	for _, i := range issue {
		if i.ID == first {
			revision = i.Revision
		}
	}
	if _, err = svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: revision, IssueID: first, Kind: "resolve", Reason: "fixed", ResolutionBoundary: 500}); err != nil {
		t.Fatal(err)
	}
	r.tick(w)
	if got := r.rec.events(all)["issue.resolved"]; got != 1 {
		t.Fatalf("issue.resolved: %d", got)
	}
	if d := r.rec.ofEvent(all, "issue.resolved")[0]; d.Template.Entity != (notify.Entity{Kind: notify.EntityIssue, ID: first}) {
		t.Fatalf("issue.resolved entity: %+v", d.Template.Entity)
	}
	r.ingest("TypeError", 2000, true, false)
	r.tick(w)
	if got := r.rec.events(all); got["issue.regressed"] != 1 || got["incident.opened"] != 2 || got["issue.resolved"] != 1 {
		t.Fatalf("after the regression: %v", got)
	}
	r.tick(w)
	if got := r.rec.events(all); got["issue.regressed"] != 1 || got["incident.opened"] != 2 {
		t.Fatalf("a repeat announced the regression again: %v", got)
	}

	// An endpoint added now has no history.
	late := r.endpoint(allEvents...)
	r.tick(w)
	if got := r.rec.events(late); len(got) != 0 {
		t.Fatalf("a later endpoint received history: %v", got)
	}
	r.ingest("URIError", 7, true, false)
	r.tick(w)
	if got := r.rec.events(late); !sameCounts(got, map[string]int{"issue.new": 1, "incident.opened": 1}) {
		t.Fatalf("a later endpoint, new events: %v", got)
	}

	// A test request pings that endpoint only, once per request, whatever it subscribes to.
	test := func() {
		cfg, _ := json.Marshal(auth.EventTestConfig{Project: r.project})
		r.command("event_test", auth.AdminPayload{ID: releasesOnly, Config: cfg})
	}
	test()
	r.tick(w)
	r.tick(w)
	if got := r.rec.events(releasesOnly); got["test.ping"] != 1 || r.rec.events(all)["test.ping"] != 0 || r.rec.events(late)["test.ping"] != 0 {
		t.Fatalf("test ping: %v / %v", got, r.rec.events(all))
	}
	ping := r.rec.ofEvent(releasesOnly, "test.ping")[0]
	if ping.Template.Entity != (notify.Entity{Kind: notify.EntityEndpoint, ID: releasesOnly}) || ping.Template.Project != r.project {
		t.Fatalf("ping: %+v", ping)
	}
	test()
	r.tick(w)
	if got := r.rec.events(releasesOnly)["test.ping"]; got != 2 {
		t.Fatalf("a second test request: %d pings", got)
	}

	// Exactly once overall: every delivery ID is distinct, outbox and recorder agree, and
	// every one was accepted.
	ids := map[model.ID]bool{}
	for _, d := range r.rec.all() {
		if d.Key.Kind != notify.KindEvent || ids[d.ID] {
			t.Fatalf("a duplicate or foreign delivery: %+v", d)
		}
		ids[d.ID] = true
	}
	recs := r.eventRecords()
	if len(recs) != len(ids) {
		t.Fatalf("outbox %d, recorder %d", len(recs), len(ids))
	}
	for _, rec := range recs {
		if rec.Phase != control.DeliveryAccepted || rec.Kind != string(notify.KindEvent) {
			t.Fatalf("a delivery that is not accepted: %+v", rec)
		}
	}
	// The feed state stays bounded to the live entities.
	if st := r.feed(); len(st.Marks) != len(r.snapshot().Issues)+len(r.incidentRecords())+1 {
		t.Fatalf("marks %d, issues %d incidents %d (+1 release)", len(st.Marks), len(r.snapshot().Issues), len(r.incidentRecords()))
	}
}

// A test request is an explicit request, not history: one that is pending before the first pass is not dropped (the baseline
// announces nothing, so it is answered by the next pass), is delivered exactly once, and the next request is a second ping.
func TestEventProducerDeliversAPendingTestRequestOfBeforeTheBaselineExactlyOnce(t *testing.T) {
	r := newEventRig(t)
	ep := r.endpoint("issue.new")
	cfg, _ := json.Marshal(auth.EventTestConfig{Project: r.project})
	r.command("event_test", auth.AdminPayload{ID: ep, Config: cfg})
	w := r.workers()
	r.tick(w) // baseline: silent
	if len(r.rec.all()) != 0 {
		t.Fatalf("the baseline announced: %v", r.rec.events(ep))
	}
	r.tick(w)
	r.tick(w)
	if got := r.rec.events(ep); !sameCounts(got, map[string]int{"test.ping": 1}) {
		t.Fatalf("a request from before the first pass: %v, want exactly one test.ping", got)
	}
	r.command("event_test", auth.AdminPayload{ID: ep, Config: cfg})
	r.tick(w)
	if got := r.rec.events(ep); !sameCounts(got, map[string]int{"test.ping": 2}) {
		t.Fatalf("a new request: %v", got)
	}
}

// Leadership: a node that is not the leader and a pass under a lease the control group does
// not hold commit nothing; the committed feed is the only memory, so the next leader announces
// exactly what was left and nothing twice.
func TestEventProducerLeaderChange(t *testing.T) {
	r := newEventRig(t)
	ep := r.endpoint(allEvents...)
	r.tick(r.workers()) // baseline
	r.ingest("TypeError", 5, true, false)

	fence := r.fence()
	fence.notLeader.Store(true)
	follower := r.workers(func(c *appcore.WorkerConfig) { c.Fence = fence })
	for range 3 {
		if rep := follower.Tick(r.ctx); rep.Leader || rep.Produced != 0 {
			t.Fatalf("a follower produced: %+v", rep)
		}
	}
	if len(r.eventRecords()) != 0 {
		t.Fatal("a follower committed events")
	}

	stale := r.workers(func(c *appcore.WorkerConfig) { c.Fence = staleLease{r.app.Control.ReplicaGroup()} })
	rep := stale.Tick(r.ctx)
	if len(rep.Errors) == 0 || len(r.eventRecords()) != 0 || len(r.rec.all()) != 0 {
		t.Fatalf("a pass under an unproven lease committed: %+v", rep)
	}

	leader := r.workers()
	r.tick(leader)
	want := map[string]int{"issue.new": 1, "incident.opened": 1}
	if got := r.rec.events(ep); !sameCounts(got, want) {
		t.Fatalf("the new leader: %v", got)
	}
	// A second leader instance and a restart announce nothing more.
	r.tick(r.workers())
	r.tick(leader)
	if got := r.rec.events(ep); !sameCounts(got, want) {
		t.Fatalf("after more passes: %v", got)
	}
}

// A normal incident notification never goes to an event endpoint, and an event never goes
// to a notification destination: the routing of notifications excludes event endpoints and
// the feed only addresses them.
func TestEventsAndNotificationsNeverCrossDestinations(t *testing.T) {
	r := newEventRig(t)
	ep := r.endpoint("incident.opened", "incident.resolved")
	r.tick(r.workers(func(c *appcore.WorkerConfig) { c.Routing = r.app.OrgRouting() })) // baseline
	id, _, _ := r.openIncident()
	r.tick(r.workers(func(c *appcore.WorkerConfig) { c.Routing = r.app.OrgRouting() }))
	var notifications, events int
	for _, d := range r.rec.all() {
		switch {
		case d.Key.Kind == notify.KindEvent:
			events++
			if d.Key.Recipient == nil || *d.Key.Recipient != ep || d.Template.Entity.ID != id {
				t.Fatalf("an event went to the wrong recipient: %+v", d)
			}
		default:
			notifications++
			if d.Key.Recipient == nil || *d.Key.Recipient == ep || *d.Key.Recipient != r.dest {
				t.Fatalf("a notification went to %v, not the notification destination", d.Key.Recipient)
			}
		}
	}
	if notifications != 1 || events != 1 {
		t.Fatalf("notifications %d, events %d", notifications, events)
	}
	recs, err := r.app.Control.PolicyRecords(r.ctx, r.admin(), r.project)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if notify.IsEventSubject(rec.Subject) {
			continue
		}
		var st notify.PolicyState
		if err = json.Unmarshal(rec.State, &st); err != nil {
			t.Fatal(err)
		}
		for _, rcp := range st.Recipients {
			if rcp.ID == ep {
				t.Fatalf("the event endpoint is a recipient of %s", rec.Subject)
			}
		}
	}
	routing, found, err := r.app.OrgRouting().Routing(r.ctx, r.admin(), r.project)
	if err != nil || !found {
		t.Fatalf("routing: %v %v", found, err)
	}
	for _, rcp := range routing.Recipients {
		if rcp == ep {
			t.Fatal("the event endpoint is a notification route")
		}
	}
}

// Another organization's endpoint never receives this organization's events, and the other
// way round: each feed is per organization and project, and an endpoint is only ever resolved
// in its own organization.
func TestEventsNeverCrossOrganizations(t *testing.T) {
	a := newEventRig(t)
	epA := a.endpoint(allEvents...)

	orgB, projectB := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := a.app.Control.View(a.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "second organization"
		raw, _ := json.Marshal(p)
		if _, err := a.app.Auth.AdminCommand(a.ctx, a.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: orgB, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "second"})
	command("create_project", auth.AdminPayload{ID: projectB, Name: "second"})
	epB := model.NewID()
	cfg, _ := json.Marshal(map[string]any{"type": "event_webhook", "endpoint": "https://events.example.test/b", "enabled": true, "events": allEvents})
	command("destination", auth.AdminPayload{ID: epB, Config: cfg, Secret: eventEndpointSecret})

	w := a.workers(func(c *appcore.WorkerConfig) { c.Orgs = []model.ID{a.org, orgB} })
	a.tick(w) // baseline of both
	// An incident in each organization.
	open := func(org, project model.ID) model.ID {
		scope, err := a.app.Auth.AuthorizeSystem(a.ctx, org, []model.ID{project}, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		id := model.NewID()
		impact := incidents.Impact{Condition: model.NewID(), Episode: model.NewID(), Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}
		if _, err = a.app.Incidents.Act(a.ctx, scope, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Project: project, Incident: id}, Impact: &impact}, workerNow); err != nil {
			t.Fatal(err)
		}
		return id
	}
	incidentA, incidentB := open(a.org, a.project), open(orgB, projectB)
	a.tick(w)
	for _, d := range a.rec.all() {
		if d.Key.Kind != notify.KindEvent || d.Key.Recipient == nil {
			t.Fatalf("unexpected delivery: %+v", d)
		}
		switch *d.Key.Recipient {
		case epA:
			if d.Key.Org != a.org || d.Template.Project != a.project || d.Template.Entity.ID != incidentA {
				t.Fatalf("organization A's endpoint received %+v", d)
			}
		case epB:
			if d.Key.Org != orgB || d.Template.Project != projectB || d.Template.Entity.ID != incidentB {
				t.Fatalf("organization B's endpoint received %+v", d)
			}
		default:
			t.Fatalf("a delivery to %s", d.Key.Recipient)
		}
	}
	if a.rec.events(epA)["incident.opened"] != 1 || a.rec.events(epB)["incident.opened"] != 1 {
		t.Fatalf("A %v B %v", a.rec.events(epA), a.rec.events(epB))
	}
	// Organization A's administrator scope reads none of B's deliveries.
	recs, err := a.app.Control.Deliveries(a.ctx, a.admin(), a.project, "", a.clock.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Org != a.org {
			t.Fatalf("a record of another organization: %+v", rec)
		}
	}
	// Forging a delivery for the other organization's endpoint through the real senders: the
	// destination is resolved in the delivery's own organization and the scope's, so it is
	// the same no_destination / scope_mismatch a missing endpoint gives.
	sender, err := a.app.NotificationSender(appcore.NotificationConfig{PublicOrigin: "https://soundpost.example.test", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	forged := a.rec.ofEvent(epB, "incident.opened")[0]
	out, err := sender.Send(a.ctx, a.admin(), forged) // organization A's scope, organization B's delivery
	if err != nil || out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" {
		t.Fatalf("a cross-organization send: %+v %v", out, err)
	}
	forged.Key.Org = a.org // B's endpoint ID under A's organization
	if out, err = sender.Send(a.ctx, a.admin(), forged); err != nil || out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" {
		t.Fatalf("an endpoint ID of another organization: %+v %v", out, err)
	}
}

// A resolve and the regression that reopens the issue inside ONE pass are both announced, with
// distinct delivery IDs, once, whatever restarts follow: events come from committed history
// (the audit log and the lifecycle's reopening record), not from a state snapshot.
func TestEventProducerResolveThenRegressionInOnePass(t *testing.T) {
	r := newEventRig(t)
	ep := r.endpoint(allEvents...)
	r.ingest("TypeError", 5, true, false)
	w := r.workers()
	r.tick(w) // baseline
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := issues.New(issues.Deps{Store: store, Authorizer: r.app.Auth, Graphs: adminGraphs{r.issueRig}, Fence: allowFence{}, Policy: allowPolicy{}, Clock: constClock(1000), Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	if err != nil {
		t.Fatal(err)
	}
	issue := r.snapshot().Issues[0]
	if _, err = svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed", ResolutionBoundary: 500}); err != nil {
		t.Fatal(err)
	}
	r.ingest("TypeError", 2000, true, false) // the regression, before any pass saw the resolve
	r.tick(w)
	want := map[string]int{"issue.resolved": 1, "issue.regressed": 1, "incident.opened": 1}
	if got := r.rec.events(ep); !sameCounts(got, want) {
		t.Fatalf("one pass: %v, want %v", got, want)
	}
	a, b := r.rec.ofEvent(ep, "issue.resolved")[0], r.rec.ofEvent(ep, "issue.regressed")[0]
	if a.ID == b.ID {
		t.Fatal("distinct events share a delivery id")
	}
	r.tick(w)
	r.tick(r.workers())
	if got := r.rec.events(ep); !sameCounts(got, want) || len(r.eventRecords()) != 3 {
		t.Fatalf("after replay and restart: %v", got)
	}
}
