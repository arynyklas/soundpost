// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// These acceptance tests drive a REAL in-process node: appcore.Open (the real
// control Raft group, auth, C03 admission and C05 storage), the real incident
// service, the real delivery handler with the cutover arm, the real outbox and
// worker. What is NOT real here, and said so plainly:
//
//   - the old notification owner is an abstract external system: the tests only
//     ever hand the product evidence about it;
//   - the destination providers are recording fakes behind the committed Sender
//     interface; no SMTP, Telegram or webhook third party is contacted;
//   - the glue that turns admitted evidence into issue/condition updates and a
//     committed incident into a policy event is parent-owned application wiring
//     that does not exist in the tree: the policy events are mapped from the
//     committed incident state the way notification-policy.md documents, by the
//     helpers below, and the issue checkpoint a barrier needs is committed
//     through the real issue handler as a checkpoint-only command.

const sec = model.UnixNano(time.Second)

type accClock struct{ v atomic.Int64 }

func (c *accClock) Now() model.UnixNano  { return model.UnixNano(c.v.Load()) }
func (c *accClock) set(t model.UnixNano) { c.v.Store(int64(t)) }
func (c *accClock) add(d model.UnixNano) { c.v.Add(int64(d)) }

// atLeast moves the clock forward to t; it never moves it back.
func (c *accClock) atLeast(t model.UnixNano) {
	for {
		cur := c.v.Load()
		if cur >= int64(t) || c.v.CompareAndSwap(cur, int64(t)) {
			return
		}
	}
}

type accNode struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	app     *appcore.App
	token   string
	cred    auth.Credential
	user    model.ID
	org     model.ID
	project model.ID
	source  model.ID
	policy  model.ID
	dest    model.ID
	group   model.ID
	clock   *accClock
	srcCred auth.SourceCredential
	issued  string
	version model.Revision // the source's committed policy revision
	seq     int
	// resource is the registered resource of the onboarded source.
	resource model.Resource

	// The notification side, rebuilt on every (re)open.
	ob   *notify.Outbox
	cut  *notify.CutoverService
	inc  *incidents.Service
	prov *recProvider
	w    *notify.Worker

	old, nw, observer, fixtureDomain model.ID
	tQuiesce                         model.UnixNano
}

func newAccNode(t *testing.T) *accNode {
	t.Helper()
	n := &accNode{t: t, ctx: context.Background(), dir: t.TempDir(), org: model.NewID(), project: model.NewID(), source: model.NewID(), policy: model.ID{0xf1}, dest: model.ID{0xd1},
		group: model.ID{0x07, 0xd0}, clock: &accClock{}, prov: &recProvider{}, old: model.ID{0x01, 0xd0}, nw: model.ID{0x02, 0xd0}, observer: model.ID{0x03, 0xd0}, fixtureDomain: model.ID{0x04, 0xd0}}
	n.clock.set(model.UnixNano(time.Now().UnixNano()))
	t.Cleanup(func() {
		if n.app != nil {
			n.app.Close()
		}
	})
	n.open()
	boot, err := n.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := n.app.Auth.Bootstrap(n.ctx, boot, "acceptance-owner@example.test", "acceptance password 2026")
	if err != nil {
		t.Fatal(err)
	}
	n.token, n.user = session.Token, session.User
	n.authenticate()
	n.admin("create_org", auth.AdminPayload{Name: "acceptance"})
	n.admin("create_project", auth.AdminPayload{ID: n.project, Name: "acceptance"})
	n.admin("membership", auth.AdminPayload{UserID: n.user, Enabled: true})
	n.admin("grant", auth.AdminPayload{UserID: n.user, ProjectID: n.project, Enabled: true, Permissions: []string{"telemetry.read", "issues.write", "policy.write"}})
	n.admin("destination", auth.AdminPayload{ID: n.dest, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "ACCEPTANCE-DESTINATION-SECRET"})
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "acc-1", Labels: model.Labels{}}
	n.resource = resource
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Resources:     model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{resource.Instance}},
		Labels:        map[string][]string{"job": {"canary"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "acceptance"})
	if err != nil {
		t.Fatal(err)
	}
	n.issued = issued.Credential
	if n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err != nil {
		t.Fatal(err)
	}
	_ = n.app.Control.View(n.ctx, func(st control.State) error { n.version = st.Sources[n.source.String()].Policy.Revision; return nil })
	if n.version == 0 {
		t.Fatal("the onboarded source has no committed policy revision")
	}
	n.commitCheckpoint(100)
	n.build()
	return n
}

func (n *accNode) open() {
	n.t.Helper()
	var err error
	if n.app, err = appcore.Open(n.dir); err != nil {
		n.t.Fatal(err)
	}
}

// build (re)creates the notification services over the open node.
func (n *accNode) build() {
	n.t.Helper()
	var err error
	if n.ob, err = notify.NewOutbox(n.app.Control, n.app.Control.ReplicaGroup(), n.clock, notify.WithJitter(func(model.ID, uint32) float64 { return 0 })); err != nil {
		n.t.Fatal(err)
	}
	if n.cut, err = notify.NewCutoverService(n.app.Control, n.clock); err != nil {
		n.t.Fatal(err)
	}
	if n.inc, err = incidents.New(n.app.Control, n.clock); err != nil {
		n.t.Fatal(err)
	}
	if n.w, err = notify.NewWorker(n.ob, n.prov, n.app.Control.ReplicaGroup()); err != nil {
		n.t.Fatal(err)
	}
}

// restart is a process restart of the whole node on the same directory.
func (n *accNode) restart() {
	n.t.Helper()
	if err := n.app.Close(); err != nil {
		n.t.Fatal(err)
	}
	n.app = nil
	n.open()
	n.authenticate()
	if n.issued != "" {
		var err error
		if n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err != nil {
			n.t.Fatal(err)
		}
	}
	n.build()
}

func (n *accNode) authenticate() {
	n.t.Helper()
	var err error
	if n.cred, err = n.app.Auth.Authenticate(n.ctx, n.token); err != nil {
		n.t.Fatal(err)
	}
}

func (n *accNode) revision() model.Revision {
	var r model.Revision
	if err := n.app.Control.View(n.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	return r
}

func (n *accNode) admin(kind string, p auth.AdminPayload) {
	n.t.Helper()
	p.Reason = "acceptance"
	raw, _ := json.Marshal(p)
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: n.revision(), OrgID: n.org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

// scope is the project-scoped organization administrator the worker runs as. A
// scope is minted per use: any administrative command ends the scopes before it.
func (n *accNode) scope() auth.Scope {
	n.t.Helper()
	s, err := n.app.Auth.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	return s
}

func (n *accNode) lease() notify.FenceToken {
	n.t.Helper()
	l, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	if err != nil {
		n.t.Fatal(err)
	}
	return l
}

// commitCheckpoint commits the project's issue checkpoint for the fixture's group
// through the real issue handler (a checkpoint-only command).
func (n *accNode) commitCheckpoint(index uint64) {
	n.t.Helper()
	scope, err := n.app.Auth.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.Permission("issues.write"))
	if err != nil {
		n.t.Fatal(err)
	}
	var book control.IssueBook
	var expected model.Revision
	_ = n.app.Control.View(n.ctx, func(st control.State) error {
		if raw, ok := st.IssueBooks[n.org.String()+":"+n.project.String()]; ok && json.Unmarshal(raw, &book) == nil {
			expected = book.Revision
		}
		return nil
	})
	raw, _ := json.Marshal(control.IssueCommand{Operation: "commit", Project: n.project, ExpectedRevision: expected, Checkpoint: &control.IssueCheckpoint{Group: n.group, Index: model.Uint64(index)}})
	if _, err = n.app.Control.TransactIssues(n.ctx, scope, control.Command{CommandID: control.IssueCommandID(raw), Kind: string(control.KindApplyIssueEvidence), Payload: raw}); err != nil {
		n.t.Fatal("issue checkpoint:", err)
	}
}

func h(s string) model.Hash { return model.Hash(sha256.Sum256([]byte(s))) }

func (n *accNode) frontier() []notify.FrontierEntry {
	return []notify.FrontierEntry{{Source: n.source, Version: n.version, Cursor: model.Cursor{Group: n.group, Index: 100}}}
}

func (n *accNode) cutState() (notify.CutoverState, bool) {
	n.t.Helper()
	s, ok, err := n.cut.Cutover(n.ctx, n.scope())
	if err != nil {
		n.t.Fatal(err)
	}
	return s, ok
}

// hostDomain is the failure domain the fixture honestly has: observer and
// product share this host.
func hostDomain() model.ID {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte("failure-domain|" + host))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

// evidence is what the adoption flow supplies when everything holds. The observer
// failure domain is the fixture's ASSERTION: the observer of these tests shares
// the host with the product, so a truthful statement would not be independent
// (see TestNotificationCutover, which shows the product refusing it).
func (n *accNode) evidence(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) *notify.BarrierEvidence {
	n.t.Helper()
	st, _ := n.cutState()
	facts, err := n.cut.Facts(n.ctx, n.scope())
	if err != nil {
		n.t.Fatal(err)
	}
	now := n.clock.Now()
	ev := &notify.BarrierEvidence{Cutover: st.Cutover, ForRevision: st.Revision, ManifestDigest: notify.ManifestDigest(n.frontier()),
		Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
		Authorization: &notify.Authorization{Principal: n.user, Ref: h("authorization"), AuthorizedAt: now - 60*sec, ExpiresAt: now + 3600*sec},
		Route:         &notify.RollbackRoute{Owner: n.old, Ref: h("route")},
		Observer:      &notify.ObserverProof{Observer: n.observer, Domain: n.fixtureDomain, ProductDomain: hostDomain(), ObservedAt: now - 10*sec, Ref: h("observer")}}
	if phase != notify.CutoverOldActive {
		ev.Owner = &notify.OwnerEvidence{Owner: n.old, Method: "scheduler_disabled", ObservedAt: now - 5*sec, Ref: h("owner")}
	}
	for _, m := range mods {
		m(ev)
	}
	return ev
}

func needsEvidence(p notify.CutoverPhase) bool {
	return p == notify.CutoverBarrierVerified || p == notify.CutoverNewActive || p == notify.CutoverOldActive
}

func (n *accNode) command(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverCommand {
	n.t.Helper()
	st, _ := n.cutState()
	n.seq++
	c := notify.CutoverCommand{ID: model.ID{0xcc, byte(n.seq >> 8), byte(n.seq)}, ExpectedRevision: st.Revision, Frontier: n.frontier(), OldOwner: n.old, NewOwner: n.nw, Phase: phase, Reason: "acceptance cutover step"}
	if needsEvidence(phase) {
		c.Evidence = n.evidence(phase, mods...)
	}
	return c
}

// advance commits one transition that must succeed, applies the phase to the
// policy states and lets the clock move on.
func (n *accNode) advance(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverState {
	n.t.Helper()
	s, err := n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(phase, mods...))
	if err != nil {
		n.t.Fatalf("advance to %s: %v", phase, err)
	}
	if phase == notify.CutoverQuiescingOld {
		n.tQuiesce = s.EnteredAt
	}
	if _, err = n.ob.SyncModes(n.ctx, n.scope(), n.lease(), s.Phase, s.Cutover, s.Revision, n.clock.Now()); err != nil {
		n.t.Fatal("sync modes:", err)
	}
	n.clock.add(30 * sec)
	return s
}

func (n *accNode) activate() notify.CutoverState {
	n.t.Helper()
	n.advance(notify.CutoverShadow)
	n.advance(notify.CutoverQuiescingOld)
	n.advance(notify.CutoverBarrierVerified)
	return n.advance(notify.CutoverNewActive)
}

func (n *accNode) assertOneOwner(want ...model.ID) {
	n.t.Helper()
	s, ok := n.cutState()
	if !ok {
		n.t.Fatal("no cutover")
	}
	if len(s.ActiveOwners) > 1 {
		n.t.Fatalf("two active normal owners in %s: %v", s.Phase, s.ActiveOwners)
	}
	if len(want) != 0 && !slices.Equal(s.ActiveOwners, want) {
		n.t.Fatalf("%s: active owners %v, want %v", s.Phase, s.ActiveOwners, want)
	}
}

// run is one worker pass at the clock's current instant.
func (n *accNode) run() notify.RunReport {
	n.t.Helper()
	at := n.clock.Now()
	r, err := n.w.RunOnce(n.ctx, n.scope(), at, n.lease())
	if err != nil {
		n.t.Fatalf("worker run: %v", err)
	}
	return r
}

func (n *accNode) records() []control.DeliveryRecord {
	n.t.Helper()
	recs, err := n.app.Control.Deliveries(n.ctx, n.scope(), n.project, "", n.clock.Now(), 0)
	if err != nil {
		n.t.Fatal(err)
	}
	return recs
}

func (n *accNode) recordOf(id model.ID) control.DeliveryRecord {
	n.t.Helper()
	r, ok, err := n.app.Control.Delivery(n.ctx, n.scope(), n.project, id, n.clock.Now())
	if err != nil || !ok {
		n.t.Fatalf("delivery %s: %v %v", id, ok, err)
	}
	return r
}

// ---------------------------------------------------------------------------
// The recording provider behind the committed Sender interface.

type provCall struct {
	ID      model.ID
	Kind    notify.Kind
	Attempt uint32
}

type recProvider struct {
	mu    sync.Mutex
	calls []provCall
}

// Send records the call and accepts with a provider message identity derived from
// the delivery ID, exactly as a provider that deduplicates on the idempotency key
// does: the same delivery ID is the same message.
func (p *recProvider) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	p.mu.Lock()
	p.calls = append(p.calls, provCall{ID: d.ID, Kind: d.Key.Kind, Attempt: d.Attempt})
	p.mu.Unlock()
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-" + d.ID.String()[:12]}, nil
}

func (p *recProvider) snapshot() []provCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

func (p *recProvider) kinds() []string {
	var out []string
	for _, c := range p.snapshot() {
		out = append(out, string(c.Kind))
	}
	return out
}

func (p *recProvider) count(id model.ID) int {
	n := 0
	for _, c := range p.snapshot() {
		if c.ID == id {
			n++
		}
	}
	return n
}

// hookQueue lets a test act between the worker's steps or kill the "process" at one.
type hookQueue struct {
	notify.Queue
	onComplete func(id model.ID, attempt uint32, o notify.Outcome) error
}

func (q *hookQueue) Complete(ctx context.Context, scope auth.Scope, id model.ID, attempt uint32, o notify.Outcome) error {
	if q.onComplete != nil {
		if err := q.onComplete(id, attempt, o); err != nil {
			return err
		}
	}
	return q.Queue.Complete(ctx, scope, id, attempt, o)
}

var errCrash = errors.New("process died")

func crash(fn func()) (died bool) {
	defer func() {
		if r := recover(); r != nil {
			if r != errCrash {
				panic(r)
			}
			died = true
		}
	}()
	fn()
	return false
}

// ---------------------------------------------------------------------------
// Mapping a committed incident to policy events (notification-policy.md).

func derive(parts ...string) model.ID {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

func (n *accNode) event(kind notify.EventKind, tag string) notify.PolicyEvent {
	cfg := notify.DefaultConfig()
	return notify.PolicyEvent{Kind: kind, Command: derive(string(kind), tag), Org: n.org, Project: n.project, Policy: n.policy, PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfg}, OwnerRevision: 1}
}

func subjectOf(incident model.ID) notify.Entity {
	return notify.Entity{Kind: notify.EntityIncident, ID: incident}
}

// submit decides one event against the committed policy state, naming its committed
// owner revision.
func (n *accNode) submit(subject notify.Entity, ev notify.PolicyEvent) notify.Submission {
	n.t.Helper()
	rec, found, err := n.app.Control.PolicyRecord(n.ctx, n.scope(), n.project, n.policy, string(subject.Kind)+":"+subject.ID.String())
	if err != nil {
		n.t.Fatal(err)
	}
	if found {
		var st notify.PolicyState
		if err = json.Unmarshal(rec.State, &st); err != nil {
			n.t.Fatal(err)
		}
		ev.OwnerRevision = st.OwnerRevision
	}
	sub, err := n.ob.Submit(n.ctx, n.scope(), n.lease(), subject, ev, n.clock.Now())
	if err != nil {
		n.t.Fatalf("submit %s: %v", ev.Kind, err)
	}
	return sub
}

func (n *accNode) addRecipient(subject notify.Entity) {
	n.t.Helper()
	ev := n.event(notify.EventDestination, "dest|"+subject.ID.String())
	ev.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: true}
	n.submit(subject, ev)
}

func (n *accNode) incidentAction(a incidents.Action) incidents.State {
	n.t.Helper()
	a.Target = incidents.Target{Org: n.org, Project: n.project, Incident: a.Target.Incident}
	a.Actor = n.user
	st, err := n.inc.Act(n.ctx, n.scope(), a, n.clock.Now())
	if err != nil {
		n.t.Fatalf("incident %s: %v", a.Type, err)
	}
	return st
}

// evidenceOf is the incident's committed snapshot as a policy event.
func (n *accNode) evidenceOf(st incidents.State) notify.PolicyEvent {
	subject := subjectOf(st.ID)
	ev := n.event(notify.EventIncident, fmt.Sprintf("evidence|%s|%d", st.ID, st.Version))
	ev.Entity = &subject
	ev.Mode = notify.ModeLive
	status := notify.HumanOpen
	if st.Status == incidents.StatusResolved {
		status = notify.HumanResolved
	}
	ev.Incident = &notify.IncidentEvidence{Version: st.Version, Status: status, Severity: notify.Severity(st.Severity), ImpactRevision: st.ImpactRevision, Episode: st.Episode,
		Source: notify.SourceState(st.Condition.State), Freshness: notify.Freshness(st.Condition.Freshness)}
	return ev
}

func (n *accNode) humanOf(st incidents.State, t notify.ActionType, mods func(*notify.HumanAction)) notify.PolicyEvent {
	subject := subjectOf(st.ID)
	ev := n.event(notify.EventAction, fmt.Sprintf("%s|%s|%d", t, st.ID, st.Version))
	ev.Entity = &subject
	ev.Action = &notify.HumanAction{Type: t, Actor: n.user, Version: st.Version}
	if mods != nil {
		mods(ev.Action)
	}
	return ev
}

// ---------------------------------------------------------------------------

func writeState(st control.State) map[string]string {
	out := map[string]string{}
	v := map[string]any{}
	raw, _ := json.Marshal(st)
	_ = json.Unmarshal(raw, &v)
	for k, x := range v {
		b, _ := json.Marshal(x)
		out[k] = string(b)
	}
	return out
}

// TestNotificationCutover drives the whole ownership journey on a real node:
// shadow -> quiescing_old -> barrier_verified -> new_active -> rollback_quiescing ->
// old_active, with a real worker and a recording provider. At every barrier at most
// one normal owner is active, the product sends only as that owner, the timeline is
// sanitized, and the cutover touches nothing outside its own books (the legacy side
// stays read-only: there is nothing here that could import or delete it).
func TestNotificationCutover(t *testing.T) {
	n := newAccNode(t)
	// The old owner is handling an episode the product shadows: a real incident.
	episode := model.ID{0xe9}
	incidentID := model.ID{0x53}
	opened := n.incidentAction(incidents.Action{CommandID: model.ID{0xa1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID},
		Impact: &incidents.Impact{Condition: model.ID{0xc1}, Episode: episode, Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	subject := subjectOf(incidentID)
	n.addRecipient(subject)

	before := writeState(func() control.State {
		var s control.State
		_ = n.app.Control.View(n.ctx, func(st control.State) error { raw, _ := json.Marshal(st); return json.Unmarshal(raw, &s) })
		return s
	}())

	var owners []int
	step := func(s notify.CutoverState, want ...model.ID) {
		t.Helper()
		n.assertOneOwner(want...)
		owners = append(owners, len(s.ActiveOwners))
	}

	// 1. The product can be told the old owner is disabled only truthfully: with the
	// failure domain it really has (this host), the product refuses to count the
	// observer as independent.
	s := n.advance(notify.CutoverShadow)
	step(s, n.old)
	// The shadow decides the episode the old owner already announced: recorded, never sent.
	n.submit(subject, n.evidenceOf(opened))
	n.run()
	if len(n.prov.snapshot()) != 0 {
		t.Fatalf("the shadow sent %v", n.prov.kinds())
	}
	n.advance(notify.CutoverQuiescingOld)
	_, err := n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverBarrierVerified, func(e *notify.BarrierEvidence) { e.Observer.Domain = e.Observer.ProductDomain }))
	var barrier *notify.BarrierError
	if !errors.As(err, &barrier) || !slices.Contains(barrier.Checks, "observer_domain") {
		t.Fatalf("a same-host observer was counted as an independent failure domain: %v", err)
	}
	// A missing observer proof is an unknown state, and also refuses.
	_, err = n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverBarrierVerified, func(e *notify.BarrierEvidence) { e.Observer = nil }))
	if !errors.As(err, &barrier) || !slices.Contains(barrier.Checks, "observer") {
		t.Fatalf("an unknown observer state passed the barrier: %v", err)
	}
	// The fixture then ASSERTS a distinct domain for the observer: an assertion, not
	// a demonstration (stated in docs/operations/external-deadman.md).
	s = n.advance(notify.CutoverBarrierVerified)
	step(s)
	if sent := n.prov.snapshot(); len(sent) != 0 {
		t.Fatalf("before the new owner is active the provider saw %v", n.prov.kinds())
	}
	n.run()
	if len(n.prov.snapshot()) != 0 {
		t.Fatalf("a worker pass in barrier_verified sent %v", n.prov.kinds())
	}

	s = n.advance(notify.CutoverNewActive)
	step(s, n.nw)
	// The shadow period's pending opening is revoked, not sent by the new owner.
	for _, r := range n.records() {
		if r.Kind == string(notify.KindOpen) && r.Phase != control.DeliveryCancelled && r.Phase != control.DeliverySuppressed {
			t.Fatalf("the old owner's opening is %s after the activation", r.Phase)
		}
	}
	n.run()
	// The policy's own rule for the end of a shadow: what was suppressed while the
	// product only watched is reevaluated ONCE, as one current-state update. The
	// old owner's opening is never re-announced.
	for _, k := range n.prov.kinds() {
		if k != string(notify.KindCurrent) {
			t.Fatalf("the new owner re-sent the old owner's episode as %q: %v", k, n.prov.kinds())
		}
	}
	if len(n.prov.snapshot()) > 1 {
		t.Fatalf("the activation sent %d updates: %v", len(n.prov.snapshot()), n.prov.kinds())
	}
	baseline := len(n.prov.snapshot())
	// A genuinely new material change is the new owner's to announce, once.
	worse := n.incidentAction(incidents.Action{CommandID: model.ID{0xa2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID}, ExpectedVersion: opened.Version,
		Impact: &incidents.Impact{Condition: model.ID{0xc1}, Episode: episode, Severity: incidents.SeverityCritical, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	n.submit(subject, n.evidenceOf(worse))
	n.clock.add(sec)
	r := n.run()
	if len(r.Accepted) == 0 || !slices.Contains(n.prov.kinds(), string(notify.KindWorseImpact)) || len(n.prov.snapshot()) != baseline+1 {
		t.Fatalf("the new owner did not announce the worse impact exactly once: %+v %v", r, n.prov.kinds())
	}
	sent := len(n.prov.snapshot())

	s, err = n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverRollbackQuiescing))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.ob.SyncModes(n.ctx, n.scope(), n.lease(), s.Phase, s.Cutover, s.Revision, n.clock.Now()); err != nil {
		t.Fatal(err)
	}
	n.clock.add(30 * sec)
	step(s)
	// The new owner no longer sends: a further impact is decided and suppressed.
	worst := n.incidentAction(incidents.Action{CommandID: model.ID{0xa3}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID}, ExpectedVersion: worse.Version,
		Impact: &incidents.Impact{Condition: model.ID{0xc1}, Episode: episode, Severity: incidents.SeverityCritical, State: incidents.ConditionRecovered, Freshness: incidents.FreshnessFresh}})
	n.submit(subject, n.evidenceOf(worst))
	n.clock.add(sec)
	n.run()
	if len(n.prov.snapshot()) != sent {
		t.Fatalf("a send went out during rollback_quiescing: %v", n.prov.kinds())
	}
	// The 3-minute default lease passes: the new owner's open claims are gone.
	n.clock.add(3 * 60 * sec)
	s = n.advance(notify.CutoverOldActive)
	step(s, n.old)
	n.run()
	if len(n.prov.snapshot()) != sent {
		t.Fatalf("a send went out after the old owner was reactivated: %v", n.prov.kinds())
	}

	// Owner count at each barrier: shadow, barrier_verified, new_active, rollback_quiescing, old_active.
	if want := []int{1, 0, 1, 0, 1}; !slices.Equal(owners, want) {
		t.Fatalf("owner counts at the barriers %v, want %v", owners, want)
	}
	for _, c := range owners {
		if c > 1 {
			t.Fatalf("owner count %d at a barrier", c)
		}
	}

	// The sanitized timeline: transitions, identities and digests; never operator text.
	final, _ := n.cutState()
	var line []string
	for _, e := range final.Timeline {
		line = append(line, fmt.Sprintf("r%d %s->%s e%d", e.Revision, e.From, e.To, e.Epoch))
	}
	if want := "r1 ->shadow e0 | r2 shadow->quiescing_old e0 | r3 quiescing_old->barrier_verified e0 | r4 barrier_verified->new_active e1 | r5 new_active->rollback_quiescing e1 | r6 rollback_quiescing->old_active e1"; strings.Join(line, " | ") != want {
		t.Fatalf("timeline:\n%s\nwant\n%s", strings.Join(line, " | "), want)
	}
	raw, _ := json.Marshal(final.Timeline)
	if strings.Contains(string(raw), "acceptance cutover step") || strings.Contains(strings.ToLower(string(raw)), "secret") {
		t.Fatalf("the timeline carries operator text: %s", raw)
	}
	t.Logf("sanitized timeline: %s", strings.Join(line, " | "))
	t.Logf("owner count at each barrier: %v; provider sends: %v", owners, n.prov.kinds())

	// Shadow decisions were compared with a legacy stream, decision by decision: the
	// legacy owner took the same decisions the product shadowed.
	ev, err := notify.NewShadowEvaluator(n.org, n.project, n.policy, subject)
	if err != nil {
		t.Fatal(err)
	}
	dest := n.event(notify.EventDestination, "parity-dest")
	dest.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: true}
	var shadow []notify.ShadowDecision
	for _, e := range []notify.PolicyEvent{dest, n.evidenceOf(opened), n.evidenceOf(worse)} {
		got, err := ev.Apply(e, n.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		shadow = append(shadow, got...)
	}
	var legacy []notify.LegacyDecision
	for i, d := range shadow {
		legacy = append(legacy, notify.LegacyDecision{Entity: d.Entity, Kind: d.Kind, ImpactRevision: d.ImpactRevision, Ordinal: d.Ordinal, Recipient: d.Recipient, SourceVersion: d.SourceVersion, DedupID: fmt.Sprintf("legacy-%d", i), Suppression: d.Suppression})
	}
	if rep := notify.CompareParity(shadow, legacy); !rep.Equal() || rep.Compared == 0 {
		t.Fatalf("parity: %+v", rep)
	}

	// The read-only legacy boundary: the whole journey wrote only the cutover's own
	// books, the delivery books and the bookkeeping every control command writes.
	var after map[string]string
	_ = n.app.Control.View(n.ctx, func(st control.State) error { after = writeState(st); return nil })
	allowed := map[string]bool{"CutoverBooks": true, "DeliveryBooks": true, "Audits": true, "Commands": true, "CommandOwners": true, "Revision": true, "IncidentBooks": true, "Orgs": true, "Sessions": true}
	for k, v := range after {
		if before[k] != v && !allowed[k] {
			t.Fatalf("the cutover changed ControlState.%s: nothing outside its own books may change", k)
		}
	}
}

// TestConcurrentIncidentDelivery runs a real incident through its whole lifecycle
// against the one canonical owner: opening, ACK, worse impact, snooze and its
// expiry, recovery and resolution, a job's retry history, and a provider that
// accepts and then the sender dies before the completion.
func TestConcurrentIncidentDelivery(t *testing.T) {
	n := newAccNode(t)
	s := n.activate()
	n.assertOneOwner(n.nw)
	_ = s

	incidentID, episode := model.ID{0x54}, model.ID{0xea}
	subject := subjectOf(incidentID)
	n.addRecipient(subject)
	condition := func(sev incidents.Severity, state incidents.ConditionState) *incidents.Impact {
		return &incidents.Impact{Condition: model.ID{0xc2}, Episode: episode, Severity: sev, State: state, Freshness: incidents.FreshnessFresh}
	}
	var version model.Revision
	act := func(a incidents.Action) incidents.State {
		a.CommandID = derive("incident-action", fmt.Sprint(len(a.Type)), string(a.Type), fmt.Sprint(version))
		a.Target.Incident = incidentID
		a.ExpectedVersion = version
		st := n.incidentAction(a)
		version = st.Version
		n.assertOneOwner(n.nw)
		return st
	}
	step := func(d model.UnixNano) notify.RunReport {
		n.clock.add(d)
		return n.run()
	}

	// 1. Opening.
	st := act(incidents.Action{Type: incidents.TypeOpen, Origin: incidents.OriginSystem, ExpectedVersion: 0, Impact: condition(incidents.SeverityMajor, incidents.ConditionFiring)})
	version = st.Version
	n.submit(subject, n.evidenceOf(st))
	step(sec)
	if got := n.prov.kinds(); !slices.Equal(got, []string{"open"}) {
		t.Fatalf("after the opening the provider saw %v", got)
	}

	// 2. ACK pauses reminders only.
	st = act(incidents.Action{Type: incidents.TypeAck, Origin: incidents.OriginHuman})
	n.submit(subject, n.humanOf(st, notify.ActionAck, func(a *notify.HumanAction) { a.ImpactRevision = st.Ack.ImpactRevision }))
	step(20 * 60 * sec)
	if got := n.prov.kinds(); !slices.Equal(got, []string{"open"}) {
		t.Fatalf("a reminder was sent to an acknowledged incident: %v", got)
	}

	// 3. A worse impact is a new material notification and ignores the ACK.
	st = act(incidents.Action{Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Impact: condition(incidents.SeverityCritical, incidents.ConditionFiring)})
	n.submit(subject, n.evidenceOf(st))
	step(sec)
	if got := n.prov.kinds(); !slices.Equal(got, []string{"open", "worse_impact"}) {
		t.Fatalf("a worse impact under an ACK: %v", got)
	}

	// 4. A snooze for an hour; its expiry produces at most one current-state update.
	until := n.clock.Now() + 3600*sec
	st = act(incidents.Action{Type: incidents.TypeSnooze, Origin: incidents.OriginHuman, Reason: "investigating", Until: until})
	n.submit(subject, n.humanOf(st, notify.ActionSnooze, func(a *notify.HumanAction) {
		a.Scope, a.Reason, a.Until = notify.Scope{Kind: notify.ScopeEntity}, "investigating", until
	}))
	step(30 * 60 * sec)
	during := len(n.prov.snapshot())
	step(2 * 3600 * sec)
	if n.prov.count(model.ID{}) != 0 || len(n.prov.snapshot()) > during+1 {
		t.Fatalf("snooze expiry sent more than one update: %v", n.prov.kinds())
	}

	// 5. Recovery, then resolution.
	st = act(incidents.Action{Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Impact: condition(incidents.SeverityCritical, incidents.ConditionRecovered)})
	n.submit(subject, n.evidenceOf(st))
	step(sec)
	st = act(incidents.Action{Type: incidents.TypeResolve, Origin: incidents.OriginHuman, Reason: "fixed in the next release"})
	n.submit(subject, n.evidenceOf(st))
	n.submit(subject, n.humanOf(st, notify.ActionResolve, nil))
	step(sec)
	kinds := n.prov.kinds()
	for _, want := range []string{"open", "worse_impact", "recovery", "resolution"} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("lifecycle kind %q never reached the provider: %v", want, kinds)
		}
	}
	for _, k := range kinds {
		if k == "digest" || k == "queue" {
			t.Fatalf("an internal entry was sent externally: %v", kinds)
		}
	}

	// 6. A job with a retry history, through the real jobs service: the failed attempt
	// stays in the history next to the success that recovered the run.
	retry := n.jobRetryHistory()
	if len(retry) != 2 || retry[0] != "failed" || retry[1] != "succeeded" {
		t.Fatalf("job attempt history %v, want [failed succeeded]", retry)
	}

	// 7. Provider acceptance before the sender's crash: a new incident's opening is
	// accepted by the provider, the worker dies before it can record the outcome, the
	// lease lapses and the SAME delivery is retried: one delivery ID, two requests,
	// one provider message, flagged possible duplicate.
	second, ep2 := model.ID{0x55}, model.ID{0xeb}
	sub2 := subjectOf(second)
	n.addRecipient(sub2)
	open2 := n.incidentAction(incidents.Action{CommandID: model.ID{0xb1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: second},
		Impact: &incidents.Impact{Condition: model.ID{0xc3}, Episode: ep2, Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	n.submit(sub2, n.evidenceOf(open2))
	var id model.ID
	for _, r := range n.records() {
		if r.Subject == "incident:"+second.String() && r.Kind == string(notify.KindOpen) && r.Phase == control.DeliveryPending {
			id = r.ID
		}
	}
	if id == (model.ID{}) {
		t.Fatal("the second incident's opening was not decided")
	}
	dying := &hookQueue{Queue: n.ob, onComplete: func(model.ID, uint32, notify.Outcome) error { panic(errCrash) }}
	w, err := notify.NewWorker(dying, n.prov, n.app.Control.ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	n.clock.add(sec)
	if !crash(func() { _, _ = w.RunOnce(n.ctx, n.scope(), n.clock.Now(), n.lease()) }) {
		t.Fatal("the worker did not die at the completion")
	}
	if rec := n.recordOf(id); rec.Phase != control.DeliveryClaimed || n.prov.count(id) != 1 {
		t.Fatalf("after the crash: %s, %d provider requests", rec.Phase, n.prov.count(id))
	}
	n.clock.add(3 * 60 * sec) // the claim's lease lapses
	n.run()
	rec := n.recordOf(id)
	if rec.Phase != control.DeliveryAccepted || !rec.PossibleDuplicate || !rec.Uncertain || len(rec.Attempts) != 2 || rec.Attempts[0].Outcome != control.DeliveryOutcomeUnknown || n.prov.count(id) != 2 {
		t.Fatalf("the retried delivery: %+v (%d requests)", rec, n.prov.count(id))
	}
	n.assertOneOwner(n.nw)

	// The sanitized timeline of the whole run: kinds and states only.
	var tl []string
	for _, c := range n.prov.snapshot() {
		tl = append(tl, fmt.Sprintf("%s#%d", c.Kind, c.Attempt))
	}
	t.Logf("provider timeline: %s", strings.Join(tl, " "))
	t.Logf("job attempt history: %v; the retried delivery %s accepted as %q, possible_duplicate=%v", retry, id.String()[:8], rec.Provider, rec.PossibleDuplicate)
}

// jobRetryHistory records a failed attempt and its successful retry through the real
// jobs service and returns the attempt states in order.
func (n *accNode) jobRetryHistory() []string {
	n.t.Helper()
	store, err := jobs.NewControlStore(n.app.Control)
	if err != nil {
		n.t.Fatal(err)
	}
	svc, err := jobs.New(store, n.app.Auth, n.clock)
	if err != nil {
		n.t.Fatal(err)
	}
	scope, err := n.app.Auth.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.PolicyWrite)
	if err != nil {
		n.t.Fatal(err)
	}
	job, run, epoch := model.ID{0x71}, model.ID{0x72}, model.ID{0x73}
	at := n.clock.Now()
	apply := func(idx uint64, attempt model.ID, ordinal, seq uint64, state string, observed model.UnixNano, terminal *model.UnixNano) {
		n.t.Helper()
		e := model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: "nightly.1", Ordinal: model.Uint64(ordinal), Epoch: epoch, Sequence: model.Uint64(seq), State: state, Observed: observed, Terminal: terminal}
		if _, _, err := svc.ApplyAttempt(n.ctx, scope, jobs.AttemptEvidence{Project: n.project, Cursor: model.Cursor{Group: n.group, Index: model.Uint64(idx)}, Record: model.ID{0xb0, byte(idx)}, Event: e}); err != nil {
			n.t.Fatalf("job attempt %d %s: %v", ordinal, state, err)
		}
	}
	a1, a2 := model.ID{0x74}, model.ID{0x75}
	t1, t2 := at-50*sec, at-10*sec
	apply(1, a1, 1, 1, "started", at-60*sec, nil)
	apply(2, a1, 1, 2, "failed", at-60*sec, &t1)
	apply(3, a2, 2, 1, "started", at-20*sec, nil)
	apply(4, a2, 2, 2, "succeeded", at-20*sec, &t2)
	st, found, err := store.Load(n.ctx, scope, n.project, job)
	if err != nil || !found {
		n.t.Fatalf("job state: %v %v", found, err)
	}
	var states []string
	for _, r := range st.Runs {
		for _, a := range r.Attempts {
			if att, ok := st.Attempts[a]; ok {
				states = append(states, string(att.Effective()))
			}
		}
	}
	return states
}

// writeFloat is used by the outage test to admit a canary sample.
func canaryRecord(resource model.Resource, at model.UnixNano, value float64) model.Record {
	bits := model.FloatBits(math.Float64bits(value))
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: "soundpost_canary", Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
}

// TestNotificationDisasterRestoreActivation is the disaster-restore acceptance: after
// the C12 quarantine of a restored control state, the restored source and sender
// credentials, the service grants and every session are inactive in the new
// authentication generation, and NO pending delivery claim sends until the
// fresh-bootstrap administrator performs the audited, explicit activation with one
// canonical owner and the reviewed pending/unknown accounting.
//
// What is real: the quarantine is auth.QuarantineRestoredState applied through the
// control store's replicated Update, exactly the call internal/backup/restore.go makes
// when it installs a restored state, followed by a process restart of the node and the
// fresh-bootstrap and reconcile flows of internal/auth. What is not exercised: the
// encrypted backup archive and its driver.
func TestNotificationDisasterRestoreActivation(t *testing.T) {
	n := newAccNode(t)
	n.activate()
	ownerToken := n.token
	serverToken := n.issueObserverToken()
	incidentID, episode := model.ID{0x57}, model.ID{0xed}
	subject := subjectOf(incidentID)
	n.addRecipient(subject)
	opened := n.incidentAction(incidents.Action{CommandID: model.ID{0xe1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID},
		Impact: &incidents.Impact{Condition: model.ID{0xc5}, Episode: episode, Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	n.submit(subject, n.evidenceOf(opened))
	var pending model.ID
	for _, r := range n.records() {
		if r.Kind == string(notify.KindOpen) && r.Phase == control.DeliveryPending {
			pending = r.ID
		}
	}
	if pending == (model.ID{}) {
		t.Fatal("no pending opening before the restore")
	}

	// The restore: the quarantine, committed through the replicated update, then a
	// process restart.
	token, hash := auth.NewRecoveryBootstrap()
	sealed, err := auth.SealedBearerKey(n.app.Control.Seal)
	if err != nil {
		t.Fatal(err)
	}
	generation := model.NewID()
	restoredAt := time.Unix(0, int64(n.clock.Now())) // the restore happens now, on the product's clock
	if err = n.app.Control.Update(n.ctx, func(st *model.ControlState) error {
		_, e := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: generation, Backup: model.NewID(), BootstrapHash: hash, SealedBearerKey: sealed, At: restoredAt})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = n.app.Close(); err != nil {
		t.Fatal(err)
	}
	n.app = nil
	n.open()
	n.build()

	// Everything restored is inactive in the new authentication generation.
	if _, err = n.app.Auth.Authenticate(n.ctx, ownerToken); err == nil {
		t.Fatal("a pre-restore session authenticates in the new generation")
	}
	if _, err = n.app.Auth.Authenticate(n.ctx, serverToken); err == nil {
		t.Fatal("a pre-restore service grant (server token) authenticates in the new generation")
	}
	if _, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err == nil {
		t.Fatal("a pre-restore source credential authenticates in the new generation")
	}
	_ = n.app.Control.View(n.ctx, func(st control.State) error {
		if _, ok := st.Orgs[n.org.String()].Settings["destination:"+n.dest.String()]; ok {
			t.Error("the restored sender is still configured")
		}
		if len(st.Orgs[n.org.String()].Secrets) != 0 {
			t.Error("a restored sender secret is still active")
		}
		return nil
	})

	// The fresh-bootstrap administrator reinstates what the operator names, one item at
	// a time, with an audit entry each.
	session, err := n.app.Auth.Bootstrap(n.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := n.app.Auth.Authenticate(n.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := func(r auth.Reconciliation) auth.Reconciled {
		t.Helper()
		r.Reason = "restore drill"
		out, e := n.app.Auth.Reconcile(n.ctx, recovery, r)
		if e != nil {
			t.Fatalf("reconcile %s: %v", r.Kind, e)
		}
		return out
	}
	reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: n.user})
	reconcile(auth.Reconciliation{Kind: auth.ReconcileOrgAdmin, Org: n.org, User: n.user})
	login, err := n.app.Auth.Login(n.ctx, "acceptance-owner@example.test", "acceptance password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	n.token = login.Token
	n.authenticate()

	// The sender is not back yet and the cutover still says new_active (it came back with
	// the backup): a claim sends nothing and does not settle the delivery as a missing
	// destination either.
	n.clock.atLeast(model.UnixNano(restoredAt.UnixNano()) + 5*sec)
	r := n.run()
	if len(r.Claimed) != 0 || len(n.prov.snapshot()) != 0 {
		t.Fatalf("a restored worker claimed or sent before the activation: %+v %v", r, n.prov.kinds())
	}
	if rec := n.recordOf(pending); rec.Phase != control.DeliveryPending || len(rec.Attempts) != 0 {
		t.Fatalf("the pending delivery after the restore: %+v", rec)
	}
	reconcile(auth.Reconciliation{Kind: auth.ReconcileIntegration, Org: n.org, Key: "destination:" + n.dest.String()})
	reissued := reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: n.source})
	n.issued = reissued.Credential
	if n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err != nil {
		t.Fatalf("the reissued source credential: %v", err)
	}
	n.clock.add(sec)
	if r = n.run(); len(r.Claimed) != 0 || len(n.prov.snapshot()) != 0 {
		t.Fatalf("a restored worker with its sender back still sent before the activation: %+v %v", r, n.prov.kinds())
	}
	facts, err := n.cut.Facts(n.ctx, n.scope())
	if err != nil || facts.Restore == nil || *facts.Restore != generation || facts.Pending != 1 {
		t.Fatalf("the activation's facts: %+v %v", facts, err)
	}
	if st, _ := n.cutState(); st.Phase != notify.CutoverNewActive || len(st.ActiveOwners) != 1 {
		t.Fatalf("restored cutover state: %+v", st)
	}

	// The activation is explicit: the previous incarnation of the new owner is shown
	// disabled (observed after the restore), the generation is acknowledged, the
	// pending delivery is accounted for and revoked, one canonical owner is active.
	n.clock.add(30 * sec)
	restoredNS := model.UnixNano(restoredAt.UnixNano())
	reactivate := func(ack *model.ID) (notify.CutoverState, error) {
		return n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverNewActive, func(e *notify.BarrierEvidence) {
			e.Owner.Owner = n.nw
			e.Owner.ObservedAt = restoredNS + sec
			e.RestoreGeneration = ack
		}))
	}
	if _, err = reactivate(nil); err == nil {
		t.Fatal("an activation that does not acknowledge the restore was accepted")
	}
	activated, err := reactivate(&generation)
	if err != nil {
		t.Fatalf("the audited activation: %v", err)
	}
	if activated.Epoch != 2 || activated.RestoreAck == nil || *activated.RestoreAck != generation || len(activated.ActiveOwners) != 1 || activated.ActiveOwners[0] != n.nw {
		t.Fatalf("activated state: %+v", activated)
	}
	if rec := n.recordOf(pending); rec.Phase != control.DeliveryCancelled || rec.Code != control.DeliveryReasonRevoked {
		t.Fatalf("the restored backlog is %s/%s, want revoked", rec.Phase, rec.Code)
	}
	n.clock.add(sec)
	n.run()
	if len(n.prov.snapshot()) != 0 {
		t.Fatalf("the restored backlog was sent after the activation: %v", n.prov.kinds())
	}
	// A second activation with nothing left to acknowledge is no transition at all.
	if _, err = reactivate(&generation); err == nil {
		t.Fatal("new_active -> new_active without an unacknowledged restore was accepted")
	}
	// New decisions of the activated installation do deliver, to the reinstated sender.
	worse := n.incidentAction(incidents.Action{CommandID: model.ID{0xe2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID}, ExpectedVersion: opened.Version,
		Impact: &incidents.Impact{Condition: model.ID{0xc5}, Episode: episode, Severity: incidents.SeverityCritical, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	if _, err = n.ob.SyncModes(n.ctx, n.scope(), n.lease(), activated.Phase, activated.Cutover, activated.Revision, n.clock.Now()); err != nil {
		t.Fatal(err)
	}
	n.submit(subject, n.evidenceOf(worse))
	n.clock.add(sec)
	if r = n.run(); len(r.Accepted) != 1 || !slices.Equal(n.prov.kinds(), []string{"worse_impact"}) {
		t.Fatalf("the activated installation did not deliver the new decision: %+v %v", r, n.prov.kinds())
	}
	t.Logf("restore drill: generation %s acknowledged; restored backlog %s revoked; one canonical owner (%v) active", generation.String()[:8], pending.String()[:8], activated.ActiveOwners)
}
