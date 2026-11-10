// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "go.etcd.io/raft/v3/raftpb"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/replica"
)

// These tests drive the REAL control store (activated single-voter Raft group,
// real auth scopes, the real incident handler and the real delivery handler)
// through the notify outbox adapter. "Restart" closes the store and reopens it
// on the same directory, which is a process death followed by a new election
// term, exactly as the condition and rule integration tests model it. The
// multi-voter group is exercised in worker_test.go.

const (
	sec  = model.UnixNano(time.Second)
	base = 1_800_000_000 * sec // a fixed "now" far from any real clock
)

type fakeClock struct{ v atomic.Int64 }

func (c *fakeClock) Now() model.UnixNano  { return model.UnixNano(c.v.Load()) }
func (c *fakeClock) set(t model.UnixNano) { c.v.Store(int64(t)) }
func (c *fakeClock) add(d model.UnixNano) { c.v.Add(int64(d)) }

type node struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	wall    time.Time
	store   *control.Store
	svc     *auth.Service
	token   string
	cred    auth.Credential
	user    model.ID
	org     model.ID
	project model.ID
	policy  model.ID
	dest    model.ID
	clock   *fakeClock
	seq     int
	opts    []notify.Option
}

var (
	incident = notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
	episode  = model.ID{0xe9}
)

func newNode(t *testing.T) *node {
	t.Helper()
	n := &node{t: t, ctx: context.Background(), dir: t.TempDir(), wall: time.Unix(1_800_000_000, 0), org: model.NewID(), project: model.NewID(), policy: model.ID{0xf1}, dest: model.ID{0xd1}, clock: &fakeClock{}}
	n.clock.set(base)
	n.open()
	boot, err := n.store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := n.svc.Bootstrap(n.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	n.token, n.user = session.Token, session.User
	n.authenticate()
	n.admin("create_org", auth.AdminPayload{Name: "notify"})
	n.admin("create_project", auth.AdminPayload{ID: n.project, Name: "p1"})
	n.setDestination(n.dest, true, "SECRET-DESTINATION-TEXT-71c2")
	t.Cleanup(func() {
		if n.store != nil {
			n.store.Close()
		}
	})
	return n
}

func (n *node) open() {
	n.t.Helper()
	var err error
	if n.store, err = control.Open(n.dir); err != nil {
		n.t.Fatal(err)
	}
	if n.svc, err = auth.NewService(auth.AuthDependencies{Control: n.store, Now: func() time.Time { return n.wall }}); err != nil {
		n.store.Close()
		n.t.Fatal(err)
	}
	if err = n.store.EnableSingle(n.ctx, filepath.Join(n.dir, "raft-control")); err != nil {
		n.store.Close()
		n.t.Fatal(err)
	}
	if err = n.store.BindIncidentAction(); err != nil {
		n.t.Fatal(err)
	}
	if err = n.store.BindDeliveryOutbox(); err != nil {
		n.t.Fatal(err)
	}
	if err = n.store.BindRetention(); err != nil {
		n.t.Fatal(err)
	}
}

// restart is a process death and a new election term on the same directory.
func (n *node) restart() {
	n.t.Helper()
	if err := n.store.Close(); err != nil {
		n.t.Fatal(err)
	}
	n.store = nil
	n.open()
	n.authenticate()
}

func (n *node) authenticate() {
	n.t.Helper()
	var err error
	if n.cred, err = n.svc.Authenticate(n.ctx, n.token); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) revision() model.Revision {
	var r model.Revision
	if err := n.store.View(n.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	return r
}

func (n *node) admin(kind string, p auth.AdminPayload) {
	n.t.Helper()
	p.Reason = "notify fixture"
	raw, _ := json.Marshal(p)
	if _, err := n.svc.AdminCommand(n.ctx, n.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: n.revision(), OrgID: n.org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

func (n *node) setDestination(id model.ID, enabled bool, secret string) {
	n.t.Helper()
	cfg := fmt.Sprintf(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":%v}`, enabled)
	n.admin("destination", auth.AdminPayload{ID: id, Config: json.RawMessage(cfg), Secret: secret})
}

// disableDestination flips the destination's enabled flag in place, the way a
// configuration change that does not revoke the worker's scope would (an admin
// command bumps the organization epoch, which ends every scope minted before it).
func (n *node) disableDestination(id model.ID) {
	n.t.Helper()
	if err := n.store.Update(n.ctx, func(st *control.State) error {
		o := st.Orgs[n.org.String()]
		o.Settings["destination:"+id.String()] = json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":false}`)
		st.Orgs[n.org.String()] = o
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) removeDestination(id model.ID) {
	n.t.Helper()
	if err := n.store.Update(n.ctx, func(st *control.State) error {
		o := st.Orgs[n.org.String()]
		delete(o.Settings, "destination:"+id.String())
		delete(o.Secrets, "destination:"+id.String())
		st.Orgs[n.org.String()] = o
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
}

// scope is the project-scoped organization administrator the worker runs as.
func (n *node) scope() auth.Scope {
	n.t.Helper()
	s, err := n.svc.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	return s
}

func (n *node) group() *replica.Group { return n.store.ReplicaGroup() }

func (n *node) lease() replica.FenceToken {
	n.t.Helper()
	l, err := n.group().Fence(n.ctx)
	if err != nil {
		n.t.Fatal(err)
	}
	return l
}

func (n *node) outbox(opts ...notify.Option) *notify.Outbox {
	n.t.Helper()
	ob, err := notify.NewOutbox(n.store, n.group(), n.clock, append(append([]notify.Option(nil), n.opts...), opts...)...)
	if err != nil {
		n.t.Fatal(err)
	}
	return ob
}

func (n *node) event(kind notify.EventKind) notify.PolicyEvent {
	n.seq++
	cfg := notify.DefaultConfig()
	return notify.PolicyEvent{Kind: kind, Command: model.ID{0xc0, byte(n.seq >> 8), byte(n.seq)}, Org: n.org, Project: n.project, Policy: n.policy,
		PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfg}, OwnerRevision: 1}
}

func (n *node) destinationEvent() notify.PolicyEvent {
	ev := n.event(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: true}
	return ev
}

// incidentEvent is what the (parent-owned) incident adapter maps a committed
// incident record to: typed fields only.
func (n *node) incidentEvent(version model.Revision, severity notify.Severity, impact uint64) notify.PolicyEvent {
	ev := n.event(notify.EventIncident)
	e := incident
	ev.Entity = &e
	ev.Mode = notify.ModeLive
	ev.Incident = &notify.IncidentEvidence{Version: version, Status: notify.HumanOpen, Severity: severity, ImpactRevision: impact, Episode: episode, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	return ev
}

// commitIncident commits one incident version through the real C05 incident
// handler: the effect that causes the notification.
func (n *node) commitIncident(version uint64) {
	n.t.Helper()
	state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"%d","status":"open","severity":2}`, incident.ID.String(), n.org.String(), n.project.String(), version))
	c := control.IncidentCommand{Project: n.project, Incident: incident.ID, Action: "open", Origin: "human", Actor: n.user, At: 100, ExpectedVersion: model.Revision(version - 1), NewVersion: model.Revision(version), State: state, Digest: model.HashCanonical(state)}
	raw, _ := json.Marshal(c)
	scope, err := n.svc.Authorize(n.ctx, n.cred, n.org, nil, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	if _, err = n.store.Transact(n.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: n.revision(), Kind: string(control.KindIncidentAction), Payload: raw}); err != nil {
		n.t.Fatal("incident action:", err)
	}
}

// committedIncidentVersion reads the committed incident the notification worker
// would map.
func (n *node) committedIncidentVersion() model.Revision {
	n.t.Helper()
	rec, found, err := n.store.Incident(n.ctx, n.scope(), n.project, incident.ID)
	if err != nil || !found {
		n.t.Fatalf("committed incident: %v %v", found, err)
	}
	return rec.Version
}

// openAndQueue is the first decision of the fixture: a recipient, then one
// incident snapshot that opens the incident for it.
func (n *node) openAndQueue(ob *notify.Outbox) (notify.Submission, error) {
	n.t.Helper()
	scope, lease := n.scope(), n.lease()
	if _, err := ob.Submit(n.ctx, scope, lease, incident, n.destinationEvent(), base); err != nil {
		return notify.Submission{}, err
	}
	return ob.Submit(n.ctx, scope, lease, incident, n.incidentEvent(1, notify.SeverityMajor, 1), base)
}

func (n *node) records(ob *notify.Outbox, phase string) []notify.Record {
	n.t.Helper()
	recs, err := ob.Records(n.ctx, n.scope(), phase, n.clock.Now(), 0)
	if err != nil {
		n.t.Fatal(err)
	}
	return recs
}

func (n *node) openRecord(ob *notify.Outbox) notify.Record {
	n.t.Helper()
	for _, r := range n.records(ob, "") {
		if r.Kind == string(notify.KindOpen) {
			return r
		}
	}
	n.t.Fatal("no open delivery")
	return notify.Record{}
}

func faultOf(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	return "", ""
}

// faultStore fails the transaction of one chosen command kind: before it commits
// (the request is lost) or after (the response is lost).
type faultStore struct {
	*control.Store
	mu     sync.Mutex
	before int // fail this many matching transactions before committing
	after  int // fail this many matching transactions after committing
	op     string
	calls  int
}

var errLost = errors.New("connection lost")

func (s *faultStore) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	var c control.DeliveryCommand
	matches := cmd.Kind == string(control.KindClaimDelivery) || cmd.Kind == string(control.KindCompleteDelivery)
	if matches && json.Unmarshal(cmd.Payload, &c) == nil && s.op != "" && c.Operation != s.op {
		matches = false
	}
	s.mu.Lock()
	failBefore, failAfter := false, false
	if matches {
		s.calls++
		if s.before > 0 {
			s.before--
			failBefore = true
		} else if s.after > 0 {
			s.after--
			failAfter = true
		}
	}
	s.mu.Unlock()
	if failBefore {
		return control.Result{}, errLost
	}
	res, err := s.Store.Transact(ctx, scope, cmd)
	if err == nil && failAfter {
		return control.Result{}, errLost
	}
	return res, err
}

// TestOutboxAtomicReplay: the incident committed, and the process died before
// the notification worker or any checkpoint existed. After the restart exactly
// one delivery ID exists for the opening, however often and however the worker
// retries, including a commit whose response was lost.
func TestOutboxAtomicReplay(t *testing.T) {
	n := newNode(t)
	// The recipient is configured on the policy before the incident exists.
	{
		ob := n.outbox()
		if _, err := ob.Submit(n.ctx, n.scope(), n.lease(), incident, n.destinationEvent(), base); err != nil {
			t.Fatal(err)
		}
	}
	n.commitIncident(1) // the effect is durable ...
	n.restart()         // ... and the process dies before the worker looked at it.

	ob := n.outbox()
	if got := n.records(ob, ""); len(got) != 0 {
		t.Fatalf("%d deliveries exist before the worker ran: %+v", len(got), got)
	}
	version := n.committedIncidentVersion()
	ev := n.incidentEvent(version, notify.SeverityMajor, 1)
	sub, err := ob.Submit(n.ctx, n.scope(), n.lease(), incident, ev, base)
	if err != nil || sub.Unchanged {
		t.Fatalf("first submit after the restart: %+v %v", sub, err)
	}
	open := n.openRecord(ob)
	wantKey := notify.IntentKey{Org: n.org, Policy: n.policy, Entity: incident, ImpactRevision: 1, Kind: notify.KindOpen, Recipient: &n.dest, Ordinal: 1}
	if open.ID != notify.KeyID(wantKey) || open.Phase != control.DeliveryPending || len(open.Attempts) != 0 {
		t.Fatalf("the opening delivery: %+v (want ID %s)", open, notify.KeyID(wantKey))
	}
	snapshot := func() string {
		raw, _ := json.Marshal(n.records(ob, ""))
		return string(raw)
	}
	before := snapshot()
	opens := func() int {
		c := 0
		for _, r := range n.records(ob, "") {
			if r.Kind == string(notify.KindOpen) {
				c++
			}
		}
		return c
	}
	if opens() != 1 {
		t.Fatalf("%d opening deliveries", opens())
	}

	// The worker dies again after the enqueue committed and before it recorded
	// its own progress: replaying the same evidence decides nothing new.
	for round := range 3 {
		n.restart()
		ob = n.outbox()
		again, err := ob.Submit(n.ctx, n.scope(), n.lease(), incident, ev, base)
		if err != nil || !again.Unchanged || len(again.Intents) != 0 {
			t.Fatalf("round %d: a replayed decision was not a no-op: %+v %v", round, again, err)
		}
		if snapshot() != before || opens() != 1 {
			t.Fatalf("round %d: the replay changed the outbox:\n%s\n%s", round, before, snapshot())
		}
	}

	// Newer evidence of the same impact does not open again either.
	if _, err = ob.Submit(n.ctx, n.scope(), n.lease(), incident, n.incidentEvent(2, notify.SeverityMajor, 1), base+sec); err != nil {
		t.Fatal(err)
	}
	if opens() != 1 {
		t.Fatalf("a later snapshot opened the incident again: %d openings", opens())
	}
}

// A decision whose commit response is lost, or whose request is lost, is retried
// by the worker: both end with exactly one set of deliveries.
func TestOutboxSubmitRetriesAreIdempotent(t *testing.T) {
	for name, fault := range map[string]*faultStore{
		"the response is lost after the commit": {after: 1, op: control.DeliveryOpEnqueue},
		"the request is lost before the commit": {before: 1, op: control.DeliveryOpEnqueue},
	} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			fault.Store = n.store
			ob, err := notify.NewOutbox(fault, n.group(), n.clock)
			if err != nil {
				t.Fatal(err)
			}
			scope, lease := n.scope(), n.lease()
			// The recipient decision is the faulty one.
			if _, err = ob.Submit(n.ctx, scope, lease, incident, n.destinationEvent(), base); !errors.Is(err, errLost) {
				t.Fatalf("the injected fault did not surface: %v", err)
			}
			// The worker retries: whether or not the first attempt committed, the
			// state converges and the recipient exists exactly once.
			ev := n.destinationEvent()
			if _, err = ob.Submit(n.ctx, scope, lease, incident, ev, base); err != nil {
				t.Fatal(err)
			}
			if _, err = ob.Submit(n.ctx, scope, lease, incident, n.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
				t.Fatal(err)
			}
			opens := 0
			for _, r := range n.records(ob, "") {
				if r.Kind == string(notify.KindOpen) {
					opens++
				}
			}
			if opens != 1 {
				t.Fatalf("%d opening deliveries after a retried decision", opens)
			}
		})
	}
	// The incident decision itself: lost response, then the same evidence again.
	n := newNode(t)
	fault := &faultStore{Store: n.store, after: 1, op: control.DeliveryOpEnqueue}
	ob, _ := notify.NewOutbox(n.store, n.group(), n.clock)
	scope, lease := n.scope(), n.lease()
	if _, err := ob.Submit(n.ctx, scope, lease, incident, n.destinationEvent(), base); err != nil {
		t.Fatal(err)
	}
	faulty, _ := notify.NewOutbox(fault, n.group(), n.clock)
	ev := n.incidentEvent(1, notify.SeverityMajor, 1)
	if _, err := faulty.Submit(n.ctx, scope, lease, incident, ev, base); !errors.Is(err, errLost) {
		t.Fatalf("the injected fault did not surface: %v", err)
	}
	sub, err := ob.Submit(n.ctx, scope, lease, incident, ev, base)
	if err != nil || !sub.Unchanged {
		t.Fatalf("the retry after a lost response: %+v %v", sub, err)
	}
	if opens := len(n.records(ob, control.DeliveryPending)); opens != 1 {
		t.Fatalf("%d pending deliveries after a lost response and a retry, want 1", opens)
	}
}

// Two workers that decide the same evidence at the same time produce one set of
// deliveries: one commits, the other converges onto it.
func TestOutboxConcurrentSubmitsConvergeOnOneDelivery(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	scope, lease := n.scope(), n.lease()
	if _, err := ob.Submit(n.ctx, scope, lease, incident, n.destinationEvent(), base); err != nil {
		t.Fatal(err)
	}
	ev := n.incidentEvent(1, notify.SeverityMajor, 1)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ob.Submit(n.ctx, scope, lease, incident, ev, base); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := len(n.records(ob, control.DeliveryPending)); got != 1 {
		t.Fatalf("%d pending deliveries after 6 concurrent identical decisions", got)
	}
}

// Claim identity: a claimed delivery carries the stable idempotency ID and every
// C08 key field, and its attempt, schedule and fence expiry.
func TestOutboxClaimReturnsTheStableDelivery(t *testing.T) {
	n := newNode(t)
	ob := n.outbox(notify.WithLeaseTTL(90 * time.Second))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	got, err := ob.Claim(n.ctx, n.scope(), base+5*sec, lease, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v %v (the queue entry must not be claimable)", got, err)
	}
	d := got[0]
	want := notify.IntentKey{Org: n.org, Policy: n.policy, Entity: incident, ImpactRevision: 1, Kind: notify.KindOpen, Recipient: &n.dest, Ordinal: 1}
	if d.ID != notify.KeyID(want) || d.Key.Org != n.org || d.Key.Policy != n.policy || d.Key.Entity != incident || d.Key.ImpactRevision != 1 || d.Key.Kind != notify.KindOpen || d.Key.Recipient == nil || *d.Key.Recipient != n.dest {
		t.Fatalf("delivery identity: %+v", d)
	}
	if d.Route != notify.RouteImmediate || d.Template.Tier != notify.TierUrgent || d.Template.Severity != notify.SeverityMajor || d.Template.Source != notify.SourceFiring || d.Template.Entity != incident {
		t.Fatalf("template fields: %+v", d.Template)
	}
	if d.Attempt != 1 || d.NextAttempt != base || d.FenceExpiry != base+5*sec+90*sec {
		t.Fatalf("attempt %d next %d expiry %d", d.Attempt, d.NextAttempt, d.FenceExpiry)
	}
	// The queue entry is a recorded, visible, never-sent entry: not accepted.
	queued := n.records(ob, control.DeliveryQueued)
	if len(queued) != 1 || len(queued[0].Attempts) != 0 || queued[0].Provider != "" {
		t.Fatalf("queue entry: %+v", queued)
	}
	// An empty or multi-project scope is not a worker scope.
	for name, scope := range map[string]auth.Scope{"no project": func() auth.Scope {
		s, err := n.svc.Authorize(n.ctx, n.cred, n.org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()} {
		if _, err := ob.Claim(n.ctx, scope, base, lease, 1); err == nil {
			t.Errorf("%s: a claim without a project scope succeeded", name)
		}
	}
	if _, err := ob.Claim(n.ctx, n.scope(), base, lease, 0); err == nil {
		t.Error("limit 0 accepted")
	}
	if _, err := ob.Claim(n.ctx, n.scope(), base, replica.FenceToken{}, 1); err == nil {
		t.Error("a zero lease accepted")
	}
}

// TestOutboxLeaderFence: the claim is made under one leader term; leadership
// moves; the old worker's completion is rejected as fenced or conflicting, never
// accepted, at the adapter (live fence) and at the control apply (stored fence).
func TestOutboxLeaderFence(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease1 := n.lease()
	got, err := ob.Claim(n.ctx, n.scope(), base+sec, lease1, 5)
	if err != nil || len(got) != 1 || got[0].Attempt != 1 {
		t.Fatalf("claim under the first term: %v %v", got, err)
	}
	d := got[0]

	n.restart() // leadership moves: the same directory elects a new term
	ob2 := n.outbox()
	lease2 := n.lease()
	if lease2.Term <= lease1.Term {
		t.Fatalf("leadership did not move: term %d -> %d", lease1.Term, lease2.Term)
	}
	accepted := notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-from-the-old-leader"}

	// 1. The adapter checks the claim's lease against a fresh quorum observation.
	err = ob2.Complete(n.ctx, n.scope(), d.ID, d.Attempt, accepted)
	if c, det := faultOf(err); c != model.Stale || det != control.DeliveryLeaseStale {
		t.Fatalf("an old leader's completion: %v", err)
	}
	rec, _, _ := ob2.Record(n.ctx, n.scope(), d.ID, n.clock.Now())
	if rec.Phase != control.DeliveryClaimed || rec.Provider != "" || rec.Attempts[0].Outcome != "" {
		t.Fatalf("a fenced completion left a mark: %+v", rec)
	}

	// 2. Past the adapter: a raw completion under the old lease, once the new
	// leader has committed anything, is stale at apply.
	if live, err := ob2.Claim(n.ctx, n.scope(), base+2*sec, lease2, 5); err != nil || len(live) != 0 {
		t.Fatalf("the new leader took over an unexpired claim: %v %v", live, err)
	}
	raw, _ := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease1,
		Complete: &control.DeliveryComplete{Project: n.project, Delivery: d.ID, Attempt: 1, At: int64ToNano(base + 3*sec), Outcome: "accepted", Provider: "raw"}})
	_, err = n.store.Transact(n.ctx, n.scope(), control.Command{CommandID: model.NewID(), ExpectedRevision: n.revision(), Kind: string(control.KindCompleteDelivery), Payload: raw})
	if c, det := faultOf(err); c != model.Stale || det != control.DeliveryLeaseStale {
		t.Fatalf("a raw completion under a deposed lease: %v", err)
	}

	// 3. The claim lapses; the new leader retries the SAME delivery; the old
	// attempt is closed unknown and the old completion can never land on it.
	n.clock.set(base + 10*60*sec)
	retry, err := ob2.Claim(n.ctx, n.scope(), n.clock.Now(), lease2, 5)
	if err != nil || len(retry) != 1 || retry[0].ID != d.ID || retry[0].Attempt != 2 {
		t.Fatalf("takeover after expiry: %v %v", retry, err)
	}
	err = ob2.Complete(n.ctx, n.scope(), d.ID, 1, accepted)
	if c, _ := faultOf(err); c != model.Stale && c != model.Conflict {
		t.Fatalf("the old attempt was completed after a takeover: %v", err)
	}
	rec, _, _ = ob2.Record(n.ctx, n.scope(), d.ID, n.clock.Now())
	if rec.Provider != "" || rec.Phase != control.DeliveryClaimed || rec.Attempts[0].Outcome != control.DeliveryOutcomeUnknown {
		t.Fatalf("after the takeover: %+v", rec)
	}
	if err = ob2.Complete(n.ctx, n.scope(), d.ID, 2, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-from-the-new-leader"}); err != nil {
		t.Fatalf("the new leader's own completion: %v", err)
	}
	if rec, _, _ = ob2.Record(n.ctx, n.scope(), d.ID, n.clock.Now()); rec.Phase != control.DeliveryAccepted || rec.Provider != "msg-from-the-new-leader" || !rec.PossibleDuplicate {
		t.Fatalf("final record: %+v", rec)
	}
}

func int64ToNano(v model.UnixNano) model.UnixNano { return v }

// Outcomes are validated at the adapter before anything is committed: accepted
// needs provider evidence, codes are closed tokens, and nothing free-form from a
// provider is ever stored.
func TestOutboxCompleteRejectsUnsafeOutcomes(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	got, _ := ob.Claim(n.ctx, n.scope(), base, lease, 1)
	if len(got) != 1 {
		t.Fatal("no claim")
	}
	id := got[0].ID
	rev := n.revision()
	for name, o := range map[string]notify.Outcome{
		"accepted without evidence": {Kind: notify.OutcomeAccepted},
		"accepted with a code":      {Kind: notify.OutcomeAccepted, ProviderID: "p", Code: "ok"},
		"unsafe provider id":        {Kind: notify.OutcomeAccepted, ProviderID: "has space"},
		"retry without a code":      {Kind: notify.OutcomeRetry},
		"free-text code":            {Kind: notify.OutcomeTerminal, Code: "Provider said: boom for " + n.dest.String()},
		"unknown kind":              {Kind: "delivered", ProviderID: "p"},
		"negative retry-after":      {Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: -1},
		"retry-after with accepted": {Kind: notify.OutcomeAccepted, ProviderID: "p", RetryAfter: sec},
	} {
		err := ob.Complete(n.ctx, n.scope(), id, 1, o)
		if c, _ := faultOf(err); c != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n.revision() != rev {
		t.Fatal("a rejected outcome reached control")
	}
	// The adapter refuses it itself: control is not even asked (control would also
	// refuse, so the revision alone cannot tell the two apart).
	counting := &faultStore{Store: n.store, op: control.DeliveryOpComplete}
	strict, err := notify.NewOutbox(counting, n.group(), n.clock)
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]notify.Outcome{
		"accepted without evidence": {Kind: notify.OutcomeAccepted},
		"free-text code":            {Kind: notify.OutcomeTerminal, Code: "Provider said: boom"},
		"negative retry-after":      {Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: -1},
	} {
		if err := strict.Complete(n.ctx, n.scope(), id, 1, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if counting.calls != 0 {
		t.Fatalf("%d completions of an unsafe outcome reached control", counting.calls)
	}
	if err := ob.Complete(n.ctx, n.scope(), model.NewID(), 1, notify.Outcome{Kind: notify.OutcomeTerminal, Code: "x"}); err == nil {
		t.Fatal("a completion of an unknown delivery succeeded")
	}
}

// A definite retry waits the capped, jittered backoff, a provider Retry-After is
// honored inside the budget, and the delivery ID never changes.
func TestOutboxRetryScheduleHonorsBackoffAndRetryAfter(t *testing.T) {
	n := newNode(t)
	zero := func(model.ID, uint32) float64 { return 0 }
	ob := n.outbox(notify.WithJitter(zero))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	d := n.openRecord(ob)
	now := base
	want := []model.UnixNano{500 * sec / 1000, 1 * sec, 2 * sec, 4 * sec, 8 * sec, 16 * sec, 32 * sec, 64 * sec, 128 * sec, 256 * sec, 450 * sec}
	// Attempt n retries after half of min(cap, 1s*2^(n-1)) with zero jitter:
	// 0.5s, 1s, 2s, 4s, ... and the 15-minute cap is half-applied at 450s.
	for i, delay := range want {
		n.clock.set(now)
		got, err := ob.Claim(n.ctx, n.scope(), now, lease, 1)
		if err != nil || len(got) != 1 || got[0].ID != d.ID || got[0].Attempt != uint32(i+1) {
			t.Fatalf("attempt %d: %v %v", i+1, got, err)
		}
		if err = ob.Complete(n.ctx, n.scope(), d.ID, uint32(i+1), notify.Outcome{Kind: notify.OutcomeRetry, Code: "unavailable"}); err != nil {
			t.Fatal(err)
		}
		rec, _, _ := ob.Record(n.ctx, n.scope(), d.ID, now)
		if rec.Next != now+delay || rec.ID != d.ID {
			t.Fatalf("attempt %d: next %d, want %d (delay %d)", i+1, rec.Next-now, delay, delay)
		}
		if early, _ := ob.Claim(n.ctx, n.scope(), rec.Next-1, lease, 1); len(early) != 0 {
			t.Fatalf("attempt %d was retried before its schedule", i+1)
		}
		now = rec.Next
	}
	// Jitter stays inside [base/2, base): the largest fraction is still below the base.
	hi := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0.9999999 }))
	n.clock.set(now)
	if got, err := hi.Claim(n.ctx, n.scope(), now, lease, 1); err != nil || len(got) != 1 || got[0].Attempt != 12 {
		t.Fatalf("attempt 12: %v %v", got, err)
	}
}

func TestOutboxRetryAfterIsHonoredWithinTheBudget(t *testing.T) {
	n := newNode(t)
	zero := func(model.ID, uint32) float64 { return 0 }
	ob := n.outbox(notify.WithJitter(zero))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	d := n.openRecord(ob)
	if got, _ := ob.Claim(n.ctx, n.scope(), base, lease, 1); len(got) != 1 {
		t.Fatal("no claim")
	}
	n.clock.set(base)
	// The provider says 10 minutes: longer than the backoff, so it wins.
	if err := ob.Complete(n.ctx, n.scope(), d.ID, 1, notify.Outcome{Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: 10 * 60 * sec}); err != nil {
		t.Fatal(err)
	}
	rec, _, _ := ob.Record(n.ctx, n.scope(), d.ID, base)
	if rec.Next != base+10*60*sec || rec.Attempts[0].RetryAfter != 10*60*sec {
		t.Fatalf("a Retry-After of 10 minutes: %+v", rec)
	}
	if got, _ := ob.Claim(n.ctx, n.scope(), base+10*60*sec-1, lease, 1); len(got) != 0 {
		t.Fatal("claimed before the provider's Retry-After")
	}
	if got, _ := ob.Claim(n.ctx, n.scope(), base+10*60*sec, lease, 1); len(got) != 1 {
		t.Fatal("not claimable at the Retry-After")
	}
	// A shorter hint never shortens the backoff.
	n.clock.set(base + 10*60*sec)
	if err := ob.Complete(n.ctx, n.scope(), d.ID, 2, notify.Outcome{Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: 1}); err != nil {
		t.Fatal(err)
	}
	if rec, _, _ = ob.Record(n.ctx, n.scope(), d.ID, n.clock.Now()); rec.Next != base+10*60*sec+1*sec {
		t.Fatalf("a tiny Retry-After shortened the backoff: %d", rec.Next-(base+10*60*sec))
	}
	// A hint beyond the 24-hour budget ends the delivery visibly instead of
	// being shortened or retried past the budget.
	if got, _ := ob.Claim(n.ctx, n.scope(), rec.Next, lease, 1); len(got) != 1 {
		t.Fatal("no third attempt")
	}
	n.clock.set(rec.Next)
	if err := ob.Complete(n.ctx, n.scope(), d.ID, 3, notify.Outcome{Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: 30 * 3600 * sec}); err != nil {
		t.Fatal(err)
	}
	if rec, _, _ = ob.Record(n.ctx, n.scope(), d.ID, n.clock.Now()); rec.Phase != control.DeliveryFailed || rec.Code != control.DeliveryReasonExhausted || len(rec.Attempts) != 3 {
		t.Fatalf("a Retry-After beyond the budget: %+v", rec)
	}
}

// The notify outbox never writes a destination secret, a provider message or any
// telemetry text into the control state: its records carry IDs, enums, counts
// and closed codes.
func TestOutboxStateNeverHoldsSecretsOrFreeText(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	got, _ := ob.Claim(n.ctx, n.scope(), base, lease, 1)
	if len(got) != 1 {
		t.Fatal("no claim")
	}
	if err := ob.Complete(n.ctx, n.scope(), got[0].ID, 1, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-1"}); err != nil {
		t.Fatal(err)
	}
	var books map[string]json.RawMessage
	_ = n.store.View(n.ctx, func(st control.State) error { books = st.DeliveryBooks; return nil })
	raw, _ := json.Marshal(books)
	for _, banned := range []string{"SECRET-DESTINATION", "hooks.example.test", "webhook"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("the outbox state holds %q: %s", banned, raw)
		}
	}
}

// ---- three voters ----------------------------------------------------------
//
// voters is a REAL three-voter control group in one process: three control stores
// (three private directories, three bbolt databases, three auth services), each
// with its own Raft group over an in-process transport that delivers through the
// real Group.Step/ReportDelivery path and can cut one node off. It is built the
// way appcore builds a distributed node: a genesis installation writes a control
// seed, and every voter opens it with control.OpenSeed and enables replication
// with the same three-member configuration at a strictly later physical term.
//
// What it does NOT cross: there are no separate processes (a "process death" is
// closing one voter's store and group and cutting it from the transport), no mTLS
// transport and no real clock. The data groups, ingest and storage are not part of
// it: the outbox lives entirely in the control group.

type meshMsg struct {
	from uint64
	m    *pb.Message
}

type mesh struct {
	mu      sync.Mutex
	groups  map[uint64]*replica.Group
	queues  map[uint64]chan meshMsg
	blocked map[uint64]bool
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func newMesh() *mesh {
	return &mesh{groups: map[uint64]*replica.Group{}, queues: map[uint64]chan meshMsg{}, blocked: map[uint64]bool{}, stop: make(chan struct{})}
}

func (m *mesh) set(id uint64, g *replica.Group) { m.mu.Lock(); m.groups[id] = g; m.mu.Unlock() }
func (m *mesh) partition(id uint64, down bool)  { m.mu.Lock(); m.blocked[id] = down; m.mu.Unlock() }
func (m *mesh) close()                          { m.once.Do(func() { close(m.stop) }); m.wg.Wait() }

type meshTransport struct {
	mesh *mesh
	node uint64
}

func (t meshTransport) Send(_ model.ID, message *pb.Message) error {
	if message == nil || message.GetFrom() != t.node {
		return replica.ErrInvalid
	}
	to := message.GetTo()
	t.mesh.mu.Lock()
	q := t.mesh.queues[to]
	if q == nil {
		q = make(chan meshMsg, 512)
		t.mesh.queues[to] = q
		t.mesh.wg.Add(1)
		go t.mesh.deliver(to, q)
	}
	t.mesh.mu.Unlock()
	select {
	case <-t.mesh.stop:
		return replica.ErrUnavailable
	case q <- meshMsg{from: t.node, m: message}:
		return nil
	default:
		return replica.ErrUnavailable
	}
}

func (m *mesh) deliver(to uint64, q <-chan meshMsg) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case in := <-q:
			m.mu.Lock()
			dst, src := m.groups[to], m.groups[in.from]
			down := m.blocked[in.from] || m.blocked[to]
			m.mu.Unlock()
			var err error
			switch {
			case dst == nil || down:
				err = replica.ErrUnavailable
			default:
				if stepped := dst.Step(context.Background(), in.m); errors.Is(stepped, replica.ErrUnavailable) {
					err = stepped
				}
			}
			if src != nil {
				src.ReportDelivery(to, in.m.GetType() == pb.MsgSnap, err)
			}
		}
	}
}

type voters struct {
	t      *testing.T
	g      *node // the genesis installation: org, project, user, destination
	mesh   *mesh
	stores map[uint64]*control.Store
	svcs   map[uint64]*auth.Service
	creds  map[uint64]auth.Credential
	alive  map[uint64]bool
}

func newVoters(t *testing.T) *voters {
	t.Helper()
	g := newNode(t)
	seed, application, err := g.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	position := g.group().Status()
	// Every voter, the genesis node included, opens a FRESH directory from the seed,
	// exactly as a distributed appcore node does.
	dirs := map[uint64]string{1: t.TempDir(), 2: t.TempDir(), 3: t.TempDir()}
	if err = g.store.Close(); err != nil {
		t.Fatal(err)
	}
	g.store = nil
	v := &voters{t: t, g: g, mesh: newMesh(), stores: map[uint64]*control.Store{}, svcs: map[uint64]*auth.Service{}, creds: map[uint64]auth.Credential{}, alive: map[uint64]bool{}}
	t.Cleanup(func() {
		for id, s := range v.stores {
			if v.alive[id] {
				s.Close()
			}
		}
		v.mesh.close()
	})
	members := replica.Members{Revision: 1}
	for id := uint64(1); id <= 3; id++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: id, Address: fmt.Sprintf("https://voter%d.invalid", id), NodeIdentity: fmt.Sprintf("voter-%d", id), FailureDomain: fmt.Sprintf("disk-%d", id)})
	}
	for id := uint64(1); id <= 3; id++ {
		store, err := control.OpenSeed(dirs[id], seed)
		if err != nil {
			t.Fatal(err)
		}
		v.stores[id], v.alive[id] = store, true
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return g.wall }})
		if err != nil {
			t.Fatal(err)
		}
		v.svcs[id] = svc
		for _, bind := range []func() error{store.BindDeliveryOutbox, store.BindIncidentAction, store.BindRetention} {
			if err = bind(); err != nil {
				t.Fatal(err)
			}
		}
		var installation model.ID
		if err = store.View(g.ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
			t.Fatal(err)
		}
		group, err := store.EnableReplication(replica.Config{ID: id, Group: installation, Directory: filepath.Join(dirs[id], "raft", "control"), TickInterval: 20 * time.Millisecond, Members: members,
			Transport: meshTransport{mesh: v.mesh, node: id}, Seed: seed, Application: application, SeedIndex: position.Applied + 1, SeedTerm: position.Term + 1})
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.set(id, group)
	}
	if err = v.stores[1].ReplicaGroup().Campaign(); err != nil {
		t.Fatal(err)
	}
	v.leaderIs(1)
	for id := uint64(1); id <= 3; id++ {
		cred, err := v.svcs[id].Authenticate(g.ctx, g.token)
		if err != nil {
			t.Fatalf("node %d does not know the genesis session: %v", id, err)
		}
		v.creds[id] = cred
	}
	return v
}

// leaderIs waits until node id is the leader of the control group and a quorum
// round succeeds on it, campaigning from it as needed. It is used for the first
// election only.
func (v *voters) leaderIs(id uint64) {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		g := v.stores[id].ReplicaGroup()
		if g.Status().Leader == id {
			ctx, cancel := context.WithTimeout(v.g.ctx, 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return
			}
		} else if round%10 == 0 {
			_ = g.Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("node %d never became the control leader", id)
}

func (m *mesh) down(id uint64) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.blocked[id] }

// survivingLeader waits for a leader among the voters that are running and not cut
// off, whichever of them wins the election, campaigning from the lowest one when
// there is none, and returns it once a quorum round succeeds on it.
func (v *voters) survivingLeader() uint64 {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		var candidates []uint64
		for id := uint64(1); id <= 3; id++ {
			if v.alive[id] && !v.mesh.down(id) {
				candidates = append(candidates, id)
			}
		}
		for _, id := range candidates {
			g := v.stores[id].ReplicaGroup()
			if g.Status().Leader != id {
				continue
			}
			ctx, cancel := context.WithTimeout(v.g.ctx, 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return id
			}
		}
		if round%10 == 0 && len(candidates) > 0 {
			_ = v.stores[candidates[0]].ReplicaGroup().Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatal("the surviving voters never elected a leader")
	return 0
}

// kill is a process death of one voter: its store and group are closed and it is
// cut from the transport.
func (v *voters) kill(id uint64) {
	v.t.Helper()
	v.mesh.partition(id, true)
	if err := v.stores[id].Close(); err != nil {
		v.t.Fatal(err)
	}
	v.mesh.set(id, nil)
	v.alive[id] = false
}

func (v *voters) scope(id uint64) auth.Scope {
	v.t.Helper()
	s, err := v.svcs[id].Authorize(v.g.ctx, v.creds[id], v.g.org, []model.ID{v.g.project}, auth.OrgAdmin)
	if err != nil {
		v.t.Fatalf("node %d scope: %v", id, err)
	}
	return s
}

func (v *voters) outbox(id uint64) *notify.Outbox {
	v.t.Helper()
	ob, err := notify.NewOutbox(v.stores[id], v.stores[id].ReplicaGroup(), v.g.clock)
	if err != nil {
		v.t.Fatal(err)
	}
	return ob
}

func (v *voters) lease(id uint64) replica.FenceToken {
	v.t.Helper()
	l, err := v.stores[id].ReplicaGroup().Fence(v.g.ctx)
	if err != nil {
		v.t.Fatalf("node %d lease: %v", id, err)
	}
	return l
}

func (v *voters) records(id uint64) []notify.Record {
	v.t.Helper()
	recs, err := v.outbox(id).Records(v.g.ctx, v.scope(id), "", v.g.clock.Now(), 0)
	if err != nil {
		v.t.Fatal(err)
	}
	return recs
}

// TestOutboxThreeNodeCrashBoundary kills the claiming leader at each boundary of
// the pipeline (before the claim, after the claim, mid-send, after the provider
// accepted, after the completion, after the next decision's checkpoint) in a real
// three-voter control group, elects a new leader and lets a new worker continue.
//
// Asserted at every boundary: no committed intent is lost or duplicated (one
// opening delivery ID), the ID and attempt numbers are stable, the possibility of a
// duplicate is recorded exactly when the provider may have seen two sends, and the
// provider is asked for at most the sends the boundary allows.
//
// Covered: real Raft replication, a real leader change with a new election term,
// every control transaction through quorum. Not covered: separate OS processes,
// the mTLS transport, a wall clock, and the data groups.
func TestOutboxThreeNodeCrashBoundary(t *testing.T) {
	type boundary struct {
		name  string
		sends int  // provider requests the whole scenario may see for the opening
		dup   bool // the delivery must be flagged possible duplicate
	}
	// possible_duplicate is set whenever an attempt of the delivery was closed
	// unknown. A claim that lapsed after the provider accepted, and a claim that
	// lapsed before the worker sent anything, are indistinguishable to the record,
	// so both are flagged: the conservative reading, stated plainly.
	for _, b := range []boundary{
		{name: "before_claim", sends: 1},
		{name: "after_claim", sends: 1, dup: true},
		{name: "mid_send", sends: 1, dup: true},
		{name: "after_accept", sends: 2, dup: true},
		{name: "after_complete", sends: 1},
	} {
		t.Run(b.name, func(t *testing.T) {
			v := newVoters(t)
			g := v.g
			p := &provider{}
			ob1 := v.outbox(1)
			scope1, lease1 := v.scope(1), v.lease(1)
			if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.destinationEvent(), base); err != nil {
				t.Fatal(err)
			}
			if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
				t.Fatal(err)
			}
			// The decision is committed through a quorum: every voter has the same
			// opening delivery before anything is killed.
			opening := func(id uint64) notify.Record {
				for _, r := range v.records(id) {
					if r.Kind == string(notify.KindOpen) {
						return r
					}
				}
				t.Fatalf("voter %d has no opening delivery", id)
				return notify.Record{}
			}
			open := opening(1)
			g.clock.set(base + sec)

			// The first leader's worker dies at the named boundary.
			q := &hookQueue{Queue: ob1}
			switch b.name {
			case "before_claim":
				// The first worker dies before it ever runs: only the committed decision exists.
			case "after_claim":
				q.afterClaim = func([]notify.Delivery) { panic(errCrash) }
			case "after_complete":
				q.afterComplete = func() { panic(errCrash) }
			case "after_accept":
				q.onComplete = func(model.ID, uint32, notify.Outcome) error { panic(errCrash) }
			case "mid_send":
				p.onSend = func(notify.Delivery) { panic(errCrash) }
			}
			w1, err := notify.NewWorker(q, p, v.stores[1].ReplicaGroup())
			if err != nil {
				t.Fatal(err)
			}
			if b.name == "before_claim" {
				// Dies before it ever runs: nothing but the committed decision exists.
			} else if !crash(func() { _, _ = w1.RunOnce(g.ctx, scope1, base+sec, lease1) }) {
				t.Fatal("the first leader's worker survived the injected process death")
			}
			sentBefore := p.total()
			if b.name == "mid_send" && sentBefore != 1 {
				t.Fatalf("the request was not on the wire at the crash: %d", sentBefore)
			}
			if b.name == "mid_send" {
				// The request died with the process before the provider accepted it.
				p.mu.Lock()
				p.calls = nil
				p.mu.Unlock()
				p.onSend = nil
			}
			v.kill(1)
			lead := v.survivingLeader()

			// The new leader sees the committed state; its worker continues after the
			// lease of the dead worker has lapsed.
			if b.name != "before_claim" {
				if got := opening(lead); got.ID != open.ID {
					t.Fatalf("the new leader sees another opening: %s vs %s", got.ID, open.ID)
				}
			}
			lease2 := v.lease(lead)
			if lease2.Term <= lease1.Term {
				t.Fatalf("no new election term: %d -> %d", lease1.Term, lease2.Term)
			}
			ob2 := v.outbox(lead)
			w2, err := notify.NewWorker(ob2, p, v.stores[lead].ReplicaGroup())
			if err != nil {
				t.Fatal(err)
			}
			later := base + 10*60*sec
			g.clock.set(later)
			if _, err = w2.RunOnce(g.ctx, v.scope(lead), later, lease2); err != nil {
				t.Fatalf("the new leader's run: %v", err)
			}

			// One opening delivery, same ID on every surviving voter, accepted with
			// evidence, and the provider asked for no more than the boundary allows.
			for _, id := range []uint64{2, 3} {
				var opens []notify.Record
				for _, r := range v.records(id) {
					if r.Kind == string(notify.KindOpen) {
						opens = append(opens, r)
					}
				}
				if len(opens) != 1 || opens[0].ID != open.ID {
					t.Fatalf("voter %d: %d opening deliveries, want exactly the original one: %+v", id, len(opens), opens)
				}
				r := opens[0]
				if r.Phase != control.DeliveryAccepted || r.Provider == "" {
					t.Fatalf("voter %d: %+v", id, r)
				}
				for i, a := range r.Attempts {
					if a.Number != uint32(i+1) {
						t.Fatalf("attempt numbers are not stable: %+v", r.Attempts)
					}
				}
				if r.PossibleDuplicate != b.dup {
					t.Fatalf("voter %d: possible_duplicate=%v at boundary %s, want %v: %+v", id, r.PossibleDuplicate, b.name, b.dup, r)
				}
			}
			total := p.count(open.ID)
			if total != b.sends {
				t.Fatalf("the provider saw %d sends of the opening at %s, want %d", total, b.name, b.sends)
			}
			// The old leader's lease can never commit again, on any survivor.
			raw, _ := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease1,
				Complete: &control.DeliveryComplete{Project: g.project, Delivery: open.ID, Attempt: 1, At: later + sec, Outcome: "accepted", Provider: "late"}})
			_, err = v.stores[lead].Transact(g.ctx, v.scope(lead), control.Command{CommandID: model.NewID(), ExpectedRevision: v.revision(lead), Kind: string(control.KindCompleteDelivery), Payload: raw})
			if c, _ := faultOf(err); c != model.Stale && c != model.Conflict {
				t.Fatalf("a deposed leader's lease committed after the failover: %v", err)
			}
		})
	}
}

func (v *voters) revision(id uint64) model.Revision {
	var r model.Revision
	if err := v.stores[id].View(v.g.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		v.t.Fatal(err)
	}
	return r
}

// TestOutboxThreeNodeCheckpointBoundary: the policy checkpoint (a timer decision
// that enqueues the next reminder) committed, and the leader died before it
// could claim anything. The new leader finds the committed reminder exactly once
// and sends it exactly once; the opening, accepted earlier, is not sent again.
func TestOutboxThreeNodeCheckpointBoundary(t *testing.T) {
	v := newVoters(t)
	g := v.g
	p := &provider{}
	ob1 := v.outbox(1)
	scope1, lease1 := v.scope(1), v.lease(1)
	if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.destinationEvent(), base); err != nil {
		t.Fatal(err)
	}
	if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
		t.Fatal(err)
	}
	w1, err := notify.NewWorker(ob1, p, v.stores[1].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	g.clock.set(base + sec)
	if r, err := w1.RunOnce(g.ctx, scope1, base+sec, lease1); err != nil || len(r.Accepted) != 1 {
		t.Fatalf("the opening: %+v %v", r, err)
	}
	// The reminder falls due; the leader decides it and dies right after the
	// checkpoint committed.
	dies := &hookQueue{Queue: ob1, afterDue: func() { panic(errCrash) }}
	w1, err = notify.NewWorker(dies, p, v.stores[1].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	due := base + 16*60*sec
	g.clock.set(due)
	if !crash(func() { _, _ = w1.RunOnce(g.ctx, scope1, due, lease1) }) {
		t.Fatal("the leader survived the injected process death")
	}
	v.kill(1)
	lead := v.survivingLeader()
	lease2 := v.lease(lead)
	w2, err := notify.NewWorker(v.outbox(lead), p, v.stores[lead].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	g.clock.set(due + sec)
	// Replaying the same timer decides nothing new; the committed reminder is sent once.
	if r, err := w2.RunOnce(g.ctx, v.scope(lead), due+sec, lease2); err != nil || r.Fired != 0 || len(r.Accepted) != 1 {
		t.Fatalf("the new leader's run: %+v %v", r, err)
	}
	for _, id := range []uint64{2, 3} {
		kinds := map[string]int{}
		for _, r := range v.records(id) {
			kinds[r.Kind]++
			if r.Kind == string(notify.KindReminder) && (r.Phase != control.DeliveryAccepted || len(r.Attempts) != 1 || r.PossibleDuplicate) {
				t.Fatalf("voter %d: the reminder: %+v", id, r)
			}
		}
		if kinds[string(notify.KindReminder)] != 1 || kinds[string(notify.KindOpen)] != 1 {
			t.Fatalf("voter %d: deliveries by kind %v, want one opening and one reminder", id, kinds)
		}
	}
	if p.total() != 2 {
		t.Fatalf("the provider saw %d sends, want 2 (the opening once, the reminder once)", p.total())
	}
}

// TestOutboxThreeNodeMinorityPartition: the claiming leader is cut off from both
// followers (a minority). It can neither claim nor complete nor send; the majority
// elects a new leader that retries the same delivery; when the partition heals the
// old worker's late completion cannot land, and the provider saw exactly one send.
func TestOutboxThreeNodeMinorityPartition(t *testing.T) {
	v := newVoters(t)
	g := v.g
	p := &provider{}
	ob1 := v.outbox(1)
	scope1, lease1 := v.scope(1), v.lease(1)
	if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.destinationEvent(), base); err != nil {
		t.Fatal(err)
	}
	if _, err := ob1.Submit(g.ctx, scope1, lease1, incident, g.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
		t.Fatal(err)
	}
	var open notify.Record
	for _, r := range v.records(1) {
		if r.Kind == string(notify.KindOpen) {
			open = r
		}
	}
	g.clock.set(base + sec)
	claimed, err := ob1.Claim(g.ctx, scope1, base+sec, lease1, 5)
	if err != nil || len(claimed) != 1 || claimed[0].ID != open.ID {
		t.Fatalf("claim: %v %v", claimed, err)
	}

	v.mesh.partition(1, true) // the old leader is now a minority of one
	lead := v.survivingLeader()
	short := func() (context.Context, context.CancelFunc) { return context.WithTimeout(g.ctx, 2*time.Second) }

	// The isolated worker can do nothing: every step needs a quorum.
	ctx, cancel := short()
	if _, err = ob1.Claim(ctx, scope1, base+2*sec, lease1, 1); err == nil {
		t.Fatal("a minority leader claimed")
	}
	cancel()
	ctx, cancel = short()
	if err = ob1.Complete(ctx, scope1, open.ID, 1, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "from-the-minority"}); err == nil {
		t.Fatal("a minority leader completed")
	}
	cancel()
	isolated, err := notify.NewWorker(ob1, p, v.stores[1].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = short()
	if _, err = isolated.RunOnce(ctx, scope1, base+3*sec, lease1); err == nil || p.total() != 0 {
		t.Fatalf("a minority worker ran: %v (provider sends %d)", err, p.total())
	}
	cancel()

	// The majority carries on: the lease lapsed, the new leader retries the SAME
	// delivery and completes it.
	lease2 := v.lease(lead)
	if lease2.Term <= lease1.Term {
		t.Fatalf("no new term: %d -> %d", lease1.Term, lease2.Term)
	}
	later := base + 10*60*sec
	g.clock.set(later)
	w2, err := notify.NewWorker(v.outbox(lead), p, v.stores[lead].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := w2.RunOnce(g.ctx, v.scope(lead), later, lease2); err != nil || len(r.Accepted) != 1 {
		t.Fatalf("the majority's run: %+v %v", r, err)
	}

	// Heal: node 1 rejoins as a follower and converges.
	v.mesh.partition(1, false)
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel = short()
		recs, err := v.outbox(1).Records(ctx, scope1, control.DeliveryAccepted, later, 0)
		cancel()
		if err == nil && len(recs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("node 1 never converged after the partition healed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The old worker's late completion of its attempt cannot land.
	ctx, cancel = short()
	err = v.outbox(1).Complete(ctx, scope1, open.ID, 1, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "stale-evidence"})
	cancel()
	if err == nil {
		t.Fatal("the old worker's late completion landed")
	}
	rec := v.records(lead)
	var final notify.Record
	for _, r := range rec {
		if r.ID == open.ID {
			final = r
		}
	}
	if final.Phase != control.DeliveryAccepted || final.Provider == "stale-evidence" || len(final.Attempts) != 2 || final.Attempts[0].Outcome != control.DeliveryOutcomeUnknown || !final.PossibleDuplicate {
		t.Fatalf("final record: %+v", final)
	}
	if p.count(open.ID) != 1 {
		t.Fatalf("the provider saw %d sends, want exactly the majority's one", p.count(open.ID))
	}
}
