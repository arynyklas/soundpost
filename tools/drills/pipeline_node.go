// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// This file is the scaffolding of the pipeline drills: a REAL in-process node (appcore.Open: the
// real control Raft group, auth, C03 admission and C05 storage), the real incident service, the
// real delivery outbox, worker and cutover service, ported from the acceptance fixtures
// (tests/acceptance/notification_cutover_test.go, notification_outage_test.go) into non-test code.
// What is NOT real, and said so in every report: the destination providers are recording senders
// behind the committed notify.Sender interface (no SMTP, Telegram or webhook third party is ever
// contacted), and the old notification owner is an abstract external system the drill only hands
// evidence about.

const pipeSec = model.UnixNano(time.Second)

// pipeAbort is how scaffolding code stops a scenario: it panics with it and pipeGuard turns it back
// into the scenario's error, so the drill code stays linear instead of checking every error.
type pipeAbort struct{ err error }

func pipeFail(format string, a ...any) { panic(pipeAbort{fmt.Errorf(format, a...)}) }

func pipeMust(err error, what string) {
	if err != nil {
		pipeFail("%s: %w", what, err)
	}
}

// pipeGuard runs fn and returns the abort it raised, if any. Any other panic is re-raised.
func pipeGuard(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a, ok := r.(pipeAbort)
			if !ok {
				panic(r)
			}
			err = a.err
		}
	}()
	fn()
	return nil
}

type pipeClock struct{ v atomic.Int64 }

func (c *pipeClock) Now() model.UnixNano  { return model.UnixNano(c.v.Load()) }
func (c *pipeClock) set(t model.UnixNano) { c.v.Store(int64(t)) }
func (c *pipeClock) add(d model.UnixNano) { c.v.Add(int64(d)) }

// atLeast moves the clock forward to t; it never moves it back.
func (c *pipeClock) atLeast(t model.UnixNano) {
	for {
		cur := c.v.Load()
		if cur >= int64(t) || c.v.CompareAndSwap(cur, int64(t)) {
			return
		}
	}
}

// ---- the recording provider ----

// pipeProvider is the recording provider behind the committed notify.Sender interface. It behaves
// like a provider that deduplicates on the idempotency key: the first acceptance of a delivery id
// mints a receipt and every later send of the same id returns that same receipt. `plan` scripts
// failures per delivery: nth is how many calls that delivery had before this one; the zero Outcome
// means accept.
type pipeProvider struct {
	mu       sync.Mutex
	calls    []pipeSend
	receipts map[model.ID]string
	plan     func(d notify.Delivery, nth int) notify.Outcome
	phase    string
	onCall   func(pipeSend)
}

func (p *pipeProvider) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	p.mu.Lock()
	nth := 0
	for _, c := range p.calls {
		if c.ID == d.ID.String() {
			nth++
		}
	}
	var out notify.Outcome
	if p.plan != nil {
		out = p.plan(d, nth)
	}
	if out.Kind == "" {
		out = notify.Outcome{Kind: notify.OutcomeAccepted}
	}
	if out.Kind == notify.OutcomeAccepted {
		if p.receipts == nil {
			p.receipts = map[model.ID]string{}
		}
		if p.receipts[d.ID] == "" {
			p.receipts[d.ID] = fmt.Sprintf("rcpt-%04d-%s", len(p.receipts)+1, d.ID.String()[:8])
		}
		out.ProviderID = p.receipts[d.ID]
	}
	recipient := ""
	if d.Key.Recipient != nil {
		recipient = d.Key.Recipient.String()
	}
	rec := pipeSend{Seq: len(p.calls) + 1, ID: d.ID.String(), Subject: string(d.Key.Entity.Kind) + ":" + d.Key.Entity.ID.String(), Kind: string(d.Key.Kind),
		ImpactRevision: d.Key.ImpactRevision, Ordinal: d.Key.Ordinal, Recipient: recipient, Attempt: d.Attempt, Outcome: string(out.Kind), Code: out.Code, Phase: p.phase}
	if out.Kind == notify.OutcomeAccepted {
		rec.Receipt = out.ProviderID
	}
	p.calls = append(p.calls, rec)
	hook := p.onCall
	p.mu.Unlock()
	if hook != nil {
		hook(rec)
	}
	return out, nil
}

func (p *pipeProvider) snapshot() []pipeSend {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

func (p *pipeProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *pipeProvider) countID(id model.ID) int {
	n := 0
	for _, c := range p.snapshot() {
		if c.ID == id.String() {
			n++
		}
	}
	return n
}

func (p *pipeProvider) kinds() []string {
	var out []string
	for _, c := range p.snapshot() {
		out = append(out, c.Kind)
	}
	return out
}

func (p *pipeProvider) setPlan(f func(d notify.Delivery, nth int) notify.Outcome) {
	p.mu.Lock()
	p.plan = f
	p.mu.Unlock()
}

func (p *pipeProvider) setPhase(ph string) {
	p.mu.Lock()
	p.phase = ph
	p.mu.Unlock()
}

// ---- the node ----

type pipeNode struct {
	env     *Env
	ctx     context.Context
	dir     string
	mu      sync.RWMutex // guards app for the heartbeat and worker goroutines
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
	clock   *pipeClock
	srcCred auth.SourceCredential
	issued  string
	version model.Revision
	seq     int

	resource model.Resource

	ob   *notify.Outbox
	cut  *notify.CutoverService
	inc  *incidents.Service
	prov *pipeProvider
	w    *notify.Worker

	old, nw, observer, fixtureDomain model.ID
}

// cur is the open application, for goroutines other than the scenario's.
func (n *pipeNode) cur() *appcore.App {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.app
}

func (n *pipeNode) setApp(a *appcore.App) {
	n.mu.Lock()
	n.app = a
	n.mu.Unlock()
}

// newPipeNode creates a fresh node under env.Work/name (approved against the allowlist first),
// bootstraps an organization, a project, a destination and an onboarded source, and builds the
// notification services over it.
func newPipeNode(env *Env, name string, prov *pipeProvider) *pipeNode {
	dir := filepath.Join(env.Work, name)
	pipeMust(env.Approve([]string{dir}, nil), "approve the node directory")
	pipeMust(os.MkdirAll(dir, 0o700), "create the node directory")
	n := &pipeNode{env: env, ctx: env.Ctx, dir: dir, org: model.NewID(), project: model.NewID(), source: model.NewID(), policy: model.ID{0xf1}, dest: model.ID{0xd1},
		group: model.ID{0x07, 0xd0}, clock: &pipeClock{}, prov: prov, old: model.ID{0x01, 0xd0}, nw: model.ID{0x02, 0xd0}, observer: model.ID{0x03, 0xd0}, fixtureDomain: model.ID{0x04, 0xd0}}
	if n.ctx == nil {
		n.ctx = context.Background()
	}
	n.clock.set(model.UnixNano(time.Now().UnixNano()))
	n.open()
	boot, err := n.app.Control.BootstrapToken()
	pipeMust(err, "bootstrap token")
	session, err := n.app.Auth.Bootstrap(n.ctx, boot, "drill-owner@example.test", "drill password 2026")
	pipeMust(err, "bootstrap")
	n.token, n.user = session.Token, session.User
	n.authenticate()
	n.admin("create_org", auth.AdminPayload{Name: "drill"})
	n.admin("create_project", auth.AdminPayload{ID: n.project, Name: "drill"})
	n.admin("membership", auth.AdminPayload{UserID: n.user, Enabled: true})
	n.admin("grant", auth.AdminPayload{UserID: n.user, ProjectID: n.project, Enabled: true, Permissions: []string{"telemetry.read", "issues.write", "policy.write"}})
	n.admin("destination", auth.AdminPayload{ID: n.dest, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "DRILL-DESTINATION-SECRET"})
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "drill-1", Labels: model.Labels{}}
	n.resource = resource
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Resources:     model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{resource.Instance}},
		Labels:        map[string][]string{"job": {"canary"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "drill"})
	pipeMust(err, "onboard source")
	n.issued = issued.Credential
	n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false)
	pipeMust(err, "authenticate source")
	_ = n.app.Control.View(n.ctx, func(st control.State) error { n.version = st.Sources[n.source.String()].Policy.Revision; return nil })
	if n.version == 0 {
		pipeFail("the onboarded source has no committed policy revision")
	}
	n.commitCheckpoint(100)
	n.build()
	return n
}

func (n *pipeNode) open() {
	app, err := appcore.Open(n.dir)
	pipeMust(err, "open the node")
	n.setApp(app)
}

// close shuts the node down. It is safe to call twice.
func (n *pipeNode) close() error {
	n.mu.Lock()
	app := n.app
	n.app = nil
	n.mu.Unlock()
	if app == nil {
		return nil
	}
	return app.Close()
}

// build (re)creates the notification services over the open node.
func (n *pipeNode) build() {
	var err error
	n.ob, err = notify.NewOutbox(n.app.Control, n.app.Control.ReplicaGroup(), n.clock, notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	pipeMust(err, "outbox")
	n.cut, err = notify.NewCutoverService(n.app.Control, n.clock)
	pipeMust(err, "cutover service")
	n.inc, err = incidents.New(n.app.Control, n.clock)
	pipeMust(err, "incident service")
	n.w, err = notify.NewWorker(n.ob, n.prov, n.app.Control.ReplicaGroup())
	pipeMust(err, "worker")
}

// reopen opens the node again on the same directory and rebuilds everything over it: the state
// after a process restart.
func (n *pipeNode) reopen() {
	n.open()
	n.authenticate()
	if n.issued != "" {
		var err error
		n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false)
		pipeMust(err, "authenticate source after the restart")
	}
	n.build()
}

// crashRestart kills the node (it is closed with none of the drill's own shutdown work) and opens it
// again on the same directory. It returns the leadership term before and after: a node that really
// restarted elects a new term, so a drill can assert the crash it claims to have exercised.
func (n *pipeNode) crashRestart(what string) (before, after uint64) {
	before = n.lease().Term
	pipeMust(n.close(), what)
	n.reopen()
	return before, n.lease().Term
}

func (n *pipeNode) authenticate() {
	var err error
	n.cred, err = n.app.Auth.Authenticate(n.ctx, n.token)
	pipeMust(err, "authenticate")
}

func (n *pipeNode) revision() model.Revision {
	var r model.Revision
	pipeMust(n.app.Control.View(n.ctx, func(st control.State) error { r = st.Revision; return nil }), "control revision")
	return r
}

func (n *pipeNode) admin(kind string, p auth.AdminPayload) {
	p.Reason = "drill"
	raw, _ := json.Marshal(p)
	_, err := n.app.Auth.AdminCommand(n.ctx, n.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: n.revision(), OrgID: n.org, Kind: kind, Payload: raw})
	pipeMust(err, "admin "+kind)
}

// scope is the project-scoped organization administrator the worker runs as. A scope is minted per
// use: any administrative command ends the scopes before it.
func (n *pipeNode) scope() auth.Scope {
	s, err := n.app.Auth.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.OrgAdmin)
	pipeMust(err, "authorize")
	return s
}

func (n *pipeNode) lease() notify.FenceToken {
	l, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	pipeMust(err, "fence")
	return l
}

// commitCheckpoint commits the project's issue checkpoint for the fixture's group through the real
// issue handler (a checkpoint-only command): the cutover barrier needs it.
func (n *pipeNode) commitCheckpoint(index uint64) {
	scope, err := n.app.Auth.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.Permission("issues.write"))
	pipeMust(err, "authorize issues.write")
	var book control.IssueBook
	var expected model.Revision
	_ = n.app.Control.View(n.ctx, func(st control.State) error {
		if raw, ok := st.IssueBooks[n.org.String()+":"+n.project.String()]; ok && json.Unmarshal(raw, &book) == nil {
			expected = book.Revision
		}
		return nil
	})
	raw, _ := json.Marshal(control.IssueCommand{Operation: "commit", Project: n.project, ExpectedRevision: expected, Checkpoint: &control.IssueCheckpoint{Group: n.group, Index: model.Uint64(index)}})
	_, err = n.app.Control.TransactIssues(n.ctx, scope, control.Command{CommandID: control.IssueCommandID(raw), Kind: string(control.KindApplyIssueEvidence), Payload: raw})
	pipeMust(err, "issue checkpoint")
}

func pipeHash(s string) model.Hash { return model.Hash(sha256.Sum256([]byte(s))) }

func (n *pipeNode) frontier() []notify.FrontierEntry {
	return []notify.FrontierEntry{{Source: n.source, Version: n.version, Cursor: model.Cursor{Group: n.group, Index: 100}}}
}

func (n *pipeNode) cutState() (notify.CutoverState, bool) {
	s, ok, err := n.cut.Cutover(n.ctx, n.scope())
	pipeMust(err, "read the cutover")
	return s, ok
}

// pipeHostDomain is the failure domain the drill honestly has: observer and product share this host.
func pipeHostDomain() model.ID {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte("failure-domain|" + host))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

// evidence is what the adoption flow supplies when everything holds. The observer failure domain is
// the drill's ASSERTION (a distinct label): the observer of these drills shares the host with the
// product, so a truthful statement would not be independent; the product refuses that truthful
// statement (see ownerCutoverRollback, which shows the refusal).
func (n *pipeNode) evidence(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) *notify.BarrierEvidence {
	st, _ := n.cutState()
	facts, err := n.cut.Facts(n.ctx, n.scope())
	pipeMust(err, "cutover facts")
	now := n.clock.Now()
	ev := &notify.BarrierEvidence{Cutover: st.Cutover, ForRevision: st.Revision, ManifestDigest: notify.ManifestDigest(n.frontier()),
		Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
		Authorization: &notify.Authorization{Principal: n.user, Ref: pipeHash("authorization"), AuthorizedAt: now - 60*pipeSec, ExpiresAt: now + 3600*pipeSec},
		Route:         &notify.RollbackRoute{Owner: n.old, Ref: pipeHash("route")},
		Observer:      &notify.ObserverProof{Observer: n.observer, Domain: n.fixtureDomain, ProductDomain: pipeHostDomain(), ObservedAt: now - 10*pipeSec, Ref: pipeHash("observer")}}
	if phase != notify.CutoverOldActive {
		ev.Owner = &notify.OwnerEvidence{Owner: n.old, Method: "scheduler_disabled", ObservedAt: now - 5*pipeSec, Ref: pipeHash("owner")}
	}
	for _, m := range mods {
		m(ev)
	}
	return ev
}

func pipeNeedsEvidence(p notify.CutoverPhase) bool {
	return p == notify.CutoverBarrierVerified || p == notify.CutoverNewActive || p == notify.CutoverOldActive
}

func (n *pipeNode) command(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverCommand {
	st, _ := n.cutState()
	n.seq++
	c := notify.CutoverCommand{ID: model.ID{0xcc, byte(n.seq >> 8), byte(n.seq)}, ExpectedRevision: st.Revision, Frontier: n.frontier(), OldOwner: n.old, NewOwner: n.nw, Phase: phase, Reason: "drill cutover step"}
	if pipeNeedsEvidence(phase) {
		c.Evidence = n.evidence(phase, mods...)
	}
	return c
}

// advanceCommitted commits one transition that must succeed and does NOT apply the phase to the
// policy states: it is the state of a process that died right after the cutover command committed.
func (n *pipeNode) advanceCommitted(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverState {
	s, err := n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(phase, mods...))
	pipeMust(err, "advance to "+string(phase))
	return s
}

// syncModes applies the phase to every policy state (idempotent) and lets the clock move on.
func (n *pipeNode) syncModes(s notify.CutoverState) int {
	changed, err := n.ob.SyncModes(n.ctx, n.scope(), n.lease(), s.Phase, s.Cutover, s.Revision, n.clock.Now())
	pipeMust(err, "sync modes")
	n.clock.add(30 * pipeSec)
	return changed
}

// advance commits one transition and applies the phase to the policy states.
func (n *pipeNode) advance(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverState {
	s := n.advanceCommitted(phase, mods...)
	n.syncModes(s)
	return s
}

func (n *pipeNode) activate() notify.CutoverState {
	n.advance(notify.CutoverShadow)
	n.advance(notify.CutoverQuiescingOld)
	n.advance(notify.CutoverBarrierVerified)
	return n.advance(notify.CutoverNewActive)
}

// ownerStep is the committed ownership state as the verifier wants it.
func (n *pipeNode) ownerStep() pipeOwnerStep {
	s, ok := n.cutState()
	if !ok {
		pipeFail("no cutover is committed")
	}
	step := pipeOwnerStep{Phase: string(s.Phase)}
	for _, o := range s.ActiveOwners {
		step.Owners = append(step.Owners, o.String())
	}
	return step
}

// run is one worker pass at the clock's current instant, labelled with the committed cutover phase.
func (n *pipeNode) run() notify.RunReport {
	if s, ok := n.cutState(); ok {
		n.prov.setPhase(string(s.Phase))
	}
	r, err := n.w.RunOnce(n.ctx, n.scope(), n.clock.Now(), n.lease())
	pipeMust(err, "worker run")
	return r
}

func (n *pipeNode) records() []control.DeliveryRecord {
	recs, err := n.app.Control.Deliveries(n.ctx, n.scope(), n.project, "", n.clock.Now(), 0)
	pipeMust(err, "list deliveries")
	return recs
}

func (n *pipeNode) recordOf(id model.ID) control.DeliveryRecord {
	r, ok, err := n.app.Control.Delivery(n.ctx, n.scope(), n.project, id, n.clock.Now())
	if err != nil || !ok {
		pipeFail("delivery %s: found %v: %v", id, ok, err)
	}
	return r
}

func pipeDerive(parts ...string) model.ID {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

func (n *pipeNode) event(kind notify.EventKind, tag string) notify.PolicyEvent {
	cfg := notify.DefaultConfig()
	return notify.PolicyEvent{Kind: kind, Command: pipeDerive(string(kind), tag), Org: n.org, Project: n.project, Policy: n.policy, PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfg}, OwnerRevision: 1}
}

func pipeSubjectOf(incident model.ID) notify.Entity {
	return notify.Entity{Kind: notify.EntityIncident, ID: incident}
}

// submit decides one event against the committed policy state, naming its committed owner revision.
func (n *pipeNode) submit(subject notify.Entity, ev notify.PolicyEvent) notify.Submission {
	rec, found, err := n.app.Control.PolicyRecord(n.ctx, n.scope(), n.project, n.policy, string(subject.Kind)+":"+subject.ID.String())
	pipeMust(err, "policy record")
	if found {
		var st notify.PolicyState
		pipeMust(json.Unmarshal(rec.State, &st), "decode the policy state")
		ev.OwnerRevision = st.OwnerRevision
	}
	sub, err := n.ob.Submit(n.ctx, n.scope(), n.lease(), subject, ev, n.clock.Now())
	pipeMust(err, "submit "+string(ev.Kind))
	return sub
}

// policyOwnerRevision is the committed canonical-owner revision of a subject's policy state.
func (n *pipeNode) policyOwnerRevision(subject notify.Entity) model.Revision {
	rec, found, err := n.app.Control.PolicyRecord(n.ctx, n.scope(), n.project, n.policy, string(subject.Kind)+":"+subject.ID.String())
	pipeMust(err, "policy record")
	if !found {
		return 0
	}
	var st notify.PolicyState
	pipeMust(json.Unmarshal(rec.State, &st), "decode the policy state")
	return st.OwnerRevision
}

func (n *pipeNode) addRecipient(subject notify.Entity) {
	ev := n.event(notify.EventDestination, "dest|"+subject.ID.String())
	ev.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: true}
	n.submit(subject, ev)
}

func (n *pipeNode) incidentAction(a incidents.Action) incidents.State {
	a.Target = incidents.Target{Org: n.org, Project: n.project, Incident: a.Target.Incident}
	a.Actor = n.user
	st, err := n.inc.Act(n.ctx, n.scope(), a, n.clock.Now())
	pipeMust(err, "incident "+string(a.Type))
	return st
}

// incidentState reads the committed incident.
func (n *pipeNode) incidentState(id model.ID) incidents.State {
	st, err := n.inc.Get(n.ctx, n.scope(), n.project, id)
	pipeMust(err, "read the incident")
	return st
}

// evidenceOf is the incident's committed snapshot as a policy event (notification-policy.md).
func (n *pipeNode) evidenceOf(st incidents.State) notify.PolicyEvent {
	subject := pipeSubjectOf(st.ID)
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

func (n *pipeNode) humanOf(st incidents.State, t notify.ActionType, mods func(*notify.HumanAction)) notify.PolicyEvent {
	subject := pipeSubjectOf(st.ID)
	ev := n.event(notify.EventAction, fmt.Sprintf("%s|%s|%d", t, st.ID, st.Version))
	ev.Entity = &subject
	ev.Action = &notify.HumanAction{Type: t, Actor: n.user, Version: st.Version}
	if mods != nil {
		mods(ev.Action)
	}
	return ev
}

// pipeImpact is the system impact of one condition.
func pipeImpact(condition, episode model.ID, sev incidents.Severity, state incidents.ConditionState) *incidents.Impact {
	return &incidents.Impact{Condition: condition, Episode: episode, Severity: sev, State: state, Freshness: incidents.FreshnessFresh}
}

// issueLate submits four evidence batches for four fresh issues: late live evidence (its window
// closed long before), a backfill, an explicit operator replay of the same late window, and current
// live evidence; it reports which of them produced a deliverable notification and the ids of the
// deliveries that were decided.
func (n *pipeNode) issueLate() (map[string]bool, []model.ID) {
	out := map[string]bool{}
	var ids []model.ID
	now := n.clock.Now()
	oldWindow := (now - 30*60*pipeSec) / notify.ErrorWindow * notify.ErrorWindow
	currentWindow := now / notify.ErrorWindow * notify.ErrorWindow
	cases := []struct {
		name   string
		window model.UnixNano
		mode   notify.Mode
	}{
		{"late live evidence", oldWindow, notify.ModeLive},
		{"backfill", oldWindow, notify.ModeBackfill},
		{"explicit operator replay", oldWindow, notify.ModeOperatorReplay},
		{"current live evidence", currentWindow, notify.ModeLive},
	}
	for i, c := range cases {
		subject := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x90, byte(i)}}
		n.addRecipient(subject)
		var occurrences []model.ID
		for k := range 25 {
			occurrences = append(occurrences, model.ID{0x91, byte(i), byte(k)})
		}
		ev := n.event(notify.EventIssue, fmt.Sprintf("late|%d", i))
		ev.Entity = &subject
		ev.Mode = c.mode
		ev.Issue = &notify.IssueEvidence{WindowStart: c.window, Occurrences: occurrences, Freshness: notify.FreshnessFresh,
			Denominator: &notify.Denominator{Name: "http_operations", WindowStart: c.window, Operations: 100, Complete: true}}
		sub := n.submit(subject, ev)
		for _, in := range sub.Intents {
			if in.Eligible() && in.Key.Kind == notify.KindOpen {
				out[c.name] = true
				ids = append(ids, in.ID)
			}
		}
	}
	return out, ids
}

// rawClaim submits a claim exactly as a worker that observed the cutover at revision `owner` would:
// it is how a stale owner is emulated at the control boundary.
func (n *pipeNode) rawClaim(owner model.Revision, lease notify.FenceToken, now model.UnixNano) (control.Result, error) {
	raw, _ := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
		Claim: &control.DeliveryClaim{Project: n.project, Now: now, Expires: now + 60*pipeSec, Limit: 8, OwnerRevision: owner}})
	return n.app.Control.Transact(n.ctx, n.scope(), control.Command{CommandID: model.NewID(), ExpectedRevision: n.revision(), Kind: string(control.KindClaimDelivery), Payload: raw})
}

// ---- the product's heartbeat endpoints, served from the real node ----

func (n *pipeNode) issueObserverToken() string {
	issued, err := n.app.Auth.IssueServerToken(n.ctx, n.cred, n.org, n.user, []model.ID{n.project}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "deadman observer")
	pipeMust(err, "observer credential")
	return issued.Token
}

func pipeCanaryRecord(resource model.Resource, at model.UnixNano, value float64) model.Record {
	bits := model.FloatBits(math.Float64bits(value))
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: "soundpost_canary", Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
}

// pipeWorkerPassStale is how old the notification worker's last completed pass may be for the
// `notification` heartbeat to still answer healthy. It is a parameter of this drill's heartbeat
// fixture, not of the observer: the drill stops the worker and then commits one decision before it
// stops the heartbeat endpoints, and on a loaded host those commits can take longer than the 2 s the
// 06.09 fixture used, which made the notification heartbeat go missing BEFORE the stop and the
// "detected after the stop" assertion fail for a reason that is not a defect. The assertions about
// the observer's detection are unchanged.
const pipeWorkerPassStale = 6 * time.Second

type pipeHeartbeat struct {
	n     *pipeNode
	token string
	addr  string
	mu    sync.Mutex
	srv   *http.Server
	seq   atomic.Uint64
	pass  atomic.Int64
}

// newPipeHeartbeat picks a free loopback port at runtime. The caller approves the address.
func newPipeHeartbeat(n *pipeNode, token string) *pipeHeartbeat {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	pipeMust(err, "pick a heartbeat port")
	addr := ln.Addr().String()
	_ = ln.Close()
	return &pipeHeartbeat{n: n, token: token, addr: addr}
}

func (h *pipeHeartbeat) url(component string) string {
	return "http://" + h.addr + "/heartbeat/" + component
}

func (h *pipeHeartbeat) start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		return
	}
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", h.addr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	pipeMust(err, "listen for heartbeats")
	mux := http.NewServeMux()
	for _, c := range []string{"product", "ingest", "notification"} {
		mux.HandleFunc("/heartbeat/"+c, h.handler(c))
	}
	h.srv = &http.Server{Handler: mux}
	go h.srv.Serve(ln)
}

func (h *pipeHeartbeat) stop() {
	h.mu.Lock()
	srv := h.srv
	h.srv = nil
	h.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = srv.Close()
	}
}

// running reports whether the heartbeat server is up.
func (h *pipeHeartbeat) running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.srv != nil
}

// handler answers one component's heartbeat from real node state. 200 means the component works:
// product = the control group answers a quorum round; ingest = a canary sample was admitted through
// the production C03 path and acknowledged; notification = the worker completed a pass recently.
func (h *pipeHeartbeat) handler(component string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fail := func(code int) { w.WriteHeader(code) }
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		app := h.n.cur()
		if token == "" || app == nil {
			fail(http.StatusUnauthorized)
			return
		}
		cred, err := app.Auth.Authenticate(r.Context(), token)
		if err != nil {
			fail(http.StatusUnauthorized)
			return
		}
		if _, err = app.Auth.Authorize(r.Context(), cred, h.n.org, []model.ID{h.n.project}, auth.Read); err != nil {
			fail(http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
		defer cancel()
		switch component {
		case "product":
			if _, err = app.Control.ReplicaGroup().Fence(ctx); err != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
		case "ingest":
			record := pipeCanaryRecord(h.n.resource, model.UnixNano(time.Now().UnixNano()), float64(h.seq.Load()))
			producer := model.ID{0xd1}
			slot, e := model.OwnerSlot(h.n.org, h.n.project, h.n.source, producer, record)
			if e != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
			batch := model.Batch{Version: 1, Project: h.n.project, Source: h.n.source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{record}}
			grant, e := app.Ingest.ResolveSource(ctx, h.n.srcCred, batch)
			if e == nil {
				_, e = app.Ingest.Admit(ctx, grant, batch)
			}
			if e != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
		case "notification":
			if time.Since(time.Unix(0, h.pass.Load())) > pipeWorkerPassStale {
				fail(http.StatusServiceUnavailable)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"component": component, "ok": true, "seq": h.seq.Add(1), "at_ns": time.Now().UnixNano()})
	}
}

// pipeWorkerLoop is the product's notification worker: one pass every 50 ms. Each completed pass is
// the notification pipeline's heartbeat.
type pipeWorkerLoop struct {
	n      *pipeNode
	cancel context.CancelFunc
	wg     sync.WaitGroup
	hb     *pipeHeartbeat
}

func (l *pipeWorkerLoop) start() {
	if l.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			app := l.n.cur()
			if app == nil {
				continue
			}
			scope, err := app.Auth.Authorize(ctx, l.n.cred, l.n.org, []model.ID{l.n.project}, auth.OrgAdmin)
			if err != nil {
				continue
			}
			lease, err := app.Control.ReplicaGroup().Fence(ctx)
			if err != nil {
				continue
			}
			l.n.clock.add(pipeSec / 20)
			if _, err = l.n.w.RunOnce(ctx, scope, l.n.clock.Now(), lease); err == nil && l.hb != nil {
				l.hb.pass.Store(time.Now().UnixNano())
			}
		}
	}()
}

func (l *pipeWorkerLoop) stop() {
	if l.cancel != nil {
		l.cancel()
		l.wg.Wait()
		l.cancel = nil
	}
}

func (l *pipeWorkerLoop) running() bool { return l.cancel != nil }

// ---- the destination the observer is authorized for: a loopback receiver ----

type pipeReceived struct {
	Kind      string `json:"kind"`
	Observer  string `json:"observer"`
	Component string `json:"component"`
	Outage    string `json:"outage"`
	Idem      string `json:"-"`
	Status    int    `json:"-"`
}

type pipeReceiver struct {
	srv   *http.Server
	addr  string
	mu    sync.Mutex
	reqs  []pipeReceived
	fail  int
	token string
}

// newPipeReceiver starts a loopback destination that fails its first failFirst requests with 503
// and then accepts. The caller approves the address.
func newPipeReceiver(token string, failFirst int) *pipeReceiver {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	pipeMust(err, "listen for the receiver")
	r := &pipeReceiver{fail: failFirst, token: token, addr: ln.Addr().String()}
	r.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body pipeReceived
		_ = json.NewDecoder(req.Body).Decode(&body)
		body.Idem = req.Header.Get("Idempotency-Key")
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case req.Header.Get("Authorization") != "Bearer "+r.token:
			body.Status = http.StatusUnauthorized
		case r.fail > 0:
			r.fail--
			body.Status = http.StatusServiceUnavailable
		default:
			body.Status = http.StatusOK
		}
		r.reqs = append(r.reqs, body)
		w.WriteHeader(body.Status)
	})}
	go r.srv.Serve(ln)
	return r
}

func (r *pipeReceiver) URL() string  { return "http://" + r.addr + "/notify" }
func (r *pipeReceiver) Host() string { return r.addr }
func (r *pipeReceiver) close()       { _ = r.srv.Close() }
func (r *pipeReceiver) requests() []pipeReceived {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// acceptedNotices is what the destination accepted (status 200), by idempotency key, as the digest
// of the notice content it received: the retained side of the observer's notice reconciliation.
func (r *pipeReceiver) acceptedNotices() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for _, q := range r.reqs {
		if q.Status == http.StatusOK && q.Idem != "" {
			out[q.Idem] = pipeNoticeDigest(q.Observer, q.Kind, q.Outage, q.Component)
		}
	}
	return out
}

// ---- the observer process ----

// pipeBuf is a goroutine-safe buffer for a child's output.
type pipeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (p *pipeBuf) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.b.Write(b)
}

func (p *pipeBuf) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.b.String()
}

type pipeObserver struct {
	cmd  *exec.Cmd
	dir  string
	args []string
	out  pipeBuf
	done chan struct{}
}

// pipeBuildObserver compiles the 06.09 observer program (tests/acceptance/observer: built, never
// forked) with the toolchain that runs the drill.
func pipeBuildObserver(root, out string) error {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		p, lerr := exec.LookPath("go")
		if lerr != nil {
			return fmt.Errorf("no Go toolchain to build the observer: %w", lerr)
		}
		goBin = p
	}
	cmd := exec.Command(goBin, "build", "-o", out, "./tests/acceptance/observer")
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building the observer: %v\n%s", err, raw)
	}
	return nil
}

// startPipeObserver runs the observer as a separate operating-system process whose environment
// holds only its own two credentials and PATH.
func startPipeObserver(bin, dir, pollToken, deliveryToken string, args []string) (*pipeObserver, error) {
	o := &pipeObserver{dir: dir, args: args, done: make(chan struct{})}
	o.cmd = exec.Command(bin, append([]string{"-state", dir}, args...)...)
	o.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OBSERVER_POLL_TOKEN=" + pollToken, "OBSERVER_DELIVERY_TOKEN=" + deliveryToken}
	o.cmd.Stdout, o.cmd.Stderr = &o.out, &o.out
	if err := o.cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _ = o.cmd.Wait(); close(o.done) }()
	return o, nil
}

func (o *pipeObserver) pid() int { return o.cmd.Process.Pid }

func (o *pipeObserver) state() (pipeObsState, error) {
	raw, err := os.ReadFile(filepath.Join(o.dir, "state.json"))
	if err != nil {
		return pipeObsState{}, err
	}
	return pipeParseObserverState(raw)
}

// kill is SIGKILL: no shutdown handler runs. It is a no-op when the process already exited.
func (o *pipeObserver) kill() {
	select {
	case <-o.done:
		return
	default:
	}
	if o.cmd.Process != nil {
		_ = o.cmd.Process.Signal(syscall.SIGKILL)
		<-o.done
	}
}

func (o *pipeObserver) alive() bool {
	select {
	case <-o.done:
		return false
	default:
		return true
	}
}

// pipeWaitFor polls ok until it holds or limit passes.
func pipeWaitFor(limit time.Duration, what string, ok func() bool) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ok() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("timed out after " + limit.String() + " waiting for " + what)
}
