// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// These tests drive the cutover and rollback tools over the REAL plan 06
// ownership engine: the control store (activated single-voter Raft group, real
// auth scopes) behind notify.CutoverService, whose barrier checks and
// ActiveOwners decide every ownership question. Everything outside the engine
// is synthetic: the legacy operator, the new route's delivery observer and the
// independent deadman are in-process fakes with fault injection. No customer
// system, provider or credential exists here and nothing is customer
// acceptance.

const cutoverSec = model.UnixNano(time.Second)

// cutoverBase is a fixed fake "now" far from any real clock.
const cutoverBase = 1_800_000_000 * cutoverSec

type cutoverClock struct{ v atomic.Int64 }

func (c *cutoverClock) Now() model.UnixNano  { return model.UnixNano(c.v.Load()) }
func (c *cutoverClock) add(d model.UnixNano) { c.v.Add(int64(d)) }

// cutoverCrashSignal is the panic that models a process death: no tool code
// runs after it, so only what was persisted before it survives.
type cutoverCrashSignal struct{ point string }

type cutoverWorld struct {
	t   *testing.T
	ctx context.Context

	clock *cutoverClock
	wall  time.Time
	dir   string

	store   *control.Store
	svc     *auth.Service
	cred    auth.Credential
	token   string
	user    model.ID
	org     model.ID
	project model.ID
	scope   auth.Scope
	real    *notify.CutoverService
	engine  *cutoverTestEngine

	legacy  *cutoverFakeLegacy
	route   *cutoverFakeRoute
	deadman *cutoverFakeDeadman

	old, nw, observer, domain, productDomain, source, group model.ID

	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	gate  ReadyGate
	plan  OwnershipPlan
	grant Authorization

	faults             map[string]func() error
	observers          map[string][]func()
	events             []string
	violations         []string
	tolerateViolations bool
	targets            []CutoverConnectTarget
}

func newCutoverWorld(t *testing.T) *cutoverWorld {
	t.Helper()
	w := &cutoverWorld{t: t, ctx: context.Background(), clock: &cutoverClock{}, wall: time.Unix(1_800_000_000, 0), dir: t.TempDir(),
		org: model.NewID(), project: model.NewID(), faults: map[string]func() error{}, observers: map[string][]func(){},
		old: model.ID{0x01, 0xd0}, nw: model.ID{0x02, 0xd0}, observer: model.ID{0x03, 0xd0}, domain: model.ID{0x04, 0xd0},
		productDomain: model.ID{0x05, 0xd0}, source: model.ID{0x06, 0xd0}, group: model.ID{0x07, 0xd0}}
	w.clock.v.Store(int64(cutoverBase))
	var err error
	if w.store, err = control.Open(w.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.store.Close() })
	if w.svc, err = auth.NewService(auth.AuthDependencies{Control: w.store, Now: func() time.Time { return w.wall }}); err != nil {
		t.Fatal(err)
	}
	if err = w.store.EnableSingle(w.ctx, filepath.Join(w.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if err = w.store.BindIncidentAction(); err != nil {
		t.Fatal(err)
	}
	if err = w.store.BindDeliveryOutbox(); err != nil {
		t.Fatal(err)
	}
	if err = w.store.BindRetention(); err != nil {
		t.Fatal(err)
	}
	boot, err := w.store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := w.svc.Bootstrap(w.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	w.token, w.user = session.Token, session.User
	if w.cred, err = w.svc.Authenticate(w.ctx, w.token); err != nil {
		t.Fatal(err)
	}
	w.admin("create_org", auth.AdminPayload{Name: "cutover"})
	w.admin("create_project", auth.AdminPayload{ID: w.project, Name: "p1"})
	if w.scope, err = w.svc.Authorize(w.ctx, w.cred, w.org, []model.ID{w.project}, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	if w.real, err = notify.NewCutoverService(w.store, w.clock); err != nil {
		t.Fatal(err)
	}
	w.seed(3, 100)
	w.engine = &cutoverTestEngine{w: w, inner: w.real}
	w.legacy = &cutoverFakeLegacy{w: w, enabled: true, results: map[string]CutoverLegacyState{}, method: "scheduler_disabled"}
	w.route = &cutoverFakeRoute{w: w, probes: map[string]CutoverDelivery{}, drop: map[string]bool{}, duplicate: map[string]bool{}, unknown: map[string]bool{}}
	w.deadman = &cutoverFakeDeadman{w: w, armed: true}
	if w.pub, w.priv, err = ed25519.GenerateKey(nil); err != nil {
		t.Fatal(err)
	}
	now := w.now()
	w.gate = w.makeGate(now)
	w.plan = OwnershipPlan{RunID: "run-1", Scope: "synthetic-scope", Environment: cutoverEnvProduction,
		StatePath: filepath.Join(t.TempDir(), "cutover-state.json"),
		Project:   w.project, OldOwner: w.old, NewOwner: w.nw, PolicyGeneration: 1,
		Frontier:           []notify.FrontierEntry{{Source: w.source, Version: 3, Cursor: model.Cursor{Group: w.group, Index: 100}}},
		OldQuiescence:      CutoverQuiescenceProof{Method: "scheduler_disabled"},
		Destination:        CutoverDestinationTest{Destination: "dest-1", ProbeID: "probe-1"},
		Deadman:            CutoverDeadmanExclusion{Observer: w.observer, Domain: w.domain, ProductDomain: w.productDomain},
		RollbackRunbookRef: "runbook-step-1"}
	w.grant = Authorization{GrantID: "grant-1", Authority: "synthetic-operator", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		MaxEvidenceAgeSeconds: 900, Scopes: []TargetScope{{ID: w.plan.Scope, Collectors: []string{"cutover", "rollback"}}}}
	t.Cleanup(func() {
		if !w.tolerateViolations && len(w.violations) > 0 {
			t.Errorf("ownership invariant violated: %v", w.violations)
		}
	})
	return w
}

func (w *cutoverWorld) revision() model.Revision {
	var r model.Revision
	if err := w.store.View(w.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *cutoverWorld) admin(kind string, p auth.AdminPayload) {
	w.t.Helper()
	p.Reason = "cutover fixture"
	raw, _ := json.Marshal(p)
	if _, err := w.svc.AdminCommand(w.ctx, w.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: w.revision(), OrgID: w.org, Kind: kind, Payload: raw}); err != nil {
		w.t.Fatal(kind, err)
	}
}

// seed commits the source the frontier names (at version) and the project's
// committed checkpoint for the group (through index): the facts the barrier is
// verified against.
func (w *cutoverWorld) seed(version model.Revision, index uint64) {
	w.t.Helper()
	if err := w.store.Update(w.ctx, func(st *control.State) error {
		if st.Sources == nil {
			st.Sources = map[string]model.SourceAuthority{}
		}
		st.Sources[w.source.String()] = model.SourceAuthority{ID: w.source, Org: w.org, Project: w.project, CredentialID: model.ID{0x08, 0xd0}, Policy: model.SourcePolicy{Revision: version, Enabled: true}}
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		raw, err := json.Marshal(control.IssueBook{Org: w.org, Project: w.project, Revision: 1, Checkpoints: map[string]model.Uint64{w.group.String(): model.Uint64(index)}})
		st.IssueBooks[w.org.String()+":"+w.project.String()] = raw
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *cutoverWorld) now() time.Time          { return time.Unix(0, int64(w.clock.Now())).UTC() }
func (w *cutoverWorld) advance(d time.Duration) { w.clock.add(model.UnixNano(d)) }

func (w *cutoverWorld) makeGate(now time.Time) ReadyGate {
	w.t.Helper()
	l, a := readinessFixture()
	l.Now = now
	for i := range l.Evidence {
		l.Evidence[i].ObservedAt = now.Add(-10 * time.Minute)
	}
	for i := range a.Items {
		a.Items[i].NotBefore = now.Add(-time.Hour)
		a.Items[i].Expires = now.Add(24 * time.Hour)
	}
	res, err := ReadyForCutover(w.ctx, l, a)
	if err != nil || !res.Ready {
		w.t.Fatalf("gate fixture not ready: %v %+v", err, res.Blockers)
	}
	g, err := SignReadyGate(res, w.priv)
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

// makeStagingGate is a valid signed gate built from staging evidence only: it
// is not production-proven.
func (w *cutoverWorld) makeStagingGate(now time.Time) ReadyGate {
	w.t.Helper()
	l, a := readinessFixture()
	l.Now, l.RequireProduction = now, false
	for i := range l.Evidence {
		l.Evidence[i].ObservedAt = now.Add(-10 * time.Minute)
		l.Evidence[i].Environment = ReadinessEnvStaging
	}
	for i := range a.Items {
		a.Items[i].NotBefore = now.Add(-time.Hour)
		a.Items[i].Expires = now.Add(24 * time.Hour)
		a.Items[i].Environment = ReadinessEnvStaging
	}
	res, err := ReadyForCutover(w.ctx, l, a)
	if err != nil || !res.Ready {
		w.t.Fatalf("staging gate fixture not ready: %v %+v", err, res.Blockers)
	}
	g, err := SignReadyGate(res, w.priv)
	if err != nil {
		w.t.Fatal(err)
	}
	if g.ProductionProven {
		w.t.Fatal("a staging gate must not be production-proven")
	}
	return g
}

func (w *cutoverWorld) runtime() CutoverRuntime {
	return CutoverRuntime{GateKey: w.pub, Now: w.now, Engine: w.engine, Scope: w.scope, Legacy: w.legacy, Route: w.route, Deadman: w.deadman, PollInterval: time.Millisecond}
}

func (w *cutoverWorld) rtctx() context.Context { return CutoverWithRuntime(w.ctx, w.runtime()) }

// ---- fault injection and instrumentation

func (w *cutoverWorld) fire(point string) error {
	for _, f := range w.observers[point] {
		f()
	}
	if f, ok := w.faults[point]; ok {
		delete(w.faults, point)
		return f()
	}
	return nil
}

func (w *cutoverWorld) observe(point string, f func()) {
	w.observers[point] = append(w.observers[point], f)
}
func (w *cutoverWorld) crashAt(point string) {
	w.faults[point] = func() error { panic(cutoverCrashSignal{point}) }
}
func (w *cutoverWorld) failAt(point string, err error) { w.faults[point] = func() error { return err } }
func (w *cutoverWorld) log(format string, args ...any) {
	w.events = append(w.events, fmt.Sprintf(format, args...))
}
func (w *cutoverWorld) violate(format string, args ...any) {
	w.violations = append(w.violations, fmt.Sprintf(format, args...))
}
func (w *cutoverWorld) indexOf(event string) int { return slices.Index(w.events, event) }

func (w *cutoverWorld) engineState() (notify.CutoverState, bool) {
	w.t.Helper()
	st, found, err := w.real.Cutover(w.ctx, w.scope)
	if err != nil {
		w.t.Fatal(err)
	}
	return st, found
}

// owners are the active normal owners the engine itself reports for the phase.
func (w *cutoverWorld) owners() []model.ID {
	st, found := w.engineState()
	if !found {
		return nil
	}
	return notify.ActiveOwners(st.Phase, w.old, w.nw)
}

func (w *cutoverWorld) newActive() bool { return slices.Contains(w.owners(), w.nw) }

// checkInstant is the one-sender invariant, evaluated at every instant the
// world changes: the engine's own ActiveOwners for the new owner, the legacy
// operator's observed state for the old one.
func (w *cutoverWorld) checkInstant(label string) {
	owners := w.owners()
	if len(owners) > 1 {
		w.violate("%s: %d active owners", label, len(owners))
	}
	if slices.Contains(owners, w.observer) {
		w.violate("%s: the deadman is counted as an owner", label)
	}
	if slices.Contains(owners, w.nw) && w.legacy.enabled {
		w.violate("%s: both senders enabled", label)
	}
}

func (w *cutoverWorld) crashed(f func()) (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(cutoverCrashSignal); !ok {
				panic(r)
			}
			crashed = true
		}
	}()
	f()
	return false
}

func (w *cutoverWorld) cutover() (rcpt CutoverReceipt, crashed bool, err error) {
	crashed = w.crashed(func() { rcpt, err = Cutover(w.rtctx(), w.gate, w.plan, w.grant) })
	return
}

func (w *cutoverWorld) rollback(rcpt CutoverReceipt, reason Reason) (rb RollbackReceipt, crashed bool, err error) {
	crashed = w.crashed(func() { rb, err = Rollback(w.rtctx(), rcpt, reason, w.grant) })
	return
}

func (w *cutoverWorld) mustCutover() CutoverReceipt {
	w.t.Helper()
	rcpt, crashed, err := w.cutover()
	if crashed || err != nil || rcpt.Phase != CutoverPhaseDone {
		w.t.Fatalf("cutover: crashed=%v err=%v receipt=%+v", crashed, err, rcpt)
	}
	return rcpt
}

func (w *cutoverWorld) state() *cutoverState {
	w.t.Helper()
	st, err := cutoverLoadState(w.plan.StatePath)
	if err != nil || st == nil {
		w.t.Fatalf("state file: %v %v", st, err)
	}
	return st
}

// emit decides one notification now: whoever is the enabled normal sender
// delivers it; when nobody is, it waits in the product's queue until the new
// owner is active.
func (w *cutoverWorld) emit(id string, urgent bool) {
	w.route.due = append(w.route.due, CutoverDue{ID: id, Urgent: urgent})
	senders := 0
	if w.legacy.enabled {
		w.legacy.deliver(id)
		senders++
	}
	if w.newActive() {
		w.route.deliver(id)
		senders++
	}
	if senders == 0 {
		w.route.queue = append(w.route.queue, id)
	}
}

// pump is one worker pass of the new owner: it delivers what waited, once.
func (w *cutoverWorld) pump() {
	if !w.newActive() {
		return
	}
	queued := w.route.queue
	w.route.queue = nil
	for _, id := range queued {
		w.route.deliver(id)
	}
}

// ---- the real engine behind fault injection

type cutoverTestEngine struct {
	w     *cutoverWorld
	inner CutoverEngine
	// inflate reports that many live claims on the next Facts calls (-1: always).
	inflate int
	// tamper rewrites what the engine answers to a committed command; readTamper
	// what it answers when read: an engine that is wrong or moved by someone else.
	tamper     func(c notify.CutoverCommand, st *notify.CutoverState)
	readTamper func(st *notify.CutoverState)
}

func (e *cutoverTestEngine) AdvanceCutover(ctx context.Context, scope auth.Scope, c notify.CutoverCommand) (notify.CutoverState, error) {
	if err := e.w.fire("engine.before." + string(c.Phase)); err != nil {
		return notify.CutoverState{}, err
	}
	st, err := e.inner.AdvanceCutover(ctx, scope, c)
	if err != nil {
		return st, err
	}
	e.w.clock.add(cutoverSec)
	e.w.log("engine:%s", c.Phase)
	e.w.checkInstant("after engine " + string(c.Phase))
	if c.Phase == notify.CutoverNewActive {
		e.w.pump()
	}
	if err := e.w.fire("engine.after." + string(c.Phase)); err != nil {
		return notify.CutoverState{}, err
	}
	if e.tamper != nil {
		e.tamper(c, &st)
	}
	return st, nil
}

func (e *cutoverTestEngine) Cutover(ctx context.Context, scope auth.Scope) (notify.CutoverState, bool, error) {
	st, found, err := e.inner.Cutover(ctx, scope)
	if err == nil && found && e.readTamper != nil {
		e.readTamper(&st)
	}
	return st, found, err
}

func (e *cutoverTestEngine) Facts(ctx context.Context, scope auth.Scope) (notify.CutoverFacts, error) {
	f, err := e.inner.Facts(ctx, scope)
	if err == nil && e.inflate != 0 {
		if e.inflate > 0 {
			e.inflate--
		}
		f.Claimed += 2
		e.w.log("facts:claimed")
	}
	return f, err
}

// ---- the legacy operator

type cutoverFakeLegacy struct {
	w       *cutoverWorld
	enabled bool
	method  string
	calls   []string
	results map[string]CutoverLegacyState
	// delivered are the legacy route's own deliveries.
	delivered []CutoverDelivery
	// restoreEffects counts real re-enablings (a replayed command is not one).
	restoreEffects int
	// faults
	disarmDeadman   bool
	pending         int
	unknown         int
	reenableOnQuiet bool
	// age is how old the legacy operator's first observation is; ackAge how old
	// the acknowledgement of a quiesce is
	age, ackAge time.Duration
	// faults of the legacy operator's answers
	echo        string
	zeroRef     bool
	ownerLie    *model.ID
	restoreNoop bool
}

func (l *cutoverFakeLegacy) state(cmd string, age time.Duration) CutoverLegacyState {
	s := CutoverLegacyState{Owner: l.w.old, Enabled: l.enabled, Method: l.method, ObservedAt: l.w.now().Add(-age), Ref: sha256.Sum256([]byte("legacy:" + cmd + fmt.Sprint(len(l.calls)))),
		Pending: l.pending, Unknown: l.unknown, CommandID: cmd}
	if l.ownerLie != nil {
		s.Owner = *l.ownerLie
	}
	if l.zeroRef {
		s.Ref = model.Hash{}
	}
	if l.echo != "" && cmd != "" {
		s.CommandID = l.echo
	}
	return s
}

func (l *cutoverFakeLegacy) Observe(ctx context.Context, owner model.ID) (CutoverLegacyState, error) {
	l.calls = append(l.calls, "Observe")
	if owner != l.w.old {
		l.w.violate("legacy observe addressed to %s", owner)
		return CutoverLegacyState{}, errors.New("unknown owner")
	}
	if err := l.w.fire("legacy.Observe"); err != nil {
		return CutoverLegacyState{}, err
	}
	// the age is the staleness of the observation taken before any quiescing
	// (later observations must be fresh enough to postdate it)
	age := time.Duration(0)
	if len(l.results) == 0 {
		age = l.age
	}
	return l.state("", age), nil
}

func (l *cutoverFakeLegacy) QuiesceNormal(ctx context.Context, cmd CutoverLegacyCommand) (CutoverLegacyState, error) {
	l.calls = append(l.calls, "QuiesceNormal:"+cmd.ID)
	if cmd.Owner != l.w.old {
		l.w.violate("legacy quiesce addressed to %s", cmd.Owner)
		return CutoverLegacyState{}, errors.New("unknown owner")
	}
	if err := l.w.fire("legacy.before.QuiesceNormal"); err != nil {
		return CutoverLegacyState{}, err
	}
	if res, ok := l.results[cmd.ID]; ok {
		return res, nil
	}
	l.enabled = false
	if l.disarmDeadman {
		l.w.deadman.armed = false
	}
	if l.reenableOnQuiet {
		l.enabled = true
	}
	l.w.clock.add(cutoverSec)
	l.w.log("legacy:quiesce")
	l.w.checkInstant("legacy quiesce")
	res := l.state(cmd.ID, l.ackAge)
	l.results[cmd.ID] = res
	if err := l.w.fire("legacy.after.QuiesceNormal"); err != nil {
		return CutoverLegacyState{}, err
	}
	return res, nil
}

func (l *cutoverFakeLegacy) RestoreNormal(ctx context.Context, cmd CutoverLegacyCommand) (CutoverLegacyState, error) {
	l.calls = append(l.calls, "RestoreNormal:"+cmd.ID)
	if cmd.Owner != l.w.old {
		l.w.violate("legacy restore addressed to %s", cmd.Owner)
		return CutoverLegacyState{}, errors.New("unknown owner")
	}
	if err := l.w.fire("legacy.before.RestoreNormal"); err != nil {
		return CutoverLegacyState{}, err
	}
	if res, ok := l.results[cmd.ID]; ok {
		return res, nil
	}
	if !l.restoreNoop {
		l.enabled = true
	}
	l.restoreEffects++
	l.w.clock.add(cutoverSec)
	l.w.log("legacy:restore")
	l.w.checkInstant("legacy restore")
	res := l.state(cmd.ID, 0)
	if !l.restoreNoop { // an ineffective restore is a failed command, not an outcome to replay
		l.results[cmd.ID] = res
	}
	if err := l.w.fire("legacy.after.RestoreNormal"); err != nil {
		return CutoverLegacyState{}, err
	}
	return res, nil
}

func (l *cutoverFakeLegacy) Delivered(ctx context.Context) ([]CutoverDelivery, error) {
	l.calls = append(l.calls, "Delivered")
	return slices.Clone(l.delivered), nil
}

func (l *cutoverFakeLegacy) deliver(id string) {
	l.delivered = append(l.delivered, CutoverDelivery{ID: id, Outcome: CutoverOutcomeDelivered, At: l.w.now()})
	l.w.log("legacy:deliver:%s", id)
}

func (l *cutoverFakeLegacy) callsNamed(prefix string) []string {
	var out []string
	for _, c := range l.calls {
		if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
			out = append(out, c)
		}
	}
	return out
}

// ---- the new route's delivery observer

type cutoverFakeRoute struct {
	w         *cutoverWorld
	calls     []string
	probes    map[string]CutoverDelivery
	due       []CutoverDue
	queue     []string
	delivered []CutoverDelivery
	// faults
	probeFails   bool
	probeOutcome string
	probeID      string
	drop         map[string]bool
	duplicate    map[string]bool
	unknown      map[string]bool
}

func (r *cutoverFakeRoute) TestDelivery(ctx context.Context, probe string) (CutoverDelivery, error) {
	r.calls = append(r.calls, "TestDelivery:"+probe)
	if err := r.w.fire("route.TestDelivery"); err != nil {
		return CutoverDelivery{}, err
	}
	if r.probeFails {
		return CutoverDelivery{}, errors.New("the destination rejected the test delivery")
	}
	if d, ok := r.probes[probe]; ok {
		return d, nil
	}
	d := CutoverDelivery{ID: probe, Outcome: CutoverOutcomeDelivered, At: r.w.now()}
	if r.probeOutcome != "" {
		d.Outcome = r.probeOutcome
	}
	if r.probeID != "" {
		d.ID = r.probeID
	}
	r.probes[probe] = d
	return d, nil
}

func (r *cutoverFakeRoute) Due(ctx context.Context) ([]CutoverDue, error) {
	r.calls = append(r.calls, "Due")
	if err := r.w.fire("route.Due"); err != nil {
		return nil, err
	}
	return slices.Clone(r.due), nil
}

func (r *cutoverFakeRoute) Delivered(ctx context.Context) ([]CutoverDelivery, error) {
	r.calls = append(r.calls, "Delivered")
	if err := r.w.fire("route.Delivered"); err != nil {
		return nil, err
	}
	return slices.Clone(r.delivered), nil
}

func (r *cutoverFakeRoute) deliver(id string) {
	if r.drop[id] {
		return
	}
	outcome := CutoverOutcomeDelivered
	if r.unknown[id] {
		outcome = CutoverOutcomeUnknown
	}
	d := CutoverDelivery{ID: id, Outcome: outcome, At: r.w.now()}
	r.delivered = append(r.delivered, d)
	if r.duplicate[id] {
		r.delivered = append(r.delivered, d)
	}
	r.w.log("route:deliver:%s", id)
}

// ---- the independent deadman: read-only

type cutoverFakeDeadman struct {
	w     *cutoverWorld
	calls []string
	armed bool
	// age is how old the proof is; identity and domain override what it names.
	age      time.Duration
	observer *model.ID
	domain   *model.ID
	// productDomain overrides the product failure domain the proof names;
	// zeroRef drops its digest.
	productDomain *model.ID
	zeroRef       bool
}

func (d *cutoverFakeDeadman) Proof(ctx context.Context) (CutoverDeadmanProof, error) {
	d.calls = append(d.calls, "Proof")
	if err := d.w.fire("deadman.Proof"); err != nil {
		return CutoverDeadmanProof{}, err
	}
	p := CutoverDeadmanProof{Observer: d.w.observer, Domain: d.w.domain, ProductDomain: d.w.productDomain, Armed: d.armed, ObservedAt: d.w.now().Add(-d.age), Ref: sha256.Sum256([]byte("deadman"))}
	if d.productDomain != nil {
		p.ProductDomain = *d.productDomain
	}
	if d.zeroRef {
		p.Ref = model.Hash{}
	}
	if d.observer != nil {
		p.Observer = *d.observer
	}
	if d.domain != nil {
		p.Domain = *d.domain
	}
	return p, nil
}

// ---- assertions shared by the tests

func cutoverIDs(ids ...model.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// committedCommands are the engine commands of the cutover, in order.
func (w *cutoverWorld) committedCommands() []model.ID {
	st, found := w.engineState()
	if !found {
		return nil
	}
	var out []model.ID
	for _, e := range st.Timeline {
		out = append(out, e.Command)
	}
	return out
}

// deliveredBy counts the confirmed deliveries of id per side.
func (w *cutoverWorld) deliveredBy(id string) (legacy, route int) {
	for _, d := range w.legacy.delivered {
		if d.ID == id && d.Outcome == CutoverOutcomeDelivered {
			legacy++
		}
	}
	for _, d := range w.route.delivered {
		if d.ID == id && d.Outcome == CutoverOutcomeDelivered {
			route++
		}
	}
	return
}

func (w *cutoverWorld) assertConverged(rcpt CutoverReceipt) {
	w.t.Helper()
	t := w.t
	if rcpt.Phase != CutoverPhaseDone || rcpt.IncompleteCode != "" || !slices.Equal(rcpt.Completed, cutoverSteps) {
		t.Fatalf("receipt is not done after the resume: %+v", rcpt)
	}
	st, found := w.engineState()
	if !found || st.Phase != notify.CutoverNewActive || st.Epoch != w.plan.PolicyGeneration {
		t.Fatalf("engine after the resume: %+v", st)
	}
	if got := w.owners(); !slices.Equal(got, []model.ID{w.nw}) {
		t.Fatalf("active owners after the resume: %v", got)
	}
	if !slices.Equal(rcpt.ActiveOwners, []model.ID{w.nw}) {
		t.Fatalf("receipt owners: %v", rcpt.ActiveOwners)
	}
	if w.legacy.enabled {
		t.Fatal("the old normal route is enabled next to the new owner")
	}
	want := []model.ID{cutoverCommandID(w.plan.RunID, cutoverCmdShadow), cutoverCommandID(w.plan.RunID, cutoverCmdQuiesce),
		cutoverCommandID(w.plan.RunID, cutoverCmdHandover), cutoverCommandID(w.plan.RunID, cutoverCmdActivate)}
	if got := w.committedCommands(); !slices.Equal(got, want) {
		t.Fatalf("engine commands %v, want exactly the run's four derived IDs %v", cutoverIDs(got...), cutoverIDs(want...))
	}
	ids := map[string]bool{}
	for _, c := range w.legacy.callsNamed("QuiesceNormal:") {
		ids[c] = true
	}
	if len(ids) != 1 || !ids["QuiesceNormal:"+cutoverCommandID(w.plan.RunID, cutoverCmdLegacyQ).String()] {
		t.Fatalf("legacy quiesce commands %v: want one ID, the run's", ids)
	}
	if n := len(w.legacy.callsNamed("RestoreNormal")); n != 0 {
		t.Fatalf("a cutover restored the old route %d times", n)
	}
	if rcpt.Reconciliation.Gaps != 0 || rcpt.Reconciliation.Duplicates != 0 || len(rcpt.Blockers) != 0 {
		t.Fatalf("reconciliation: %+v %v", rcpt.Reconciliation, rcpt.Blockers)
	}
	if got := w.state(); got.Phase != CutoverPhaseDone || !slices.Equal(got.Completed, cutoverSteps) || got.TestDelivery != w.plan.Destination.ProbeID {
		t.Fatalf("state file: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// The named tests.

// TestCutoverCrashBetweenDisableAndEnableRecoversOneOwner kills or times out the
// tool between every pair of durable phases, with an urgent alert queued while
// the old route is already disabled and the new one is not yet active. Each
// stop is an explicit incomplete phase, never done; at no instant are two
// owners active; the resume uses the run's same command IDs, never activates a
// second owner, and the urgent work is delivered exactly once by the new owner.
func TestCutoverCrashBetweenDisableAndEnableRecoversOneOwner(t *testing.T) {
	cases := []struct {
		name, point    string
		completed      []string
		enginePhase    notify.CutoverPhase
		legacyEnabled  bool
		urgentDelivery bool // the urgent alert was already delivered by the new owner at the stop
	}{
		{"before the old route is disabled", "legacy.before.QuiesceNormal", []string{cutoverStepPreflight}, notify.CutoverQuiescingOld, true, false},
		{"old route disabled, acknowledgement not recorded", "legacy.after.QuiesceNormal", []string{cutoverStepPreflight}, notify.CutoverQuiescingOld, false, false},
		{"barrier committed, response lost", "engine.after.barrier_verified", []string{cutoverStepPreflight, cutoverStepQuiesce}, notify.CutoverBarrierVerified, false, false},
		{"between handover and activation", "engine.before.new_active", []string{cutoverStepPreflight, cutoverStepQuiesce, cutoverStepHandover}, notify.CutoverBarrierVerified, false, false},
		{"activated, response lost", "engine.after.new_active", []string{cutoverStepPreflight, cutoverStepQuiesce, cutoverStepHandover}, notify.CutoverNewActive, false, true},
		{"activated, before reconciliation reads the observers", "route.Due", []string{cutoverStepPreflight, cutoverStepQuiesce, cutoverStepHandover, cutoverStepActivate}, notify.CutoverNewActive, false, true},
	}
	for _, mode := range []string{"crash", "timeout"} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				w := newCutoverWorld(t)
				w.emit("normal-before", false)
				// The alert fires the instant the old route is disabled.
				w.observe("legacy.after.QuiesceNormal", func() { w.emit("urgent-gap", true) })
				if mode == "crash" {
					w.crashAt(c.point)
				} else {
					w.failAt(c.point, fmt.Errorf("provider call: %w", context.DeadlineExceeded))
				}
				rcpt, crashed, err := w.cutover()
				switch mode {
				case "crash":
					if !crashed || err != nil {
						t.Fatalf("the crash did not happen: crashed=%v err=%v", crashed, err)
					}
				default:
					if crashed || err == nil {
						t.Fatalf("the timeout was not reported: crashed=%v err=%v", crashed, err)
					}
					if rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteTimeout || !slices.Equal(rcpt.Completed, c.completed) {
						t.Fatalf("a timeout between phases must be an explicit incomplete phase: %+v", rcpt)
					}
				}
				// What survives is the durable state: explicitly incomplete, never done.
				st := w.state()
				if st.Phase != CutoverPhaseIncomplete || !slices.Equal(st.Completed, c.completed) {
					t.Fatalf("durable state after the %s: phase %q completed %v, want incomplete after %v", mode, st.Phase, st.Completed, c.completed)
				}
				if es, _ := w.engineState(); es.Phase != c.enginePhase {
					t.Fatalf("engine phase %s, want %s", es.Phase, c.enginePhase)
				}
				if w.legacy.enabled != c.legacyEnabled {
					t.Fatalf("legacy enabled=%v, want %v", w.legacy.enabled, c.legacyEnabled)
				}
				if n := len(w.owners()); n > 1 {
					t.Fatalf("%d owners active at the stop", n)
				}
				if _, route := w.deliveredBy("urgent-gap"); (route == 1) != c.urgentDelivery || route > 1 {
					t.Fatalf("urgent alert delivered %d times by the new owner at the stop (want delivered=%v)", route, c.urgentDelivery)
				}
				// The resume: same plan, same IDs, no second owner, no lost alert.
				rcpt, crashed, err = w.cutover()
				if crashed || err != nil {
					t.Fatalf("resume: crashed=%v err=%v receipt=%+v", crashed, err, rcpt)
				}
				w.assertConverged(rcpt)
				if legacy, route := w.deliveredBy("urgent-gap"); legacy != 0 || route != 1 {
					t.Fatalf("urgent alert delivered legacy=%d new=%d, want exactly once by the new owner", legacy, route)
				}
				if legacy, route := w.deliveredBy("normal-before"); legacy != 1 || route != 0 {
					t.Fatalf("pre-cutover alert delivered legacy=%d new=%d", legacy, route)
				}
				if rcpt.Reconciliation.UrgentDue != 1 || rcpt.Reconciliation.UrgentGaps != 0 {
					t.Fatalf("urgent accounting: %+v", rcpt.Reconciliation)
				}
			})
		}
	}
}

// TestRollbackNeverEnablesBothSenders stops the rollback at every point between
// quiescing the new owner and re-enabling the old one: the new owner is
// quiesced first, the old owner is recorded and only then restored, exactly
// once, and no instant of the run (including a crash and the resume) has both
// senders enabled.
func TestRollbackNeverEnablesBothSenders(t *testing.T) {
	reason := Reason{Code: "operator_requested", Text: "rollback drill: return the normal route to the legacy owner"}
	cases := []struct {
		name, point   string
		completed     []string
		enginePhase   notify.CutoverPhase
		legacyEnabled bool
	}{
		{"new owner quiesced, nothing active", "engine.after.rollback_quiescing", nil, notify.CutoverRollbackQuiescing, false},
		{"old owner recorded, not yet restored", "engine.after.old_active", []string{rollbackStepNewQuiesced}, notify.CutoverOldActive, false},
		{"about to restore the old route", "legacy.before.RestoreNormal", []string{rollbackStepNewQuiesced, rollbackStepOldRecorded}, notify.CutoverOldActive, false},
		{"old route restored, not yet acknowledged", "legacy.after.RestoreNormal", []string{rollbackStepNewQuiesced, rollbackStepOldRecorded}, notify.CutoverOldActive, true},
	}
	for _, mode := range []string{"crash", "timeout"} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				w := newCutoverWorld(t)
				w.emit("normal-before", false)
				done := w.mustCutover()
				w.emit("normal-new", false)
				if mode == "crash" {
					w.crashAt(c.point)
				} else {
					w.failAt(c.point, context.DeadlineExceeded)
				}
				rb, crashed, err := w.rollback(done, reason)
				if mode == "crash" {
					if !crashed || err != nil {
						t.Fatalf("the crash did not happen: crashed=%v err=%v", crashed, err)
					}
				} else {
					if crashed || err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteTimeout || !slices.Equal(rb.Completed, c.completed) {
						t.Fatalf("a timeout must be an explicit incomplete rollback: crashed=%v err=%v %+v", crashed, err, rb)
					}
				}
				if rs := w.state().Rollback; rs == nil || rs.Phase != CutoverPhaseIncomplete {
					t.Fatalf("durable rollback state: %+v", rs)
				}
				if es, _ := w.engineState(); es.Phase != c.enginePhase {
					t.Fatalf("engine phase %s, want %s", es.Phase, c.enginePhase)
				}
				if w.legacy.enabled != c.legacyEnabled {
					t.Fatalf("legacy enabled=%v at the stop, want %v", w.legacy.enabled, c.legacyEnabled)
				}
				if w.newActive() {
					t.Fatal("the new owner is still active after the rollback began")
				}
				// An alert in the gap is not delivered by the quiesced new owner.
				before := len(w.route.delivered)
				w.emit("alert-in-rollback", true)
				if len(w.route.delivered) != before {
					t.Fatal("the quiesced new owner delivered")
				}
				rb, crashed, err = w.rollback(done, reason)
				if crashed || err != nil || rb.Phase != CutoverPhaseDone {
					t.Fatalf("resume: crashed=%v err=%v %+v", crashed, err, rb)
				}
				if !slices.Equal(rb.Completed, []string{rollbackStepNewQuiesced, rollbackStepOldRecorded, rollbackStepOldRestored}) {
					t.Fatalf("completed phases %v", rb.Completed)
				}
				es, _ := w.engineState()
				if es.Phase != notify.CutoverOldActive || !slices.Equal(w.owners(), []model.ID{w.old}) || !slices.Equal(rb.ActiveOwners, []model.ID{w.old}) {
					t.Fatalf("after the rollback: phase %s owners %v", es.Phase, w.owners())
				}
				if !w.legacy.enabled || !rb.OldRouteEnabled {
					t.Fatal("the old normal route is not restored")
				}
				if w.legacy.restoreEffects != 1 {
					t.Fatalf("the old route was re-enabled %d times", w.legacy.restoreEffects)
				}
				ids := map[string]bool{}
				for _, c := range w.legacy.callsNamed("RestoreNormal:") {
					ids[c] = true
				}
				if len(ids) != 1 {
					t.Fatalf("restore commands %v: a resume must repeat the same command ID", ids)
				}
				quiesced, recorded, restored := w.indexOf("engine:rollback_quiescing"), w.indexOf("engine:old_active"), w.indexOf("legacy:restore")
				if !(0 <= quiesced && quiesced < recorded && recorded < restored) {
					t.Fatalf("order must be new owner quiesced, old recorded, old restored: %v", w.events)
				}
				if !rb.DeadmanArmed || !w.deadman.armed {
					t.Fatal("the deadman was disturbed")
				}
			})
		}
	}
}

// TestDeadmanExcludedFromOwnershipBarrier: the independent deadman is an
// observer only. It is never one of the engine's active owners, no cutover or
// rollback operation addresses it, a plan that makes it an owner or puts it in
// the product's failure domain is refused before anything changes, and a
// cutover whose quiescence would disarm it stops before the new owner is active.
func TestDeadmanExcludedFromOwnershipBarrier(t *testing.T) {
	t.Run("never counted, quiesced or switched across cutover and rollback", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		st, _ := w.engineState()
		for _, e := range st.Timeline {
			for _, o := range notify.ActiveOwners(e.To, w.old, w.nw) {
				if o == w.observer {
					t.Fatalf("the deadman is an active owner in %s", e.To)
				}
			}
		}
		rb, crashed, err := w.rollback(done, Reason{Code: "operator_requested", Text: "drill"})
		if crashed || err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("rollback: %v %v %+v", crashed, err, rb)
		}
		for _, c := range w.deadman.calls {
			if c != "Proof" {
				t.Fatalf("the deadman was driven: %v", w.deadman.calls)
			}
		}
		if len(w.deadman.calls) == 0 || !w.deadman.armed || !rb.DeadmanArmed {
			t.Fatalf("the deadman proof was never read, or it was disarmed: %v", w.deadman.calls)
		}
		for _, c := range w.legacy.calls {
			if c != "Observe" && c != "Delivered" && c != "QuiesceNormal:"+cutoverCommandID(w.plan.RunID, cutoverCmdLegacyQ).String() && c != "RestoreNormal:"+cutoverCommandID(w.plan.RunID, cutoverCmdLegacyR).String() {
				t.Fatalf("unexpected legacy call %q", c)
			}
		}
		// The committed barrier evidence names the deadman as the observer, never as an owner.
		rec, found, err := w.store.Cutover(w.ctx, w.scope, w.project)
		if err != nil || !found {
			t.Fatal(err)
		}
		evidence := 0
		for _, s := range rec.Steps {
			if len(s.Payload) == 0 {
				continue
			}
			var ev control.CutoverEvidence
			if err := json.Unmarshal(s.Payload, &ev); err != nil {
				t.Fatal(err)
			}
			evidence++
			if ev.Observer == nil || ev.Observer.Observer != w.observer || ev.Observer.Observer == rec.Old || ev.Observer.Observer == rec.New || ev.Observer.Domain == ev.Observer.ProductDomain {
				t.Fatalf("barrier evidence observer: %+v", ev.Observer)
			}
		}
		if evidence != 3 {
			t.Fatalf("%d evidence-carrying commands, want barrier, activation and old_active", evidence)
		}
	})

	t.Run("a plan that makes the deadman an owner or shares the product domain is refused untouched", func(t *testing.T) {
		for name, mutate := range map[string]func(*cutoverWorld){
			"deadman is the old owner":   func(w *cutoverWorld) { w.plan.Deadman.Observer = w.old },
			"deadman is the new owner":   func(w *cutoverWorld) { w.plan.Deadman.Observer = w.nw },
			"product failure domain":     func(w *cutoverWorld) { w.plan.Deadman.Domain = w.plan.Deadman.ProductDomain },
			"no deadman identity":        func(w *cutoverWorld) { w.plan.Deadman.Observer = model.ID{} },
			"no deadman failure domain":  func(w *cutoverWorld) { w.plan.Deadman.Domain = model.ID{} },
			"no product failure domain":  func(w *cutoverWorld) { w.plan.Deadman.ProductDomain = model.ID{} },
			"old owner is the new owner": func(w *cutoverWorld) { w.plan.NewOwner = w.old },
			"old owner without identity": func(w *cutoverWorld) { w.plan.OldOwner = model.ID{} },
		} {
			t.Run(name, func(t *testing.T) {
				w := newCutoverWorld(t)
				mutate(w)
				w.wantRefusal("invalid ownership plan")
				w.assertUntouched()
			})
		}
	})

	t.Run("an absent, stale or foreign deadman proof refuses before any change", func(t *testing.T) {
		other := model.ID{0x77, 0xd0}
		for name, mutate := range map[string]func(*cutoverWorld){
			"not armed":      func(w *cutoverWorld) { w.deadman.armed = false },
			"stale proof":    func(w *cutoverWorld) { w.deadman.age = 2 * time.Hour },
			"future proof":   func(w *cutoverWorld) { w.deadman.age = -time.Hour },
			"another entity": func(w *cutoverWorld) { w.deadman.observer = &other },
			"another domain": func(w *cutoverWorld) { w.deadman.domain = &other },
			"proof fails":    func(w *cutoverWorld) { w.failAt("deadman.Proof", errors.New("unreachable")) },
		} {
			t.Run(name, func(t *testing.T) {
				w := newCutoverWorld(t)
				mutate(w)
				if rcpt, _, err := w.cutover(); err == nil || rcpt.Phase == CutoverPhaseDone {
					t.Fatalf("a cutover started without an armed independent deadman: %+v", rcpt)
				}
				w.assertUntouched()
			})
		}
	})

	t.Run("a quiescence that disarms the deadman stops before the new owner is active", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.legacy.disarmDeadman = true
		rcpt, crashed, err := w.cutover()
		if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteDeadman {
			t.Fatalf("crashed=%v err=%v %+v", crashed, err, rcpt)
		}
		if w.newActive() || len(w.owners()) > 1 {
			t.Fatalf("owners %v", w.owners())
		}
		if es, _ := w.engineState(); es.Phase == notify.CutoverNewActive || es.Phase == notify.CutoverBarrierVerified {
			t.Fatalf("the cutover went on without the deadman: %s", es.Phase)
		}
	})

	t.Run("the deadman interface cannot change anything", func(t *testing.T) {
		typ := reflect.TypeOf((*CutoverDeadman)(nil)).Elem()
		if typ.NumMethod() != 1 || typ.Method(0).Name != "Proof" {
			t.Fatalf("deadman surface: %d methods", typ.NumMethod())
		}
	})
}

// assertUntouched: a refusal changed nothing anywhere.
func (w *cutoverWorld) assertUntouched() {
	w.t.Helper()
	if _, found := w.engineState(); found {
		w.t.Fatal("the engine has a cutover record")
	}
	if len(w.legacy.callsNamed("QuiesceNormal")) != 0 || len(w.legacy.callsNamed("RestoreNormal")) != 0 || !w.legacy.enabled {
		w.t.Fatalf("the legacy route was touched: %v", w.legacy.calls)
	}
	if len(w.route.calls) != 0 {
		w.t.Fatalf("the new route was used: %v", w.route.calls)
	}
	if st, err := cutoverLoadState(w.plan.StatePath); st != nil || err != nil {
		w.t.Fatalf("a state file was created: %v %v", st, err)
	}
}

// ---------------------------------------------------------------------------
// Boundary tests of the cutover.

type cutoverSnapshot struct {
	commands, legacy, route int
	version                 uint64
}

// snapshot is what a refusal must leave exactly as it was.
func (w *cutoverWorld) snapshot() cutoverSnapshot {
	s := cutoverSnapshot{commands: len(w.committedCommands()), legacy: len(w.legacy.calls), route: len(w.route.calls)}
	if st, err := cutoverLoadState(w.plan.StatePath); err == nil && st != nil {
		s.version = st.Version
	}
	return s
}

func (w *cutoverWorld) writeState(st *cutoverState) {
	w.t.Helper()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		w.t.Fatal(err)
	}
	if err = os.WriteFile(w.plan.StatePath, append(b, '\n'), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func cutoverCloneState(t *testing.T, st *cutoverState) *cutoverState {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var out cutoverState
	if err = json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func (w *cutoverWorld) wantRefusal(substr string) {
	w.t.Helper()
	rcpt, crashed, err := w.cutover()
	if crashed || err == nil || rcpt.Version != 0 || rcpt.Phase == CutoverPhaseDone {
		w.t.Fatalf("not refused: crashed=%v err=%v %+v", crashed, err, rcpt)
	}
	if !strings.Contains(err.Error(), substr) {
		w.t.Fatalf("refusal %q does not name %q", err, substr)
	}
}

func TestCutoverRefusesAGateThatIsStaleTamperedOrForAnotherScope(t *testing.T) {
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*cutoverWorld){
		"expired":                  func(w *cutoverWorld) { w.advance(55 * time.Minute) },
		"expires at this instant":  func(w *cutoverWorld) { w.advance(50 * time.Minute) },
		"unsigned":                 func(w *cutoverWorld) { w.gate.Signature = "" },
		"tampered scope":           func(w *cutoverWorld) { w.gate.Scope = "other-scope" },
		"tampered expiry":          func(w *cutoverWorld) { w.gate.ExpiresAt = w.gate.ExpiresAt.Add(24 * time.Hour) },
		"tampered production flag": func(w *cutoverWorld) { w.gate.ProductionProven = !w.gate.ProductionProven },
		"signed by another key":    func(w *cutoverWorld) { w.pub = other },
		"future dated":             func(w *cutoverWorld) { w.gate = w.makeGate(w.now().Add(time.Hour)) },
		"incomplete criteria":      func(w *cutoverWorld) { w.gate.Criteria = w.gate.Criteria[1:] },
		"valid gate of another scope": func(w *cutoverWorld) {
			w.plan.Scope = "other-scope"
			w.grant.Scopes[0].ID = "other-scope"
		},
		"production plan on a staging-only gate": func(w *cutoverWorld) { w.gate = w.makeStagingGate(w.now()) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newCutoverWorld(t)
			mutate(w)
			w.wantRefusal("cutover refused")
			w.assertUntouched()
		})
	}
	t.Run("a runtime without a gate key refuses", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.pub = nil
		w.wantRefusal("runtime is incomplete")
		w.assertUntouched()
	})
	t.Run("a staging-only gate runs a staging cutover", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.gate = w.makeStagingGate(w.now())
		w.plan.Environment = cutoverEnvStaging
		w.assertConverged(w.mustCutover())
	})
}

func TestCutoverRefusesAuthorizationThatIsNotExplicitCurrentAndForThisPlan(t *testing.T) {
	refused := map[string]func(*Authorization, time.Time){
		"read-only grant": func(a *Authorization, now time.Time) { a.ReadOnly = true },
		"expired":         func(a *Authorization, now time.Time) { a.ExpiresAt = now },
		"not yet valid":   func(a *Authorization, now time.Time) { a.NotBefore = now.Add(time.Second) },
		"no not-before":   func(a *Authorization, now time.Time) { a.NotBefore = time.Time{} },
		"no authority":    func(a *Authorization, now time.Time) { a.Authority = "" },
		"no grant id":     func(a *Authorization, now time.Time) { a.GrantID = "" },
		"another scope":   func(a *Authorization, now time.Time) { a.Scopes[0].ID = "other-scope" },
		"no scope":        func(a *Authorization, now time.Time) { a.Scopes = nil },
		"rollback only":   func(a *Authorization, now time.Time) { a.Scopes[0].Collectors = []string{"rollback"} },
		"intake collectors": func(a *Authorization, now time.Time) {
			a.Scopes[0].Collectors = []string{"git-current-ref", "http-live-evidence"}
		},
		"unknown extra collector": func(a *Authorization, now time.Time) { a.Scopes[0].Collectors = []string{"cutover", "sh -c x"} },
		"duplicate collector":     func(a *Authorization, now time.Time) { a.Scopes[0].Collectors = []string{"cutover", "cutover"} },
		"duplicate scopes":        func(a *Authorization, now time.Time) { a.Scopes = append(a.Scopes, a.Scopes[0]) },
		"no evidence age":         func(a *Authorization, now time.Time) { a.MaxEvidenceAgeSeconds = 0 },
		"evidence age too large":  func(a *Authorization, now time.Time) { a.MaxEvidenceAgeSeconds = 86401 },
		"window over 24 hours":    func(a *Authorization, now time.Time) { a.ExpiresAt = a.NotBefore.Add(24*time.Hour + time.Second) },
	}
	for name, mutate := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			w := newCutoverWorld(t)
			mutate(&w.grant, w.now())
			w.wantRefusal("authorization validation failed")
			w.assertUntouched()
		})
	}
	accepted := map[string]func(*Authorization, time.Time){
		"valid from this instant":         func(a *Authorization, now time.Time) { a.NotBefore = now },
		"a window of exactly 24 hours":    func(a *Authorization, now time.Time) { a.ExpiresAt = a.NotBefore.Add(24 * time.Hour) },
		"evidence age at its upper bound": func(a *Authorization, now time.Time) { a.MaxEvidenceAgeSeconds = 86400 },
		"scopes of other plans are ignored": func(a *Authorization, now time.Time) {
			a.Scopes = append(a.Scopes, TargetScope{ID: "unrelated", Collectors: []string{"anything"}})
		},
		"a grant that also permits rollback only once": func(a *Authorization, now time.Time) { a.Scopes[0].Collectors = []string{"rollback", "cutover"} },
	}
	for name, mutate := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			w := newCutoverWorld(t)
			mutate(&w.grant, w.now())
			w.assertConverged(w.mustCutover())
		})
	}
}

func TestCutoverResumeWithDifferentCommandIDOrPlanIsRefused(t *testing.T) {
	w := newCutoverWorld(t)
	w.crashAt("legacy.after.QuiesceNormal")
	if _, crashed, err := w.cutover(); !crashed || err != nil {
		t.Fatalf("setup: crashed=%v err=%v", crashed, err)
	}
	good := w.plan
	before := w.snapshot()
	moved := model.ID{0x09, 0xd0}
	for name, mutate := range map[string]func(*OwnershipPlan){
		"another run id, so other command IDs": func(p *OwnershipPlan) { p.RunID = "run-2" },
		"another policy generation":            func(p *OwnershipPlan) { p.PolicyGeneration = 2 },
		"raised declared uncertainty":          func(p *OwnershipPlan) { p.ProviderUncertainty = 5 },
		"another reviewed attestation":         func(p *OwnershipPlan) { p.UnknownReviewed = true },
		"another new owner":                    func(p *OwnershipPlan) { p.NewOwner = moved },
		"another destination probe":            func(p *OwnershipPlan) { p.Destination.ProbeID = "probe-2" },
		"another frontier": func(p *OwnershipPlan) {
			p.Frontier = []notify.FrontierEntry{{Source: w.source, Version: 3, Cursor: model.Cursor{Group: w.group, Index: 99}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			w.plan = good
			mutate(&w.plan)
			w.wantRefusal("resume refused")
			if got := w.snapshot(); got != before {
				t.Fatalf("a refused resume changed the world: %+v -> %+v", before, got)
			}
		})
	}
	w.plan = good
	orig := cutoverCloneState(t, w.state())
	tamper := func(name, want string, change func(*cutoverState), resign bool) {
		t.Run("state file: "+name, func(t *testing.T) {
			st := cutoverCloneState(t, orig)
			change(st)
			if resign {
				st.Checksum = cutoverStateChecksum(*st)
			}
			w.writeState(st)
			w.wantRefusal(want)
			if got := w.snapshot(); got.commands != before.commands || got.legacy != before.legacy {
				t.Fatalf("a refused resume changed the world: %+v -> %+v", before, got)
			}
		})
	}
	tamper("recorded command IDs differ from the run's", "resume refused", func(st *cutoverState) {
		st.Commands[cutoverCmdActivate] = cutoverCommandID("run-2", cutoverCmdActivate).String()
	}, true)
	tamper("a command ID is missing", "resume refused", func(st *cutoverState) { delete(st.Commands, cutoverCmdHandover) }, true)
	tamper("an extra command ID", "resume refused", func(st *cutoverState) { st.Commands["extra"] = cutoverCommandID("run-1", "extra").String() }, true)
	tamper("recorded plan differs from its digest", "resume refused", func(st *cutoverState) { st.Plan.ProviderUncertainty = 9 }, true)
	tamper("phase edited without the checksum", "state corrupt", func(st *cutoverState) { st.Phase = CutoverPhaseDone }, false)
	tamper("unknown schema", "state corrupt", func(st *cutoverState) { st.Schema = 2 }, true)
	t.Run("state file: not JSON", func(t *testing.T) {
		if err := os.WriteFile(w.plan.StatePath, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.wantRefusal("state corrupt")
	})
	// The genuine state resumes and finishes: every refusal above was harmless.
	w.writeState(orig)
	rcpt, crashed, err := w.cutover()
	if crashed || err != nil {
		t.Fatalf("resume of the genuine state: %v %v", crashed, err)
	}
	w.assertConverged(rcpt)
}

func TestCutoverDoubleActivationIsRefused(t *testing.T) {
	t.Run("the same plan again", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		before := w.snapshot()
		rcpt, crashed, err := w.cutover()
		if crashed || !errors.Is(err, errCutoverAlreadyDone) || rcpt.Phase != CutoverPhaseDone || rcpt.StateVersion != done.StateVersion {
			t.Fatalf("crashed=%v err=%v %+v", crashed, err, rcpt)
		}
		if got := w.snapshot(); got != before {
			t.Fatalf("a second run changed the world: %+v -> %+v", before, got)
		}
	})
	t.Run("another run on an engine that already has the new owner", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.mustCutover()
		before := w.snapshot()
		w.plan.RunID = "run-2"
		w.plan.StatePath = filepath.Join(t.TempDir(), "second.json")
		w.wantRefusal("new_active")
		if got := w.snapshot(); got.commands != before.commands || got.legacy != before.legacy {
			t.Fatalf("a refused second run changed the world: %+v -> %+v", before, got)
		}
		if st, err := cutoverLoadState(w.plan.StatePath); st != nil || err != nil {
			t.Fatalf("a state file was created: %v %v", st, err)
		}
	})
	t.Run("a stale copy of the state file cannot activate twice", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.crashAt("legacy.after.QuiesceNormal")
		if _, crashed, _ := w.cutover(); !crashed {
			t.Fatal("setup crash")
		}
		stale, err := os.ReadFile(w.plan.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		w.assertConverged(w.mustCutover())
		before := w.snapshot()
		if err = os.WriteFile(w.plan.StatePath, stale, 0o600); err != nil {
			t.Fatal(err)
		}
		rcpt, crashed, err := w.cutover()
		if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteEngine {
			t.Fatalf("the stale state was accepted: crashed=%v err=%v %+v", crashed, err, rcpt)
		}
		if got := w.snapshot(); got.commands != before.commands || got.legacy != before.legacy {
			t.Fatalf("the stale state moved the world: %+v -> %+v", before, got)
		}
		if !slices.Equal(w.owners(), []model.ID{w.nw}) {
			t.Fatalf("owners %v", w.owners())
		}
	})
	t.Run("a plan for the first generation after a rollback", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		if rb, crashed, err := w.rollback(done, Reason{Code: RollbackReasonOperator, Text: "drill"}); crashed || err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("rollback: %v %v %+v", crashed, err, rb)
		}
		// The run that was rolled back is finished for good.
		w.wantRefusal("rollback was started")
		first := w.plan
		w.plan.RunID = "run-2"
		w.plan.StatePath = filepath.Join(t.TempDir(), "second.json")
		w.wantRefusal("policy generation")
		w.plan.PolicyGeneration = 2
		rcpt, crashed, err := w.cutover()
		if crashed || err != nil || rcpt.Phase != CutoverPhaseDone || rcpt.Epoch != 2 || !slices.Equal(rcpt.ActiveOwners, []model.ID{w.nw}) {
			t.Fatalf("the next generation: crashed=%v err=%v %+v", crashed, err, rcpt)
		}
		if w.legacy.enabled || !w.newActive() || len(w.owners()) != 1 {
			t.Fatalf("after the second cutover: legacy=%v owners=%v", w.legacy.enabled, w.owners())
		}
		if first.RunID == w.plan.RunID {
			t.Fatal("test bug")
		}
	})
}

func TestCutoverPreflightRefusalsChangeNothingOnTheOldRoute(t *testing.T) {
	cases := []struct {
		name, want string
		setup      func(*cutoverWorld)
	}{
		{"old normal route not enabled", CutoverIncompleteLegacyUnexpected, func(w *cutoverWorld) { w.legacy.enabled = false }},
		{"old route observation stale", CutoverIncompleteQuiescence, func(w *cutoverWorld) { w.legacy.age = 2 * time.Hour }},
		{"old route observation from the future", CutoverIncompleteQuiescence, func(w *cutoverWorld) { w.legacy.age = -time.Hour }},
		{"destination rejects the test delivery", CutoverIncompleteDestination, func(w *cutoverWorld) { w.route.probeFails = true }},
		{"destination test not confirmed", CutoverIncompleteDestination, func(w *cutoverWorld) { w.route.probeOutcome = CutoverOutcomeUnknown }},
		{"destination test answers another probe", CutoverIncompleteDestination, func(w *cutoverWorld) { w.route.probeID = "another-probe" }},
		{"destination test times out", CutoverIncompleteTimeout, func(w *cutoverWorld) { w.failAt("route.TestDelivery", context.DeadlineExceeded) }},
		{"source checkpoint behind the frontier", "checkpoint", func(w *cutoverWorld) { w.plan.Frontier[0].Cursor.Index = 101 }},
		{"source checkpoint of another journal group", "checkpoint", func(w *cutoverWorld) { w.plan.Frontier[0].Cursor.Group = model.ID{0x31, 0xd0} }},
		{"engine new owner differs from the plan", "owners differ", func(w *cutoverWorld) {
			cmd := notify.CutoverCommand{ID: model.ID{0x0d, 0xd0}, Frontier: w.plan.Frontier, OldOwner: w.old, NewOwner: model.ID{0x0e, 0xd0}, Phase: notify.CutoverShadow, Reason: "someone else's cutover"}
			if _, err := w.real.AdvanceCutover(w.ctx, w.scope, cmd); err != nil {
				w.t.Fatal(err)
			}
		}},
		{"policy generation does not follow the epoch", "policy generation", func(w *cutoverWorld) { w.plan.PolicyGeneration = 2 }},
		{"the old route reports another method", CutoverIncompleteLegacyUnexpected, func(w *cutoverWorld) { w.legacy.method = "something_else" }},
		{"engine owners differ from the plan", "owners differ", func(w *cutoverWorld) {
			cmd := notify.CutoverCommand{ID: model.ID{0x0a, 0xd0}, Frontier: w.plan.Frontier, OldOwner: model.ID{0x0b, 0xd0}, NewOwner: w.nw, Phase: notify.CutoverShadow, Reason: "someone else's cutover"}
			if _, err := w.real.AdvanceCutover(w.ctx, w.scope, cmd); err != nil {
				w.t.Fatal(err)
			}
		}},
		{"a disaster restore awaits acknowledgement", "disaster restore", func(w *cutoverWorld) {
			if err := w.store.Update(w.ctx, func(st *control.State) error {
				if st.OIDC == nil {
					st.OIDC = map[string]json.RawMessage{}
				}
				st.OIDC["restore:quarantine"] = json.RawMessage(`{"generation":"` + model.ID{0x0c, 0xd0}.String() + `","at":1}`)
				return nil
			}); err != nil {
				w.t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newCutoverWorld(t)
			// the plan owns its frontier slice
			w.plan.Frontier = slices.Clone(w.plan.Frontier)
			c.setup(w)
			enabledBefore := w.legacy.enabled
			commandsBefore := len(w.committedCommands())
			w.wantRefusal(c.want)
			if len(w.committedCommands()) != commandsBefore {
				t.Fatal("the engine moved")
			}
			if len(w.legacy.callsNamed("QuiesceNormal")) != 0 || len(w.legacy.callsNamed("RestoreNormal")) != 0 || w.legacy.enabled != enabledBefore {
				t.Fatalf("the legacy route was touched: %v", w.legacy.calls)
			}
			if st, err := cutoverLoadState(w.plan.StatePath); st != nil || err != nil {
				t.Fatalf("a state file was created: %v %v", st, err)
			}
		})
	}
	t.Run("a state directory that does not exist refuses before any change", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.plan.StatePath = filepath.Join(t.TempDir(), "missing", "state.json")
		w.wantRefusal("cutover refused")
		if _, found := w.engineState(); found || len(w.legacy.callsNamed("QuiesceNormal")) != 0 || !w.legacy.enabled {
			t.Fatal("the cutover changed something although its state could not be kept")
		}
	})
}

// TestCutoverObservationFreshnessIsBoundedByTheGrantAndTheEngine: an operator's
// observation may be as old as the authorization says, but never older than the
// engine itself accepts as barrier evidence (an hour for the old owner, a
// quarter hour for the deadman), so a lax grant cannot defer the refusal to the
// barrier, after the old route is quiesced.
func TestCutoverObservationFreshnessIsBoundedByTheGrantAndTheEngine(t *testing.T) {
	cases := []struct {
		name                  string
		grantAge              int64
		legacyAge, deadmanAge time.Duration
		accept                bool
	}{
		{"old route exactly at the grant's bound", 900, 900 * time.Second, 0, true},
		{"old route one second beyond the grant's bound", 900, 901 * time.Second, 0, false},
		{"old route: the engine's hour caps a larger grant", 86400, 61 * time.Minute, 0, false},
		{"old route exactly at the engine's hour", 86400, time.Hour, 0, true},
		{"old route under a small grant", 60, 61 * time.Second, 0, false},
		{"deadman exactly at the grant's bound", 900, 0, 900 * time.Second, true},
		{"deadman one second beyond the grant's bound", 900, 0, 901 * time.Second, false},
		{"deadman: the engine's quarter hour caps a larger grant", 86400, 0, 15*time.Minute + time.Second, false},
		{"deadman exactly at the engine's quarter hour", 86400, 0, 15 * time.Minute, true},
		{"deadman under a small grant", 60, 0, 61 * time.Second, false},
		{"observations from the future", 900, -time.Nanosecond, 0, false},
		{"a deadman proof from the future", 900, 0, -time.Nanosecond, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newCutoverWorld(t)
			w.grant.MaxEvidenceAgeSeconds = c.grantAge
			w.legacy.age, w.deadman.age = c.legacyAge, c.deadmanAge
			if c.accept {
				w.assertConverged(w.mustCutover())
				return
			}
			w.wantRefusal("cutover refused")
			w.assertUntouched()
		})
	}
}

// TestCutoverStopsWhenTheGateLapsesBetweenPhases: the gate that authorised the
// start does not authorise a phase after it expired. The run is explicitly
// incomplete with the old route disabled and only one (the old) owner; a fresh
// gate resumes it.
func TestCutoverStopsWhenTheGateLapsesBetweenPhases(t *testing.T) {
	w := newCutoverWorld(t)
	calls := 0
	// the deadman proof is read once at the end of each phase that checks it;
	// the second read closes the quiescence phase
	w.observe("deadman.Proof", func() {
		if calls++; calls == 2 {
			w.advance(55 * time.Minute)
		}
	})
	rcpt, crashed, err := w.cutover()
	if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteGuard {
		t.Fatalf("crashed=%v err=%v %+v", crashed, err, rcpt)
	}
	if es, _ := w.engineState(); es.Phase != notify.CutoverQuiescingOld || w.newActive() || !slices.Equal(rcpt.Completed, []string{cutoverStepPreflight, cutoverStepQuiesce}) {
		t.Fatalf("engine %s completed %v", es.Phase, rcpt.Completed)
	}
	// An expired gate cannot resume it either.
	if rcpt, _, err = w.cutover(); err == nil || rcpt.Version != 0 {
		t.Fatalf("an expired gate resumed the run: %v %+v", err, rcpt)
	}
	w.gate = w.makeGate(w.now())
	w.assertConverged(w.mustCutover())
}

// TestCutoverBarrierRefusalLeavesAnIncompleteRunThatRollbackAborts: a barrier the
// engine refuses (here a frontier at a source version the engine does not hold)
// is an explicit incomplete phase naming the failed checks; the old route is
// restored by a rollback, which aborts the engine to shadow.
func TestCutoverBarrierRefusalLeavesAnIncompleteRunThatRollbackAborts(t *testing.T) {
	w := newCutoverWorld(t)
	w.plan.Frontier = []notify.FrontierEntry{{Source: w.source, Version: 4, Cursor: model.Cursor{Group: w.group, Index: 100}}}
	rcpt, crashed, err := w.cutover()
	if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteBarrier {
		t.Fatalf("crashed=%v err=%v %+v", crashed, err, rcpt)
	}
	if !strings.Contains(err.Error(), "source_version") {
		t.Fatalf("the failed check is not named: %v", err)
	}
	if !slices.Equal(rcpt.Completed, []string{cutoverStepPreflight, cutoverStepQuiesce}) || rcpt.EnginePhase != string(notify.CutoverQuiescingOld) || w.legacy.enabled {
		t.Fatalf("the stop point: %+v legacy=%v", rcpt, w.legacy.enabled)
	}
	if !slices.Equal(rcpt.ActiveOwners, []model.ID{w.old}) || w.newActive() {
		t.Fatalf("owners %v", rcpt.ActiveOwners)
	}
	rb, crashed, err := w.rollback(rcpt, Reason{Code: RollbackReasonIncomplete, Text: "barrier refused; restoring the old route"})
	if crashed || err != nil || rb.Phase != CutoverPhaseDone || !slices.Equal(rb.Completed, rollbackSteps) {
		t.Fatalf("rollback: crashed=%v err=%v %+v", crashed, err, rb)
	}
	es, _ := w.engineState()
	if es.Phase != notify.CutoverShadow || !slices.Equal(w.owners(), []model.ID{w.old}) || !w.legacy.enabled || w.legacy.restoreEffects != 1 {
		t.Fatalf("after the abort: engine %s owners %v legacy=%v restores=%d", es.Phase, w.owners(), w.legacy.enabled, w.legacy.restoreEffects)
	}
	if last := slices.Index(w.events, "legacy:restore"); last < 0 || slices.Index(w.events[last:], "engine:shadow") >= 0 {
		t.Fatalf("the engine abort must come before the restore: %v", w.events)
	}
}

func TestCutoverNeverActivatesNextToAnEnabledOldRoute(t *testing.T) {
	t.Run("the legacy operator does not actually disable the route", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.legacy.reenableOnQuiet = true
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteQuiescence || w.newActive() {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
		if es, _ := w.engineState(); es.Phase != notify.CutoverQuiescingOld || !slices.Equal(rcpt.Completed, []string{cutoverStepPreflight}) {
			t.Fatalf("engine %s completed %v", es.Phase, rcpt.Completed)
		}
	})
	t.Run("the old route is re-enabled between the barrier and the activation", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.observe("engine.after.barrier_verified", func() { w.legacy.enabled = true })
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteBothSenders || w.newActive() {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
		if es, _ := w.engineState(); es.Phase != notify.CutoverBarrierVerified || len(w.owners()) != 0 {
			t.Fatalf("engine %s owners %v", es.Phase, w.owners())
		}
		w.legacy.enabled = false // the operator disables it again
		w.assertConverged(w.mustCutover())
	})
	t.Run("the old route comes back after the activation and rollback resolves it", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.observe("engine.after.new_active", func() { w.legacy.enabled = true })
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteBothSenders {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
		rb, crashed, err := w.rollback(rcpt, Reason{Code: RollbackReasonDuplicate, Text: "two senders observed"})
		if crashed || err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("rollback: %v %v %+v", crashed, err, rb)
		}
		if w.legacy.restoreEffects != 0 || !w.legacy.enabled || !slices.Equal(w.owners(), []model.ID{w.old}) {
			t.Fatalf("restores=%d enabled=%v owners=%v", w.legacy.restoreEffects, w.legacy.enabled, w.owners())
		}
	})
	t.Run("the invariant itself", func(t *testing.T) {
		old, nw := model.ID{1}, model.ID{2}
		for _, c := range []struct {
			phase   notify.CutoverPhase
			enabled bool
			wantErr bool
		}{
			{notify.CutoverNewActive, true, true},
			{notify.CutoverNewActive, false, false},
			{notify.CutoverShadow, true, false},
			{notify.CutoverQuiescingOld, true, false},
			{notify.CutoverBarrierVerified, true, false},
			{notify.CutoverBarrierVerified, false, false},
			{notify.CutoverRollbackQuiescing, false, false},
			{notify.CutoverOldActive, true, false},
			{notify.CutoverOldActive, false, false},
		} {
			err := cutoverSenderViolation(c.phase, old, nw, c.enabled)
			if (err != nil) != c.wantErr || err != nil && cutoverStopCode(err) != CutoverIncompleteBothSenders {
				t.Errorf("%s enabled=%v: %v", c.phase, c.enabled, err)
			}
		}
	})
}

func TestCutoverOldRouteUnknownOutcomesNeedReview(t *testing.T) {
	for name, c := range map[string]struct {
		reviewed bool
		pending  int
		unknown  int
		wantErr  bool
	}{
		"unreviewed unknown deliveries":   {false, 0, 1, true},
		"reviewed unknown deliveries":     {true, 0, 1, false},
		"deliveries still pending":        {true, 1, 0, true},
		"reviewed with nothing unknown":   {true, 0, 0, false},
		"unreviewed with nothing unknown": {false, 0, 0, false},
		"pending even when reviewed":      {true, 2, 3, true},
		"unreviewed pending and unknown":  {false, 1, 1, true},
	} {
		t.Run(name, func(t *testing.T) {
			w := newCutoverWorld(t)
			w.plan.UnknownReviewed = c.reviewed
			w.plan.ProviderUncertainty = 0
			w.legacy.pending, w.legacy.unknown = c.pending, c.unknown
			// the route's pending/unknown state only applies once it is quiesced
			rcpt, _, err := w.cutover()
			if c.wantErr {
				if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteQuiescence || !slices.Equal(rcpt.Completed, cutoverSteps[:1]) {
					t.Fatalf("the quiescence must be refused at its own phase, not at the barrier: %v %+v", err, rcpt)
				}
				if w.newActive() || len(w.owners()) > 1 {
					t.Fatalf("owners %v", w.owners())
				}
				return
			}
			if err != nil || rcpt.Phase != CutoverPhaseDone {
				t.Fatalf("refused: %v %+v", err, rcpt)
			}
		})
	}
}

func TestCutoverReconciliationClassifiesGapsDuplicatesAndUncertainty(t *testing.T) {
	t0 := time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC)
	d := func(id string) CutoverDelivery {
		return CutoverDelivery{ID: id, Outcome: CutoverOutcomeDelivered, At: t0}
	}
	u := func(id string) CutoverDelivery {
		return CutoverDelivery{ID: id, Outcome: CutoverOutcomeUnknown, At: t0}
	}
	due := func(ids ...string) []CutoverDue {
		out := make([]CutoverDue, len(ids))
		for i, id := range ids {
			out[i] = CutoverDue{ID: id}
		}
		return out
	}
	long := strings.Repeat("x", 256)
	cases := []struct {
		name     string
		due      []CutoverDue
		old, nw  []CutoverDelivery
		declared int
		quiesced time.Time
		want     CutoverReconciliation
		blockers []CutoverBlocker
	}{
		{name: "everything delivered once", due: due("a", "b"), old: []CutoverDelivery{d("a")}, nw: []CutoverDelivery{d("b")}, want: CutoverReconciliation{Due: 2, Delivered: 2}},
		{name: "nothing due, nothing delivered"},
		{name: "a gap", due: due("a", "b"), nw: []CutoverDelivery{d("a")},
			want: CutoverReconciliation{Due: 2, Delivered: 1, Gaps: 1, GapIDs: []string{"b"}}, blockers: []CutoverBlocker{{CutoverBlockGap, 1}}},
		{name: "an urgent gap", due: []CutoverDue{{ID: "a", Urgent: true}, {ID: "b"}}, nw: []CutoverDelivery{d("b")},
			want:     CutoverReconciliation{Due: 2, Delivered: 1, UrgentDue: 1, Gaps: 1, UrgentGaps: 1, GapIDs: []string{"a"}},
			blockers: []CutoverBlocker{{CutoverBlockGap, 1}, {CutoverBlockUrgentGap, 1}}},
		{name: "an urgent notification that was delivered", due: []CutoverDue{{ID: "a", Urgent: true}}, nw: []CutoverDelivery{d("a")}, want: CutoverReconciliation{Due: 1, Delivered: 1, UrgentDue: 1}},
		{name: "duplicate across both sides", due: due("a"), old: []CutoverDelivery{d("a")}, nw: []CutoverDelivery{d("a")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Duplicates: 1}, blockers: []CutoverBlocker{{CutoverBlockDuplicate, 1}}},
		{name: "duplicate on one side", due: due("a"), nw: []CutoverDelivery{d("a"), d("a")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Duplicates: 1}, blockers: []CutoverBlocker{{CutoverBlockDuplicate, 1}}},
		{name: "three deliveries are one duplicated notification", due: due("a"), nw: []CutoverDelivery{d("a"), d("a"), d("a")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Duplicates: 1}, blockers: []CutoverBlocker{{CutoverBlockDuplicate, 1}}},
		{name: "duplicates win over an unknown outcome", due: due("a"), declared: 5, nw: []CutoverDelivery{d("a"), d("a"), u("a")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Duplicates: 1}, blockers: []CutoverBlocker{{CutoverBlockDuplicate, 1}}},
		{name: "unknown outcome within the declared uncertainty", due: due("a"), declared: 1, nw: []CutoverDelivery{u("a")}, want: CutoverReconciliation{Due: 1, Uncertain: 1}},
		{name: "unknown outcome beyond the declared uncertainty", due: due("a"), nw: []CutoverDelivery{u("a")},
			want: CutoverReconciliation{Due: 1, Uncertain: 1}, blockers: []CutoverBlocker{{CutoverBlockUncertainty, 1}}},
		{name: "uncertain exactly at the declared count", due: due("a", "b"), declared: 2, nw: []CutoverDelivery{u("a"), u("b")}, want: CutoverReconciliation{Due: 2, Uncertain: 2}},
		{name: "uncertain one above the declared count", due: due("a", "b"), declared: 1, nw: []CutoverDelivery{u("a"), u("b")},
			want: CutoverReconciliation{Due: 2, Uncertain: 2}, blockers: []CutoverBlocker{{CutoverBlockUncertainty, 2}}},
		{name: "confirmed on one side and unknown on the other", due: due("a"), declared: 1, old: []CutoverDelivery{d("a")}, nw: []CutoverDelivery{u("a")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Uncertain: 1}},
		{name: "an unexpected delivery", due: due("a"), nw: []CutoverDelivery{d("a"), d("x")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Unexpected: 1}, blockers: []CutoverBlocker{{CutoverBlockUnexpected, 1}}},
		{name: "an unexpected unknown outcome", due: due("a"), nw: []CutoverDelivery{d("a"), u("x")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Unexpected: 1}, blockers: []CutoverBlocker{{CutoverBlockUnexpected, 1}}},
		{name: "an unexpected id is counted once", due: due("a"), nw: []CutoverDelivery{d("a"), d("x"), u("x")},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Unexpected: 1}, blockers: []CutoverBlocker{{CutoverBlockUnexpected, 1}}},
		{name: "an old delivery after the old route was quiesced", due: due("a"), quiesced: t0, old: []CutoverDelivery{{ID: "a", Outcome: CutoverOutcomeDelivered, At: t0.Add(time.Nanosecond)}},
			want: CutoverReconciliation{Due: 1, Delivered: 1, OldLate: 1}, blockers: []CutoverBlocker{{CutoverBlockOldLate, 1}}},
		{name: "an old delivery at the quiescence instant", due: due("a"), quiesced: t0, old: []CutoverDelivery{d("a")}, want: CutoverReconciliation{Due: 1, Delivered: 1}},
		{name: "no quiescence instant, no late old delivery", due: due("a"), old: []CutoverDelivery{{ID: "a", Outcome: CutoverOutcomeDelivered, At: t0.Add(time.Hour)}}, want: CutoverReconciliation{Due: 1, Delivered: 1}},
		{name: "malformed observations", due: []CutoverDue{{ID: ""}, {ID: "a"}, {ID: "a"}}, old: []CutoverDelivery{{ID: "", Outcome: CutoverOutcomeDelivered}},
			nw:   []CutoverDelivery{{ID: "a", Outcome: "weird"}},
			want: CutoverReconciliation{Due: 1, Gaps: 1, GapIDs: []string{"a"}, Malformed: 4}, blockers: []CutoverBlocker{{CutoverBlockGap, 1}, {CutoverBlockMalformed, 4}}},
		{name: "identifiers with spaces or beyond the bound are malformed", due: due("has space", long+"y", long), nw: []CutoverDelivery{d(long)},
			want: CutoverReconciliation{Due: 1, Delivered: 1, Malformed: 2}, blockers: []CutoverBlocker{{CutoverBlockMalformed, 2}}},
		{name: "blockers come in the closed order", quiesced: t0, due: []CutoverDue{{ID: "a"}, {ID: "b", Urgent: true}},
			old: []CutoverDelivery{{ID: "a", Outcome: CutoverOutcomeDelivered, At: t0.Add(time.Second)}}, nw: []CutoverDelivery{d("x"), d("a"), d("a")},
			want:     CutoverReconciliation{Due: 2, Delivered: 1, UrgentDue: 1, Gaps: 1, UrgentGaps: 1, Duplicates: 1, Unexpected: 1, OldLate: 1, GapIDs: []string{"b"}},
			blockers: []CutoverBlocker{{CutoverBlockGap, 1}, {CutoverBlockUrgentGap, 1}, {CutoverBlockDuplicate, 1}, {CutoverBlockUnexpected, 1}, {CutoverBlockOldLate, 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, blockers := cutoverReconcile(c.due, c.old, c.nw, c.declared, c.quiesced)
			if !reflect.DeepEqual(rec, c.want) {
				t.Errorf("reconciliation\n got %+v\nwant %+v", rec, c.want)
			}
			if blockers == nil || !slices.Equal(blockers, c.blockers) {
				t.Errorf("blockers %+v (nil=%v), want %+v", blockers, blockers == nil, c.blockers)
			}
		})
	}
}

// TestCutoverBlockedReconciliationDiscardsNothingAndResumesToDone: an urgent
// notification the new route lost is a blocker, not a done cutover; nothing is
// rolled back or deleted automatically; once the delivery exists, the same
// run resumes the reconciliation alone and finishes.
func TestCutoverBlockedReconciliationDiscardsNothingAndResumesToDone(t *testing.T) {
	w := newCutoverWorld(t)
	w.route.drop["urgent-gap-7731"] = true
	w.observe("legacy.after.QuiesceNormal", func() { w.emit("urgent-gap-7731", true) })
	rcpt, crashed, err := w.cutover()
	if crashed || err == nil || rcpt.Phase != CutoverPhaseBlocked || rcpt.IncompleteCode != "" {
		t.Fatalf("crashed=%v err=%v %+v", crashed, err, rcpt)
	}
	wantBlockers := []CutoverBlocker{{CutoverBlockGap, 1}, {CutoverBlockUrgentGap, 1}}
	if !slices.Equal(rcpt.Blockers, wantBlockers) || !slices.Equal(rcpt.Reconciliation.GapIDs, []string{"urgent-gap-7731"}) || rcpt.Reconciliation.UrgentGaps != 1 {
		t.Fatalf("blockers %+v reconciliation %+v", rcpt.Blockers, rcpt.Reconciliation)
	}
	if !slices.Equal(rcpt.Completed, cutoverSteps[:4]) || !slices.Equal(rcpt.ActiveOwners, []model.ID{w.nw}) {
		t.Fatalf("completed %v owners %v", rcpt.Completed, rcpt.ActiveOwners)
	}
	if st := w.state(); st.Phase != CutoverPhaseBlocked || !slices.Equal(st.Blockers, wantBlockers) {
		t.Fatalf("durable state %+v", st)
	}
	if !w.newActive() || w.legacy.enabled || w.legacy.restoreEffects != 0 {
		t.Fatal("a blocked reconciliation must not roll anything back on its own")
	}
	// Still blocked while nothing changed; the run is not completed by asking again.
	if again, _, err := w.cutover(); err == nil || again.Phase != CutoverPhaseBlocked {
		t.Fatalf("a second look at the same gap: %v %+v", err, again)
	}
	commands, quiesces := len(w.committedCommands()), len(w.legacy.callsNamed("QuiesceNormal"))
	// The operator recovers the delivery; the reconciliation alone is repeated.
	delete(w.route.drop, "urgent-gap-7731")
	w.route.deliver("urgent-gap-7731")
	rcpt, crashed, err = w.cutover()
	if crashed || err != nil || rcpt.Phase != CutoverPhaseDone || !slices.Equal(rcpt.Completed, cutoverSteps) || len(rcpt.Blockers) != 0 {
		t.Fatalf("resume: crashed=%v err=%v %+v", crashed, err, rcpt)
	}
	if len(w.committedCommands()) != commands || len(w.legacy.callsNamed("QuiesceNormal")) != quiesces {
		t.Fatal("the resumed reconciliation issued commands")
	}
}

func TestCutoverPublicProjectionsAreClosed(t *testing.T) {
	cutoverKeys := []string{"schema_version", "phase", "phases_required", "phases_completed", "incomplete_code", "active_owners", "old_route_quiesced", "new_route_active",
		"due", "delivered", "gaps", "urgent_due", "urgent_gaps", "duplicates", "uncertain", "unexpected", "blocker_counts", "customer_acceptance"}
	rollbackKeys := []string{"schema_version", "phase", "phases_required", "phases_completed", "incomplete_code", "reason_code", "active_owners", "new_owner_quiesced",
		"old_route_restored", "unknown_outcomes", "unknown_reviewed", "deadman_armed", "blocker_counts", "customer_acceptance"}
	hex32 := regexp.MustCompile(`[0-9a-f]{32}`)
	codes := map[string]bool{}
	for _, c := range cutoverBlockCodes {
		codes[c] = true
	}
	codes[CutoverIncompleteUnknown] = true
	incompleteCodes := map[string]bool{"": true, CutoverIncompleteTimeout: true, CutoverIncompleteUnknown: true, CutoverIncompleteBarrier: true}
	check := func(t *testing.T, label string, summary any, keys []string, secrets []string) map[string]any {
		t.Helper()
		raw, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(fields))
		for k := range fields {
			got = append(got, k)
		}
		if !slices.Equal(sortedStrings(got), sortedStrings(keys)) {
			t.Fatalf("%s: public keys %v, want exactly %v", label, sortedStrings(got), sortedStrings(keys))
		}
		if fields["customer_acceptance"] != false {
			t.Fatalf("%s: customer_acceptance must be false", label)
		}
		if hex32.Match(raw) {
			t.Fatalf("%s: an identifier leaked: %s", label, raw)
		}
		for _, s := range secrets {
			if strings.Contains(string(raw), s) {
				t.Fatalf("%s: %q leaked into the public projection", label, s)
			}
		}
		if code, _ := fields["incomplete_code"].(string); !incompleteCodes[code] {
			t.Fatalf("%s: incomplete_code %q outside the exercised enum", label, code)
		}
		for _, b := range fields["blocker_counts"].([]any) {
			if !codes[b.(map[string]any)["code"].(string)] {
				t.Fatalf("%s: blocker code outside the closed set: %v", label, b)
			}
		}
		return fields
	}
	w := newCutoverWorld(t)
	secrets := []string{w.plan.RunID, w.plan.Scope, w.plan.StatePath, "urgent-gap-7731", "unknown-id-4417", "rollback drill text", w.plan.Destination.ProbeID}
	w.route.drop["urgent-gap-7731"] = true
	w.observe("legacy.after.QuiesceNormal", func() { w.emit("urgent-gap-7731", true) })
	blocked, _, _ := w.cutover()
	f := check(t, "blocked cutover", CutoverPublicSummary(blocked), cutoverKeys, secrets)
	doneBase := map[string]any{"schema_version": 1.0, "phase": CutoverPhaseDone, "phases_required": 5.0, "phases_completed": 5.0, "incomplete_code": "", "active_owners": 1.0,
		"old_route_quiesced": true, "new_route_active": true, "due": 0.0, "delivered": 0.0, "gaps": 0.0, "urgent_due": 0.0, "urgent_gaps": 0.0, "duplicates": 0.0, "uncertain": 0.0,
		"unexpected": 0.0, "blocker_counts": []any{}, "customer_acceptance": false}
	with := func(base map[string]any, over map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range over {
			out[k] = v
		}
		return out
	}
	count := func(code string, n float64) map[string]any { return map[string]any{"code": code, "count": n} }
	wantExactly := func(label string, got, want map[string]any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s projection\n got %v\nwant %v", label, got, want)
		}
	}
	wantExactly("blocked cutover", f, with(doneBase, map[string]any{"phase": CutoverPhaseBlocked, "phases_completed": 4.0, "due": 1.0, "gaps": 1.0, "urgent_due": 1.0, "urgent_gaps": 1.0,
		"blocker_counts": []any{count(CutoverBlockGap, 1), count(CutoverBlockUrgentGap, 1)}}))
	delete(w.route.drop, "urgent-gap-7731")
	w.route.deliver("urgent-gap-7731")
	done := w.mustCutover()
	f = check(t, "done cutover", CutoverPublicSummary(done), cutoverKeys, secrets)
	wantExactly("done cutover", f, with(doneBase, map[string]any{"due": 1.0, "delivered": 1.0, "urgent_due": 1.0}))
	w2 := newCutoverWorld(t)
	w2.failAt("legacy.before.QuiesceNormal", context.DeadlineExceeded)
	incomplete, _, _ := w2.cutover()
	f = check(t, "incomplete cutover", CutoverPublicSummary(incomplete), cutoverKeys, secrets)
	wantExactly("incomplete cutover", f, with(doneBase, map[string]any{"phase": CutoverPhaseIncomplete, "phases_completed": 1.0, "incomplete_code": CutoverIncompleteTimeout,
		"old_route_quiesced": false, "new_route_active": false}))
	w3 := newCutoverWorld(t)
	w3.failAt("engine.before.shadow", context.DeadlineExceeded)
	early, _, _ := w3.cutover()
	f = check(t, "cutover before the engine moved", CutoverPublicSummary(early), cutoverKeys, secrets)
	wantExactly("cutover before the engine moved", f, with(doneBase, map[string]any{"phase": CutoverPhaseIncomplete, "phases_completed": 1.0, "incomplete_code": CutoverIncompleteTimeout,
		"active_owners": 0.0, "old_route_quiesced": false, "new_route_active": false}))
	w.route.unknown["unknown-id-4417"] = true
	w.emit("unknown-id-4417", false)
	reason := Reason{Code: RollbackReasonOperator, Text: "rollback drill text"}
	stopped, _, _ := w.rollback(done, reason)
	f = check(t, "stopped rollback", RollbackPublicSummary(stopped), rollbackKeys, secrets)
	rollbackBase := map[string]any{"schema_version": 1.0, "phase": CutoverPhaseDone, "phases_required": 3.0, "phases_completed": 3.0, "incomplete_code": "", "reason_code": RollbackReasonOperator,
		"active_owners": 1.0, "new_owner_quiesced": true, "old_route_restored": true, "unknown_outcomes": 1.0, "unknown_reviewed": true, "deadman_armed": true, "blocker_counts": []any{},
		"customer_acceptance": false}
	wantExactly("stopped rollback", f, with(rollbackBase, map[string]any{"phase": CutoverPhaseIncomplete, "phases_completed": 0.0, "incomplete_code": CutoverIncompleteUnknown, "active_owners": 0.0,
		"new_owner_quiesced": false, "old_route_restored": false, "unknown_reviewed": false, "deadman_armed": false, "blocker_counts": []any{count(CutoverIncompleteUnknown, 1)}}))
	reason.UnknownReviewed = true
	finished, _, _ := w.rollback(done, reason)
	f = check(t, "finished rollback", RollbackPublicSummary(finished), rollbackKeys, secrets)
	wantExactly("finished rollback", f, rollbackBase)
	w4 := newCutoverWorld(t)
	w4.failAt("engine.before.rollback_quiescing", context.DeadlineExceeded)
	untouched, _, _ := w4.rollback(w4.mustCutover(), Reason{Code: RollbackReasonGap, Text: "rollback drill text"})
	f = check(t, "rollback that stopped before the engine moved", RollbackPublicSummary(untouched), rollbackKeys, secrets)
	wantExactly("rollback that stopped before the engine moved", f, with(rollbackBase, map[string]any{"phase": CutoverPhaseIncomplete, "phases_completed": 0.0, "incomplete_code": CutoverIncompleteTimeout,
		"reason_code": RollbackReasonGap, "new_owner_quiesced": false, "old_route_restored": false, "unknown_outcomes": 0.0, "unknown_reviewed": false, "deadman_armed": false}))
}

func sortedStrings(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func TestCutoverStateFileIsAtomicMonotonicAndPrivate(t *testing.T) {
	w := newCutoverWorld(t)
	var seen []uint64
	for _, point := range []string{"legacy.before.QuiesceNormal", "engine.before.barrier_verified", "engine.before.new_active", "route.Due"} {
		w.observe(point, func() { seen = append(seen, w.state().Version) })
	}
	rcpt := w.mustCutover()
	// preflight, quiescence, handover and activation are persisted before the
	// next phase starts: one version each, no gaps, none repeated.
	if !slices.Equal(seen, []uint64{1, 2, 3, 4}) || rcpt.StateVersion != 5 || w.state().Version != 5 {
		t.Fatalf("versions seen at the phase starts %v, final %d", seen, rcpt.StateVersion)
	}
	entries, err := os.ReadDir(filepath.Dir(w.plan.StatePath))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(w.plan.StatePath) {
		t.Fatalf("directory after the run: %v %v", entries, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(w.plan.StatePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode %v %v", info, err)
		}
	}
	// A second writer that loaded the same version cannot overwrite the first.
	first := w.state()
	second := cutoverCloneState(t, first)
	first.IncompleteCode = "first-writer"
	if err = cutoverSaveState(first); err != nil || first.Version != 6 {
		t.Fatalf("first writer: %v version %d", err, first.Version)
	}
	second.IncompleteCode = "second-writer"
	if err = cutoverSaveState(second); err == nil || !strings.Contains(err.Error(), "moved under") || second.Version != 5 {
		t.Fatalf("a stale writer was accepted: %v version %d", err, second.Version)
	}
	if got := w.state(); got.IncompleteCode != "first-writer" || got.Version != 6 {
		t.Fatalf("the first writer's state was lost: %+v", got)
	}
	// A writer that thinks the file is gone cannot recreate it over a live one.
	third := cutoverCloneState(t, first)
	third.Version = 0
	if err = cutoverSaveState(third); err == nil {
		t.Fatal("a writer with version 0 overwrote an existing state")
	}
	// An unwritable location is an error, never a silent success.
	missing := cutoverCloneState(t, first)
	missing.Plan.StatePath = filepath.Join(t.TempDir(), "missing", "state.json")
	missing.Version = 0
	if err = cutoverSaveState(missing); err == nil {
		t.Fatal("a state in a missing directory was reported saved")
	}
}

func TestCutoverLegacySurfaceCannotRetireAnything(t *testing.T) {
	methods := func(v any) []string {
		typ := reflect.TypeOf(v).Elem()
		out := make([]string, typ.NumMethod())
		for i := range out {
			out[i] = typ.Method(i).Name
		}
		return sortedStrings(out)
	}
	for name, c := range map[string]struct {
		got  []string
		want []string
	}{
		"legacy operator": {methods((*CutoverLegacyOperator)(nil)), []string{"Delivered", "Observe", "QuiesceNormal", "RestoreNormal"}},
		"new route":       {methods((*CutoverNewRoute)(nil)), []string{"Delivered", "Due", "TestDelivery"}},
		"engine":          {methods((*CutoverEngine)(nil)), []string{"AdvanceCutover", "Cutover", "Facts"}},
		"deadman":         {methods((*CutoverDeadman)(nil)), []string{"Proof"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s surface %v, want exactly %v: nothing may delete, disable or reconfigure beyond the normal route", name, c.got, c.want)
		}
	}
	// A whole cutover and rollback only ever calls the normal-route operations
	// of the old owner (the fake flags any other target).
	w := newCutoverWorld(t)
	done := w.mustCutover()
	if rb, _, err := w.rollback(done, Reason{Code: RollbackReasonOther, Text: "surface check"}); err != nil || rb.Phase != CutoverPhaseDone {
		t.Fatal(err)
	}
	for _, c := range w.legacy.calls {
		name, _, _ := strings.Cut(c, ":")
		if !slices.Contains([]string{"Observe", "QuiesceNormal", "RestoreNormal", "Delivered"}, name) {
			t.Fatalf("unexpected legacy call %q", c)
		}
	}
}

// ---------------------------------------------------------------------------
// Boundary tests of the rollback.

func cutoverCloneGrant(t *testing.T, g Authorization) Authorization {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var out Authorization
	if err = json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRollbackRefusesWhatIsNotAnAuthorizedReasonedRollbackOfThisRun(t *testing.T) {
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	w := newCutoverWorld(t)
	done := w.mustCutover()
	before := w.snapshot()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.json")
	cases := map[string]func(*CutoverReceipt, *Reason, *Authorization, time.Time){
		"unknown reason code": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Code = "because" },
		"no reason code":      func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Code = "" },
		"no reason text":      func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Text = "" },
		"reason text over 512 bytes": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			rs.Text = strings.Repeat("a", 513)
		},
		"reason text with a control byte": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Text = "line\nbreak" },
		"reason text with a DEL byte":     func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Text = "del\x7f" },
		"reason text that is not UTF-8":   func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { rs.Text = "bad\xff" },
		"receipt of another run":          func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { r.RunID = "run-2" },
		"receipt of another plan": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			r.PlanDigest = strings.Repeat("0", 64)
		},
		"receipt of another scope":           func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { r.Scope = "other-scope" },
		"receipt without a state path":       func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { r.StatePath = "" },
		"receipt with a relative state path": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { r.StatePath = "state.json" },
		"receipt whose state file is gone":   func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { r.StatePath = elsewhere },
		"read-only grant":                    func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { g.ReadOnly = true },
		"expired grant":                      func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { g.ExpiresAt = now },
		"grant not yet valid": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			g.NotBefore = now.Add(time.Second)
		},
		"grant for cutover only": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			g.Scopes[0].Collectors = []string{"cutover"}
		},
		"grant for another scope": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { g.Scopes[0].ID = "other-scope" },
		"grant without scopes":    func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) { g.Scopes = nil },
		"grant with duplicate scopes": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			g.Scopes = append(g.Scopes, g.Scopes[0])
		},
		"grant with an unknown operation": func(r *CutoverReceipt, rs *Reason, g *Authorization, now time.Time) {
			g.Scopes[0].Collectors = []string{"rollback", "wipe"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, rs, g := done, reason, cutoverCloneGrant(t, w.grant)
			mutate(&r, &rs, &g, w.now())
			rb, err := Rollback(w.rtctx(), r, rs, g)
			if err == nil || rb.Version != 0 || !strings.Contains(err.Error(), "rollback refused") {
				t.Fatalf("not refused: %v %+v", err, rb)
			}
			if got := w.snapshot(); got != before || !w.newActive() || w.state().Rollback != nil {
				t.Fatalf("a refused rollback changed the world: %+v -> %+v", before, got)
			}
		})
	}
	t.Run("a runtime without an engine refuses", func(t *testing.T) {
		rt := w.runtime()
		rt.Engine = nil
		if _, err := Rollback(CutoverWithRuntime(w.ctx, rt), done, reason, w.grant); err == nil || !strings.Contains(err.Error(), "runtime is incomplete") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a reason of exactly 512 bytes is accepted", func(t *testing.T) {
		rb, crashed, err := w.rollback(done, Reason{Code: RollbackReasonOther, Text: strings.Repeat("a", 512)})
		if crashed || err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("%v %v %+v", crashed, err, rb)
		}
	})
}

func TestRollbackIsIndependentOfTheReadyGate(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	w.advance(55 * time.Minute) // the gate expired; the grant has five minutes left
	if err := VerifyReadyGate(w.gate, w.pub, w.now()); err == nil {
		t.Fatal("test bug: the gate is still valid")
	}
	rb, crashed, err := w.rollback(done, Reason{Code: RollbackReasonGap, Text: "gate expired; rolling back"})
	if crashed || err != nil || rb.Phase != CutoverPhaseDone || !w.legacy.enabled {
		t.Fatalf("%v %v %+v", crashed, err, rb)
	}
}

func TestRollbackStopsWhenItsAuthorizationLapsesBetweenPhases(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	w.advance(50 * time.Minute)
	calls := 0
	w.observe("deadman.Proof", func() {
		if calls++; calls == 1 { // the evidence of the old_active record
			w.advance(15 * time.Minute) // past the grant, which ends 60 minutes after the cutover began
		}
	})
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	rb, _, err := w.rollback(done, reason)
	if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteGuard && rb.IncompleteCode != CutoverIncompleteBarrier {
		t.Fatalf("err=%v %+v", err, rb)
	}
	if w.legacy.enabled || w.legacy.restoreEffects != 0 || w.newActive() {
		t.Fatalf("a lapsed rollback must leave nobody sending: legacy=%v owners=%v", w.legacy.enabled, w.owners())
	}
	// A fresh authorization resumes it with the same reason.
	w.grant = cutoverCloneGrant(t, w.grant)
	w.grant.NotBefore, w.grant.ExpiresAt = w.now().Add(-time.Minute), w.now().Add(time.Hour)
	if rb, _, err = w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone || !slices.Equal(w.owners(), []model.ID{w.old}) {
		t.Fatalf("resume: %v %+v", err, rb)
	}
}

func TestRollbackWaitsForLiveClaimsBeforeRecordingTheOldOwner(t *testing.T) {
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	t.Run("claims drain", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		w.engine.inflate = 3
		rb, crashed, err := w.rollback(done, reason)
		if crashed || err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("%v %v %+v", crashed, err, rb)
		}
		claims := 0
		for _, e := range w.events {
			if e == "facts:claimed" {
				claims++
			}
		}
		last, recorded, restored := slices.Index(w.events, "facts:claimed")+claims-1, w.indexOf("engine:old_active"), w.indexOf("legacy:restore")
		if claims != 3 || !(w.indexOf("engine:rollback_quiescing") < last && last < recorded && recorded < restored) {
			t.Fatalf("the old owner was recorded or restored before the claims drained: %v", w.events)
		}
	})
	t.Run("claims never drain", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		w.engine.inflate = -1
		ctx, cancel := context.WithTimeout(w.rtctx(), 100*time.Millisecond)
		defer cancel()
		rb, err := Rollback(ctx, done, reason, w.grant)
		if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteTimeout || len(rb.Completed) != 0 {
			t.Fatalf("err=%v %+v", err, rb)
		}
		if es, _ := w.engineState(); es.Phase != notify.CutoverRollbackQuiescing || len(w.owners()) != 0 || w.legacy.enabled || w.legacy.restoreEffects != 0 || w.indexOf("engine:old_active") >= 0 {
			t.Fatalf("a rollback that cannot quiesce the new owner must restore nothing: %s %v", es.Phase, w.owners())
		}
		// Cancellation is reported as such.
		ctx2, cancel2 := context.WithCancel(w.rtctx())
		cancel2()
		if rb, err = Rollback(ctx2, done, reason, w.grant); err == nil || rb.IncompleteCode != CutoverIncompleteCancelled {
			t.Fatalf("cancelled: %v %+v", err, rb)
		}
		w.engine.inflate = 0
		if rb, _, err = w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone || !slices.Equal(w.owners(), []model.ID{w.old}) {
			t.Fatalf("resume: %v %+v", err, rb)
		}
	})
}

func TestRollbackRecordsUnknownProviderOutcomesAndRestoresOnlyAfterReview(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	w.route.unknown["unknown-id-4417"] = true
	w.emit("unknown-id-4417", false)
	reason := Reason{Code: RollbackReasonDestination, Text: "provider outcomes are unknown"}
	rb, crashed, err := w.rollback(done, reason)
	if crashed || err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteUnknown || len(rb.Completed) != 0 {
		t.Fatalf("crashed=%v err=%v %+v", crashed, err, rb)
	}
	if !slices.Equal(rb.Unknown.RouteIDs, []string{"unknown-id-4417"}) || rb.Unknown.Engine != 0 || rb.Unknown.Reviewed || !slices.Equal(rb.Blockers, []CutoverBlocker{{CutoverIncompleteUnknown, 1}}) {
		t.Fatalf("the unknown outcome is not recorded: %+v", rb)
	}
	if got := w.state().Rollback; got == nil || !slices.Equal(got.Unknown.RouteIDs, []string{"unknown-id-4417"}) {
		t.Fatalf("durable record: %+v", got)
	}
	if es, _ := w.engineState(); es.Phase != notify.CutoverRollbackQuiescing || len(w.owners()) != 0 || w.legacy.enabled || w.legacy.restoreEffects != 0 {
		t.Fatalf("unreviewed unknown outcomes must hold the old owner back: %s %v legacy=%v", es.Phase, w.owners(), w.legacy.enabled)
	}
	reason.UnknownReviewed = true
	rb, crashed, err = w.rollback(done, reason)
	if crashed || err != nil || rb.Phase != CutoverPhaseDone || !rb.Unknown.Reviewed || !slices.Equal(rb.Unknown.RouteIDs, []string{"unknown-id-4417"}) || len(rb.Blockers) != 0 {
		t.Fatalf("after the review: crashed=%v err=%v %+v", crashed, err, rb)
	}
	if !w.legacy.enabled || w.legacy.restoreEffects != 1 {
		t.Fatalf("legacy=%v restores=%d", w.legacy.enabled, w.legacy.restoreEffects)
	}
	// A rollback with no unknown outcome does not need the attestation.
	w2 := newCutoverWorld(t)
	if rb, _, err = w2.rollback(w2.mustCutover(), Reason{Code: RollbackReasonOther, Text: "nothing unknown"}); err != nil || rb.Phase != CutoverPhaseDone || rb.Unknown.Engine != 0 || len(rb.Unknown.RouteIDs) != 0 {
		t.Fatalf("%v %+v", err, rb)
	}
}

func TestRollbackResumeMustRepeatTheSameReason(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	reason := Reason{Code: RollbackReasonOperator, Text: "first reason"}
	w.crashAt("engine.after.rollback_quiescing")
	if _, crashed, _ := w.rollback(done, reason); !crashed {
		t.Fatal("setup crash")
	}
	before := w.snapshot()
	for name, other := range map[string]Reason{
		"another text": {Code: RollbackReasonOperator, Text: "second reason"},
		"another code": {Code: RollbackReasonGap, Text: "first reason"},
	} {
		rb, _, err := w.rollback(done, other)
		if err == nil || rb.Version != 0 || !strings.Contains(err.Error(), "differs") {
			t.Fatalf("%s: %v %+v", name, err, rb)
		}
		if got := w.snapshot(); got != before {
			t.Fatalf("%s: a refused resume changed the world: %+v -> %+v", name, before, got)
		}
	}
	reason.UnknownReviewed = true // the attestation alone may change
	rb, _, err := w.rollback(done, reason)
	if err != nil || rb.Phase != CutoverPhaseDone {
		t.Fatalf("%v %+v", err, rb)
	}
}

func TestRollbackTwiceAndCutoverAfterRollbackAreRefused(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	first, crashed, err := w.rollback(done, reason)
	if crashed || err != nil || first.Phase != CutoverPhaseDone {
		t.Fatalf("%v %v %+v", crashed, err, first)
	}
	before := w.snapshot()
	again, _, err := w.rollback(done, reason)
	if !errors.Is(err, errRollbackAlreadyDone) || again.Phase != CutoverPhaseDone || again.StateVersion != first.StateVersion {
		t.Fatalf("%v %+v", err, again)
	}
	if got := w.snapshot(); got != before || w.legacy.restoreEffects != 1 {
		t.Fatalf("a second rollback changed the world: %+v -> %+v restores=%d", before, got, w.legacy.restoreEffects)
	}
	w.wantRefusal("rollback was started")
}

func TestRollbackOfAnEngineThatNeverStartedRestoresNothingNeeded(t *testing.T) {
	// A cutover that stopped in the preflight phase never touched the engine or
	// the route; rolling it back confirms the old route and records the old
	// owner as the one owner without changing either.
	w := newCutoverWorld(t)
	w.failAt("engine.before.shadow", context.DeadlineExceeded)
	rcpt, _, err := w.cutover()
	if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteTimeout {
		t.Fatalf("%v %+v", err, rcpt)
	}
	if _, found := w.engineState(); found {
		t.Fatal("the engine has a record")
	}
	rb, _, err := w.rollback(rcpt, Reason{Code: RollbackReasonIncomplete, Text: "stopped before the engine moved"})
	if err != nil || rb.Phase != CutoverPhaseDone || !rb.OldRouteEnabled || w.legacy.restoreEffects != 0 || len(w.legacy.callsNamed("RestoreNormal")) != 0 {
		t.Fatalf("%v %+v restores=%d", err, rb, w.legacy.restoreEffects)
	}
}

// ---------------------------------------------------------------------------
// The engine's own accounting: real pending and unknown deliveries.

// cutoverUnknownSender is a provider that never says whether it delivered.
type cutoverUnknownSender struct{ calls int }

func (s *cutoverUnknownSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	s.calls++
	return notify.Outcome{Kind: notify.OutcomeUnknown, Code: "provider_timeout"}, nil
}

// commitPendingDecision commits one decision for the project before any cutover
// record exists: a pending delivery the old owner is already handling. With
// unknown set, a worker pass then tries it against a provider whose outcome is
// unknown, so the delivery is also in the product's unknown set.
func (w *cutoverWorld) commitPendingDecision(unknown bool) (*notify.Outbox, notify.FenceToken) {
	w.t.Helper()
	dest := model.ID{0xd1}
	cfg := `{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`
	w.admin("destination", auth.AdminPayload{ID: dest, Config: json.RawMessage(cfg), Secret: "SECRET-DESTINATION-TEXT-71c2"})
	var err error
	// an administrative command ends every scope minted before it
	if w.scope, err = w.svc.Authorize(w.ctx, w.cred, w.org, []model.ID{w.project}, auth.OrgAdmin); err != nil {
		w.t.Fatal(err)
	}
	group := w.store.ReplicaGroup()
	ob, err := notify.NewOutbox(w.store, group, w.clock, notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	if err != nil {
		w.t.Fatal(err)
	}
	lease, err := group.Fence(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	incident := notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
	cfgp := notify.DefaultConfig()
	event := func(seq byte, kind notify.EventKind) notify.PolicyEvent {
		return notify.PolicyEvent{Kind: kind, Command: model.ID{0xc0, seq}, Org: w.org, Project: w.project, Policy: model.ID{0xf1},
			PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfgp}, OwnerRevision: 1}
	}
	dev := event(1, notify.EventDestination)
	dev.Destination = &notify.DestinationChange{Recipient: dest, Enabled: true}
	if _, err = ob.Submit(w.ctx, w.scope, lease, incident, dev, w.clock.Now()); err != nil {
		w.t.Fatal(err)
	}
	iev := event(2, notify.EventIncident)
	ent := incident
	iev.Entity, iev.Mode = &ent, notify.ModeLive
	iev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: model.ID{0xe9}, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if _, err = ob.Submit(w.ctx, w.scope, lease, incident, iev, w.clock.Now()); err != nil {
		w.t.Fatal(err)
	}
	if unknown {
		sender := &cutoverUnknownSender{}
		worker, err := notify.NewWorker(ob, sender, group)
		if err != nil {
			w.t.Fatal(err)
		}
		w.advance(time.Second)
		if _, err = worker.RunOnce(w.ctx, w.scope, w.clock.Now(), lease); err != nil || sender.calls != 1 {
			w.t.Fatalf("worker pass: %v calls=%d", err, sender.calls)
		}
	}
	facts, err := w.real.Facts(w.ctx, w.scope)
	if err != nil || facts.Pending != 1 || (facts.Unknown == 1) != unknown {
		w.t.Fatalf("fixture facts: %+v %v", facts, err)
	}
	return ob, lease
}

func (w *cutoverWorld) deliveries() []control.DeliveryRecord {
	w.t.Helper()
	recs, err := w.store.Deliveries(w.ctx, w.scope, w.project, "", w.clock.Now(), 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return recs
}

// openDelivery is the opening notification's delivery: the one the old owner
// was handling before the cutover.
func (w *cutoverWorld) openDelivery() control.DeliveryRecord {
	w.t.Helper()
	for _, r := range w.deliveries() {
		if r.Kind == string(notify.KindOpen) {
			return r
		}
	}
	w.t.Fatal("no open delivery")
	return control.DeliveryRecord{}
}

// TestCutoverAccountingFollowsTheEnginesOwnFacts: the barrier evidence carries
// the product's own pending and unknown counts, read from the engine, and the
// engine verifies them against its committed deliveries; what the old owner may
// already have handled is revoked, never sent late.
func TestCutoverAccountingFollowsTheEnginesOwnFacts(t *testing.T) {
	t.Run("a pending delivery the old owner was handling", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.commitPendingDecision(false)
		w.assertConverged(w.mustCutover())
		open := w.openDelivery()
		if open.Phase != control.DeliveryCancelled || open.Code != control.DeliveryReasonRevoked {
			t.Fatalf("the pending delivery must be revoked at activation: %+v", open)
		}
	})
	t.Run("an unknown outcome the operator reviewed", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.commitPendingDecision(true)
		w.plan.UnknownReviewed = true
		done := w.mustCutover()
		w.assertConverged(done)
		open := w.openDelivery()
		if open.Phase != control.DeliveryUncertain || open.Code != control.DeliveryReasonRevoked {
			t.Fatalf("an unknown send settles as uncertain, never as success: %+v", open)
		}
		// The unknown send stays in the product's unknown set: a rollback records
		// it and needs the review before the old owner is restored.
		reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
		rb, _, err := w.rollback(done, reason)
		if err == nil || rb.IncompleteCode != CutoverIncompleteUnknown || rb.Unknown.Engine != 1 || len(rb.Unknown.RouteIDs) != 0 || w.legacy.enabled {
			t.Fatalf("err=%v %+v", err, rb)
		}
		if got := RollbackPublicSummary(rb); got.UnknownOutcomes != 1 || got.UnknownReviewed {
			t.Fatalf("public projection of the engine's unknown outcomes: %+v", got)
		}
		reason.UnknownReviewed = true
		if rb, _, err = w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone || rb.Unknown.Engine != 1 || !rb.Unknown.Reviewed || !w.legacy.enabled {
			t.Fatalf("after the review: err=%v %+v", err, rb)
		}
	})
	t.Run("an unknown outcome nobody reviewed", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.commitPendingDecision(true)
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteBarrier || !strings.Contains(err.Error(), "unknown_unreviewed") {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
		if w.newActive() || len(w.owners()) > 1 {
			t.Fatalf("owners %v", w.owners())
		}
	})
}

// ---------------------------------------------------------------------------
// The command line.

type cutoverCLIEnv struct {
	inputs, private, summary, grant string
	args                            []string
}

func (w *cutoverWorld) connectCLI() {
	w.t.Helper()
	prev := cutoverConnect
	cutoverConnect = func(ctx context.Context, target CutoverConnectTarget) (CutoverRuntime, error) {
		w.targets = append(w.targets, target)
		rt := w.runtime()
		rt.GateKey = nil // the CLI supplies the gate's public key from its flag
		return rt, nil
	}
	w.t.Cleanup(func() { cutoverConnect = prev })
}

func (w *cutoverWorld) cliEnv() *cutoverCLIEnv {
	w.t.Helper()
	inputs := w.t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(inputs, name)
		if err := writeExclusive(p, v); err != nil {
			w.t.Fatal(err)
		}
		return p
	}
	plan := w.plan
	plan.StatePath = "" // the CLI keeps the state in the private directory
	keyPath := filepath.Join(inputs, "gate.pub")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(w.pub)+"\n"), 0o600); err != nil {
		w.t.Fatal(err)
	}
	env := &cutoverCLIEnv{inputs: inputs, private: privateTempDir(w.t), summary: filepath.Join(inputs, "public.json")}
	env.grant = write("grant.json", w.grant)
	env.args = []string{"--gate", write("gate.json", w.gate), "--gate-public-key", keyPath, "--plan", write("plan.json", plan), "--authorization", env.grant,
		"--private-directory", env.private, "--private-directory-acl-confirmed", "--public-summary", env.summary}
	return env
}

// cutoverFlag returns args with the value of name replaced (or, with value "",
// the flag and its value dropped).
func cutoverFlag(args []string, name, value string) []string {
	out := slices.Clone(args)
	i := slices.Index(out, name)
	if i < 0 {
		return out
	}
	if value == "" {
		return slices.Delete(out, i, i+2)
	}
	out[i+1] = value
	return out
}

func cutoverGlob(t *testing.T, dir, pattern string) []string {
	t.Helper()
	out, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCutoverCLIRunsTheJourneyAndWritesClosedOutputs(t *testing.T) {
	w := newCutoverWorld(t)
	w.connectCLI()
	env := w.cliEnv()
	if err := runCutover(w.ctx, append(slices.Clone(env.args), "--timeout", "1h")); err != nil {
		t.Fatal(err)
	}
	if len(w.targets) != 1 || w.targets[0] != (CutoverConnectTarget{Scope: w.plan.Scope, Environment: cutoverEnvProduction, Project: w.project}) {
		t.Fatalf("connector targets %+v", w.targets)
	}
	receipts := cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json")
	if len(receipts) != 1 {
		t.Fatalf("receipts %v", receipts)
	}
	var rcpt CutoverReceipt
	if err := readInput(receipts[0], &rcpt); err != nil || rcpt.Phase != CutoverPhaseDone || rcpt.StateVersion != 5 || filepath.Base(rcpt.StatePath) != "cutover-run-1.state.json" {
		t.Fatalf("receipt: %v %+v", err, rcpt)
	}
	var pub CutoverPublic
	if err := readInput(env.summary, &pub); err != nil || pub.Phase != CutoverPhaseDone || pub.PhasesCompleted != 5 || pub.ActiveOwners != 1 || pub.CustomerAcceptance {
		t.Fatalf("public summary: %v %+v", err, pub)
	}
	if !w.newActive() || w.legacy.enabled {
		t.Fatalf("the cutover did not happen: owners %v", w.owners())
	}
	// Again: refused as already done; nothing new is written.
	second := filepath.Join(env.inputs, "public-second.json")
	if err := runCutover(w.ctx, cutoverFlag(env.args, "--public-summary", second)); err == nil || !strings.Contains(err.Error(), "already done") {
		t.Fatalf("a second run: %v", err)
	}
	if _, err := os.Stat(second); err == nil || len(cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json")) != 1 {
		t.Fatal("a refused second run wrote outputs")
	}

	rsum := filepath.Join(env.inputs, "rollback-public.json")
	rargs := []string{"--receipt", receipts[0], "--authorization", env.grant, "--reason-code", RollbackReasonOperator, "--reason-text", "drill through the command line",
		"--private-directory", env.private, "--private-directory-acl-confirmed", "--public-summary", rsum}
	if err := runRollback(w.ctx, append(slices.Clone(rargs), "--timeout", "1h")); err != nil {
		t.Fatal(err)
	}
	rbReceipts := cutoverGlob(t, env.private, "rollback-run-1.receipt-v*.json")
	var rb RollbackReceipt
	if len(rbReceipts) != 1 || readInput(rbReceipts[0], &rb) != nil || rb.Phase != CutoverPhaseDone || !rb.OldRouteEnabled || !rb.DeadmanArmed {
		t.Fatalf("rollback receipts %v %+v", rbReceipts, rb)
	}
	var rpub RollbackPublic
	if err := readInput(rsum, &rpub); err != nil || rpub.Phase != CutoverPhaseDone || rpub.PhasesCompleted != 3 || !rpub.OldRouteRestored || rpub.CustomerAcceptance || rpub.ReasonCode != RollbackReasonOperator {
		t.Fatalf("rollback summary: %v %+v", err, rpub)
	}
	if !w.legacy.enabled || !slices.Equal(w.owners(), []model.ID{w.old}) || len(w.targets) != 3 || w.targets[2].Project != w.project {
		t.Fatalf("after the rollback: legacy=%v owners=%v targets=%+v", w.legacy.enabled, w.owners(), w.targets)
	}
	if err := runRollback(w.ctx, cutoverFlag(rargs, "--public-summary", filepath.Join(env.inputs, "rollback-second.json"))); err == nil || !strings.Contains(err.Error(), "already done") {
		t.Fatalf("a second rollback: %v", err)
	}
	if len(cutoverGlob(t, env.private, "rollback-run-1.receipt-v*.json")) != 1 {
		t.Fatal("a refused second rollback wrote outputs")
	}
	// An existing public summary is never overwritten; the private receipt stays.
	w2 := newCutoverWorld(t)
	w2.connectCLI()
	env2 := w2.cliEnv()
	if err := os.WriteFile(env2.summary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCutover(w2.ctx, env2.args); err == nil || !strings.Contains(err.Error(), "summary creation failed") {
		t.Fatalf("an existing summary: %v", err)
	}
	if got, _ := os.ReadFile(env2.summary); string(got) != "x" || len(cutoverGlob(t, env2.private, "cutover-run-1.receipt-v*.json")) != 1 {
		t.Fatal("the existing summary was overwritten or the private receipt was lost")
	}
}

func TestCutoverCLIWritesOutputsForAnIncompleteRunAndResumes(t *testing.T) {
	w := newCutoverWorld(t)
	w.connectCLI()
	w.failAt("legacy.before.QuiesceNormal", context.DeadlineExceeded)
	env := w.cliEnv()
	err := runCutover(w.ctx, env.args)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("%v", err)
	}
	receipts := cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json")
	var rcpt CutoverReceipt
	if len(receipts) != 1 || readInput(receipts[0], &rcpt) != nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteTimeout {
		t.Fatalf("%v %+v", receipts, rcpt)
	}
	var pub CutoverPublic
	if err = readInput(env.summary, &pub); err != nil || pub.Phase != CutoverPhaseIncomplete || pub.IncompleteCode != CutoverIncompleteTimeout || pub.OldRouteQuiesced || pub.NewRouteActive {
		t.Fatalf("%v %+v", err, pub)
	}
	second := filepath.Join(env.inputs, "public-second.json")
	if err = runCutover(w.ctx, cutoverFlag(env.args, "--public-summary", second)); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json"); len(got) != 2 {
		t.Fatalf("receipts %v", got)
	}
	if err = readInput(second, &pub); err != nil || pub.Phase != CutoverPhaseDone {
		t.Fatalf("%v %+v", err, pub)
	}
	// A rollback that stops on unreviewed unknown outcomes still writes what it knows.
	w.route.unknown["unknown-id-4417"] = true
	w.emit("unknown-id-4417", false)
	var done CutoverReceipt
	if got := cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json"); readInput(got[len(got)-1], &done) != nil {
		t.Fatal("receipt unreadable")
	}
	latest := ""
	for _, p := range cutoverGlob(t, env.private, "cutover-run-1.receipt-v*.json") {
		var r CutoverReceipt
		if readInput(p, &r) == nil && r.Phase == CutoverPhaseDone {
			latest = p
		}
	}
	rsum := filepath.Join(env.inputs, "rb1.json")
	rargs := []string{"--receipt", latest, "--authorization", env.grant, "--reason-code", RollbackReasonDestination, "--reason-text", "unknown outcomes",
		"--private-directory", env.private, "--private-directory-acl-confirmed", "--public-summary", rsum}
	if err = runRollback(w.ctx, rargs); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("%v", err)
	}
	var rpub RollbackPublic
	if err = readInput(rsum, &rpub); err != nil || rpub.Phase != CutoverPhaseIncomplete || rpub.IncompleteCode != CutoverIncompleteUnknown || rpub.UnknownOutcomes != 1 || rpub.UnknownReviewed {
		t.Fatalf("%v %+v", err, rpub)
	}
	rsum2 := filepath.Join(env.inputs, "rb2.json")
	if err = runRollback(w.ctx, append(cutoverFlag(rargs, "--public-summary", rsum2), "--unknown-reviewed")); err != nil {
		t.Fatalf("reviewed: %v", err)
	}
	if err = readInput(rsum2, &rpub); err != nil || rpub.Phase != CutoverPhaseDone || !rpub.UnknownReviewed || rpub.UnknownOutcomes != 1 {
		t.Fatalf("%v %+v", err, rpub)
	}
	if got := cutoverGlob(t, env.private, "rollback-run-1.receipt-v*.json"); len(got) != 2 {
		t.Fatalf("rollback receipts %v", got)
	}
}

func TestCutoverCLIRefusesBadInputsBeforeAnyChange(t *testing.T) {
	type mutation struct {
		name, want string
		connect    bool
		mutate     func(w *cutoverWorld, env *cutoverCLIEnv) []string
	}
	rewrite := func(w *cutoverWorld, env *cutoverCLIEnv, change func(*OwnershipPlan)) []string {
		plan := w.plan
		plan.Frontier = slices.Clone(plan.Frontier)
		plan.StatePath = ""
		change(&plan)
		p := filepath.Join(env.inputs, "plan-changed.json")
		if err := writeExclusive(p, plan); err != nil {
			t.Fatal(err)
		}
		return cutoverFlag(env.args, "--plan", p)
	}
	var cases []mutation
	for _, f := range []string{"--gate", "--gate-public-key", "--plan", "--authorization", "--private-directory", "--public-summary"} {
		cases = append(cases, mutation{"missing " + f, "usage", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return cutoverFlag(env.args, f, "") }})
	}
	cases = append(cases,
		mutation{"zero timeout", "timeout", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return append(env.args, "--timeout", "0s") }},
		mutation{"timeout beyond an hour", "timeout", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return append(env.args, "--timeout", "61m") }},
		mutation{"a stray argument", "usage", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return append(env.args, "extra") }},
		mutation{"an unknown flag", "flag provided but not defined", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return append(env.args, "--force") }},
		mutation{"key that is not hex", "gate public key", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			p := filepath.Join(env.inputs, "bad.pub")
			os.WriteFile(p, []byte("zz"), 0o600)
			return cutoverFlag(env.args, "--gate-public-key", p)
		}},
		mutation{"key of the wrong length", "gate public key", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			p := filepath.Join(env.inputs, "short.pub")
			os.WriteFile(p, []byte(strings.Repeat("ab", 31)), 0o600)
			return cutoverFlag(env.args, "--gate-public-key", p)
		}},
		mutation{"key file missing", "cannot read gate public key", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return cutoverFlag(env.args, "--gate-public-key", filepath.Join(env.inputs, "absent.pub"))
		}},
		mutation{"plan that names a state file", "state path", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return rewrite(w, env, func(p *OwnershipPlan) { p.StatePath = filepath.Join(env.private, "mine.json") })
		}},
		mutation{"plan without a valid run id", "run id", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return rewrite(w, env, func(p *OwnershipPlan) { p.RunID = "Run_1" })
		}},
		mutation{"plan with an unknown field", "invalid private operator input", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			p := filepath.Join(env.inputs, "plan-extra.json")
			os.WriteFile(p, []byte(`{"run_id":"run-1","unexpected":true}`), 0o600)
			return cutoverFlag(env.args, "--plan", p)
		}},
		mutation{"gate file missing", "invalid private operator input", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return cutoverFlag(env.args, "--gate", filepath.Join(env.inputs, "absent.json"))
		}},
		mutation{"private directory missing", "private directory", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return cutoverFlag(env.args, "--private-directory", filepath.Join(env.inputs, "absent"))
		}},
		mutation{"no adapters in this build", "no legacy-operator", false, func(w *cutoverWorld, env *cutoverCLIEnv) []string { return env.args }},
		mutation{"adapter connection fails", "connector down", false, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			prev := cutoverConnect
			cutoverConnect = func(context.Context, CutoverConnectTarget) (CutoverRuntime, error) {
				return CutoverRuntime{}, errors.New("connector down")
			}
			t.Cleanup(func() { cutoverConnect = prev })
			return env.args
		}},
		mutation{"gate signed by another key", "ready gate", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			other, _, _ := ed25519.GenerateKey(nil)
			p := filepath.Join(env.inputs, "other.pub")
			os.WriteFile(p, []byte(hex.EncodeToString(other)), 0o600)
			return cutoverFlag(env.args, "--gate-public-key", p)
		}},
		mutation{"expired gate", "ready gate", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string { w.advance(55 * time.Minute); return env.args }},
		mutation{"authorization for another scope", "authorization validation failed", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			g := cutoverCloneGrant(t, w.grant)
			g.Scopes[0].ID = "other-scope"
			p := filepath.Join(env.inputs, "grant-other.json")
			if err := writeExclusive(p, g); err != nil {
				t.Fatal(err)
			}
			return cutoverFlag(env.args, "--authorization", p)
		}},
	)
	if runtime.GOOS == "windows" {
		cases = append(cases, mutation{"unconfirmed Windows ACL", "ACL", true, func(w *cutoverWorld, env *cutoverCLIEnv) []string {
			return slices.DeleteFunc(slices.Clone(env.args), func(a string) bool { return a == "--private-directory-acl-confirmed" })
		}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newCutoverWorld(t)
			if c.connect {
				w.connectCLI()
			}
			env := w.cliEnv()
			err := runCutover(w.ctx, c.mutate(w, env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one naming %q", err, c.want)
			}
			// only the refusals of the gate and the authorization come after the adapters connect
			reachesAdapters := slices.Contains([]string{"gate signed by another key", "expired gate", "authorization for another scope"}, c.name)
			if c.connect && (len(w.targets) != 0) != reachesAdapters {
				t.Fatalf("connector called %d times, want it called=%v", len(w.targets), reachesAdapters)
			}
			if _, found := w.engineState(); found || len(w.legacy.callsNamed("QuiesceNormal")) != 0 || !w.legacy.enabled {
				t.Fatal("a refused command changed the engine or the old route")
			}
			if files := cutoverGlob(t, env.private, "*"); len(files) != 0 {
				t.Fatalf("a refused command wrote %v", files)
			}
			if _, err := os.Stat(env.summary); err == nil {
				t.Fatal("a refused command wrote a summary")
			}
		})
	}
}

func TestRollbackCLIRefusesBadInputsBeforeAnyChange(t *testing.T) {
	type mutation struct {
		name, want string
		connect    bool
		mutate     func(w *cutoverWorld, args []string, receipt, inputs string) []string
	}
	var cases []mutation
	for _, f := range []string{"--receipt", "--authorization", "--reason-code", "--reason-text", "--private-directory", "--public-summary"} {
		cases = append(cases, mutation{"missing " + f, "usage", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string { return cutoverFlag(args, f, "") }})
	}
	cases = append(cases,
		mutation{"zero timeout", "timeout", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string {
			return append(args, "--timeout", "0s")
		}},
		mutation{"a stray argument", "usage", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string { return append(args, "extra") }},
		mutation{"unknown reason code", "rollback refused", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string {
			return cutoverFlag(args, "--reason-code", "because")
		}},
		mutation{"receipt file missing", "invalid private operator input", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string {
			return cutoverFlag(args, "--receipt", filepath.Join(inputs, "absent.json"))
		}},
		mutation{"state file in another directory", "not in the private directory", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string {
			return cutoverFlag(args, "--private-directory", privateTempDir(t))
		}},
		mutation{"no adapters in this build", "no legacy-operator", false, func(w *cutoverWorld, args []string, receipt, inputs string) []string { return args }},
		mutation{"authorization for cutover only", "rollback refused", true, func(w *cutoverWorld, args []string, receipt, inputs string) []string {
			g := cutoverCloneGrant(t, w.grant)
			g.Scopes[0].Collectors = []string{"cutover"}
			p := filepath.Join(inputs, "grant-cutover-only.json")
			if err := writeExclusive(p, g); err != nil {
				t.Fatal(err)
			}
			return cutoverFlag(args, "--authorization", p)
		}},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newCutoverWorld(t)
			if c.connect {
				w.connectCLI()
			}
			env := w.cliEnv()
			w.plan.StatePath = filepath.Join(env.private, "cutover-run-1.state.json")
			done := w.mustCutover()
			receipt := filepath.Join(env.inputs, "receipt.json")
			if err := writeExclusive(receipt, done); err != nil {
				t.Fatal(err)
			}
			rsum := filepath.Join(env.inputs, "rb.json")
			args := []string{"--receipt", receipt, "--authorization", env.grant, "--reason-code", RollbackReasonOperator, "--reason-text", "drill",
				"--private-directory", env.private, "--private-directory-acl-confirmed", "--public-summary", rsum}
			before := w.snapshot()
			err := runRollback(w.ctx, c.mutate(w, args, receipt, env.inputs))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one naming %q", err, c.want)
			}
			if got := w.snapshot(); got != before || !w.newActive() {
				t.Fatalf("a refused rollback changed the world: %+v -> %+v", before, got)
			}
			if files := cutoverGlob(t, env.private, "rollback-*"); len(files) != 0 {
				t.Fatalf("a refused rollback wrote %v", files)
			}
			if _, err := os.Stat(rsum); err == nil {
				t.Fatal("a refused rollback wrote a summary")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Plan, grant, deadman and adapter boundaries.

// receiptFromState is what an operator holds after a process death: the
// locator of the run, rebuilt from the state file.
func (w *cutoverWorld) receiptFromState() CutoverReceipt {
	st := w.state()
	return CutoverReceipt{Version: 1, RunID: st.Plan.RunID, Scope: st.Plan.Scope, Environment: st.Plan.Environment, PlanDigest: st.PlanDigest, StatePath: st.Plan.StatePath,
		StateVersion: st.Version, Phase: st.Phase, Completed: st.Completed, ActiveOwners: []model.ID{}, Blockers: []CutoverBlocker{}}
}

func TestCutoverRefusesAMalformedPlanAndAcceptsEveryBoundary(t *testing.T) {
	refused := map[string]func(*cutoverWorld){
		"empty run id":                         func(w *cutoverWorld) { w.plan.RunID = "" },
		"run id with a capital":                func(w *cutoverWorld) { w.plan.RunID = "Run-1" },
		"run id starting with a dash":          func(w *cutoverWorld) { w.plan.RunID = "-run" },
		"run id of 64 characters":              func(w *cutoverWorld) { w.plan.RunID = strings.Repeat("a", 64) },
		"no scope":                             func(w *cutoverWorld) { w.plan.Scope = "" },
		"unknown environment":                  func(w *cutoverWorld) { w.plan.Environment = "prod" },
		"no environment":                       func(w *cutoverWorld) { w.plan.Environment = "" },
		"relative state path":                  func(w *cutoverWorld) { w.plan.StatePath = "state.json" },
		"no state path":                        func(w *cutoverWorld) { w.plan.StatePath = "" },
		"no project":                           func(w *cutoverWorld) { w.plan.Project = model.ID{} },
		"project that is not the engine scope": func(w *cutoverWorld) { w.plan.Project = model.ID{0x44, 0xd0} },
		"no old owner":                         func(w *cutoverWorld) { w.plan.OldOwner = model.ID{} },
		"no new owner":                         func(w *cutoverWorld) { w.plan.NewOwner = model.ID{} },
		"the same owner twice":                 func(w *cutoverWorld) { w.plan.NewOwner = w.plan.OldOwner },
		"no policy generation":                 func(w *cutoverWorld) { w.plan.PolicyGeneration = 0 },
		"no frontier":                          func(w *cutoverWorld) { w.plan.Frontier = nil },
		"method with a capital":                func(w *cutoverWorld) { w.plan.OldQuiescence.Method = "Scheduler_disabled" },
		"method with a space":                  func(w *cutoverWorld) { w.plan.OldQuiescence.Method = "scheduler disabled" },
		"method of 65 characters":              func(w *cutoverWorld) { w.plan.OldQuiescence.Method = strings.Repeat("m", 65) },
		"no method":                            func(w *cutoverWorld) { w.plan.OldQuiescence.Method = "" },
		"no destination":                       func(w *cutoverWorld) { w.plan.Destination.Destination = "" },
		"destination with a space":             func(w *cutoverWorld) { w.plan.Destination.Destination = "dest 1" },
		"destination of 129 bytes":             func(w *cutoverWorld) { w.plan.Destination.Destination = strings.Repeat("d", 129) },
		"no probe id":                          func(w *cutoverWorld) { w.plan.Destination.ProbeID = "" },
		"probe id with a space":                func(w *cutoverWorld) { w.plan.Destination.ProbeID = "probe 1" },
		"probe id of 129 bytes":                func(w *cutoverWorld) { w.plan.Destination.ProbeID = strings.Repeat("p", 129) },
		"no runbook reference":                 func(w *cutoverWorld) { w.plan.RollbackRunbookRef = "" },
		"runbook reference with a space":       func(w *cutoverWorld) { w.plan.RollbackRunbookRef = "step 1" },
		"runbook reference of 257 bytes":       func(w *cutoverWorld) { w.plan.RollbackRunbookRef = strings.Repeat("b", 257) },
		"negative provider uncertainty":        func(w *cutoverWorld) { w.plan.ProviderUncertainty = -1 },
	}
	for name, mutate := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			w := newCutoverWorld(t)
			mutate(w)
			w.wantRefusal("invalid ownership plan")
			w.assertUntouched()
		})
	}
	t.Run("accepts every boundary at once", func(t *testing.T) {
		w := newCutoverWorld(t)
		method := strings.Repeat("m", 59) + "_.:-9"
		w.legacy.method = method
		w.plan.RunID = strings.Repeat("r", 63)
		w.plan.OldQuiescence.Method = method
		w.plan.Destination = CutoverDestinationTest{Destination: strings.Repeat("d", 128), ProbeID: strings.Repeat("p", 128)}
		w.plan.RollbackRunbookRef = strings.Repeat("b", 256)
		w.assertConverged(w.mustCutover())
	})
}

func TestDeadmanProofMustBeTheExcludedOnesAndStayArmedUntilTheEnd(t *testing.T) {
	other := model.ID{0x77, 0xd0}
	for name, mutate := range map[string]func(*cutoverWorld){
		"another product failure domain": func(w *cutoverWorld) { w.deadman.productDomain = &other },
		"a proof without a digest":       func(w *cutoverWorld) { w.deadman.zeroRef = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newCutoverWorld(t)
			mutate(w)
			w.wantRefusal("cutover refused")
			w.assertUntouched()
		})
	}
	t.Run("disarmed after the activation", func(t *testing.T) {
		w := newCutoverWorld(t)
		once := false
		w.observe("route.Due", func() {
			if !once {
				once, w.deadman.armed = true, false
			}
		})
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteDeadman || !slices.Equal(rcpt.Completed, cutoverSteps[:4]) {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
		if !slices.Equal(w.owners(), []model.ID{w.nw}) {
			t.Fatalf("owners %v", w.owners())
		}
		w.deadman.armed = true
		w.assertConverged(w.mustCutover())
	})
	t.Run("disarmed after the old route is restored", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		w.observe("legacy.after.RestoreNormal", func() { w.deadman.armed = false })
		reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
		rb, _, err := w.rollback(done, reason)
		if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteDeadman || rb.DeadmanArmed || len(rb.Completed) != 2 {
			t.Fatalf("err=%v %+v", err, rb)
		}
		w.deadman.armed = true
		rb, _, err = w.rollback(done, reason)
		if err != nil || rb.Phase != CutoverPhaseDone || !rb.DeadmanArmed || w.legacy.restoreEffects != 1 {
			t.Fatalf("err=%v %+v restores=%d", err, rb, w.legacy.restoreEffects)
		}
	})
}

func TestCutoverRefusesLegacyAnswersThatAreNotTheOldOwnersAcknowledgement(t *testing.T) {
	other := model.ID{0x78, 0xd0}
	t.Run("an observation before any change", func(t *testing.T) {
		for name, mutate := range map[string]func(*cutoverWorld){
			"about another owner":     func(w *cutoverWorld) { w.legacy.ownerLie = &other },
			"without an artifact ref": func(w *cutoverWorld) { w.legacy.zeroRef = true },
		} {
			w := newCutoverWorld(t)
			mutate(w)
			w.wantRefusal(CutoverIncompleteLegacyUnexpected)
			w.assertUntouched()
			_ = name
		}
	})
	t.Run("the acknowledgement of the quiescence", func(t *testing.T) {
		for name, mutate := range map[string]func(*cutoverWorld){
			"echoes another command":   func(w *cutoverWorld) { w.legacy.echo = "another-command" },
			"about another owner":      func(w *cutoverWorld) { w.legacy.ownerLie = &other },
			"without an artifact ref":  func(w *cutoverWorld) { w.legacy.zeroRef = true },
			"older than the quiescing": func(w *cutoverWorld) { w.legacy.ackAge = 10 * time.Second },
		} {
			t.Run(name, func(t *testing.T) {
				w := newCutoverWorld(t)
				// the faults apply from the moment the old route is told to quiesce
				w.observe("legacy.before.QuiesceNormal", func() { mutate(w) })
				rcpt, _, err := w.cutover()
				if err == nil || rcpt.Phase != CutoverPhaseIncomplete || !slices.Equal(rcpt.Completed, []string{cutoverStepPreflight}) || w.newActive() {
					t.Fatalf("err=%v %+v", err, rcpt)
				}
				if es, _ := w.engineState(); es.Phase != notify.CutoverQuiescingOld {
					t.Fatalf("engine %s", es.Phase)
				}
			})
		}
	})
	t.Run("the acknowledgement of the restore", func(t *testing.T) {
		for name, c := range map[string]struct {
			mutate func(*cutoverWorld)
			enable bool // the fake's effect happened
		}{
			"echoes another command": {func(w *cutoverWorld) { w.legacy.echo = "another-command" }, true},
			"has no effect":          {func(w *cutoverWorld) { w.legacy.restoreNoop = true }, false},
		} {
			t.Run(name, func(t *testing.T) {
				w := newCutoverWorld(t)
				done := w.mustCutover()
				c.mutate(w)
				reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
				rb, _, err := w.rollback(done, reason)
				if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteLegacyUnexpected || len(rb.Completed) != 2 || w.legacy.enabled != c.enable {
					t.Fatalf("err=%v %+v enabled=%v", err, rb, w.legacy.enabled)
				}
				if !slices.Equal(w.owners(), []model.ID{w.old}) {
					t.Fatalf("owners %v", w.owners())
				}
				w.legacy.echo, w.legacy.restoreNoop = "", false
				if rb, _, err = w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone || !w.legacy.enabled {
					t.Fatalf("resume: %v %+v", err, rb)
				}
			})
		}
	})
}

func TestCutoverAuthorizesExactlyTheOperationItNames(t *testing.T) {
	w := newCutoverWorld(t)
	w.grant.Scopes[0].Collectors = []string{"cutover"}
	done := w.mustCutover()
	if rb, err := Rollback(w.rtctx(), done, Reason{Code: RollbackReasonOperator, Text: "drill"}, w.grant); err == nil || rb.Version != 0 {
		t.Fatalf("a cutover grant authorized a rollback: %v %+v", err, rb)
	}
	w.grant.Scopes[0].Collectors = []string{"rollback"}
	if rb, _, err := w.rollback(done, Reason{Code: RollbackReasonOperator, Text: "drill"}); err != nil || rb.Phase != CutoverPhaseDone {
		t.Fatalf("a rollback grant must suffice for every rollback phase: %v %+v", err, rb)
	}
}

func TestCutoverStopsWhenTheGrantLapsesBetweenPhases(t *testing.T) {
	w := newCutoverWorld(t)
	w.grant.ExpiresAt = w.now().Add(10 * time.Minute) // the gate lives 50 minutes
	calls := 0
	w.observe("deadman.Proof", func() {
		if calls++; calls == 2 {
			w.advance(15 * time.Minute)
		}
	})
	rcpt, _, err := w.cutover()
	if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteGuard || !slices.Equal(rcpt.Completed, cutoverSteps[:2]) {
		t.Fatalf("err=%v %+v", err, rcpt)
	}
	if !strings.Contains(err.Error(), "authorization") || w.newActive() {
		t.Fatalf("the lapsed grant, not the gate, must stop it: %v", err)
	}
	w.grant.ExpiresAt = w.now().Add(time.Hour)
	w.assertConverged(w.mustCutover())
}

// TestCutoverStopsOnAnEngineReplyThatContradictsTheRequest: the tool does not
// take a successful reply for granted; whatever the engine answers must be the
// phase, owner and generation it was asked for. The engine's committed state is
// the truth, so the resume reads it and finishes.
func TestCutoverStopsOnAnEngineReplyThatContradictsTheRequest(t *testing.T) {
	cases := []struct {
		name      string
		phase     notify.CutoverPhase
		tamper    func(w *cutoverWorld, st *notify.CutoverState)
		completed []string
	}{
		{"the quiescing is answered as shadow", notify.CutoverQuiescingOld, func(w *cutoverWorld, st *notify.CutoverState) { st.Phase = notify.CutoverShadow }, cutoverSteps[:1]},
		{"the barrier is answered as still quiescing", notify.CutoverBarrierVerified, func(w *cutoverWorld, st *notify.CutoverState) { st.Phase = notify.CutoverQuiescingOld }, cutoverSteps[:2]},
		{"the activation is answered in another phase", notify.CutoverNewActive, func(w *cutoverWorld, st *notify.CutoverState) { st.Phase = notify.CutoverBarrierVerified }, cutoverSteps[:3]},
		{"the activation is answered with another generation", notify.CutoverNewActive, func(w *cutoverWorld, st *notify.CutoverState) { st.Epoch++ }, cutoverSteps[:3]},
		{"the activation is answered without an active owner", notify.CutoverNewActive, func(w *cutoverWorld, st *notify.CutoverState) { st.ActiveOwners = nil }, cutoverSteps[:3]},
		{"the activation is answered with the old owner active", notify.CutoverNewActive, func(w *cutoverWorld, st *notify.CutoverState) { st.ActiveOwners = []model.ID{w.old} }, cutoverSteps[:3]},
		{"the activation is answered as the barrier with nobody active", notify.CutoverNewActive, func(w *cutoverWorld, st *notify.CutoverState) {
			st.Phase, st.ActiveOwners = notify.CutoverBarrierVerified, nil
		}, cutoverSteps[:3]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newCutoverWorld(t)
			w.engine.tamper = func(cmd notify.CutoverCommand, st *notify.CutoverState) {
				if cmd.Phase == c.phase {
					c.tamper(w, st)
				}
			}
			rcpt, _, err := w.cutover()
			if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteEngine || !slices.Equal(rcpt.Completed, c.completed) {
				t.Fatalf("err=%v %+v", err, rcpt)
			}
			if len(w.owners()) > 1 {
				t.Fatalf("owners %v", w.owners())
			}
			w.engine.tamper = nil
			w.assertConverged(w.mustCutover())
		})
	}
	t.Run("the old owner's record is answered as still quiescing the new one", func(t *testing.T) {
		w := newCutoverWorld(t)
		done := w.mustCutover()
		w.engine.tamper = func(cmd notify.CutoverCommand, st *notify.CutoverState) {
			if cmd.Phase == notify.CutoverOldActive {
				st.Phase = notify.CutoverRollbackQuiescing
			}
		}
		reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
		rb, _, err := w.rollback(done, reason)
		if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteEngine || !slices.Equal(rb.Completed, rollbackSteps[:1]) || w.legacy.enabled {
			t.Fatalf("err=%v %+v", err, rb)
		}
		w.engine.tamper = nil
		if rb, _, err = w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone {
			t.Fatalf("resume: %v %+v", err, rb)
		}
	})
}

func TestRollbackNeverRestoresWhileTheEngineReportsAnotherOwner(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	w.crashAt("legacy.before.RestoreNormal")
	if _, crashed, _ := w.rollback(done, reason); !crashed {
		t.Fatal("setup crash")
	}
	calls := len(w.legacy.callsNamed("RestoreNormal"))
	for name, lie := range map[string]func(*cutoverWorld, *notify.CutoverState){
		"the new owner active again": func(w *cutoverWorld, st *notify.CutoverState) {
			st.Phase, st.ActiveOwners = notify.CutoverNewActive, []model.ID{w.nw}
		},
		"nobody active":              func(w *cutoverWorld, st *notify.CutoverState) { st.Phase = notify.CutoverRollbackQuiescing },
		"the barrier verified again": func(w *cutoverWorld, st *notify.CutoverState) { st.Phase = notify.CutoverBarrierVerified },
	} {
		w.engine.readTamper = func(st *notify.CutoverState) {
			if st.Phase == notify.CutoverOldActive {
				lie(w, st)
			}
		}
		rb, _, err := w.rollback(done, reason)
		if err == nil || rb.Phase != CutoverPhaseIncomplete || rb.IncompleteCode != CutoverIncompleteEngine || w.legacy.enabled || len(w.legacy.callsNamed("RestoreNormal")) != calls {
			t.Fatalf("%s: err=%v %+v", name, err, rb)
		}
	}
	w.engine.readTamper = nil
	if rb, _, err := w.rollback(done, reason); err != nil || rb.Phase != CutoverPhaseDone || w.legacy.restoreEffects != 1 {
		t.Fatalf("resume: %v %+v", err, rb)
	}
}

func TestRollbackAbortsFromTheVerifiedBarrierAndResumesAfterTheAbort(t *testing.T) {
	w := newCutoverWorld(t)
	w.crashAt("engine.before.new_active")
	if _, crashed, _ := w.cutover(); !crashed {
		t.Fatal("setup crash")
	}
	if es, _ := w.engineState(); es.Phase != notify.CutoverBarrierVerified || w.legacy.enabled {
		t.Fatalf("setup: engine %s legacy=%v", es.Phase, w.legacy.enabled)
	}
	receipt := w.receiptFromState()
	reason := Reason{Code: RollbackReasonIncomplete, Text: "abandoning the activation"}
	w.crashAt("engine.after.shadow") // the abort's own command
	if _, crashed, _ := w.rollback(receipt, reason); !crashed {
		t.Fatal("the abort did not crash")
	}
	if es, _ := w.engineState(); es.Phase != notify.CutoverShadow || w.legacy.enabled || w.legacy.restoreEffects != 0 {
		t.Fatalf("after the abort: engine %s legacy=%v", es.Phase, w.legacy.enabled)
	}
	rb, crashed, err := w.rollback(receipt, reason)
	if crashed || err != nil || rb.Phase != CutoverPhaseDone || !slices.Equal(rb.Completed, rollbackSteps) {
		t.Fatalf("resume: %v %v %+v", crashed, err, rb)
	}
	if !w.legacy.enabled || w.legacy.restoreEffects != 1 || !slices.Equal(w.owners(), []model.ID{w.old}) {
		t.Fatalf("legacy=%v restores=%d owners=%v", w.legacy.enabled, w.legacy.restoreEffects, w.owners())
	}
}

func TestRollbackRefusesAStateFileThatIsNotTheRunsOwn(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	reason := Reason{Code: RollbackReasonOperator, Text: "drill"}
	before := w.snapshot()
	t.Run("a copy of the state file under another name", func(t *testing.T) {
		copyPath := filepath.Join(t.TempDir(), "copy.json")
		raw, err := os.ReadFile(w.plan.StatePath)
		if err != nil || os.WriteFile(copyPath, raw, 0o600) != nil {
			t.Fatal(err)
		}
		r := done
		r.StatePath = copyPath
		if rb, err := Rollback(w.rtctx(), r, reason, w.grant); err == nil || rb.Version != 0 || !strings.Contains(err.Error(), "rollback refused") {
			t.Fatalf("%v %+v", err, rb)
		}
	})
	orig := cutoverCloneState(t, w.state())
	for name, change := range map[string]func(*cutoverState){
		"recorded command IDs of another run": func(st *cutoverState) {
			st.Commands[cutoverCmdLegacyR] = cutoverCommandID("run-2", cutoverCmdLegacyR).String()
		},
		"a recorded plan that does not match its digest": func(st *cutoverState) { st.Plan.ProviderUncertainty = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			st := cutoverCloneState(t, orig)
			change(st)
			st.Checksum = cutoverStateChecksum(*st)
			w.writeState(st)
			rb, err := Rollback(w.rtctx(), done, reason, w.grant)
			if err == nil || rb.Version != 0 || !strings.Contains(err.Error(), "resume refused") {
				t.Fatalf("%v %+v", err, rb)
			}
		})
	}
	w.writeState(orig)
	if got := w.snapshot(); got.commands != before.commands || got.legacy != before.legacy || !w.newActive() {
		t.Fatalf("a refused rollback changed the world: %+v -> %+v", before, got)
	}
}

func TestCutoverReconciliationSeesAStillSendingOldRouteAndDeclaredUncertainty(t *testing.T) {
	t.Run("an old delivery after the quiescence was acknowledged", func(t *testing.T) {
		w := newCutoverWorld(t)
		w.observe("engine.after.new_active", func() {
			w.route.due = append(w.route.due, CutoverDue{ID: "late-old-9031"})
			w.legacy.deliver("late-old-9031")
		})
		rcpt, _, err := w.cutover()
		if err == nil || rcpt.Phase != CutoverPhaseBlocked || rcpt.Reconciliation.OldLate != 1 || !slices.Equal(rcpt.Blockers, []CutoverBlocker{{CutoverBlockOldLate, 1}}) {
			t.Fatalf("err=%v %+v", err, rcpt)
		}
	})
	t.Run("a provider outcome that stays unknown", func(t *testing.T) {
		for name, c := range map[string]struct {
			declared int
			phase    string
		}{"within the declared uncertainty": {1, CutoverPhaseDone}, "beyond the declared uncertainty": {0, CutoverPhaseBlocked}} {
			t.Run(name, func(t *testing.T) {
				w := newCutoverWorld(t)
				w.plan.ProviderUncertainty = c.declared
				w.route.unknown["unknown-id-4417"] = true
				w.observe("legacy.after.QuiesceNormal", func() { w.emit("unknown-id-4417", true) })
				rcpt, _, err := w.cutover()
				if rcpt.Phase != c.phase || rcpt.Reconciliation.Uncertain != 1 || rcpt.Reconciliation.Gaps != 0 || (err == nil) != (c.phase == CutoverPhaseDone) {
					t.Fatalf("err=%v %+v", err, rcpt)
				}
				if c.phase == CutoverPhaseBlocked && !slices.Equal(rcpt.Blockers, []CutoverBlocker{{CutoverBlockUncertainty, 1}}) {
					t.Fatalf("blockers %+v", rcpt.Blockers)
				}
			})
		}
	})
}

func TestRollbackReasonTextBoundaries(t *testing.T) {
	for name, c := range map[string]struct {
		text   string
		accept bool
	}{
		"unit separator":      {"a\x1fb", false},
		"a space":             {" ", true},
		"tilde and non-ASCII": {"~ \u00e9 \u4e2d", true},
		"delete":              {"a\x7fb", false},
		"a tab":               {"a\tb", false},
	} {
		t.Run(name, func(t *testing.T) {
			w := newCutoverWorld(t)
			done := w.mustCutover()
			rb, _, err := w.rollback(done, Reason{Code: RollbackReasonOther, Text: c.text})
			if c.accept {
				if err != nil || rb.Phase != CutoverPhaseDone {
					t.Fatalf("refused: %v %+v", err, rb)
				}
				return
			}
			if err == nil || rb.Version != 0 || !strings.Contains(err.Error(), "invalid rollback reason text") {
				t.Fatalf("the reason was not refused before anything changed: %v %+v", err, rb)
			}
		})
	}
}

// TestCutoverEngineMovedByAnotherOperatorIsAConflictAndNeverAdopted: another
// operator takes the engine to quiescing_old between this run's read and its
// command. The stale revision is an engine conflict, and the resume does not
// adopt a quiescing this run's command did not start: the old route stays
// untouched.
func TestCutoverEngineMovedByAnotherOperatorIsAConflictAndNeverAdopted(t *testing.T) {
	w := newCutoverWorld(t)
	other := notify.CutoverCommand{ID: model.ID{0x99, 0xd0}, ExpectedRevision: 1, Frontier: w.plan.Frontier, OldOwner: w.old, NewOwner: w.nw,
		Phase: notify.CutoverQuiescingOld, Reason: "another operator's command"}
	w.observe("engine.before.quiescing_old", func() {
		if _, err := w.real.AdvanceCutover(w.ctx, w.scope, other); err != nil {
			t.Fatal(err)
		}
	})
	for attempt := 1; attempt <= 2; attempt++ {
		rcpt, crashed, err := w.cutover()
		if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteEngine || !slices.Equal(rcpt.Completed, cutoverSteps[:1]) {
			t.Fatalf("attempt %d: crashed=%v err=%v %+v", attempt, crashed, err, rcpt)
		}
		if len(w.legacy.callsNamed("QuiesceNormal")) != 0 || !w.legacy.enabled {
			t.Fatalf("attempt %d: the old route was touched: %v", attempt, w.legacy.calls)
		}
	}
}

// TestCutoverLiveClaimsRefuseTheBarrierWithHonestAccounting: a delivery claimed
// by the old owner's worker and not completed is a live claim. The evidence
// reports the product's own claimed count, so the engine refuses the barrier
// with exactly that check (not with an accounting mismatch of a convenient zero).
func TestCutoverLiveClaimsRefuseTheBarrierWithHonestAccounting(t *testing.T) {
	w := newCutoverWorld(t)
	ob, lease := w.commitPendingDecision(false)
	claimed, err := ob.Claim(w.ctx, w.scope, w.clock.Now(), lease, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("fixture claim: %v %d", err, len(claimed))
	}
	rcpt, _, err := w.cutover()
	if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteBarrier || !slices.Equal(rcpt.Completed, cutoverSteps[:2]) {
		t.Fatalf("err=%v %+v", err, rcpt)
	}
	if !strings.Contains(err.Error(), "claims_live") || strings.Contains(err.Error(), "accounting_claimed") {
		t.Fatalf("the barrier evidence must carry the engine's own claimed count: %v", err)
	}
	if w.newActive() || len(w.owners()) > 1 {
		t.Fatalf("owners %v", w.owners())
	}
}

// TestCutoverNeverRecordsTheBarrierWhileTheOldRouteIsEnabled: the engine cannot
// see the legacy route, so the tool must not hand it barrier evidence when the
// route is observed enabled again after its quiescence was acknowledged.
func TestCutoverNeverRecordsTheBarrierWhileTheOldRouteIsEnabled(t *testing.T) {
	w := newCutoverWorld(t)
	calls := 0
	w.observe("deadman.Proof", func() {
		if calls++; calls == 2 { // the end of the quiescence phase
			w.legacy.enabled = true
		}
	})
	rcpt, _, err := w.cutover()
	if err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteLegacyEnabled || !slices.Equal(rcpt.Completed, cutoverSteps[:2]) {
		t.Fatalf("err=%v %+v", err, rcpt)
	}
	if es, _ := w.engineState(); es.Phase != notify.CutoverQuiescingOld || !slices.Equal(w.owners(), []model.ID{w.old}) {
		t.Fatalf("the barrier was recorded: engine %s owners %v", es.Phase, w.owners())
	}
	w.legacy.enabled = false // the operator disables it again
	w.assertConverged(w.mustCutover())
}
