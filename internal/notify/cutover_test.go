// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// These tests drive the ownership cutover over the REAL control store (the
// activated single-voter Raft group, real auth scopes, the real delivery
// handler that carries the cutover arm) and, for leader loss, over the real
// three-voter group of worker_test.go. The old owner is an abstract external
// system: the fixtures only ever hand the product evidence about it.

type cutoverFx struct {
	*node
	cut      *notify.CutoverService
	old, nw  model.ID
	observer model.ID
	domain   model.ID
	product  model.ID
	source   model.ID
	grp      model.ID
	cmdSeq   int
	ob       *notify.Outbox
	p        *provider
	w        *notify.Worker
	// tQuiesce is when quiescing_old was last entered.
	tQuiesce model.UnixNano
}

const (
	srcVersion = model.Revision(3)
	srcIndex   = uint64(100)
)

func newCutoverFx(t *testing.T) *cutoverFx {
	t.Helper()
	return newCutoverFxOn(t, newNode(t))
}

func newCutoverFxOn(t *testing.T, n *node) *cutoverFx {
	t.Helper()
	cut, err := notify.NewCutoverService(n.store, n.clock)
	if err != nil {
		t.Fatal(err)
	}
	fx := &cutoverFx{node: n, cut: cut, old: model.ID{0x01, 0xd0}, nw: model.ID{0x02, 0xd0}, observer: model.ID{0x03, 0xd0}, domain: model.ID{0x04, 0xd0}, product: model.ID{0x05, 0xd0},
		source: model.ID{0x06, 0xd0}, grp: model.ID{0x07, 0xd0}}
	fx.seed(srcVersion, srcIndex)
	fx.ob = n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	fx.p = &provider{}
	fx.w = n.worker(fx.ob, fx.p)
	return fx
}

// seed commits the source the frontier names (at version) and the project's
// committed checkpoint for the group (through index): the facts a barrier is
// verified against.
func (fx *cutoverFx) seed(version model.Revision, index uint64) {
	fx.t.Helper()
	if err := fx.store.Update(fx.ctx, func(st *control.State) error {
		if st.Sources == nil {
			st.Sources = map[string]model.SourceAuthority{}
		}
		st.Sources[fx.source.String()] = model.SourceAuthority{ID: fx.source, Org: fx.org, Project: fx.project, CredentialID: model.ID{0x08, 0xd0}, Policy: model.SourcePolicy{Revision: version, Enabled: true}}
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		raw, err := json.Marshal(control.IssueBook{Org: fx.org, Project: fx.project, Revision: 1, Checkpoints: map[string]model.Uint64{fx.grp.String(): model.Uint64(index)}})
		st.IssueBooks[fx.org.String()+":"+fx.project.String()] = raw
		return err
	}); err != nil {
		fx.t.Fatal(err)
	}
}

func hashOf(s string) model.Hash { return model.Hash(sha256.Sum256([]byte(s))) }

func (fx *cutoverFx) frontier(index uint64) []notify.FrontierEntry {
	return []notify.FrontierEntry{{Source: fx.source, Version: srcVersion, Cursor: model.Cursor{Group: fx.grp, Index: model.Uint64(index)}}}
}

func (fx *cutoverFx) state() (notify.CutoverState, bool) {
	fx.t.Helper()
	s, ok, err := fx.cut.Cutover(fx.ctx, fx.scope())
	if err != nil {
		fx.t.Fatal(err)
	}
	return s, ok
}

// reopen is a process death and restart of the node: the services over the store
// are rebuilt, the provider (the outside world) is not.
func (fx *cutoverFx) reopen() {
	fx.t.Helper()
	fx.restart()
	cut, err := notify.NewCutoverService(fx.store, fx.clock)
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.cut = cut
	fx.ob = fx.node.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	fx.w = fx.node.worker(fx.ob, fx.p)
}

func (fx *cutoverFx) mustState() notify.CutoverState {
	fx.t.Helper()
	s, ok := fx.state()
	if !ok {
		fx.t.Fatal("no cutover")
	}
	return s
}

func (fx *cutoverFx) newID() model.ID {
	fx.cmdSeq++
	return model.ID{0xcc, byte(fx.cmdSeq >> 8), byte(fx.cmdSeq)}
}

func (fx *cutoverFx) facts() notify.CutoverFacts {
	fx.t.Helper()
	f, err := fx.cut.Facts(fx.ctx, fx.scope())
	if err != nil {
		fx.t.Fatal(err)
	}
	return f
}

// evidence is what the adoption flow supplies when everything holds: fresh,
// bound to the current cutover and revision, accounting equal to the committed
// facts. Mods then break exactly one thing.
func (fx *cutoverFx) evidence(phase notify.CutoverPhase, mods ...func(*cutoverFx, *notify.BarrierEvidence)) *notify.BarrierEvidence {
	fx.t.Helper()
	st, _ := fx.state()
	facts := fx.facts()
	now := fx.clock.Now()
	ev := &notify.BarrierEvidence{
		Cutover: st.Cutover, ForRevision: st.Revision, ManifestDigest: notify.ManifestDigest(fx.frontier(srcIndex)),
		Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
		Authorization: &notify.Authorization{Principal: fx.user, Ref: hashOf("authorization"), AuthorizedAt: now - 60*sec, ExpiresAt: now + 3600*sec},
		Route:         &notify.RollbackRoute{Owner: fx.old, Ref: hashOf("route")},
		Observer:      &notify.ObserverProof{Observer: fx.observer, Domain: fx.domain, ProductDomain: fx.product, ObservedAt: now - 10*sec, Ref: hashOf("observer")},
	}
	if phase != notify.CutoverOldActive {
		ev.Owner = &notify.OwnerEvidence{Owner: fx.old, Method: "scheduler_disabled", ObservedAt: now - 5*sec, Ref: hashOf("owner")}
	}
	for _, m := range mods {
		m(fx, ev)
	}
	return ev
}

func needsEvidence(p notify.CutoverPhase) bool {
	return p == notify.CutoverBarrierVerified || p == notify.CutoverNewActive || p == notify.CutoverOldActive
}

// command builds the next command for the phase from the current state.
func (fx *cutoverFx) command(phase notify.CutoverPhase, mods ...func(*cutoverFx, *notify.BarrierEvidence)) notify.CutoverCommand {
	fx.t.Helper()
	st, _ := fx.state()
	c := notify.CutoverCommand{ID: fx.newID(), ExpectedRevision: st.Revision, Frontier: fx.frontier(srcIndex), OldOwner: fx.old, NewOwner: fx.nw, Phase: phase, Reason: "operator reason: maintenance window"}
	if needsEvidence(phase) {
		c.Evidence = fx.evidence(phase, mods...)
	}
	return c
}

func (fx *cutoverFx) try(c notify.CutoverCommand) (notify.CutoverState, error) {
	fx.t.Helper()
	return fx.cut.AdvanceCutover(fx.ctx, fx.scope(), c)
}

// advance commits one transition that must succeed, then lets the clock move on
// so later evidence is observed after it.
func (fx *cutoverFx) advance(phase notify.CutoverPhase, mods ...func(*cutoverFx, *notify.BarrierEvidence)) notify.CutoverState {
	fx.t.Helper()
	s, err := fx.try(fx.command(phase, mods...))
	if err != nil {
		fx.t.Fatalf("advance to %s: %v", phase, err)
	}
	if s.Phase != phase {
		fx.t.Fatalf("advanced to %s, state says %s", phase, s.Phase)
	}
	if phase == notify.CutoverQuiescingOld {
		fx.tQuiesce = s.EnteredAt
	}
	fx.clock.add(30 * sec)
	return s
}

// forward walks shadow -> quiescing_old -> barrier_verified -> new_active.
func (fx *cutoverFx) forward() notify.CutoverState {
	fx.t.Helper()
	fx.advance(notify.CutoverShadow)
	fx.advance(notify.CutoverQuiescingOld)
	fx.advance(notify.CutoverBarrierVerified)
	return fx.advance(notify.CutoverNewActive)
}

func code(err error) model.Code {
	c, _ := faultOf(err)
	return c
}

func checksOf(err error) []string {
	var b *notify.BarrierError
	if errors.As(err, &b) {
		return b.Checks
	}
	return nil
}

func (fx *cutoverFx) sends() int { return fx.p.total() }

// runWorker is one worker pass at the clock's instant.
func (fx *cutoverFx) runWorker() notify.RunReport {
	fx.t.Helper()
	r, err := fx.run(fx.w, fx.clock.Now())
	if err != nil {
		fx.t.Fatalf("worker run: %v", err)
	}
	return r
}

func (fx *cutoverFx) policyState() notify.PolicyState {
	fx.t.Helper()
	rec, found, err := fx.store.PolicyRecord(fx.ctx, fx.scope(), fx.project, fx.policy, "incident:"+incident.ID.String())
	if err != nil || !found {
		fx.t.Fatalf("policy record: %v %v", found, err)
	}
	var st notify.PolicyState
	if err = json.Unmarshal(rec.State, &st); err != nil {
		fx.t.Fatal(err)
	}
	return st
}

// submit decides one event against the committed state, naming its committed
// canonical-owner revision.
func (fx *cutoverFx) submit(ev notify.PolicyEvent, at model.UnixNano) (notify.Submission, error) {
	fx.t.Helper()
	if _, found, _ := fx.store.PolicyRecord(fx.ctx, fx.scope(), fx.project, fx.policy, "incident:"+incident.ID.String()); found {
		ev.OwnerRevision = fx.policyState().OwnerRevision
	}
	return fx.ob.Submit(fx.ctx, fx.scope(), fx.lease(), incident, ev, at)
}

func (fx *cutoverFx) mustSubmit(ev notify.PolicyEvent, at model.UnixNano) notify.Submission {
	fx.t.Helper()
	s, err := fx.submit(ev, at)
	if err != nil {
		fx.t.Fatal(err)
	}
	return s
}

// syncModes applies the cutover phase to the policy states.
func (fx *cutoverFx) syncModes(s notify.CutoverState) int {
	fx.t.Helper()
	n, err := fx.ob.SyncModes(fx.ctx, fx.scope(), fx.lease(), s.Phase, s.Cutover, s.Revision, fx.clock.Now())
	if err != nil {
		fx.t.Fatal("sync modes:", err)
	}
	return n
}

func (fx *cutoverFx) deliveries() []control.DeliveryRecord {
	fx.t.Helper()
	recs, err := fx.store.Deliveries(fx.ctx, fx.scope(), fx.project, "", fx.clock.Now(), 0)
	if err != nil {
		fx.t.Fatal(err)
	}
	return recs
}

func (fx *cutoverFx) countBy(kind string, phase string) int {
	n := 0
	for _, r := range fx.deliveries() {
		if (kind == "" || r.Kind == kind) && (phase == "" || r.Phase == phase) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// The named test: one normal owner at every barrier.

// TestCutoverSingleNormalOwner walks the whole journey with a real worker and a
// recording provider. At every phase at most one normal owner is active, and the
// product sends if and only if it is that owner.
func TestCutoverSingleNormalOwner(t *testing.T) {
	fx := newCutoverFx(t)
	// A decision committed before the cutover exists: a pending delivery the old
	// owner is already handling.
	if _, err := fx.openAndQueue(fx.ob); err != nil {
		t.Fatal(err)
	}
	if pre := fx.openRecord(fx.ob); pre.Phase != control.DeliveryPending {
		t.Fatalf("fixture: the opening is %s", pre.Phase)
	}

	check := func(s notify.CutoverState, want []model.ID, mayDeliver bool) {
		t.Helper()
		if len(s.ActiveOwners) > 1 {
			t.Fatalf("%s: %d active normal owners: %v", s.Phase, len(s.ActiveOwners), s.ActiveOwners)
		}
		if !slices.Equal(s.ActiveOwners, want) {
			t.Fatalf("%s: active owners %v, want %v", s.Phase, s.ActiveOwners, want)
		}
		if got := notify.ActiveOwners(s.Phase, fx.old, fx.nw); !slices.Equal(got, want) {
			t.Fatalf("%s: ActiveOwners() = %v, want %v", s.Phase, got, want)
		}
		if isNew := len(s.ActiveOwners) == 1 && s.ActiveOwners[0] == fx.nw; mayDeliver != isNew {
			t.Fatalf("%s: the product may deliver (%v) iff it is the one active owner (%v)", s.Phase, mayDeliver, isNew)
		}
		if notify.ModeFor(s.Phase) == notify.ModeActive != mayDeliver {
			t.Fatalf("%s: delivery mode %s disagrees with the ownership", s.Phase, notify.ModeFor(s.Phase))
		}
		if !mayDeliver {
			before := fx.sends()
			fx.clock.add(sec)
			fx.runWorker()
			if sent := fx.sends() - before; sent != 0 {
				t.Fatalf("%s: the product sent %d messages although it is not the active owner", s.Phase, sent)
			}
		}
	}

	s := fx.advance(notify.CutoverShadow)
	check(s, []model.ID{fx.old}, false)
	if got := fx.openRecord(fx.ob); got.Phase != control.DeliveryPending || len(got.Attempts) != 0 {
		t.Fatalf("shadow: the pre-existing delivery was claimed: %+v", got)
	}
	s = fx.advance(notify.CutoverQuiescingOld)
	check(s, []model.ID{fx.old}, false)
	s = fx.advance(notify.CutoverBarrierVerified)
	check(s, nil, false)
	if fx.sends() != 0 {
		t.Fatalf("before the new owner is active the provider saw %d sends", fx.sends())
	}
	s = fx.advance(notify.CutoverNewActive)
	check(s, []model.ID{fx.nw}, true)
	// The backlog of the old owner is not sent retroactively: it is revoked.
	if got := fx.openRecord(fx.ob); got.Phase != control.DeliveryCancelled || got.Code != control.DeliveryReasonRevoked {
		t.Fatalf("new_active: the pre-existing delivery is %s/%s, want cancelled/revoked", got.Phase, got.Code)
	}
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("the old owner's backlog was sent by the new owner: %d sends", fx.sends())
	}
	// New evidence now delivers, once.
	fx.syncModes(s)
	fx.mustSubmit(fx.incidentEvent(2, notify.SeverityCritical, 2), fx.clock.Now())
	if r := fx.runWorker(); len(r.Accepted) == 0 || fx.sends() == 0 {
		t.Fatalf("new_active: nothing was delivered: %+v", r)
	}
	sent := fx.sends()

	s = fx.advance(notify.CutoverRollbackQuiescing)
	check(s, nil, false)
	fx.syncModes(s)
	fx.mustSubmit(fx.incidentEvent(3, notify.SeverityCritical, 3), fx.clock.Now())
	fx.runWorker()
	s = fx.advance(notify.CutoverOldActive)
	check(s, []model.ID{fx.old}, false)
	if fx.sends() != sent {
		t.Fatalf("after the rollback began the product sent %d more messages", fx.sends()-sent)
	}

	// The sanitized timeline names every transition and nothing the operator typed.
	want := []notify.CutoverPhase{notify.CutoverShadow, notify.CutoverQuiescingOld, notify.CutoverBarrierVerified, notify.CutoverNewActive, notify.CutoverRollbackQuiescing, notify.CutoverOldActive}
	if len(s.Timeline) != len(want) {
		t.Fatalf("timeline has %d entries, want %d: %+v", len(s.Timeline), len(want), s.Timeline)
	}
	for i, e := range s.Timeline {
		if e.To != want[i] || e.Revision != model.Revision(i+1) || e.Principal != fx.user {
			t.Fatalf("timeline[%d] = %+v, want to=%s revision=%d", i, e, want[i], i+1)
		}
		if i > 0 && e.From != want[i-1] {
			t.Fatalf("timeline[%d].From = %s, want %s", i, e.From, want[i-1])
		}
	}
	raw, _ := json.Marshal(s.Timeline)
	if strings.Contains(string(raw), "operator reason") {
		t.Fatalf("the timeline carries the operator's text: %s", raw)
	}
	if s.Epoch != 1 {
		t.Fatalf("epoch %d after one activation, want 1", s.Epoch)
	}
}

// ---------------------------------------------------------------------------
// The new owner can never be enabled before a verified old-owner barrier.

func TestCutoverEnablingTheNewOwnerBeforeTheBarrierIsRejected(t *testing.T) {
	fx := newCutoverFx(t)
	// No record at all: the first command can only start the shadow.
	for _, phase := range []notify.CutoverPhase{notify.CutoverQuiescingOld, notify.CutoverBarrierVerified, notify.CutoverNewActive, notify.CutoverRollbackQuiescing, notify.CutoverOldActive} {
		if _, err := fx.try(fx.command(phase)); err == nil {
			t.Fatalf("a cutover that does not exist yet was started in %s", phase)
		}
	}
	if _, ok := fx.state(); ok {
		t.Fatal("a refused first command created a cutover")
	}
	fx.advance(notify.CutoverShadow)
	for _, from := range []notify.CutoverPhase{notify.CutoverShadow, notify.CutoverQuiescingOld} {
		if from == notify.CutoverQuiescingOld {
			fx.advance(from)
		}
		before := fx.mustState()
		// Even with flawless evidence the new owner cannot jump the barrier.
		_, err := fx.try(fx.command(notify.CutoverNewActive))
		if err == nil {
			t.Fatalf("from %s: new_active was accepted before the barrier was verified", from)
		}
		if code(err) != model.Conflict {
			t.Fatalf("from %s: %v, want a conflict", from, err)
		}
		after := fx.mustState()
		if after.Revision != before.Revision || after.Phase != before.Phase || len(after.ActiveOwners) != 1 || after.ActiveOwners[0] != fx.old {
			t.Fatalf("from %s: a refused command changed the state: %+v -> %+v", from, before, after)
		}
	}
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("the provider saw %d sends", fx.sends())
	}
}

// Every part of the barrier evidence is verified. Each defect is refused with the
// closed code of the failed check, leaves the state untouched, and a flawless
// retry then succeeds.
func TestCutoverBarrierVerification(t *testing.T) {
	type mod = func(*cutoverFx, *notify.BarrierEvidence)
	owner := func(f func(*cutoverFx, *notify.OwnerEvidence)) mod {
		return func(fx *cutoverFx, e *notify.BarrierEvidence) {
			if e.Owner != nil {
				f(fx, e.Owner)
			}
		}
	}
	plain := func(f func(*notify.BarrierEvidence)) mod {
		return func(_ *cutoverFx, e *notify.BarrierEvidence) { f(e) }
	}
	type defect struct {
		name string
		mod  mod
		cmd  func(*notify.CutoverCommand)
		// pre runs before the cutover starts (a live claim has to exist before the
		// shadow gates claims); such a case never gets as far as new_active.
		pre  func(*cutoverFx)
		want []string
	}
	cases := []defect{
		{name: "no evidence at all", cmd: func(c *notify.CutoverCommand) { c.Evidence = nil }, want: []string{"evidence_missing"}},
		{name: "evidence of another cutover", mod: plain(func(e *notify.BarrierEvidence) { e.Cutover = model.ID{0xee} }), want: []string{"evidence_binding"}},
		{name: "evidence prepared for an older revision", mod: plain(func(e *notify.BarrierEvidence) { e.ForRevision-- }), want: []string{"evidence_binding"}},
		{name: "evidence for another manifest", mod: plain(func(e *notify.BarrierEvidence) { e.ManifestDigest = hashOf("other manifest") }), want: []string{"manifest_digest"}},
		{name: "old owner not evidenced", mod: plain(func(e *notify.BarrierEvidence) { e.Owner = nil }), want: []string{"owner_evidence"}},
		{name: "evidence names the new owner as the disabled one", mod: owner(func(fx *cutoverFx, o *notify.OwnerEvidence) { o.Owner = fx.nw }), want: []string{"owner_evidence"}},
		{name: "disabled evidence without a method", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.Method = "" }), want: []string{"owner_evidence"}},
		{name: "disabled evidence without a reference", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.Ref = model.Hash{} }), want: []string{"owner_evidence"}},
		{name: "old owner observation too old", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.ObservedAt -= model.UnixNano(2 * time.Hour) }), want: []string{"owner_stale"}},
		{name: "old owner observed before the quiescing began", mod: owner(func(fx *cutoverFx, o *notify.OwnerEvidence) { o.ObservedAt = fx.tQuiesce - sec }), want: []string{"owner_stale"}},
		{name: "old owner observation in the future", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.ObservedAt += model.UnixNano(time.Hour) }), want: []string{"owner_stale"}},
		{name: "old owner still has pending sends", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.Pending = 2 }), want: []string{"owner_pending"}},
		{name: "old owner unknown sends not reviewed", mod: owner(func(_ *cutoverFx, o *notify.OwnerEvidence) { o.Unknown = 1 }), want: []string{"unknown_unreviewed"}},
		{name: "pending accounting does not match the committed deliveries", mod: plain(func(e *notify.BarrierEvidence) { e.Accounting.Pending += 3 }), want: []string{"accounting_pending"}},
		{name: "unknown accounting does not match", mod: plain(func(e *notify.BarrierEvidence) { e.Accounting.Unknown = 2; e.Accounting.Reviewed = true }), want: []string{"accounting_unknown"}},
		{name: "unknown set digest does not match", mod: plain(func(e *notify.BarrierEvidence) { e.Accounting.UnknownDigest = hashOf("not the set") }), want: []string{"accounting_unknown"}},
		{name: "a live claim of the product", pre: func(fx *cutoverFx) { fx.liveClaim() }, want: []string{"claims_live"}},
		{name: "a live claim claimed to be dead", pre: func(fx *cutoverFx) { fx.liveClaim() }, mod: plain(func(e *notify.BarrierEvidence) { e.Accounting.Claimed = 0 }), want: []string{"claims_live", "accounting_claimed"}},
		{name: "authorization of another principal", mod: plain(func(e *notify.BarrierEvidence) { e.Authorization.Principal = model.ID{0xaa} }), want: []string{"authorization"}},
		{name: "authorization without a reference", mod: plain(func(e *notify.BarrierEvidence) { e.Authorization.Ref = model.Hash{} }), want: []string{"authorization"}},
		{name: "authorization not yet valid", mod: plain(func(e *notify.BarrierEvidence) {
			e.Authorization.AuthorizedAt += model.UnixNano(time.Hour)
			e.Authorization.ExpiresAt += model.UnixNano(2 * time.Hour)
		}), want: []string{"authorization"}},
		{name: "authorization expired", mod: plain(func(e *notify.BarrierEvidence) { e.Authorization.ExpiresAt = e.Authorization.AuthorizedAt + sec }), want: []string{"authorization"}},
		{name: "authorization window longer than a day", mod: plain(func(e *notify.BarrierEvidence) { e.Authorization.ExpiresAt += model.UnixNano(48 * time.Hour) }), want: []string{"authorization"}},
		{name: "rollback route to another owner", mod: func(fx *cutoverFx, e *notify.BarrierEvidence) { e.Route.Owner = fx.nw }, want: []string{"route"}},
		{name: "rollback route without a reference", mod: plain(func(e *notify.BarrierEvidence) { e.Route.Ref = model.Hash{} }), want: []string{"route"}},
		{name: "observer unknown", mod: plain(func(e *notify.BarrierEvidence) { e.Observer = nil }), want: []string{"observer"}},
		{name: "observer proof stale", mod: plain(func(e *notify.BarrierEvidence) { e.Observer.ObservedAt -= model.UnixNano(time.Hour) }), want: []string{"observer_stale"}},
		{name: "observer proof in the future", mod: plain(func(e *notify.BarrierEvidence) { e.Observer.ObservedAt += model.UnixNano(time.Hour) }), want: []string{"observer_stale"}},
		{name: "observer in the product's own failure domain", mod: plain(func(e *notify.BarrierEvidence) { e.Observer.Domain = e.Observer.ProductDomain }), want: []string{"observer_domain"}},
		{name: "observer is one of the owners", mod: func(fx *cutoverFx, e *notify.BarrierEvidence) { e.Observer.Observer = fx.old }, want: []string{"observer_domain"}},
		{name: "frontier of an unknown source", cmd: func(c *notify.CutoverCommand) {
			c.Frontier = append(c.Frontier, notify.FrontierEntry{Source: model.ID{0xbb}, Version: 1, Cursor: model.Cursor{Group: model.ID{0x07, 0xd0}, Index: 1}})
		}, want: []string{"source_unknown"}},
		{name: "frontier at another source version", cmd: func(c *notify.CutoverCommand) { c.Frontier[0].Version++ }, want: []string{"source_version"}},
		{name: "frontier ahead of the committed checkpoint", cmd: func(c *notify.CutoverCommand) { c.Frontier[0].Cursor.Index++ }, want: []string{"checkpoint_behind"}},
		{name: "frontier of a group with no checkpoint", cmd: func(c *notify.CutoverCommand) { c.Frontier[0].Cursor.Group = model.ID{0xcd} }, want: []string{"checkpoint_behind"}},
	}
	frontierDefect := func(tc defect) bool { return strings.HasPrefix(tc.name, "frontier") }
	for _, tc := range cases {
		for _, phase := range []notify.CutoverPhase{notify.CutoverBarrierVerified, notify.CutoverNewActive} {
			if tc.pre != nil && phase == notify.CutoverNewActive {
				continue
			}
			t.Run(fmt.Sprintf("%s into %s", tc.name, phase), func(t *testing.T) {
				fx := newCutoverFx(t)
				if tc.pre != nil {
					tc.pre(fx)
				}
				fx.advance(notify.CutoverShadow)
				fx.advance(notify.CutoverQuiescingOld)
				if phase == notify.CutoverNewActive {
					fx.advance(notify.CutoverBarrierVerified, func(fx *cutoverFx, _ *notify.BarrierEvidence) {})
				}
				var mods []func(*cutoverFx, *notify.BarrierEvidence)
				if tc.mod != nil {
					mods = append(mods, tc.mod)
				}
				c := fx.command(phase, mods...)
				if tc.cmd != nil {
					tc.cmd(&c)
					if c.Evidence != nil && frontierDefect(tc) {
						c.Evidence.ManifestDigest = notify.ManifestDigest(c.Frontier)
					}
				}
				before := fx.mustState()
				_, err := fx.try(c)
				if err == nil {
					t.Fatalf("a defective barrier was accepted: %s", tc.name)
				}
				for _, want := range tc.want {
					if !slices.Contains(checksOf(err), want) {
						t.Fatalf("checks %v (%v), want %q among them", checksOf(err), err, want)
					}
				}
				after := fx.mustState()
				if after.Revision != before.Revision || after.Phase != before.Phase || len(after.Timeline) != len(before.Timeline) {
					t.Fatalf("a refused barrier changed the state: %+v -> %+v", before, after)
				}
				fx.runWorker()
				if fx.sends() != 0 {
					t.Fatalf("the provider saw %d sends", fx.sends())
				}
				if tc.pre != nil {
					return // a live claim cannot be made flawless inside the test's clock
				}
				if _, err = fx.try(fx.command(phase)); err != nil {
					t.Fatalf("flawless evidence refused after the defect: %v", err)
				}
			})
		}
	}
}

// liveClaim leaves one live claim of the product on the project: a delivery
// decided before the cutover that a worker leased, whose send never completed.
func (fx *cutoverFx) liveClaim() {
	fx.t.Helper()
	if _, err := fx.openAndQueue(fx.ob); err != nil {
		fx.t.Fatal(err)
	}
	got, err := fx.ob.Claim(fx.ctx, fx.scope(), fx.clock.Now(), fx.lease(), 4)
	if err != nil || len(got) != 1 {
		fx.t.Fatalf("fixture claim: %v %d", err, len(got))
	}
}

// ---------------------------------------------------------------------------
// Rollback ordering.

func (fx *cutoverFx) decideOpening() {
	fx.t.Helper()
	now := fx.clock.Now()
	fx.mustSubmit(fx.destinationEvent(), now)
	fx.mustSubmit(fx.incidentEvent(1, notify.SeverityMajor, 1), now)
}

func (fx *cutoverFx) rawClaim(owner model.Revision, now model.UnixNano) (control.Result, error) {
	fx.t.Helper()
	lease := fx.lease()
	raw, _ := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
		Claim: &control.DeliveryClaim{Project: fx.project, Now: now, Expires: now + 60*sec, Limit: 8, OwnerRevision: owner}})
	return fx.store.Transact(fx.ctx, fx.scope(), control.Command{CommandID: model.NewID(), ExpectedRevision: fx.revision(), Kind: string(control.KindClaimDelivery), Payload: raw})
}

// Rollback cannot reactivate the old owner while the new owner still has a live
// claim, and not before the unknown sends are accounted for; the transition
// straight from new_active is refused outright.
func TestCutoverRollbackCannotReactivateTheOldOwnerBeforeTheNewOneQuiesces(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	// The new owner's worker leased the opening (a live claim: its send may be in
	// flight right now).
	got, err := fx.ob.Claim(fx.ctx, fx.scope(), fx.clock.Now(), fx.lease(), 4)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v %d", err, len(got))
	}
	d := got[0].ID

	// new_active -> old_active directly is no rollback at all.
	before := fx.mustState()
	if _, err = fx.try(fx.command(notify.CutoverOldActive)); err == nil || code(err) != model.Conflict {
		t.Fatalf("the old owner was reactivated straight from new_active: %v", err)
	}
	if after := fx.mustState(); after.Revision != before.Revision || after.Phase != notify.CutoverNewActive {
		t.Fatalf("a refused rollback changed the state: %+v", after)
	}

	s = fx.advance(notify.CutoverRollbackQuiescing)
	if len(s.ActiveOwners) != 0 {
		t.Fatalf("rollback_quiescing has active owners %v", s.ActiveOwners)
	}
	// The new owner's claim is still live: it is not quiesced.
	_, err = fx.try(fx.command(notify.CutoverOldActive))
	if err == nil || !slices.Contains(checksOf(err), "claims_live") {
		t.Fatalf("old_active accepted with a live claim of the new owner: %v (%v)", err, checksOf(err))
	}
	if fx.mustState().Phase != notify.CutoverRollbackQuiescing {
		t.Fatal("the refused rollback moved the phase")
	}

	// The lease lapses with no completion: the claim is an unknown send now.
	fx.clock.add(3 * 60 * sec)
	facts := fx.facts()
	if facts.Claimed != 0 || facts.Unknown != 1 {
		t.Fatalf("facts after the lapse: %+v", facts)
	}
	for name, mod := range map[string]func(*cutoverFx, *notify.BarrierEvidence){
		"unknown sends not reviewed":  func(_ *cutoverFx, e *notify.BarrierEvidence) { e.Accounting.Reviewed = false },
		"unknown set digest is wrong": func(_ *cutoverFx, e *notify.BarrierEvidence) { e.Accounting.UnknownDigest = hashOf("other") },
		"unknown not counted": func(_ *cutoverFx, e *notify.BarrierEvidence) {
			e.Accounting.Unknown = 0
			e.Accounting.UnknownDigest = model.Hash{}
		},
	} {
		if _, err = fx.try(fx.command(notify.CutoverOldActive, mod)); err == nil {
			t.Fatalf("%s: the old owner was reactivated", name)
		}
	}
	// The product never sent for the leased delivery while all of this happened.
	if fx.sends() != 0 {
		t.Fatalf("the provider saw %d sends", fx.sends())
	}
	s = fx.advance(notify.CutoverOldActive)
	if len(s.ActiveOwners) != 1 || s.ActiveOwners[0] != fx.old {
		t.Fatalf("old_active owners: %v", s.ActiveOwners)
	}
	// The unknown send stays visible as uncertain: it is never retried and never
	// turned into success.
	rec := fx.record(fx.ob, d)
	if rec.Phase != control.DeliveryUncertain || !rec.Uncertain || len(rec.Attempts) != 1 || rec.Attempts[0].Outcome != control.DeliveryOutcomeUnknown {
		t.Fatalf("the unknown claim after the rollback: %+v", rec)
	}
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("after the rollback the provider saw %d sends", fx.sends())
	}
}

// Leadership of the cutover is not needed to stop a send: a rollback that begins
// between the claim and the send stops that very send at the worker's own
// pre-send check.
func TestCutoverRollbackBetweenClaimAndSendNeverSends(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	q := &hookQueue{Queue: fx.ob}
	q.afterClaim = func(d []notify.Delivery) {
		if len(d) != 1 {
			t.Errorf("claimed %d", len(d))
			return
		}
		fx.advance(notify.CutoverRollbackQuiescing)
	}
	w := fx.worker(q, fx.p)
	report := fx.mustRun(w, fx.clock.Now())
	if fx.sends() != 0 {
		t.Fatalf("a send went out after the rollback began: %+v", report)
	}
	if len(report.Cancelled) != 1 || len(report.Accepted) != 0 {
		t.Fatalf("report: %+v", report)
	}
	rec := fx.openRecord(fx.ob)
	if rec.Phase != control.DeliveryCancelled || rec.Code != control.DeliveryReasonRevoked || len(rec.Attempts) != 1 || rec.Attempts[0].Outcome != control.DeliveryOutcomeTerminal || rec.Uncertain {
		t.Fatalf("the interrupted delivery: %+v", rec)
	}
}

// ---------------------------------------------------------------------------
// Expected revision, command reuse and racing commands.

func TestCutoverStaleRevisionConflictsAndReusedCommandReturnsTheOriginalResult(t *testing.T) {
	fx := newCutoverFx(t)
	fx.advance(notify.CutoverShadow)
	fx.advance(notify.CutoverQuiescingOld)

	stale := fx.command(notify.CutoverBarrierVerified)
	stale.ExpectedRevision = 1
	_, err := fx.try(stale)
	cur, ok := notify.CutoverCurrent(err)
	if err == nil || !ok || cur != 2 || code(err) != model.Conflict {
		t.Fatalf("a stale expected revision: %v (current %d, %v)", err, cur, ok)
	}
	var conflict *notify.CutoverConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("not a typed conflict: %T", err)
	}
	// A stale revision from an old owner's flow gains nothing: the state is intact.
	if s := fx.mustState(); s.Revision != 2 || s.Phase != notify.CutoverQuiescingOld {
		t.Fatalf("a stale command changed the state: %+v", s)
	}

	c := fx.command(notify.CutoverBarrierVerified)
	first, err := fx.try(c)
	if err != nil || first.Revision != 3 || first.Replayed {
		t.Fatalf("barrier: %+v %v", first, err)
	}
	fx.clock.add(30 * sec)
	fx.advance(notify.CutoverNewActive)

	// The same command again, long after the state moved on: the ORIGINAL result,
	// nothing applied twice.
	again, err := fx.try(c)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !again.Replayed || again.Revision != 3 || again.Phase != notify.CutoverBarrierVerified || len(again.ActiveOwners) != 0 || len(again.Timeline) != 3 {
		t.Fatalf("the replay did not return the original result: %+v", again)
	}
	if cur := fx.mustState(); cur.Revision != 4 || cur.Phase != notify.CutoverNewActive || len(cur.Timeline) != 4 {
		t.Fatalf("the replay changed the state: %+v", cur)
	}
	// A reused ID with another request is a conflict, never the original result.
	other := c
	other.Phase = notify.CutoverNewActive
	if _, err = fx.try(other); err == nil || code(err) != model.Conflict {
		t.Fatalf("a reused command ID with other content: %v", err)
	}
	if reason, ok := notify.ReasonOf(err); !ok || reason != notify.ReasonCutoverReused {
		t.Fatalf("reason %q %v", reason, ok)
	}
	// The result survives a process restart.
	fx.reopen()
	if again, err = fx.try(c); err != nil || !again.Replayed || again.Revision != 3 {
		t.Fatalf("replay after restart: %+v %v", again, err)
	}
}

// Racing operators, one expected revision: exactly one wins, the others learn the
// current revision. The same command racing itself applies once.
func TestCutoverRacingAdvancesResolveByExpectedRevision(t *testing.T) {
	fx := newCutoverFx(t)
	fx.advance(notify.CutoverShadow)
	const racers = 8
	cmds := make([]notify.CutoverCommand, racers)
	scopes := make([]auth.Scope, racers)
	for i := range cmds {
		cmds[i] = fx.command(notify.CutoverQuiescingOld)
		scopes[i] = fx.scope()
	}
	results := make([]error, racers)
	var wg sync.WaitGroup
	for i := range cmds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = fx.cut.AdvanceCutover(fx.ctx, scopes[i], cmds[i])
		}()
	}
	wg.Wait()
	wins := 0
	for i, err := range results {
		switch cur, ok := notify.CutoverCurrent(err); {
		case err == nil:
			wins++
		case ok && cur == 2:
		default:
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d racers won one expected revision", wins)
	}
	if s := fx.mustState(); s.Revision != 2 || len(s.Timeline) != 2 {
		t.Fatalf("state after the race: %+v", s)
	}

	// One command, many deliveries of it (lost responses, a retrying client): once.
	fx.clock.add(30 * sec)
	same := fx.command(notify.CutoverBarrierVerified)
	for i := range results {
		results[i] = nil
	}
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = fx.cut.AdvanceCutover(fx.ctx, scopes[i], same)
		}()
	}
	wg.Wait()
	for i, err := range results {
		if err != nil {
			t.Fatalf("delivery %d of one command: %v", i, err)
		}
	}
	if s := fx.mustState(); s.Revision != 3 || len(s.Timeline) != 3 {
		t.Fatalf("one command applied %d times: %+v", len(s.Timeline)-2, s)
	}
}

// The fences that arbitrate a cutover against a worker claim and a policy edit.
func TestCutoverClaimAndPolicyEditResolveByRevisionAndFence(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward() // new_active at revision 4
	fx.syncModes(s)
	fx.decideOpening()
	now := fx.clock.Now()

	// A claim decided under an older cutover revision is refused, typed; the
	// committed revision is accepted.
	if _, err := fx.rawClaim(s.Revision-1, now); err == nil {
		t.Fatal("a claim under a stale cutover revision committed")
	} else if c, d := faultOf(err); c != model.Stale || d != control.DeliveryOwnerStale {
		t.Fatalf("stale claim: %v %q", c, d)
	}
	if _, err := fx.rawClaim(0, now); err == nil {
		t.Fatal("a claim that saw no cutover committed in a project that has one")
	}
	if fx.countBy("", control.DeliveryClaimed) != 0 {
		t.Fatal("a refused claim left a claim behind")
	}
	// The rollback begins; a claim prepared under new_active (its revision) now
	// loses against the committed revision and opens no attempt.
	rolled := fx.advance(notify.CutoverRollbackQuiescing)
	if _, err := fx.rawClaim(s.Revision, now); err == nil {
		t.Fatal("a claim decided before the rollback committed after it")
	} else if c, d := faultOf(err); c != model.Stale || d != control.DeliveryOwnerStale {
		t.Fatalf("claim after rollback: %v %q", c, d)
	}
	// The current revision is accepted but the phase fences it: nothing is leased.
	res, err := fx.rawClaim(rolled.Revision, now)
	if err != nil || len(res.AffectedIDs) != 0 {
		t.Fatalf("claim in rollback_quiescing: %+v %v", res, err)
	}
	got, err := fx.ob.Claim(fx.ctx, fx.scope(), now, fx.lease(), 4)
	if err != nil || len(got) != 0 {
		t.Fatalf("outbox claim in rollback_quiescing: %d %v", len(got), err)
	}
	if fx.countBy("", control.DeliveryClaimed) != 0 {
		t.Fatal("a claim was opened while the new owner was quiescing")
	}

	// A policy edit prepared before the mode sync names the canonical-owner
	// revision it saw; the sync advanced it, so the edit loses and decides nothing.
	stale := fx.destinationEvent()
	stale.OwnerRevision = fx.policyState().OwnerRevision
	fx.syncModes(rolled) // active -> shadow: the owner revision moves
	if _, err = fx.ob.Submit(fx.ctx, fx.scope(), fx.lease(), incident, stale, fx.clock.Now()); err == nil {
		t.Fatal("a policy edit under a stale owner revision committed")
	} else if reason, ok := notify.ReasonOf(err); !ok || reason != notify.ReasonOwnerRevision {
		t.Fatalf("stale policy edit: %v", err)
	}
	if _, err = fx.submit(fx.destinationEvent(), fx.clock.Now()); err != nil {
		t.Fatalf("the same edit under the committed revision: %v", err)
	}
}

// A cutover racing workers and policy decisions: whatever interleaving, every
// claim ever opened belongs to the new owner's active revision, and the
// provider only ever saw claims of that revision.
func TestCutoverRollbackRacingWorkersAndDecisions(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var mu sync.Mutex
	var failures []string
	decided := 0 // decisions that committed a change (guarded by mu)
	fail := func(f string, a ...any) { mu.Lock(); failures = append(failures, fmt.Sprintf(f, a...)); mu.Unlock() }
	// Lost races are expected here: a conflict or stale answer, or a retryable
	// unavailable whose every attempt lost the control revision to the other
	// writers (nothing committed). Anything else is a failure.
	expected := func(err error) bool {
		if err == nil || code(err) == model.Conflict || code(err) == model.Stale {
			return true
		}
		var f *model.Fault
		return errors.As(err, &f) && f.Code == model.Unavailable && f.Retryable && f.SafeDetail == notify.DetailRevisionContention
	}
	for w := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wk := fx.worker(fx.ob, fx.p, notify.WithBatch(2))
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// Each pass is its own instant so claims lapse and retry.
				if _, err := wk.RunOnce(fx.ctx, fx.scope(), fx.clock.Now()+model.UnixNano(i)*sec, fx.lease()); !expected(err) {
					fail("worker %d: %v", w, err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 2; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ev := fx.incidentEvent(model.Revision(i), notify.SeverityCritical, uint64(i))
			// As fx.submit, but without t.Fatal off the test goroutine.
			rec, found, err := fx.store.PolicyRecord(fx.ctx, fx.scope(), fx.project, fx.policy, "incident:"+incident.ID.String())
			if err != nil {
				fail("decision: policy record: %v", err)
				continue
			}
			if found {
				var st notify.PolicyState
				if err = json.Unmarshal(rec.State, &st); err != nil {
					fail("decision: policy state: %v", err)
					continue
				}
				ev.OwnerRevision = st.OwnerRevision
			}
			sub, err := fx.ob.Submit(fx.ctx, fx.scope(), fx.lease(), incident, ev, fx.clock.Now())
			if !expected(err) {
				fail("decision: %v", err)
			} else if err == nil && !sub.Unchanged {
				mu.Lock()
				decided++
				mu.Unlock()
			}
			if i > 40 {
				return
			}
		}
	}()
	time.Sleep(150 * time.Millisecond)
	// The rollback races the same writers for the control revision: a lost race
	// is retried from the state it lost to, as an operator would.
	var rolled notify.CutoverState
	var err error
	for range 200 {
		if rolled, err = fx.try(fx.command(notify.CutoverRollbackQuiescing)); err == nil || code(err) != model.Conflict {
			break
		}
	}
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	if err != nil || rolled.Phase != notify.CutoverRollbackQuiescing {
		t.Fatalf("advance to %s: %v (state %s)", notify.CutoverRollbackQuiescing, err, rolled.Phase)
	}
	fx.clock.add(30 * sec)
	if len(failures) != 0 {
		t.Fatalf("failures: %v", failures)
	}
	// The tolerance for lost races must not make the race vacuous.
	t.Logf("%d decisions committed while the workers and the rollback raced", decided)
	if decided == 0 {
		t.Fatal("no decision committed: the decisions never raced the workers")
	}
	for _, r := range fx.deliveries() {
		for _, a := range r.Attempts {
			if a.Owner != s.Revision {
				t.Fatalf("delivery %s attempt %d was opened under cutover revision %d, only new_active (revision %d) may open claims", r.ID, a.Number, a.Owner, s.Revision)
			}
		}
	}
	// After the rollback began, no new attempt can appear and the provider is quiet.
	sends := fx.sends()
	before := fx.deliveries()
	fx.runWorker()
	fx.runWorker()
	if fx.sends() != sends || len(before) != len(fx.deliveries()) {
		t.Fatalf("activity after the rollback began: sends %d -> %d", sends, fx.sends())
	}
	if fx.mustState().Revision != rolled.Revision {
		t.Fatal("the cutover moved by itself")
	}
}

// ---------------------------------------------------------------------------
// Late old-owner retries and source-checkpoint replays.

// Whatever the old owner's flow or a pre-rollback worker retries late gains no
// authority: a settled-revoked delivery is never sent, its closed attempt never
// changes, and an old command only returns its original result.
func TestCutoverLateOldOwnerRetryGainsNoAuthority(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	got, err := fx.ob.Claim(fx.ctx, fx.scope(), fx.clock.Now(), fx.lease(), 4)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v %d", err, len(got))
	}
	d := got[0]
	fx.advance(notify.CutoverRollbackQuiescing)
	fx.clock.add(3 * 60 * sec)
	rollbackOld := fx.command(notify.CutoverOldActive)
	if _, err = fx.try(rollbackOld); err != nil {
		t.Fatal(err)
	}
	fx.clock.add(30 * sec)
	// The cutover runs forward again: a second epoch of the new owner.
	fx.advance(notify.CutoverQuiescingOld)
	fx.advance(notify.CutoverBarrierVerified)
	s2 := fx.advance(notify.CutoverNewActive)
	if s2.Epoch != 2 {
		t.Fatalf("second activation: epoch %d", s2.Epoch)
	}

	// (1) The late worker of the first epoch reports its send as accepted: the
	// attempt was closed by the rollback and never changes.
	err = fx.ob.Complete(fx.ctx, fx.scope(), d.ID, d.Attempt, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "late-provider-id"})
	if err == nil {
		t.Fatal("a late completion of a first-epoch claim was accepted")
	}
	rec := fx.record(fx.ob, d.ID)
	if rec.Phase != control.DeliveryUncertain || rec.Provider != "" {
		t.Fatalf("the late completion changed the delivery: %+v", rec)
	}
	// (2) It is not sendable: the pre-send check of any worker holds it.
	hold, err := fx.ob.Hold(fx.ctx, fx.scope(), d.ID, fx.clock.Now())
	if err != nil || hold != control.DeliveryReasonRevoked {
		t.Fatalf("the first-epoch delivery's hold: %q %v", hold, err)
	}
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("a first-epoch delivery was sent in the second epoch: %d sends", fx.sends())
	}
	// (3) The old command that reactivated the old owner is replayed by a retrying
	// flow: it gets its original result and changes nothing.
	again, err := fx.try(rollbackOld)
	if err != nil || !again.Replayed || again.Phase != notify.CutoverOldActive || again.Epoch != 1 {
		t.Fatalf("replay of the old command: %+v %v", again, err)
	}
	if cur := fx.mustState(); cur.Phase != notify.CutoverNewActive || cur.Epoch != 2 || len(cur.ActiveOwners) != 1 || cur.ActiveOwners[0] != fx.nw {
		t.Fatalf("the replay changed the state: %+v", cur)
	}
	// (4) A fresh command from the old flow with the revision it last saw loses.
	late := fx.command(notify.CutoverOldActive)
	late.ExpectedRevision = rollbackOld.ExpectedRevision
	if _, err = fx.try(late); err == nil {
		t.Fatal("a late old-owner command with a stale revision committed")
	} else if _, ok := notify.CutoverCurrent(err); !ok {
		t.Fatalf("not a revision conflict: %v", err)
	}
	if cur := fx.mustState(); cur.Phase != notify.CutoverNewActive {
		t.Fatalf("phase %s", cur.Phase)
	}
}

// Replaying source evidence across the cutover (a source checkpoint replay, with
// the same command or with new commands for the same occurrences) cannot create a
// second set of normal-owner intents: every intent identity is committed once, no
// delivery of the shadow period turns into a send, and the opening of an
// episode the old owner already announced is never announced again.
func TestCutoverSourceCheckpointReplayCannotDuplicateNormalOwnerIntents(t *testing.T) {
	fx := newCutoverFx(t)
	fx.advance(notify.CutoverShadow)
	// The shadow period decides the whole episode.
	now := fx.clock.Now()
	fx.mustSubmit(fx.destinationEvent(), now)
	evs := []notify.PolicyEvent{fx.incidentEvent(1, notify.SeverityMajor, 1), fx.incidentEvent(2, notify.SeverityCritical, 2)}
	for _, ev := range evs {
		fx.mustSubmit(ev, now)
	}
	fx.syncModes(fx.mustState())
	fx.advance(notify.CutoverQuiescingOld)
	fx.advance(notify.CutoverBarrierVerified)
	s := fx.advance(notify.CutoverNewActive)
	fx.syncModes(s)
	fx.runWorker()
	afterActivation := fx.deliveries()
	sendsAfter := fx.sends()
	// No opening was ever deliverable: the old owner announced the episode.
	for _, r := range afterActivation {
		if r.Kind == string(notify.KindOpen) && (r.Phase == control.DeliveryAccepted || r.Phase == control.DeliveryClaimed || r.Phase == control.DeliveryPending) {
			t.Fatalf("an opening of the shadow period is deliverable: %+v", r)
		}
	}

	// Replay: the very same events again, then the same evidence under new commands.
	for _, ev := range evs {
		if sub, err := fx.submit(ev, now); err == nil && !sub.Unchanged && len(sub.Intents) != 0 {
			t.Fatalf("a replayed command decided %d intents", len(sub.Intents))
		}
	}
	for i, ev := range evs {
		replay := fx.incidentEvent(model.Revision(i+1), ev.Incident.Severity, ev.Incident.ImpactRevision)
		sub, err := fx.submit(replay, fx.clock.Now())
		if err != nil {
			t.Fatalf("replay of version %d under a new command: %v", i+1, err)
		}
		for _, in := range sub.Intents {
			if in.Eligible() {
				t.Fatalf("version %d replayed under a new command decided a deliverable %s", i+1, in.Key.Kind)
			}
		}
	}
	fx.clock.add(sec)
	fx.runWorker()
	final := fx.deliveries()
	if len(final) != len(afterActivation) || fx.sends() != sendsAfter {
		t.Fatalf("replays created work: %d -> %d deliveries, %d -> %d sends", len(afterActivation), len(final), sendsAfter, fx.sends())
	}
	seen := map[model.ID]bool{}
	for _, r := range final {
		if seen[r.ID] {
			t.Fatalf("intent %s committed twice", r.ID)
		}
		seen[r.ID] = true
	}
}

// ---------------------------------------------------------------------------
// Shadow decisions.

// In shadow the whole policy runs -- opening, worse impact, ACK, snooze, reminders,
// recovery -- and the provider is never called, whether or not the policy state
// itself was switched to shadow mode.
func TestCutoverShadowProducesDecisionsAndNeverSends(t *testing.T) {
	for _, synced := range []bool{false, true} {
		t.Run(fmt.Sprintf("policy mode synced=%v", synced), func(t *testing.T) {
			fx := newCutoverFx(t)
			s := fx.advance(notify.CutoverShadow)
			// The sender must never be called: a tripwire beside the recording one.
			w := fx.worker(fx.ob, tripwire{t: t})
			now := fx.clock.Now()
			fx.mustSubmit(fx.destinationEvent(), now)
			if synced {
				fx.syncModes(s)
				if m := fx.policyState().Mode; m != notify.ModeShadow {
					t.Fatalf("policy mode %s after the sync in shadow", m)
				}
			}
			var intents []notify.Intent
			for i, ev := range []notify.PolicyEvent{fx.incidentEvent(1, notify.SeverityMajor, 1), fx.incidentEvent(2, notify.SeverityCritical, 2)} {
				sub := fx.mustSubmit(ev, now+model.UnixNano(i)*sec)
				intents = append(intents, sub.Intents...)
			}
			if len(intents) == 0 {
				t.Fatal("the shadow produced no decisions at all")
			}
			if synced {
				for _, in := range intents {
					if in.Route != notify.RouteQueue && (in.Eligible() || in.Code != notify.CodeShadow) {
						t.Fatalf("a shadow-mode decision is not suppressed as shadow: %+v", in)
					}
				}
			}
			// Time passes: reminders and digests come due.
			for _, d := range []model.UnixNano{20 * 60 * sec, 2 * 3600 * sec, 26 * 3600 * sec} {
				fx.mustRun(w, fx.clock.Now()+d)
			}
			for _, r := range fx.deliveries() {
				switch r.Phase {
				case control.DeliverySuppressed:
					if r.Code != control.DeliveryCodeShadow {
						t.Fatalf("a suppressed shadow decision carries code %q", r.Code)
					}
				case control.DeliveryQueued, control.DeliveryFailed:
				default:
					t.Fatalf("shadow left a %s delivery (%s %s)", r.Phase, r.Kind, r.Code)
				}
				if len(r.Attempts) != 0 {
					t.Fatalf("shadow opened an attempt: %+v", r)
				}
			}
			if fx.countBy("", control.DeliverySuppressed) == 0 {
				t.Fatal("no suppressed decision is recorded: the shadow decisions are invisible")
			}
		})
	}
}

// tripwire is a Sender that fails the test if it is ever called.
type tripwire struct{ t *testing.T }

func (w tripwire) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	w.t.Errorf("the sender was called for %s %s while the product is not the active owner", d.Key.Kind, d.ID)
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "must-not-happen"}, nil
}

// ---------------------------------------------------------------------------
// Parity between the shadow decisions and a legacy decision stream.

var (
	pOrg, pProject, pPolicy = model.ID{0x91}, model.ID{0x92}, model.ID{0xf1}
	pR1, pR2, pR3           = model.ID{0xd1}, model.ID{0xd2}, model.ID{0xd3}
)

func pevent(kind notify.EventKind, seq int) notify.PolicyEvent {
	cfg := notify.DefaultConfig()
	return notify.PolicyEvent{Kind: kind, Command: model.ID{0xc9, byte(seq >> 8), byte(seq)}, Org: pOrg, Project: pProject, Policy: pPolicy,
		PolicyRef: notify.PolicyRef{Revision: 1, Config: &cfg}, OwnerRevision: 1}
}

func pdest(seq int, r model.ID) notify.PolicyEvent {
	ev := pevent(notify.EventDestination, seq)
	ev.Destination = &notify.DestinationChange{Recipient: r, Enabled: true}
	return ev
}

func pincident(seq int, version model.Revision, sev notify.Severity, impact uint64) notify.PolicyEvent {
	ev := pevent(notify.EventIncident, seq)
	e := incident
	ev.Entity = &e
	ev.Mode = notify.ModeLive
	ev.Incident = &notify.IncidentEvidence{Version: version, Status: notify.HumanOpen, Severity: sev, ImpactRevision: impact, Episode: episode, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	return ev
}

func pmaintenance(seq int, version model.Revision, from, until model.UnixNano) notify.PolicyEvent {
	ev := pevent(notify.EventAction, seq)
	e := incident
	ev.Entity = &e
	ev.Action = &notify.HumanAction{Type: notify.ActionMaintenance, Actor: model.ID{0xa1}, Version: version, Scope: notify.Scope{Kind: notify.ScopeProject}, Reason: "planned work", Until: until}
	return ev
}

// journey runs a realistic episode through a fresh evaluator: two recipients,
// an opening, a worse impact, a maintenance window and a worse impact inside it.
func journey(t *testing.T) []notify.ShadowDecision {
	t.Helper()
	ev, err := notify.NewShadowEvaluator(pOrg, pProject, pPolicy, incident)
	if err != nil {
		t.Fatal(err)
	}
	var out []notify.ShadowDecision
	steps := []struct {
		ev notify.PolicyEvent
		at model.UnixNano
	}{
		{pdest(1, pR1), base}, {pdest(2, pR2), base},
		{pincident(3, 1, notify.SeverityMajor, 1), base + sec},
		{pincident(4, 2, notify.SeverityCritical, 2), base + 2*sec},
		{pmaintenance(5, 3, base+3*sec, base+3600*sec), base + 3*sec},
		{pincident(6, 4, notify.SeverityCritical, 3), base + 4*sec},
	}
	for i, s := range steps {
		got, err := ev.Apply(s.ev, s.at)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		out = append(out, got...)
	}
	return out
}

func legacyOf(shadow []notify.ShadowDecision) []notify.LegacyDecision {
	out := make([]notify.LegacyDecision, len(shadow))
	for i, d := range shadow {
		out[i] = notify.LegacyDecision{Entity: d.Entity, Kind: d.Kind, ImpactRevision: d.ImpactRevision, Ordinal: d.Ordinal, Recipient: d.Recipient, SourceVersion: d.SourceVersion,
			DedupID: fmt.Sprintf("legacy-%d", i), Suppression: d.Suppression}
	}
	return out
}

func fieldsOf(r notify.ParityReport) map[string]int {
	out := map[string]int{}
	for _, m := range r.Mismatches {
		out[m.Field]++
	}
	return out
}

func TestCutoverShadowEvaluatorDecidesAsTheActiveOwnerWouldAndStoresNothing(t *testing.T) {
	d := journey(t)
	if len(d) == 0 {
		t.Fatal("no decisions")
	}
	var delivered, maint, toR1, toR2, queue int
	for _, x := range d {
		switch {
		case x.Suppression == "":
			delivered++
		case x.Suppression == notify.CodeMaintenance:
			maint++
		case x.Suppression == notify.CodeShadow:
			t.Fatalf("the evaluator reports the shadow code instead of the would-be disposition: %+v", x)
		}
		switch {
		case x.Recipient == nil:
			queue++
		case *x.Recipient == pR1:
			toR1++
		case *x.Recipient == pR2:
			toR2++
		}
		if x.DedupID == (model.ID{}) || x.Entity != incident {
			t.Fatalf("decision without identity: %+v", x)
		}
	}
	if delivered == 0 || maint == 0 || toR1 == 0 || toR2 == 0 || queue == 0 {
		t.Fatalf("the journey should deliver (%d), be suppressed by maintenance (%d), reach both recipients (%d/%d) and the queue (%d)", delivered, maint, toR1, toR2, queue)
	}
	// A refused event decides nothing and leaves the twin as it was.
	ev, err := notify.NewShadowEvaluator(pOrg, pProject, pPolicy, incident)
	if err != nil {
		t.Fatal(err)
	}
	bad := pincident(9, 1, notify.SeverityMajor, 1)
	bad.Org = model.ID{0x77}
	if got, err := ev.Apply(bad, base); err == nil || len(got) != 0 {
		t.Fatalf("an event of another org was decided: %v %v", got, err)
	}
	if _, err = ev.Apply(pdest(1, pR1), base); err != nil {
		t.Fatal(err)
	}
	// The twin follows its own owner revision: callers need not track it.
	skewed := pincident(10, 1, notify.SeverityMajor, 1)
	skewed.OwnerRevision = 42
	if _, err = ev.Apply(skewed, base+sec); err != nil {
		t.Fatalf("the evaluator did not follow its own owner revision: %v", err)
	}
}

func TestCutoverParityComparesDecisionsNotTotals(t *testing.T) {
	shadow := journey(t)
	if len(shadow) < 3 {
		t.Fatalf("the journey produced %d decisions", len(shadow))
	}
	legacy := legacyOf(shadow)
	if r := notify.CompareParity(shadow, legacy); !r.Equal() || r.Compared != len(shadow) {
		t.Fatalf("identical streams differ: %+v", r)
	}
	// Order of the legacy stream does not matter.
	rev := slices.Clone(legacy)
	slices.Reverse(rev)
	if r := notify.CompareParity(shadow, rev); !r.Equal() {
		t.Fatalf("a reordered legacy stream differs: %+v", r)
	}
	// A legacy dedup collapse of a replayed decision is not a difference.
	dup := append(slices.Clone(legacy), legacy[2])
	if r := notify.CompareParity(shadow, dup); !r.Equal() {
		t.Fatalf("a legacy replay of one decision (same dedup ID) differs: %+v", r)
	}

	pick := func(f func(d notify.ShadowDecision) bool) int {
		for i, d := range shadow {
			if f(d) {
				return i
			}
		}
		t.Fatal("no such decision")
		return -1
	}
	toR2 := pick(func(d notify.ShadowDecision) bool {
		return d.Recipient != nil && *d.Recipient == pR2 && d.Suppression == ""
	})
	delivered := pick(func(d notify.ShadowDecision) bool {
		return d.Recipient != nil && *d.Recipient == pR1 && d.Suppression == "" && d.ImpactRevision > 0
	})
	suppressed := pick(func(d notify.ShadowDecision) bool { return d.Suppression == notify.CodeMaintenance })

	cases := []struct {
		name   string
		mutate func([]notify.LegacyDecision) []notify.LegacyDecision
		want   map[string]int
	}{
		{"same totals, one recipient swapped", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			r := pR3
			l[toR2].Recipient = &r
			return l
		}, map[string]int{"recipients": 1}},
		{"same totals, one impact revision off", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			l[delivered].ImpactRevision += 7
			return l
		}, map[string]int{"recipients": 1, "only_legacy": 1}},
		{"same totals, a suppression differs", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			l[suppressed].Suppression = ""
			return l
		}, map[string]int{"suppression": 1}},
		{"same totals, a delivered decision suppressed by legacy", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			l[delivered].Suppression = notify.CodeSnoozed
			return l
		}, map[string]int{"suppression": 1}},
		{"same totals, a source version differs", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			l[delivered].SourceVersion++
			return l
		}, map[string]int{"source_version": 1}},
		{"a legacy decision is missing", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			return slices.Delete(l, delivered, delivered+1)
		}, map[string]int{"recipients": 1}},
		{"the legacy sent one more", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			extra := l[delivered]
			extra.Ordinal += 9
			extra.DedupID = "legacy-extra"
			return append(l, extra)
		}, map[string]int{"only_legacy": 1}},
		{"two different decisions share one legacy dedup ID", func(l []notify.LegacyDecision) []notify.LegacyDecision {
			l[delivered].DedupID = l[toR2].DedupID
			return l
		}, map[string]int{"dedup": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.mutate(slices.Clone(legacy))
			r := notify.CompareParity(shadow, l)
			if r.Equal() {
				t.Fatalf("a difference went unnoticed: %s", tc.name)
			}
			got := fieldsOf(r)
			for f, n := range tc.want {
				if got[f] < n {
					t.Fatalf("mismatches %v, want %d x %s", got, n, f)
				}
			}
		})
	}
}

// A shadow evaluation that suppressed a decision because of a maintenance window
// disagrees with a legacy stream that delivered it, even when the decision count is
// identical: the comparison is on what each side would do, not on the shadow code.
func TestCutoverParityUsesTheWouldBeSuppression(t *testing.T) {
	shadow := journey(t)
	legacy := legacyOf(shadow)
	n := 0
	for i := range legacy {
		if legacy[i].Suppression == notify.CodeMaintenance {
			legacy[i].Suppression = ""
			n++
		}
	}
	if n == 0 {
		t.Fatal("fixture: nothing was suppressed")
	}
	r := notify.CompareParity(shadow, legacy)
	if got := fieldsOf(r)["suppression"]; got != n || len(shadow) != len(legacy) {
		t.Fatalf("%d suppression mismatches, want %d: %+v", got, n, r)
	}
}

// ---------------------------------------------------------------------------
// Malformed commands, scope and the frontier.

func TestCutoverRejectsMalformedCommandsAndWrongScopes(t *testing.T) {
	fx := newCutoverFx(t)
	fx.advance(notify.CutoverShadow)
	cases := map[string]func(*notify.CutoverCommand){
		"a zero command ID":                     func(c *notify.CutoverCommand) { c.ID = model.ID{} },
		"an unknown phase":                      func(c *notify.CutoverCommand) { c.Phase = "enabled" },
		"an empty phase":                        func(c *notify.CutoverCommand) { c.Phase = "" },
		"no reason":                             func(c *notify.CutoverCommand) { c.Reason = "" },
		"a reason of control characters":        func(c *notify.CutoverCommand) { c.Reason = "bad\x00reason" },
		"a reason longer than the bound":        func(c *notify.CutoverCommand) { c.Reason = strings.Repeat("r", 513) },
		"the same owner twice":                  func(c *notify.CutoverCommand) { c.NewOwner = c.OldOwner },
		"a zero old owner":                      func(c *notify.CutoverCommand) { c.OldOwner = model.ID{} },
		"a zero new owner":                      func(c *notify.CutoverCommand) { c.NewOwner = model.ID{} },
		"owners that changed mid-cutover":       func(c *notify.CutoverCommand) { c.OldOwner = model.ID{0x99} },
		"an empty frontier":                     func(c *notify.CutoverCommand) { c.Frontier = nil },
		"a frontier with a zero source":         func(c *notify.CutoverCommand) { c.Frontier[0].Source = model.ID{} },
		"a frontier with a zero group":          func(c *notify.CutoverCommand) { c.Frontier[0].Cursor.Group = model.ID{} },
		"a frontier with a zero version":        func(c *notify.CutoverCommand) { c.Frontier[0].Version = 0 },
		"a frontier naming a source twice":      func(c *notify.CutoverCommand) { c.Frontier = append(c.Frontier, c.Frontier[0]) },
		"a frontier larger than the bound":      func(c *notify.CutoverCommand) { c.Frontier = bigFrontier(17) },
		"evidence on a phase that takes none":   func(c *notify.CutoverCommand) { c.Evidence = &notify.BarrierEvidence{} },
		"a frontier that went backwards":        func(c *notify.CutoverCommand) { c.Frontier[0].Cursor.Index-- },
		"a frontier dropping a known source":    func(c *notify.CutoverCommand) { c.Frontier[0].Source = model.ID{0xbc} },
		"a frontier at an older source version": func(c *notify.CutoverCommand) { c.Frontier[0].Version-- },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			before := fx.mustState()
			c := fx.command(notify.CutoverQuiescingOld)
			mutate(&c)
			if _, err := fx.try(c); err == nil {
				t.Fatalf("%s was accepted", name)
			} else if c := code(err); c != model.Invalid && c != model.Conflict {
				t.Fatalf("%s: %v", name, err)
			}
			if after := fx.mustState(); after.Revision != before.Revision || len(after.Timeline) != len(before.Timeline) {
				t.Fatalf("%s changed the state", name)
			}
		})
	}
	t.Run("a scope that names no project", func(t *testing.T) {
		scope, err := fx.svc.Authorize(fx.ctx, fx.cred, fx.org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = fx.cut.AdvanceCutover(fx.ctx, scope, fx.command(notify.CutoverQuiescingOld)); code(err) != model.Invalid {
			t.Fatalf("an organization-wide scope: %v", err)
		}
		if _, _, err = fx.cut.Cutover(fx.ctx, scope); code(err) != model.Invalid {
			t.Fatalf("an organization-wide read: %v", err)
		}
	})
	t.Run("a read-only scope", func(t *testing.T) {
		scope, err := fx.svc.Authorize(fx.ctx, fx.cred, fx.org, []model.ID{fx.project}, auth.Read)
		if err != nil {
			t.Skip("fixture owner holds no read grant: " + err.Error())
		}
		if _, err = fx.cut.AdvanceCutover(fx.ctx, scope, fx.command(notify.CutoverQuiescingOld)); code(err) != model.NotFound {
			t.Fatalf("a read scope advanced the cutover: %v", err)
		}
	})
}

func bigFrontier(n int) []notify.FrontierEntry {
	out := make([]notify.FrontierEntry, n)
	for i := range out {
		out[i] = notify.FrontierEntry{Source: model.ID{0xf0, byte(i)}, Version: 1, Cursor: model.Cursor{Group: model.ID{0xf1, byte(i)}, Index: 1}}
	}
	return out
}

// ---------------------------------------------------------------------------
// Determinism: restart, snapshot, journal truncation and the order of retries.

// normalized is the committed cutover record with the identities that differ
// between two otherwise identical installations replaced.
var digestRE = regexp.MustCompile(`"(evidence_)?digest":"[0-9a-f]{64}"`)

func (fx *cutoverFx) normalized() string {
	fx.t.Helper()
	var raw string
	if err := fx.store.View(fx.ctx, func(st control.State) error {
		raw = string(st.CutoverBooks[fx.org.String()+":"+fx.project.String()])
		return nil
	}); err != nil {
		fx.t.Fatal(err)
	}
	for id, name := range map[string]string{fx.org.String(): "ORG", fx.project.String(): "PROJECT", fx.user.String(): "USER"} {
		raw = strings.ReplaceAll(raw, id, name)
	}
	// The command and evidence digests bind the random organization, project and
	// principal: equal within one installation (the replays prove it), not across two.
	return digestRE.ReplaceAllString(raw, `"digest":"D"`)
}

func TestCutoverStateIsDeterministicAcrossRestartSnapshotAndRetryOrder(t *testing.T) {
	journey := []notify.CutoverPhase{notify.CutoverShadow, notify.CutoverQuiescingOld, notify.CutoverBarrierVerified, notify.CutoverNewActive, notify.CutoverRollbackQuiescing, notify.CutoverOldActive}
	run := func(t *testing.T, chaos bool) string {
		fx := newCutoverFx(t)
		var committed []notify.CutoverCommand
		for i, phase := range journey {
			c := fx.command(phase)
			if _, err := fx.try(c); err != nil {
				t.Fatalf("%s: %v", phase, err)
			}
			committed = append(committed, c)
			fx.clock.add(30 * sec)
			if !chaos {
				continue
			}
			// Retries in a different order each round, including commands several
			// transitions old.
			for j := range i + 1 {
				k := (j*5 + i*3) % (i + 1)
				if s, err := fx.try(committed[k]); err != nil || !s.Replayed {
					t.Fatalf("retry of %s: %+v %v", committed[k].Phase, s, err)
				}
			}
			switch i {
			case 1:
				fx.reopen()
			case 3:
				group := fx.node.group()
				cut, err := group.ReadIndex(fx.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = group.CreateSnapshot(fx.ctx, cut); err != nil {
					t.Fatal(err)
				}
				if _, err = group.CompactJournal(fx.ctx); err != nil {
					t.Fatal(err)
				}
				fx.reopen()
			}
		}
		for _, c := range committed {
			if s, err := fx.try(c); err != nil || !s.Replayed {
				t.Fatalf("final retry of %s: %+v %v", c.Phase, s, err)
			}
		}
		return fx.normalized()
	}
	plain, noisy := run(t, false), run(t, true)
	if plain == "" || plain != noisy {
		t.Fatalf("the cutover record depends on restarts, snapshots or retries:\nplain: %s\nnoisy: %s", plain, noisy)
	}
	var rec struct {
		Phase string `json:"phase"`
		Epoch string `json:"epoch"`
		Steps []any  `json:"steps"`
	}
	if err := json.Unmarshal([]byte(plain), &rec); err != nil || rec.Phase != "old_active" || rec.Epoch != "1" || len(rec.Steps) != len(journey) {
		t.Fatalf("record: %+v %v", rec, err)
	}
}

// ---------------------------------------------------------------------------
// Disaster restore: no claim sends until the audited explicit activation.

// restoreAndRecover applies the real C12 quarantine through the replicated update
// path and walks the fresh-bootstrap admin through the reconciliations that give the
// fixture's owner an organization-administrator scope again, WITHOUT reinstating
// the sender (so a claim that reached the destination check would fail the delivery).
func (fx *cutoverFx) restoreAndRecover() (generation model.ID) {
	fx.t.Helper()
	token, hash := auth.NewRecoveryBootstrap()
	sealed, err := auth.SealedBearerKey(fx.store.Seal)
	if err != nil {
		fx.t.Fatal(err)
	}
	generation = model.NewID()
	if err = fx.store.Update(fx.ctx, func(st *model.ControlState) error {
		_, e := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: generation, Backup: model.NewID(), BootstrapHash: hash, SealedBearerKey: sealed, At: fx.wall})
		return e
	}); err != nil {
		fx.t.Fatal(err)
	}
	svc, err := auth.NewService(auth.AuthDependencies{Control: fx.store, Now: func() time.Time { return fx.wall }})
	if err != nil {
		fx.t.Fatal(err)
	}
	session, err := svc.Bootstrap(fx.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		fx.t.Fatal(err)
	}
	recovery, err := svc.Authenticate(fx.ctx, session.Token)
	if err != nil {
		fx.t.Fatal(err)
	}
	for _, r := range []auth.Reconciliation{
		{Kind: auth.ReconcileAccount, User: fx.user},
		{Kind: auth.ReconcileOrgAdmin, Org: fx.org, User: fx.user},
	} {
		r.Reason = "restore recovery"
		if _, err = svc.Reconcile(fx.ctx, recovery, r); err != nil {
			fx.t.Fatalf("reconcile %s: %v", r.Kind, err)
		}
	}
	login, err := svc.Login(fx.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.svc, fx.token = svc, login.Token
	fx.authenticate()
	return generation
}

func TestCutoverRestoredInstallationSendsNothingUntilAuditedActivation(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	pending := fx.openRecord(fx.ob)
	if pending.Phase != control.DeliveryPending {
		t.Fatalf("fixture: the opening is %s", pending.Phase)
	}
	oldScope, oldLease := fx.scope(), fx.lease()

	generation := fx.restoreAndRecover()

	// The restored worker credentials and grants are inactive: the scope and the
	// lease of the previous generation commit nothing.
	if _, err := fx.ob.Claim(fx.ctx, oldScope, fx.clock.Now(), oldLease, 4); err == nil {
		t.Fatal("a pre-restore worker scope claimed after the restore")
	}
	_ = fx.store.View(fx.ctx, func(st control.State) error {
		if src := st.Sources[fx.source.String()]; !src.Revoked {
			t.Error("the restored source credential is active")
		}
		return nil
	})
	if facts := fx.facts(); facts.Restore == nil || *facts.Restore != generation {
		t.Fatalf("the committed restore generation is not visible to the cutover: %+v", facts)
	}

	// A fresh, valid administrator scope: the cutover record still says new_active
	// (it came back from the backup), yet nothing is claimed and the pending
	// delivery is neither sent nor settled as a missing destination.
	fx.clock.add(sec)
	got, err := fx.ob.Claim(fx.ctx, fx.scope(), fx.clock.Now(), fx.lease(), 4)
	if err != nil || len(got) != 0 {
		t.Fatalf("claim after the restore: %d %v", len(got), err)
	}
	rec := fx.openRecord(fx.ob)
	if rec.Phase != control.DeliveryPending || len(rec.Attempts) != 0 {
		t.Fatalf("the pending delivery was touched by a claim before the activation: %+v", rec)
	}
	if fx.mustState().Phase != notify.CutoverNewActive {
		t.Fatal("fixture: the restored record is not new_active")
	}
	// New decisions in the unactivated installation are recorded and suppressed.
	fx.seed(srcVersion, srcIndex) // the source, reconciled by its administrator
	fx.syncModes(fx.mustState())
	fx.mustSubmit(fx.incidentEvent(2, notify.SeverityCritical, 2), fx.clock.Now())
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("the restored installation sent %d messages before the activation", fx.sends())
	}
	for _, r := range fx.deliveries() {
		if r.Phase == control.DeliveryClaimed || len(r.Attempts) != 0 {
			t.Fatalf("a delivery was claimed before the activation: %+v", r)
		}
		if r.Kind == string(notify.KindWorseImpact) && r.Phase != control.DeliverySuppressed {
			t.Fatalf("a decision of the unactivated installation is %s, want suppressed", r.Phase)
		}
	}

	// The activation is explicit: the barrier is verified again, with the restore
	// generation acknowledged and the previous incarnation shown disabled.
	fx.clock.add(30 * sec)
	reactivate := func(mods ...func(*cutoverFx, *notify.BarrierEvidence)) (notify.CutoverState, error) {
		mods = append([]func(*cutoverFx, *notify.BarrierEvidence){func(fx *cutoverFx, e *notify.BarrierEvidence) {
			e.Owner.Owner = fx.nw // the previous incarnation of the new owner
			e.Owner.ObservedAt = fx.clock.Now() - sec
		}}, mods...)
		return fx.try(fx.command(notify.CutoverNewActive, mods...))
	}
	if _, err = reactivate(); err == nil || !slices.Contains(checksOf(err), "restore_unacknowledged") {
		t.Fatalf("an activation that does not acknowledge the restore: %v (%v)", err, checksOf(err))
	}
	wrong := model.NewID()
	if _, err = reactivate(func(_ *cutoverFx, e *notify.BarrierEvidence) { e.RestoreGeneration = &wrong }); err == nil || !slices.Contains(checksOf(err), "restore_unacknowledged") {
		t.Fatalf("an activation acknowledging another generation: %v (%v)", err, checksOf(err))
	}
	if _, err = reactivate(func(_ *cutoverFx, e *notify.BarrierEvidence) {
		e.RestoreGeneration = &generation
		e.Owner.ObservedAt = model.UnixNano(fx.wall.UnixNano()) - sec // observed before the restore
	}); err == nil || !slices.Contains(checksOf(err), "owner_stale") {
		t.Fatalf("an old-incarnation observation from before the restore: %v (%v)", err, checksOf(err))
	}
	if fx.sends() != 0 {
		t.Fatalf("a refused activation let %d messages out", fx.sends())
	}
	activated, err := reactivate(func(_ *cutoverFx, e *notify.BarrierEvidence) { e.RestoreGeneration = &generation })
	if err != nil {
		t.Fatalf("the audited activation: %v", err)
	}
	if activated.Epoch != 2 || activated.RestoreAck == nil || *activated.RestoreAck != generation || len(activated.ActiveOwners) != 1 || activated.ActiveOwners[0] != fx.nw {
		t.Fatalf("activated state: %+v", activated)
	}
	// The restored backlog is revoked, not sent late.
	if r := fx.openRecord(fx.ob); r.Phase != control.DeliveryCancelled || r.Code != control.DeliveryReasonRevoked {
		t.Fatalf("the restored pending delivery is %s/%s", r.Phase, r.Code)
	}
	fx.runWorker()
	if fx.sends() != 0 {
		t.Fatalf("the restored backlog was sent after the activation: %d", fx.sends())
	}
	// A reactivation without a restore to acknowledge is no transition.
	if _, err = reactivate(func(_ *cutoverFx, e *notify.BarrierEvidence) { e.RestoreGeneration = &generation }); err == nil {
		t.Fatal("new_active -> new_active without an unacknowledged restore was accepted")
	}
}

// ---------------------------------------------------------------------------
// Leader loss in the real three-voter control group.

// The cutover is committed control state: it survives the loss of the leader that
// committed it, a lost response is a replay on the new leader, and a worker of the
// dead leader's term gains nothing.
func TestCutoverSurvivesLeaderLossAndFencesTheDeadLeadersWorker(t *testing.T) {
	v := newVoters(t)
	g := v.g
	src, grp := model.ID{0x06, 0xd0}, model.ID{0x07, 0xd0}
	old, nw, observer, domain, product := model.ID{0x01, 0xd0}, model.ID{0x02, 0xd0}, model.ID{0x03, 0xd0}, model.ID{0x04, 0xd0}, model.ID{0x05, 0xd0}
	if err := v.stores[1].Update(g.ctx, func(st *control.State) error {
		st.Sources = map[string]model.SourceAuthority{src.String(): {ID: src, Org: g.org, Project: g.project, CredentialID: model.ID{0x08, 0xd0}, Policy: model.SourcePolicy{Revision: srcVersion, Enabled: true}}}
		raw, err := json.Marshal(control.IssueBook{Org: g.org, Project: g.project, Revision: 1, Checkpoints: map[string]model.Uint64{grp.String(): model.Uint64(srcIndex)}})
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		st.IssueBooks[g.org.String()+":"+g.project.String()] = raw
		return err
	}); err != nil {
		t.Fatal(err)
	}
	frontier := []notify.FrontierEntry{{Source: src, Version: srcVersion, Cursor: model.Cursor{Group: grp, Index: model.Uint64(srcIndex)}}}
	cut := func(id uint64) *notify.CutoverService {
		c, err := notify.NewCutoverService(v.stores[id], g.clock)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	seq := 0
	command := func(id uint64, phase notify.CutoverPhase) notify.CutoverCommand {
		cs := cut(id)
		st, _, err := cs.Cutover(g.ctx, v.scope(id))
		if err != nil {
			t.Fatal(err)
		}
		seq++
		c := notify.CutoverCommand{ID: model.ID{0xcc, 0xee, byte(seq)}, ExpectedRevision: st.Revision, Frontier: frontier, OldOwner: old, NewOwner: nw, Phase: phase, Reason: "three-node drill"}
		if !needsEvidence(phase) {
			return c
		}
		facts, err := cs.Facts(g.ctx, v.scope(id))
		if err != nil {
			t.Fatal(err)
		}
		now := g.clock.Now()
		c.Evidence = &notify.BarrierEvidence{Cutover: st.Cutover, ForRevision: st.Revision, ManifestDigest: notify.ManifestDigest(frontier),
			Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
			Owner:         &notify.OwnerEvidence{Owner: old, Method: "scheduler_disabled", ObservedAt: now - 5*sec, Ref: hashOf("owner")},
			Authorization: &notify.Authorization{Principal: g.user, Ref: hashOf("authorization"), AuthorizedAt: now - 60*sec, ExpiresAt: now + 3600*sec},
			Route:         &notify.RollbackRoute{Owner: old, Ref: hashOf("route")},
			Observer:      &notify.ObserverProof{Observer: observer, Domain: domain, ProductDomain: product, ObservedAt: now - 10*sec, Ref: hashOf("observer")}}
		return c
	}
	leader := uint64(1)
	for _, phase := range []notify.CutoverPhase{notify.CutoverShadow, notify.CutoverQuiescingOld, notify.CutoverBarrierVerified} {
		if _, err := cut(leader).AdvanceCutover(g.ctx, v.scope(leader), command(leader, phase)); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
		g.clock.add(30 * sec)
	}
	// The activation commits and its response is lost with the leader.
	lost := command(leader, notify.CutoverNewActive)
	if _, err := cut(leader).AdvanceCutover(g.ctx, v.scope(leader), lost); err != nil {
		t.Fatal(err)
	}
	g.clock.add(sec)
	oldLease := v.lease(leader)
	ob1 := v.outbox(leader)
	if _, err := ob1.Submit(g.ctx, v.scope(leader), oldLease, incident, g.destinationEvent(), g.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := ob1.Submit(g.ctx, v.scope(leader), oldLease, incident, g.incidentEvent(1, notify.SeverityMajor, 1), g.clock.Now()); err != nil {
		t.Fatal(err)
	}
	v.kill(leader)
	leader = v.survivingLeader()

	// The retry on the new leader is a replay: the original result, nothing twice.
	got, err := cut(leader).AdvanceCutover(g.ctx, v.scope(leader), lost)
	if err != nil || !got.Replayed || got.Phase != notify.CutoverNewActive || got.Revision != 4 || len(got.ActiveOwners) != 1 || got.ActiveOwners[0] != nw {
		t.Fatalf("the retry after leader loss: %+v %v", got, err)
	}
	if cur, _, _ := cut(leader).Cutover(g.ctx, v.scope(leader)); cur.Revision != 4 || len(cur.Timeline) != 4 {
		t.Fatalf("leader loss changed the cutover: %+v", cur)
	}
	// The dead leader's lease commits nothing, even under the right owner revision.
	if _, err = v.outbox(leader).Claim(g.ctx, v.scope(leader), g.clock.Now(), oldLease, 4); err == nil {
		t.Fatal("the dead leader's lease claimed after the election")
	} else if c, d := faultOf(err); c != model.Stale || d != control.DeliveryLeaseStale {
		t.Fatalf("dead leader's claim: %v %q", c, d)
	}
	// The new leader's worker delivers the opening once, then the rollback fences it.
	p := &provider{}
	w, err := notify.NewWorker(v.outbox(leader), p, v.stores[leader].ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	g.clock.add(sec)
	if r, err := w.RunOnce(g.ctx, v.scope(leader), g.clock.Now(), v.lease(leader)); err != nil || len(r.Accepted) != 1 || p.total() != 1 {
		t.Fatalf("the new leader's worker: %+v %v (%d sends)", r, err, p.total())
	}
	g.clock.add(30 * sec)
	if _, err = cut(leader).AdvanceCutover(g.ctx, v.scope(leader), command(leader, notify.CutoverRollbackQuiescing)); err != nil {
		t.Fatal(err)
	}
	if _, err = v.outbox(leader).Submit(g.ctx, v.scope(leader), v.lease(leader), incident, g.incidentEvent(2, notify.SeverityCritical, 2), g.clock.Now()); err != nil {
		t.Fatal(err)
	}
	g.clock.add(sec)
	if r, err := w.RunOnce(g.ctx, v.scope(leader), g.clock.Now(), v.lease(leader)); err != nil || len(r.Claimed) != 0 || p.total() != 1 {
		t.Fatalf("a worker ran during the rollback: %+v %v (%d sends)", r, err, p.total())
	}
	// Every survivor holds the same committed cutover record.
	var books []string
	for id := uint64(1); id <= 3; id++ {
		if !v.alive[id] {
			continue
		}
		_ = v.stores[id].View(g.ctx, func(st control.State) error {
			books = append(books, string(st.CutoverBooks[g.org.String()+":"+g.project.String()]))
			return nil
		})
	}
	if len(books) != 2 || books[0] == "" || books[0] != books[1] {
		t.Fatalf("the survivors disagree on the cutover record: %v", books)
	}
}

// ---------------------------------------------------------------------------
// The closed phase vocabulary, the mode sync and the claim's owner-revision retry.

func TestCutoverPhasesNeverHaveTwoActiveOwnersAndModeFollowsOwnership(t *testing.T) {
	old, nw := model.ID{1}, model.ID{2}
	want := map[notify.CutoverPhase][]model.ID{
		notify.CutoverShadow: {old}, notify.CutoverQuiescingOld: {old}, notify.CutoverBarrierVerified: nil,
		notify.CutoverNewActive: {nw}, notify.CutoverRollbackQuiescing: nil, notify.CutoverOldActive: {old},
	}
	for phase, owners := range want {
		if !phase.Valid() {
			t.Fatalf("%s is not a valid phase", phase)
		}
		got := notify.ActiveOwners(phase, old, nw)
		if len(got) > 1 || !slices.Equal(got, owners) {
			t.Fatalf("%s: active owners %v, want %v", phase, got, owners)
		}
		wantMode := notify.ModeShadow
		if phase == notify.CutoverNewActive {
			wantMode = notify.ModeActive
		}
		if notify.ModeFor(phase) != wantMode {
			t.Fatalf("%s: mode %s, want %s", phase, notify.ModeFor(phase), wantMode)
		}
		// The product delivers exactly when it is the one active owner.
		if (notify.ModeFor(phase) == notify.ModeActive) != slices.Equal(got, []model.ID{nw}) {
			t.Fatalf("%s: delivery mode and ownership disagree", phase)
		}
	}
	for _, bad := range []notify.CutoverPhase{"", "active", "NEW_ACTIVE", "shadow "} {
		if bad.Valid() {
			t.Fatalf("%q is a valid phase", bad)
		}
	}
	if _, err := notify.NewCutoverService(nil, &fakeClock{}); code(err) != model.Invalid {
		t.Fatalf("a service without a store: %v", err)
	}
	if _, err := notify.NewCutoverService(newNode(t).store, nil); code(err) != model.Invalid {
		t.Fatalf("a service without a clock: %v", err)
	}
}

func TestCutoverSyncModesFollowsThePhaseAndRefusesNonsense(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.decideOpening()
	if m := fx.policyState().Mode; m != notify.ModeActive {
		t.Fatalf("fixture: a state decided in new_active is in mode %s", m)
	}
	// Active in new_active: nothing to change.
	if n := fx.syncModes(s); n != 0 {
		t.Fatalf("sync in new_active changed %d states", n)
	}
	rolled := fx.advance(notify.CutoverRollbackQuiescing)
	revision := fx.policyState().OwnerRevision
	if n := fx.syncModes(rolled); n != 1 {
		t.Fatalf("sync in rollback_quiescing changed %d states, want 1", n)
	}
	if st := fx.policyState(); st.Mode != notify.ModeShadow || st.OwnerRevision != revision+1 {
		t.Fatalf("after the sync: mode %s owner revision %d (was %d)", st.Mode, st.OwnerRevision, revision)
	}
	// Idempotent, and a restart changes nothing either.
	if n := fx.syncModes(rolled); n != 0 {
		t.Fatalf("a second sync changed %d states", n)
	}
	fx.reopen()
	if n := fx.syncModes(rolled); n != 0 {
		t.Fatalf("a sync after a restart changed %d states", n)
	}
	// Back to the new owner: shadow -> active, once, through the same event kind.
	fx.advance(notify.CutoverOldActive)
	fx.advance(notify.CutoverQuiescingOld)
	fx.advance(notify.CutoverBarrierVerified)
	active := fx.advance(notify.CutoverNewActive)
	if n := fx.syncModes(active); n != 1 || fx.policyState().Mode != notify.ModeActive {
		t.Fatalf("sync into the second activation: changed %d, mode %s", n, fx.policyState().Mode)
	}
	// Arguments are validated before anything is read or written.
	ob, scope, lease := fx.ob, fx.scope(), fx.lease()
	bad := map[string]func() (int, error){
		"an unknown phase": func() (int, error) {
			return ob.SyncModes(fx.ctx, scope, lease, "bogus", active.Cutover, active.Revision, 1)
		},
		"a zero cutover": func() (int, error) {
			return ob.SyncModes(fx.ctx, scope, lease, active.Phase, model.ID{}, active.Revision, 1)
		},
		"a zero revision": func() (int, error) { return ob.SyncModes(fx.ctx, scope, lease, active.Phase, active.Cutover, 0, 1) },
		"a zero time": func() (int, error) {
			return ob.SyncModes(fx.ctx, scope, lease, active.Phase, active.Cutover, active.Revision, 0)
		},
		"a zero lease": func() (int, error) {
			return ob.SyncModes(fx.ctx, scope, notify.FenceToken{}, active.Phase, active.Cutover, active.Revision, 1)
		},
	}
	for name, call := range bad {
		if _, err := call(); code(err) != model.Invalid {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// racingStore performs a cutover transition between the outbox's read of the cutover
// revision and its first claim commit: the situation the claim's owner revision decides.
type racingStore struct {
	*control.Store
	once   sync.Once
	before func()
	claims int
	mu     sync.Mutex
}

func (s *racingStore) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	var c control.DeliveryCommand
	if cmd.Kind == string(control.KindClaimDelivery) && json.Unmarshal(cmd.Payload, &c) == nil && c.Operation == control.DeliveryOpClaim {
		s.mu.Lock()
		s.claims++
		s.mu.Unlock()
		s.once.Do(s.before)
	}
	return s.Store.Transact(ctx, scope, cmd)
}

// A rollback that commits between the worker's read and its claim makes that claim stale;
// the outbox re-reads, sees the rollback and leases nothing, without an error and without
// an attempt.
func TestCutoverClaimRetriesAfterTheCutoverMovedUnderIt(t *testing.T) {
	fx := newCutoverFx(t)
	s := fx.forward()
	fx.syncModes(s)
	fx.decideOpening()
	racing := &racingStore{Store: fx.store, before: func() { fx.advance(notify.CutoverRollbackQuiescing) }}
	ob, err := notify.NewOutbox(racing, fx.group2(), fx.clock)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ob.Claim(fx.ctx, fx.scope(), fx.clock.Now(), fx.lease(), 4)
	if err != nil || len(got) != 0 {
		t.Fatalf("a claim that lost the race: %d deliveries, %v", len(got), err)
	}
	// (1) lost the control-revision race to the rollback itself, (2) went through
	// under the stale owner revision and was refused, (3) the re-read claim.
	if racing.claims != 3 {
		t.Fatalf("the claim was committed %d times, want 3 (control race, stale owner, re-read)", racing.claims)
	}
	if fx.countBy("", control.DeliveryClaimed) != 0 || fx.sends() != 0 {
		t.Fatal("a claim survived the rollback")
	}
	if fx.mustState().Phase != notify.CutoverRollbackQuiescing {
		t.Fatal("the rollback did not commit")
	}
}

func (fx *cutoverFx) group2() notify.Fencer { return fx.node.group() }
