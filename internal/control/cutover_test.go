// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// cutFx is the real control store (activated single-voter Raft group, real auth
// scopes, the delivery handler that carries the cutover arm) with one real
// source onboarded at policy revision 1 and a committed issue checkpoint.
type cutFx struct {
	*delFx
	old, nw, observer, domain, product model.ID
	group                              model.ID
	at                                 model.UnixNano
	tQuiesce                           model.UnixNano
}

const cs = model.UnixNano(time.Second)

func newCutFx(t *testing.T) *cutFx {
	t.Helper()
	f := &cutFx{delFx: newDelFx(t), old: model.ID{0x01, 0xd0}, nw: model.ID{0x02, 0xd0}, observer: model.ID{0x03, 0xd0}, domain: model.ID{0x04, 0xd0}, product: model.ID{0x05, 0xd0},
		group: model.ID{0x07, 0xd0}, at: model.UnixNano(f0.UnixNano())}
	f.checkpoint(100)
	return f
}

var f0 = time.Unix(1_800_000_000, 0)

func (f *cutFx) checkpoint(index uint64) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		raw, err := json.Marshal(control.IssueBook{Org: f.org, Project: f.project, Revision: 1, Checkpoints: map[string]model.Uint64{f.group.String(): model.Uint64(index)}})
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		st.IssueBooks[f.org.String()+":"+f.project.String()] = raw
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *cutFx) frontier() []control.CutoverFrontier {
	return []control.CutoverFrontier{{Source: f.source, Version: 1, Cursor: model.Cursor{Group: f.group, Index: 100}}}
}

func chash(s string) model.Hash { return model.Hash(sha256.Sum256([]byte(s))) }

func (f *cutFx) record() (control.CutoverRecord, bool) {
	f.t.Helper()
	rec, found, err := f.store.Cutover(f.ctx, f.adminScope(), f.project)
	if err != nil {
		f.t.Fatal(err)
	}
	return rec, found
}

func (f *cutFx) facts() control.CutoverFacts {
	f.t.Helper()
	facts, err := f.store.CutoverFacts(f.ctx, f.adminScope(), f.project, f.at)
	if err != nil {
		f.t.Fatal(err)
	}
	return facts
}

func needsEv(phase string) bool {
	return phase == control.CutoverBarrierVerified || phase == control.CutoverNewActive || phase == control.CutoverOldActive
}

// transition builds the next command from the committed record: flawless
// evidence when the phase takes any.
func (f *cutFx) transition(phase string, mods ...func(*control.CutoverTransition)) control.CutoverTransition {
	f.t.Helper()
	rec, _ := f.record()
	t := control.CutoverTransition{Project: f.project, ExpectedRevision: rec.Revision, Old: f.old, New: f.nw, Phase: phase, At: f.at, Reason: "operator reason", Frontier: f.frontier()}
	if needsEv(phase) {
		facts := f.facts()
		e := &control.CutoverEvidence{Cutover: rec.ID, ForRevision: rec.Revision, ManifestDigest: control.CutoverManifestDigest(t.Frontier),
			Accounting:    control.CutoverAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: facts.Unknown > 0},
			Authorization: &control.CutoverAuthorization{Principal: f.user, Ref: chash("auth"), AuthorizedAt: f.at - 60*cs, ExpiresAt: f.at + 3600*cs},
			Route:         &control.CutoverRoute{Owner: f.old, Ref: chash("route")},
			Observer:      &control.CutoverObserver{Observer: f.observer, Domain: f.domain, ProductDomain: f.product, ObservedAt: f.at - 10*cs, Ref: chash("observer")}}
		if phase != control.CutoverOldActive {
			e.Owner = &control.CutoverOwnerEvidence{Owner: f.old, Method: "scheduler_disabled", ObservedAt: f.at - 5*cs, Ref: chash("owner")}
		}
		t.Evidence = e
	}
	for _, m := range mods {
		m(&t)
	}
	return t
}

func (f *cutFx) do(t control.CutoverTransition) (control.CutoverRecord, error) {
	f.t.Helper()
	return f.store.TransactCutover(f.ctx, f.adminScope(), model.NewID(), t)
}

func (f *cutFx) must(phase string, mods ...func(*control.CutoverTransition)) control.CutoverRecord {
	f.t.Helper()
	rec, err := f.do(f.transition(phase, mods...))
	if err != nil {
		f.t.Fatalf("%s: %v", phase, err)
	}
	if phase == control.CutoverQuiescingOld {
		f.tQuiesce = rec.EnteredAt
	}
	f.at += 30 * cs
	return rec
}

func (f *cutFx) forward() control.CutoverRecord {
	f.t.Helper()
	f.must(control.CutoverShadow)
	f.must(control.CutoverQuiescingOld)
	f.must(control.CutoverBarrierVerified)
	return f.must(control.CutoverNewActive)
}

func (f *cutFx) barrierDetail(err error) string {
	return detail(err)
}

func (f *cutFx) fails(t control.CutoverTransition, want ...string) {
	f.t.Helper()
	before, _ := f.record()
	_, err := f.do(t)
	if err == nil {
		f.t.Fatalf("accepted: %+v", t.Phase)
	}
	for _, w := range want {
		if !strings.Contains(detail(err), w) {
			f.t.Fatalf("refusal %q lacks %q", detail(err), w)
		}
	}
	if after, _ := f.record(); after.Revision != before.Revision || len(after.Steps) != len(before.Steps) {
		f.t.Fatalf("a refused transition changed the record: %+v -> %+v", before.Revision, after.Revision)
	}
}

func (f *cutFx) booksJSON() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.CutoverBooks)
		out = string(raw)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// The cutover arm is part of the delivery handler: without it bound it does
// nothing at all, and binding it twice is still the handler's own conflict.
func TestCutoverArmNeedsTheBoundDeliveryHandler(t *testing.T) {
	f := newFenceFx(t)
	scope := f.adminScope()
	_, err := f.store.TransactCutover(f.ctx, scope, model.NewID(), control.CutoverTransition{Project: f.project, Old: model.ID{1}, New: model.ID{2}, Phase: control.CutoverShadow, At: 1, Reason: "r",
		Frontier: []control.CutoverFrontier{{Source: f.source, Version: 1, Cursor: model.Cursor{Group: model.ID{9}, Index: 1}}}})
	if code(err) != model.Unsupported {
		t.Fatalf("an unbound handler committed a cutover: %v", err)
	}
}

// Scope and grants are checked before the cutover is looked up, parsed or answered:
// a scope that may not act on the project cannot tell an existing cutover from a
// missing project.
func TestCutoverScopeIsCheckedBeforeAnythingElse(t *testing.T) {
	f := newCutFx(t)
	f.must(control.CutoverShadow)
	foreign, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.otherProject}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(scope auth.Scope, project model.ID) (string, string) {
		tr := f.transition(control.CutoverQuiescingOld)
		tr.Project = project
		_, e := f.store.TransactCutover(f.ctx, scope, model.NewID(), tr)
		c, d := faultCode(e), detail(e)
		return string(c), d
	}
	existing := func(scope auth.Scope) (string, string) { return probe(scope, f.project) }
	missing := func(scope auth.Scope) (string, string) { return probe(scope, model.NewID()) }
	for name, want := range map[string]struct {
		scope auth.Scope
		code  model.Code
	}{"a scope of another project": {foreign, model.NotFound}, "a read scope": {read, model.Forbidden}} {
		c1, d1 := existing(want.scope)
		c2, d2 := missing(want.scope)
		if c1 != string(want.code) || c1 != c2 || d1 != d2 {
			t.Fatalf("%s: existing answers %s/%s, missing answers %s/%s", name, c1, d1, c2, d2)
		}
	}
	if rec, _ := f.record(); rec.Revision != 1 {
		t.Fatalf("a refused scope changed the cutover: %d", rec.Revision)
	}
	// Reads keep the same line.
	if _, _, err = f.store.Cutover(f.ctx, foreign, f.project); faultCode(err) != model.NotFound {
		t.Fatalf("a scope of another project read the cutover: %v", err)
	}
	if _, err = f.store.CutoverFacts(f.ctx, foreign, f.project, f.at); faultCode(err) != model.NotFound {
		t.Fatalf("a scope of another project read the facts: %v", err)
	}
	// The read scope may read: it is a read.
	if rec, found, err := f.store.Cutover(f.ctx, read, f.project); err != nil || !found || rec.Revision != 1 {
		t.Fatalf("a read scope could not read: %+v %v", rec, err)
	}
}

func faultCode(err error) model.Code { return code(err) }

// Malformed payloads are refused outright, whichever way they are wrong, and
// change nothing.
func TestCutoverRejectsMalformedPayloads(t *testing.T) {
	f := newCutFx(t)
	lease := f.lease()
	good := f.transition(control.CutoverShadow)
	enc := func(v any) json.RawMessage { raw, _ := json.Marshal(v); return raw }
	cases := map[string]struct {
		kind    control.CommandKind
		payload json.RawMessage
		want    model.Code
	}{
		"an unknown field":                  {control.KindClaimDelivery, json.RawMessage(`{"operation":"cutover","cutover":{"bogus":1}}`), model.Invalid},
		"trailing data":                     {control.KindClaimDelivery, append(enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover, Cutover: &good}), []byte(` {}`)...), model.Invalid},
		"the wrong command kind":            {control.KindCompleteDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover, Cutover: &good}), model.Invalid},
		"the wrong operation":               {control.KindClaimDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpClaim, Cutover: &good}), model.Invalid},
		"two arms":                          {control.KindClaimDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover, Cutover: &good, Claim: &control.DeliveryClaim{Project: f.project, Now: 1, Expires: 2, Limit: 1}}), model.Invalid},
		"a lease on an operator command":    {control.KindClaimDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover, Lease: &lease, Cutover: &good}), model.Invalid},
		"no arm at all":                     {control.KindClaimDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover}), model.Invalid},
		"a zero project (refused by scope)": {control.KindClaimDelivery, enc(control.DeliveryCommand{Operation: control.DeliveryOpCutover, Cutover: withProject(good, model.ID{})}), model.Invalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := f.booksJSON()
			_, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(c.kind), Payload: c.payload})
			if err == nil || code(err) != c.want && code(err) != model.NotFound {
				t.Fatalf("%s: %v", name, err)
			}
			if f.booksJSON() != before {
				t.Fatalf("%s changed the books", name)
			}
		})
	}
	shape := map[string]func(*control.CutoverTransition){
		"a zero old owner":               func(t *control.CutoverTransition) { t.Old = model.ID{} },
		"the same owner twice":           func(t *control.CutoverTransition) { t.New = t.Old },
		"a zero time":                    func(t *control.CutoverTransition) { t.At = 0 },
		"an empty reason":                func(t *control.CutoverTransition) { t.Reason = "" },
		"a reason with a control byte":   func(t *control.CutoverTransition) { t.Reason = "a\x07b" },
		"a reason with a DEL":            func(t *control.CutoverTransition) { t.Reason = "a\x7fb" },
		"a reason over the bound":        func(t *control.CutoverTransition) { t.Reason = strings.Repeat("x", 513) },
		"an empty phase":                 func(t *control.CutoverTransition) { t.Phase = "" },
		"an unknown phase":               func(t *control.CutoverTransition) { t.Phase = "enabled" },
		"an empty frontier":              func(t *control.CutoverTransition) { t.Frontier = nil },
		"a frontier over the bound":      func(t *control.CutoverTransition) { t.Frontier = frontierOf(17) },
		"a zero source":                  func(t *control.CutoverTransition) { t.Frontier[0].Source = model.ID{} },
		"a zero version":                 func(t *control.CutoverTransition) { t.Frontier[0].Version = 0 },
		"a zero group":                   func(t *control.CutoverTransition) { t.Frontier[0].Cursor.Group = model.ID{} },
		"a source twice":                 func(t *control.CutoverTransition) { t.Frontier = append(t.Frontier, t.Frontier[0]) },
		"evidence where none is allowed": func(t *control.CutoverTransition) { t.Evidence = &control.CutoverEvidence{} },
	}
	for name, mutate := range shape {
		t.Run(name, func(t *testing.T) {
			tr := f.transition(control.CutoverShadow)
			mutate(&tr)
			f.fails(tr)
		})
	}
	// The bound itself is fine: 16 sources are a frontier.
	if _, err := f.do(f.transition(control.CutoverShadow, func(t *control.CutoverTransition) { t.Frontier = append(frontierOf(15), t.Frontier[0]) })); err != nil {
		t.Fatalf("a frontier at the bound: %v", err)
	}
}

func withProject(t control.CutoverTransition, p model.ID) *control.CutoverTransition {
	t.Project = p
	return &t
}

func frontierOf(n int) []control.CutoverFrontier {
	out := make([]control.CutoverFrontier, n)
	for i := range out {
		out[i] = control.CutoverFrontier{Source: model.ID{0xf0, byte(i)}, Version: 1, Cursor: model.Cursor{Group: model.ID{0xf1, byte(i)}, Index: 1}}
	}
	return out
}

// The transition table is closed: from every phase reached by the legitimate path,
// every request but the allowed next ones is refused as an invalid transition, even
// with flawless evidence.
func TestCutoverTransitionTableIsClosed(t *testing.T) {
	f := newCutFx(t)
	phases := []string{control.CutoverShadow, control.CutoverQuiescingOld, control.CutoverBarrierVerified, control.CutoverNewActive, control.CutoverRollbackQuiescing, control.CutoverOldActive}
	allowed := map[string][]string{
		"":                               {control.CutoverShadow},
		control.CutoverShadow:            {control.CutoverQuiescingOld},
		control.CutoverQuiescingOld:      {control.CutoverBarrierVerified, control.CutoverShadow},
		control.CutoverBarrierVerified:   {control.CutoverNewActive, control.CutoverShadow},
		control.CutoverNewActive:         {control.CutoverRollbackQuiescing},
		control.CutoverRollbackQuiescing: {control.CutoverOldActive},
		control.CutoverOldActive:         {control.CutoverQuiescingOld},
	}
	check := func(from string) {
		t.Helper()
		for _, to := range phases {
			if slices.Contains(allowed[from], to) {
				continue
			}
			f.fails(f.transition(to, func(t *control.CutoverTransition) {
				if t.Evidence != nil && t.Evidence.Cutover == (model.ID{}) {
					t.Evidence.Cutover = model.ID{0x66} // no record yet: evidence of a cutover that does not exist
				}
			}), control.CutoverTransitionInvalid)
		}
	}
	check("")
	f.must(control.CutoverShadow)
	check(control.CutoverShadow)
	f.must(control.CutoverQuiescingOld)
	check(control.CutoverQuiescingOld)
	f.must(control.CutoverBarrierVerified)
	check(control.CutoverBarrierVerified)
	f.must(control.CutoverNewActive)
	check(control.CutoverNewActive)
	f.must(control.CutoverRollbackQuiescing)
	check(control.CutoverRollbackQuiescing)
	f.must(control.CutoverOldActive)
	check(control.CutoverOldActive)
	// And the loop closes: old_active -> quiescing_old starts the next attempt.
	f.must(control.CutoverQuiescingOld)
}

// The two aborts return the project to shadow and need no evidence; nothing was
// active that has to be accounted for.
func TestCutoverAbortReturnsToShadow(t *testing.T) {
	for _, from := range []string{control.CutoverQuiescingOld, control.CutoverBarrierVerified} {
		f := newCutFx(t)
		f.must(control.CutoverShadow)
		f.must(control.CutoverQuiescingOld)
		if from == control.CutoverBarrierVerified {
			f.must(control.CutoverBarrierVerified)
		}
		rec := f.must(control.CutoverShadow)
		if rec.Phase != control.CutoverShadow || len(rec.ActiveOwners()) != 1 || rec.ActiveOwners()[0] != f.old {
			t.Fatalf("abort from %s: %+v", from, rec)
		}
	}
}

// Owners are fixed by the first command; time and revision only go forward.
func TestCutoverIdentityRevisionAndTimeAreMonotone(t *testing.T) {
	f := newCutFx(t)
	f.must(control.CutoverShadow)
	f.fails(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.Old = model.ID{0x99} }), control.CutoverIdentityConflict)
	f.fails(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.New = model.ID{0x99} }), control.CutoverIdentityConflict)
	// The stale revision wins over the identity: the operator learns where it is.
	f.fails(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.ExpectedRevision = 0; t.Old = model.ID{0x99} }), control.CutoverRevisionConflict+" current=1")
	f.fails(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.ExpectedRevision = 7 }), control.CutoverRevisionConflict+" current=1")
	// A command timed before the phase was entered is refused; the same instant is fine.
	rec, _ := f.record()
	f.fails(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.At = rec.EnteredAt - 1 }), "cutover_time_regressed")
	if _, err := f.do(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) { t.At = rec.EnteredAt })); err != nil {
		t.Fatalf("a command at the very instant the phase was entered: %v", err)
	}
	if v, ok := control.CutoverVersionOf(fmt.Errorf("x")); ok || v != 0 {
		t.Fatal("a foreign error carries a cutover revision")
	}
}

// The frontier only moves forward: no known source dropped, no version or cursor
// of the same group back; a later one is the new frontier.
func TestCutoverFrontierOnlyMovesForward(t *testing.T) {
	f := newCutFx(t)
	f.must(control.CutoverShadow, func(t *control.CutoverTransition) { t.Frontier[0].Version = 2 })
	cases := map[string]func(*control.CutoverTransition){
		"a source dropped":        func(t *control.CutoverTransition) { t.Frontier[0].Source = model.ID{0xbb}; t.Frontier[0].Version = 2 },
		"an older version":        func(t *control.CutoverTransition) { t.Frontier[0].Version = 1 },
		"a cursor that went back": func(t *control.CutoverTransition) { t.Frontier[0].Version = 2; t.Frontier[0].Cursor.Index = 99 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f.fails(f.transition(control.CutoverQuiescingOld, mutate), "cutover_frontier_regressed")
		})
	}
	// A cursor in another group is another stream: not a regression.
	rec, err := f.do(f.transition(control.CutoverQuiescingOld, func(t *control.CutoverTransition) {
		t.Frontier[0].Version = 2
		t.Frontier[0].Cursor.Group = model.ID{0x08, 0xd0}
		t.Frontier[0].Cursor.Index = 5
	}))
	if err != nil || rec.Frontier[0].Cursor.Group != (model.ID{0x08, 0xd0}) {
		t.Fatalf("a moved group: %+v %v", rec, err)
	}
	// A later version, the same cursor and a new source are the new frontier, kept
	// in source order whatever order they were sent in.
	rec, err = f.do(f.transition(control.CutoverShadow, func(t *control.CutoverTransition) {
		t.Frontier[0].Version = 3
		t.Frontier[0].Cursor.Group = model.ID{0x08, 0xd0}
		t.Frontier[0].Cursor.Index = 5
		t.Frontier = append(t.Frontier, control.CutoverFrontier{Source: model.ID{0x00, 0x01}, Version: 2, Cursor: model.Cursor{Group: f.group, Index: 3}})
	}))
	if err != nil || len(rec.Frontier) != 2 || rec.Frontier[0].Source.String() > rec.Frontier[1].Source.String() {
		t.Fatalf("frontier after a forward move: %+v %v", rec.Frontier, err)
	}
}

// ---------------------------------------------------------------------------
// What the committed phase does to deliveries.

// claimUnder is a claim that names the cutover revision the worker observed.
func (f *cutFx) claimUnder(owner model.Revision, now, ttl model.UnixNano, limit uint32) (control.Result, error) {
	f.t.Helper()
	lease := f.lease()
	return f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
		Claim: &control.DeliveryClaim{Project: f.project, Now: now, Expires: now + ttl, Limit: limit, OwnerRevision: owner}})
}

func (f *cutFx) enqueueAt(version uint64, intents ...control.DeliveryIntent) {
	f.t.Helper()
	if _, err := f.enqueue(version, intents...); err != nil {
		f.t.Fatalf("enqueue v%d: %v", version, err)
	}
}

func (f *cutFx) deliverable(seed byte) control.DeliveryIntent {
	return f.intent(seed, withAt(f.at))
}

// While the project is not new_active, the product decides but never sends: every
// external delivery is recorded suppressed (never pending), the shared queue entry
// stays a queue entry, a delivery that was already suppressed or failed keeps its
// own reason, and a claim leases nothing and settles nothing. Each claim must name
// the committed revision.
func TestCutoverEnqueueClaimAndHoldFollowThePhase(t *testing.T) {
	f := newCutFx(t)
	rec := f.must(control.CutoverShadow) // revision 1
	queue := f.intent(2, withAt(f.at), withDisposition(control.DeliveryDispositionDeliver, control.DeliveryRouteQueue, ""), withRecipient(nil))
	supp := f.intent(3, withAt(f.at), withDisposition(control.DeliveryDispositionSuppressed, control.DeliveryRouteImmediate, "maintenance"))
	failed := f.intent(4, withAt(f.at), withDisposition(control.DeliveryDispositionFailed, control.DeliveryRouteImmediate, "no_destination"), withRecipient(nil))
	digest := f.intent(5, withAt(f.at), withDisposition(control.DeliveryDispositionDeliver, control.DeliveryRouteDigest, ""))
	f.enqueueAt(0, f.deliverable(1), queue, supp, failed, digest)
	want := map[byte][2]string{1: {control.DeliverySuppressed, control.DeliveryCodeShadow}, 2: {control.DeliveryQueued, ""}, 3: {control.DeliverySuppressed, "maintenance"},
		4: {control.DeliveryFailed, "no_destination"}, 5: {control.DeliverySuppressed, control.DeliveryCodeShadow}}
	for seed, w := range want {
		r := f.rec(model.ID{0xe0, seed})
		if r.Phase != w[0] || r.Code != w[1] || len(r.Attempts) != 0 {
			t.Fatalf("seed %d: %s/%s, want %s/%s", seed, r.Phase, r.Code, w[0], w[1])
		}
	}
	if r := f.rec(model.ID{0xe0, 1}); r.Disposition != control.DeliveryDispositionSuppressed {
		t.Fatalf("the forced decision keeps the disposition %q", r.Disposition)
	}
	for _, owner := range []model.Revision{0, rec.Revision + 1} {
		if _, err := f.claimUnder(owner, f.at, 60*cs, 8); code(err) != model.Stale || detail(err) != control.DeliveryOwnerStale {
			t.Fatalf("a claim under cutover revision %d (committed %d): %v", owner, rec.Revision, err)
		}
	}
	for _, phase := range []string{control.CutoverShadow, control.CutoverQuiescingOld, control.CutoverBarrierVerified} {
		rec, _ = f.record()
		if rec.Phase != phase {
			f.must(phase)
			rec, _ = f.record()
		}
		res, err := f.claimUnder(rec.Revision, f.at, 60*cs, 8)
		if err != nil || len(res.AffectedIDs) != 0 || res.Phase != "empty" {
			t.Fatalf("%s: a claim leased %v (%s): %v", phase, res.AffectedIDs, res.Phase, err)
		}
	}
	// A decision made before the record existed is still pending, untouched.
	f2 := newCutFx(t)
	f2.enqueueAt(0, f2.deliverable(1))
	f2.must(control.CutoverShadow)
	rec2, _ := f2.record()
	if _, err := f2.claimUnder(rec2.Revision, f2.at, 60*cs, 8); err != nil {
		t.Fatal(err)
	}
	if r := f2.rec(model.ID{0xe0, 1}); r.Phase != control.DeliveryPending || len(r.Attempts) != 0 {
		t.Fatalf("a claim in shadow touched a pending delivery: %+v", r)
	}

	// new_active: external deliveries are pending again and a claim records the
	// revision it was opened under.
	rec = f.must(control.CutoverNewActive) // barrier was entered above
	f.enqueueAt(1, f.deliverable(6))
	if r := f.rec(model.ID{0xe0, 6}); r.Phase != control.DeliveryPending || r.Disposition != control.DeliveryDispositionDeliver {
		t.Fatalf("new_active: %+v", r)
	}
	if _, err := f.claimUnder(rec.Revision-1, f.at, 60*cs, 8); code(err) != model.Stale {
		t.Fatalf("a claim under the previous revision: %v", err)
	}
	res, err := f.claimUnder(rec.Revision, f.at, 60*cs, 8)
	if err != nil || len(res.AffectedIDs) != 1 {
		t.Fatalf("new_active claim: %+v %v", res, err)
	}
	r := f.rec(res.AffectedIDs[0])
	if r.Phase != control.DeliveryClaimed || r.Attempts[0].Owner != rec.Revision {
		t.Fatalf("the attempt does not carry the owner revision: %+v", r.Attempts)
	}
	if hold := f.recAt(r.ID, f.at).Hold; hold != "" {
		t.Fatalf("new_active: an open claim is held (%q)", hold)
	}
	// The rollback begins: the very claim that was valid a moment ago is revoked at
	// the worker's pre-send check, and nothing more is leased.
	rb := f.must(control.CutoverRollbackQuiescing)
	if hold := f.recAt(r.ID, f.at).Hold; hold != control.DeliveryReasonRevoked {
		t.Fatalf("rollback_quiescing: the open claim's hold is %q", hold)
	}
	if res, err = f.claimUnder(rb.Revision, f.at, 60*cs, 8); err != nil || len(res.AffectedIDs) != 0 {
		t.Fatalf("a claim leased during rollback_quiescing: %+v %v", res, err)
	}
	if _, err = f.claimUnder(rec.Revision, f.at, 60*cs, 8); code(err) != model.Stale {
		t.Fatalf("a claim decided before the rollback: %v", err)
	}
	// The holder cancels it as revoked: a definite non-send, no uncertainty.
	if _, err = f.cancel(r.Attempts[0].Fence, control.DeliveryCancel{Project: f.project, Delivery: r.ID, Attempt: 1, At: f.at, Reason: control.DeliveryReasonRevoked}); err != nil {
		t.Fatal(err)
	}
	if got := f.rec(r.ID); got.Phase != control.DeliveryCancelled || got.Code != control.DeliveryReasonRevoked || got.Uncertain || got.Attempts[0].Outcome != control.DeliveryOutcomeTerminal {
		t.Fatalf("the revoked claim: %+v", got)
	}
	// And a settled-revoked delivery stays held for any worker with an old view.
	if hold := f.recAt(r.ID, f.at).Hold; hold != control.DeliveryReasonRevoked {
		t.Fatalf("a revoked delivery is not held: %q", hold)
	}
}

// Entering new_active or old_active ends every delivery that is still open, in the
// same transition, with an audit entry each: nothing the previous owner may have
// handled is sent late by the next one, and what may have reached the provider is
// never turned into success or into a plain cancellation.
func TestCutoverActivationRevokesOpenDeliveries(t *testing.T) {
	setup := func(t *testing.T) (*cutFx, map[string]model.ID) {
		f := newCutFx(t)
		ids := map[string]model.ID{"accepted": {0xe0, 1}, "retry-after-unknown": {0xe0, 2}, "lapsing": {0xe0, 3}, "pending": {0xe0, 4}, "failed": {0xe0, 5}}
		f.enqueueAt(0, f.deliverable(1), f.deliverable(2), f.deliverable(3))
		lease := f.lease()
		claimed := f.mustClaim(lease, f.at, 60*cs, 3)
		if len(claimed) != 3 {
			t.Fatalf("fixture: %d claimed", len(claimed))
		}
		f.mustComplete(lease, f.completeCmd(ids["accepted"], 1, f.at, control.DeliveryOutcomeAccepted, "provider-1", "", 0))
		f.mustComplete(lease, f.completeCmd(ids["retry-after-unknown"], 1, f.at, control.DeliveryOutcomeUnknown, "", "send_error", f.at+3600*cs))
		// "lapsing" stays claimed: its lease runs out with no completion.
		f.enqueueAt(1, f.deliverable(4), f.intent(5, withAt(f.at), withDisposition(control.DeliveryDispositionFailed, control.DeliveryRouteImmediate, "no_destination"), withRecipient(nil)))
		return f, ids
	}
	check := func(t *testing.T, f *cutFx, ids map[string]model.ID, at model.UnixNano) {
		t.Helper()
		if r := f.rec(ids["accepted"]); r.Phase != control.DeliveryAccepted || r.Code != "" {
			t.Fatalf("an accepted delivery was touched: %+v", r)
		}
		if r := f.rec(ids["failed"]); r.Phase != control.DeliveryFailed || r.Code != "no_destination" {
			t.Fatalf("a failed delivery was touched: %+v", r)
		}
		if r := f.rec(ids["pending"]); r.Phase != control.DeliveryCancelled || r.Code != control.DeliveryReasonRevoked || r.SettledAt != at || len(r.Attempts) != 0 || r.Uncertain {
			t.Fatalf("an unsent delivery: %+v", r)
		}
		r := f.rec(ids["retry-after-unknown"])
		if r.Phase != control.DeliveryUncertain || r.Code != control.DeliveryReasonRevoked || !r.Uncertain || len(r.Attempts) != 1 {
			t.Fatalf("a retry after an unknown attempt: %+v", r)
		}
		r = f.rec(ids["lapsing"])
		a := r.Attempts[0]
		if r.Phase != control.DeliveryUncertain || r.Code != control.DeliveryReasonRevoked || !r.Uncertain || a.Outcome != control.DeliveryOutcomeUnknown || a.Code != control.DeliveryCodeClaimExpired || a.ClosedBy != "system" || a.ClosedAt != at {
			t.Fatalf("a lapsed claim: %+v %+v", r, a)
		}
		for name, id := range ids {
			if name == "accepted" || name == "failed" {
				continue
			}
			found := false
			var audits []control.Audit
			_ = f.store.View(f.ctx, func(st control.State) error { audits = st.Audits; return nil })
			for _, a := range audits {
				if len(a.Targets) == 1 && a.Targets[0] == id && a.Reason == control.DeliveryReasonRevoked {
					found = true
				}
			}
			if !found {
				t.Fatalf("no audit entry for the revoked %s delivery", name)
			}
		}
	}
	t.Run("into new_active", func(t *testing.T) {
		f, ids := setup(t)
		f.must(control.CutoverShadow)
		f.must(control.CutoverQuiescingOld)
		f.must(control.CutoverBarrierVerified) // the claim's lease ends exactly now
		facts := f.facts()
		if facts.Pending != 2 || facts.Claimed != 0 || facts.Lapsed != 1 || facts.Unknown != 2 {
			t.Fatalf("facts before the activation: %+v", facts)
		}
		at := f.at
		f.must(control.CutoverNewActive)
		check(t, f, ids, at)
	})
	t.Run("into old_active", func(t *testing.T) {
		f, ids := setup(t)
		// The cutover runs; the open deliveries are revoked when the new owner
		// activates and again, for new ones, when it hands back.
		f.must(control.CutoverShadow)
		f.must(control.CutoverQuiescingOld)
		f.must(control.CutoverBarrierVerified)
		f.must(control.CutoverNewActive)
		rec, _ := f.record()
		f.enqueueAt(2, f.deliverable(7))
		lease := f.lease()
		if got := f.mustClaimUnder(rec.Revision, lease, f.at, 30*cs); len(got) != 1 {
			t.Fatalf("fixture: %d claimed", len(got))
		}
		f.enqueueAt(3, f.deliverable(8)) // never claimed
		f.must(control.CutoverRollbackQuiescing)
		f.at += 120 * cs // the lease lapses
		at := f.at
		f.must(control.CutoverOldActive)
		if r := f.rec(model.ID{0xe0, 7}); r.Phase != control.DeliveryUncertain || r.Code != control.DeliveryReasonRevoked || r.Attempts[0].Outcome != control.DeliveryOutcomeUnknown || r.Attempts[0].ClosedAt != at {
			t.Fatalf("the new owner's lapsed claim: %+v", r)
		}
		if r := f.rec(model.ID{0xe0, 8}); r.Phase != control.DeliveryCancelled || r.Code != control.DeliveryReasonRevoked {
			t.Fatalf("the new owner's unsent delivery: %+v", r)
		}
		_ = ids
	})
}

func (f *cutFx) mustClaimUnder(owner model.Revision, lease replica.FenceToken, now, ttl model.UnixNano) []model.ID {
	f.t.Helper()
	res, err := f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
		Claim: &control.DeliveryClaim{Project: f.project, Now: now, Expires: now + ttl, Limit: 8, OwnerRevision: owner}})
	if err != nil {
		f.t.Fatal(err)
	}
	return res.AffectedIDs
}

// ---------------------------------------------------------------------------
// Boundaries of the evidence's freshness and of the lease that decides "live".

func TestCutoverEvidenceBoundariesAreExact(t *testing.T) {
	type bound struct {
		name string
		mod  func(f *cutFx, t *control.CutoverTransition)
		ok   bool
		want string
	}
	// soon keeps the command right after the quiescing began; the others sit two
	// hours later so the longest evidence age fits.
	soon := map[string]bool{"owner observed at the very instant the quiescing began": true, "owner observed one nanosecond before the quiescing began": true}
	age := control.CutoverMaxEvidenceAge
	obs := control.CutoverMaxObserverAge
	win := control.CutoverMaxAuthorization
	cases := []bound{
		{"owner observed exactly at the limit of its age", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = t.At - age }, true, ""},
		{"owner observed one nanosecond too long ago", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = t.At - age - 1 }, false, "owner_stale"},
		{"owner observed at the very instant of the command", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = t.At }, true, ""},
		{"owner observed one nanosecond in the future", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = t.At + 1 }, false, "owner_stale"},
		{"owner observed at the very instant the quiescing began", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = f.tQuiesce }, true, ""},
		{"owner observed one nanosecond before the quiescing began", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = f.tQuiesce - 1 }, false, "owner_stale"},
		{"owner observation of time zero", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Owner.ObservedAt = 0; f.tQuiesce = 0 }, false, "owner_stale"},
		{"observer proof exactly at the limit of its age", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Observer.ObservedAt = t.At - obs }, true, ""},
		{"observer proof one nanosecond too old", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Observer.ObservedAt = t.At - obs - 1 }, false, "observer_stale"},
		{"observer proof at the very instant of the command", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Observer.ObservedAt = t.At }, true, ""},
		{"observer proof one nanosecond in the future", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Observer.ObservedAt = t.At + 1 }, false, "observer_stale"},
		{"observer proof of time zero", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Observer.ObservedAt = 0 }, false, "observer_stale"},
		{"authorized at the very instant of the command", func(f *cutFx, t *control.CutoverTransition) {
			t.Evidence.Authorization.AuthorizedAt = t.At
			t.Evidence.Authorization.ExpiresAt = t.At + 10
		}, true, ""},
		{"authorized one nanosecond in the future", func(f *cutFx, t *control.CutoverTransition) {
			t.Evidence.Authorization.AuthorizedAt = t.At + 1
			t.Evidence.Authorization.ExpiresAt = t.At + 10
		}, false, "authorization"},
		{"authorization expiring one nanosecond after the command", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Authorization.ExpiresAt = t.At + 1 }, true, ""},
		{"authorization expiring at the very instant of the command", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Authorization.ExpiresAt = t.At }, false, "authorization"},
		{"authorization window of exactly a day", func(f *cutFx, t *control.CutoverTransition) {
			t.Evidence.Authorization.AuthorizedAt = t.At - 10
			t.Evidence.Authorization.ExpiresAt = t.At - 10 + win
		}, true, ""},
		{"authorization window one nanosecond over a day", func(f *cutFx, t *control.CutoverTransition) {
			t.Evidence.Authorization.AuthorizedAt = t.At - 10
			t.Evidence.Authorization.ExpiresAt = t.At - 10 + win + 1
		}, false, "authorization"},
		{"authorization time zero", func(f *cutFx, t *control.CutoverTransition) { t.Evidence.Authorization.AuthorizedAt = 0 }, false, "authorization"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCutFx(t)
			f.must(control.CutoverShadow)
			f.must(control.CutoverQuiescingOld)
			if !soon[tc.name] {
				f.at += model.UnixNano(2 * time.Hour) // room for the longest age
			}
			tr := f.transition(control.CutoverBarrierVerified, func(t *control.CutoverTransition) { tc.mod(f, t) })
			if tc.ok {
				if _, err := f.do(tr); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				return
			}
			f.fails(tr, tc.want)
		})
	}
	// "Live" is strictly before the lease ends: at the expiry instant the claim has lapsed.
	f := newCutFx(t)
	f.enqueueAt(0, f.deliverable(1))
	f.mustClaim(f.lease(), f.at, 60*cs, 1)
	expires := f.at + 60*cs
	for at, want := range map[model.UnixNano][2]uint32{expires - 1: {1, 0}, expires: {0, 1}, expires + 1: {0, 1}} {
		facts, err := f.store.CutoverFacts(f.ctx, f.adminScope(), f.project, at)
		if err != nil || facts.Claimed != want[0] || facts.Lapsed != want[1] {
			t.Fatalf("facts at %d (lease ends %d): %+v %v", at-f.at, expires-f.at, facts, err)
		}
	}
}

// The unknown set is the product's own outstanding ambiguous sends: lapsed claims,
// retries after an unknown attempt and settled-uncertain deliveries; its digest does
// not depend on any order and moves with the membership.
func TestCutoverFactsAreTheCommittedUnknownSet(t *testing.T) {
	f := newCutFx(t)
	f.enqueueAt(0, f.deliverable(1), f.deliverable(2), f.deliverable(3), f.deliverable(4))
	lease := f.lease()
	f.mustClaim(lease, f.at, 60*cs, 4)
	f.mustComplete(lease, f.completeCmd(model.ID{0xe0, 1}, 1, f.at, control.DeliveryOutcomeAccepted, "p-1", "", 0))
	f.mustComplete(lease, f.completeCmd(model.ID{0xe0, 2}, 1, f.at, control.DeliveryOutcomeUnknown, "", "send_error", f.at+3600*cs))
	f.mustComplete(lease, f.completeCmd(model.ID{0xe0, 3}, 1, f.at, control.DeliveryOutcomeRetry, "", "http_503", f.at+3600*cs))
	// 1 accepted, 2 pending after unknown, 3 pending after a definite retry, 4 lapsing.
	facts, err := f.store.CutoverFacts(f.ctx, f.adminScope(), f.project, f.at+120*cs)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Pending != 2 || facts.Claimed != 0 || facts.Lapsed != 1 || facts.Unknown != 2 {
		t.Fatalf("facts: %+v", facts)
	}
	want := sha256.New()
	want.Write([]byte("soundpost.control.cutover.unknown.v1\x00"))
	for _, id := range []model.ID{{0xe0, 2}, {0xe0, 4}} {
		want.Write(id[:])
	}
	var digest model.Hash
	copy(digest[:], want.Sum(nil))
	if facts.UnknownDigest != digest {
		t.Fatalf("the unknown digest is not the digest of the ascending IDs of the set")
	}
	// Another project's deliveries are not this one's accounting.
	other, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.otherProject}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.CutoverFacts(f.ctx, other, f.otherProject, f.at+120*cs); err != nil || got.Pending != 0 || got.Unknown != 0 {
		t.Fatalf("another project's facts: %+v %v", got, err)
	}
}

// ---------------------------------------------------------------------------
// Bounds, audits and sanitation.

func TestCutoverHistoryIsBoundedAndKeepsTheNewest(t *testing.T) {
	f := newCutFx(t)
	f.must(control.CutoverShadow)
	var first model.ID
	for i := range 35 {
		rec := f.must(control.CutoverQuiescingOld)
		if i == 0 {
			first = rec.Steps[len(rec.Steps)-1].Command
		}
		f.must(control.CutoverShadow)
	}
	rec, _ := f.record()
	if rec.Revision != 71 || len(rec.Steps) != 64 {
		t.Fatalf("revision %d with %d steps, want 71 with 64", rec.Revision, len(rec.Steps))
	}
	if rec.Steps[0].Revision != 8 || rec.Steps[len(rec.Steps)-1].Revision != 71 {
		t.Fatalf("the history keeps revisions %d..%d, want the newest 8..71", rec.Steps[0].Revision, rec.Steps[len(rec.Steps)-1].Revision)
	}
	for _, s := range rec.Steps {
		if s.Command == first {
			t.Fatal("an evicted step is still in the history")
		}
	}
	if n := len(f.booksJSON()); n > 128<<10 {
		t.Fatalf("a full history is %d bytes", n)
	}
	// The control command table still answers a replay of an evicted step.
	if _, err := f.store.TransactCutover(f.ctx, f.adminScope(), first, f.transition(control.CutoverShadow)); err != nil {
		t.Fatalf("replay of an evicted step: %v", err)
	}
	if again, _ := f.record(); again.Revision != 71 {
		t.Fatalf("the replay of an evicted step moved the cutover: %d", again.Revision)
	}
}

// Every transition leaves one audit entry with a closed reason; nothing the operator
// typed, and no evidence, is in an audit entry.
func TestCutoverAuditsCarryClosedCodesOnly(t *testing.T) {
	f := newCutFx(t)
	secret := "OPERATOR-FREE-TEXT-7731"
	reason := func(t *control.CutoverTransition) { t.Reason = secret }
	for _, ph := range []string{control.CutoverShadow, control.CutoverQuiescingOld, control.CutoverBarrierVerified, control.CutoverNewActive, control.CutoverRollbackQuiescing, control.CutoverOldActive} {
		f.must(ph, reason)
	}
	var audits []control.Audit
	_ = f.store.View(f.ctx, func(st control.State) error { audits = st.Audits; return nil })
	got := map[string]string{}
	for _, a := range audits {
		if strings.HasPrefix(a.Action, "notify.cutover.") {
			got[a.Action] = a.Reason
			if a.Principal != f.user || a.Outcome != model.AuditAllowed || len(a.Targets) != 1 {
				t.Fatalf("audit: %+v", a)
			}
		}
		if raw, _ := json.Marshal(a); strings.Contains(string(raw), secret) {
			t.Fatalf("operator text reached an audit entry: %s", raw)
		}
	}
	want := map[string]string{"notify.cutover.shadow": "none->shadow", "notify.cutover.quiescing_old": "shadow->quiescing_old", "notify.cutover.barrier_verified": "quiescing_old->barrier_verified",
		"notify.cutover.new_active": "barrier_verified->new_active", "notify.cutover.rollback_quiescing": "new_active->rollback_quiescing", "notify.cutover.old_active": "rollback_quiescing->old_active"}
	for action, reason := range want {
		if got[action] != reason {
			t.Fatalf("%s: reason %q, want %q (all: %v)", action, got[action], reason, got)
		}
	}
	rec, _ := f.record()
	if raw, _ := json.Marshal(rec); !strings.Contains(string(raw), secret) {
		t.Fatal("the record lost the operator reason it keeps until a retirement")
	}
}

// A frontier is verified against THIS project's own committed sources and issue
// checkpoints: a revoked, retired, closing, disabled or foreign source, and a
// checkpoint that only another project has, do not count.
func TestCutoverFrontierIsVerifiedAgainstTheProjectsOwnSourcesAndCheckpoints(t *testing.T) {
	type edit func(f *cutFx, st *control.State)
	source := func(mutate func(*model.SourceAuthority)) edit {
		return func(f *cutFx, st *control.State) {
			s := st.Sources[f.source.String()]
			mutate(&s)
			st.Sources[f.source.String()] = s
		}
	}
	cases := map[string]struct {
		edit edit
		want string
	}{
		"a revoked source":                   {source(func(s *model.SourceAuthority) { s.Revoked = true }), "source_unknown"},
		"a retired source":                   {source(func(s *model.SourceAuthority) { s.Retired = true }), "source_unknown"},
		"a source being closed":              {source(func(s *model.SourceAuthority) { s.Closing = true }), "source_unknown"},
		"a disabled source":                  {source(func(s *model.SourceAuthority) { s.Policy.Enabled = false }), "source_unknown"},
		"a source of another project":        {source(func(s *model.SourceAuthority) { s.Project = model.ID{0x99} }), "source_unknown"},
		"a source of another organization":   {source(func(s *model.SourceAuthority) { s.Org = model.ID{0x99} }), "source_unknown"},
		"a source at another policy version": {source(func(s *model.SourceAuthority) { s.Policy.Revision = 7 }), "source_version"},
		"a checkpoint only another project has": {func(f *cutFx, st *control.State) {
			st.IssueBooks[f.org.String()+":"+f.otherProject.String()] = st.IssueBooks[f.org.String()+":"+f.project.String()]
			delete(st.IssueBooks, f.org.String()+":"+f.project.String())
		}, "checkpoint_behind"},
		"a project with no issue book at all": {func(f *cutFx, st *control.State) { delete(st.IssueBooks, f.org.String()+":"+f.project.String()) }, "checkpoint_behind"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCutFx(t)
			f.must(control.CutoverShadow)
			f.must(control.CutoverQuiescingOld)
			if err := f.store.Update(f.ctx, func(st *control.State) error { tc.edit(f, st); return nil }); err != nil {
				t.Fatal(err)
			}
			f.fails(f.transition(control.CutoverBarrierVerified), tc.want)
		})
	}
	// The exact index is enough; one more is not.
	f := newCutFx(t)
	f.must(control.CutoverShadow)
	f.must(control.CutoverQuiescingOld)
	f.checkpoint(100)
	if _, err := f.do(f.transition(control.CutoverBarrierVerified)); err != nil {
		t.Fatalf("a checkpoint exactly at the frontier: %v", err)
	}
	g := newCutFx(t)
	g.must(control.CutoverShadow)
	g.must(control.CutoverQuiescingOld)
	g.checkpoint(99)
	g.fails(g.transition(control.CutoverBarrierVerified), "checkpoint_behind")
	// An evidence method must be a closed token.
	h := newCutFx(t)
	h.must(control.CutoverShadow)
	h.must(control.CutoverQuiescingOld)
	h.fails(h.transition(control.CutoverBarrierVerified, func(t *control.CutoverTransition) { t.Evidence.Owner.Method = "Has Spaces" }), "owner_evidence")
}
