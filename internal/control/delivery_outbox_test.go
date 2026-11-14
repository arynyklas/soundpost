// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// delFx is the real control store (activated single-voter Raft group, real auth
// scopes) with the delivery outbox handler bound and one enabled destination
// whose secret is a sentinel no delivery record may ever contain. Leases come
// from the group; a "newer leader" is a lease of a higher term, exactly as the
// condition and rule fixtures do it.
type delFx struct {
	*fenceFx
	dest    model.ID
	policy  model.ID
	subject string
}

const destSecret = "SECRET-DESTINATION-TEXT-9f31"

func newDelFx(t *testing.T) *delFx {
	t.Helper()
	f := &delFx{fenceFx: newFenceFx(t), dest: model.ID{0xd1}, policy: model.ID{0xf1}}
	f.subject = "incident:" + model.ID{0xa1}.String()
	if err := f.store.BindDeliveryOutbox(); err != nil {
		t.Fatal(err)
	}
	f.setDestination(f.dest, true)
	return f
}

func (f *delFx) setDestination(id model.ID, enabled bool) {
	f.t.Helper()
	cfg := fmt.Sprintf(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":%v}`, enabled)
	f.admin("destination", f.org, auth.AdminPayload{ID: id, Config: json.RawMessage(cfg), Secret: destSecret, Reason: "fixture"})
}

func (f *delFx) lease() replica.FenceToken {
	f.t.Helper()
	token, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

// newer is a lease of the next election term: a newer leader.
func (f *delFx) newer(l replica.FenceToken) replica.FenceToken { l.Term++; return l }

func withBody(s string) func(*control.DeliveryIntent) {
	return func(in *control.DeliveryIntent) { in.Body = json.RawMessage(s); in.Digest = digest(in.Body) }
}
func withAt(at model.UnixNano) func(*control.DeliveryIntent) {
	return func(in *control.DeliveryIntent) { in.At = at }
}
func withOrigin(from, to model.UnixNano) func(*control.DeliveryIntent) {
	return func(in *control.DeliveryIntent) { in.OriginFrom, in.OriginTo = from, to }
}
func withRecipient(id *model.ID) func(*control.DeliveryIntent) {
	return func(in *control.DeliveryIntent) { in.Recipient = id }
}
func withDisposition(d, route, code string) func(*control.DeliveryIntent) {
	return func(in *control.DeliveryIntent) { in.Disposition, in.Route, in.Code = d, route, code }
}

func (f *delFx) intent(seed byte, mods ...func(*control.DeliveryIntent)) control.DeliveryIntent {
	body := json.RawMessage(fmt.Sprintf(`{"seed":%d}`, seed))
	dest := f.dest
	in := control.DeliveryIntent{ID: model.ID{0xe0, seed}, Kind: "open", Disposition: control.DeliveryDispositionDeliver, Route: control.DeliveryRouteImmediate,
		Recipient: &dest, At: 100, Body: body, Digest: digest(body)}
	for _, m := range mods {
		m(&in)
	}
	return in
}

func (f *delFx) enqueueBody(version uint64, intents ...control.DeliveryIntent) control.DeliveryEnqueue {
	state := json.RawMessage(fmt.Sprintf(`{"org_id":%q,"version":%d}`, f.org.String(), version+1))
	return control.DeliveryEnqueue{Project: f.project, Policy: f.policy, Subject: f.subject, ExpectedVersion: model.Revision(version), NewVersion: model.Revision(version + 1),
		At: 100, State: state, Digest: digest(state), Intents: intents}
}

func (f *delFx) send(kind control.CommandKind, id model.ID, c control.DeliveryCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, f.adminScope(), f.cmd(kind, id, c))
}
func (f *delFx) enqueueWith(id model.ID, lease replica.FenceToken, e control.DeliveryEnqueue) (control.Result, error) {
	f.t.Helper()
	return f.send(control.KindClaimDelivery, id, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e})
}
func (f *delFx) enqueue(version uint64, intents ...control.DeliveryIntent) (control.Result, error) {
	f.t.Helper()
	return f.enqueueWith(model.NewID(), f.lease(), f.enqueueBody(version, intents...))
}
func (f *delFx) mustEnqueue(version uint64, intents ...control.DeliveryIntent) control.Result {
	f.t.Helper()
	res, err := f.enqueue(version, intents...)
	if err != nil {
		f.t.Fatalf("enqueue v%d: %v", version, err)
	}
	return res
}
func (f *delFx) claim(lease replica.FenceToken, now, ttl model.UnixNano, limit uint32) (control.Result, error) {
	f.t.Helper()
	return f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
		Claim: &control.DeliveryClaim{Project: f.project, Now: now, Expires: now + ttl, Limit: limit}})
}
func (f *delFx) mustClaim(lease replica.FenceToken, now, ttl model.UnixNano, limit uint32) []model.ID {
	f.t.Helper()
	res, err := f.claim(lease, now, ttl, limit)
	if err != nil {
		f.t.Fatalf("claim at %d: %v", now, err)
	}
	return res.AffectedIDs
}
func (f *delFx) completeCmd(id model.ID, attempt uint32, at model.UnixNano, outcome, provider, code string, next model.UnixNano) control.DeliveryComplete {
	return control.DeliveryComplete{Project: f.project, Delivery: id, Attempt: attempt, At: at, Outcome: outcome, Provider: provider, Code: code, Next: next}
}
func (f *delFx) complete(lease replica.FenceToken, c control.DeliveryComplete) (control.Result, error) {
	f.t.Helper()
	return f.send(control.KindCompleteDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease, Complete: &c})
}
func (f *delFx) mustComplete(lease replica.FenceToken, c control.DeliveryComplete) control.Result {
	f.t.Helper()
	res, err := f.complete(lease, c)
	if err != nil {
		f.t.Fatalf("complete %s attempt %d: %v", c.Outcome, c.Attempt, err)
	}
	return res
}
func (f *delFx) cancel(lease replica.FenceToken, c control.DeliveryCancel) (control.Result, error) {
	f.t.Helper()
	return f.send(control.KindCompleteDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpCancel, Lease: &lease, Cancel: &c})
}
func (f *delFx) rec(id model.ID) control.DeliveryRecord {
	f.t.Helper()
	r, ok, err := f.store.Delivery(f.ctx, f.adminScope(), f.project, id, 0)
	if err != nil || !ok {
		f.t.Fatalf("delivery %s: found=%v err=%v", id, ok, err)
	}
	return r
}
func (f *delFx) recAt(id model.ID, now model.UnixNano) control.DeliveryRecord {
	f.t.Helper()
	r, ok, err := f.store.Delivery(f.ctx, f.adminScope(), f.project, id, now)
	if err != nil || !ok {
		f.t.Fatalf("delivery %s: found=%v err=%v", id, ok, err)
	}
	return r
}
func (f *delFx) all(phase string) []control.DeliveryRecord {
	f.t.Helper()
	out, err := f.store.Deliveries(f.ctx, f.adminScope(), f.project, phase, 0, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *delFx) auditCount(action string) int {
	f.t.Helper()
	n := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				n++
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}
func (f *delFx) stateJSON() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := json.Marshal(st)
		out = string(raw)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// delBooks are the raw delivery outbox entries of the committed state.
func (f *delFx) delBooks() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	if err := f.store.View(f.ctx, func(st control.State) error {
		for k, v := range st.DeliveryBooks {
			out[k] = string(v)
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// retryRevision retries a command that only lost the race for the control
// revision (never a semantic conflict).
func retryRevision(fn func() (control.Result, error)) (control.Result, error) {
	for range 200 {
		res, err := fn()
		var fault *model.Fault
		if err != nil && errors.As(err, &fault) && fault.Code == model.Conflict && fault.SafeDetail == string(model.Conflict) {
			continue
		}
		return res, err
	}
	return control.Result{}, model.Fail(model.Unavailable)
}

func detail(err error) string { return faultDetail(err) }

// Without the handler a delivery command has no durable behavior at all, and the
// binder installs both closed kinds exactly once.
func TestDeliveryOutboxRequiresBoundHandler(t *testing.T) {
	f := newFenceFx(t)
	lease, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Claim: &control.DeliveryClaim{Project: f.project, Now: 10, Expires: 20, Limit: 1}}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindClaimDelivery, model.NewID(), c)); code(err) != model.Unsupported {
		t.Fatalf("an unbound claim handler committed: %v", err)
	}
	k := control.DeliveryCommand{Operation: control.DeliveryOpCancel, Lease: &lease, Cancel: &control.DeliveryCancel{Project: f.project, Delivery: model.NewID(), At: 5, Reason: "deleted"}}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindCompleteDelivery, model.NewID(), k)); code(err) != model.Unsupported {
		t.Fatalf("an unbound completion handler committed: %v", err)
	}
	if err = f.store.BindDeliveryOutbox(); err != nil {
		t.Fatal(err)
	}
	if code(f.store.BindDeliveryOutbox()) != model.Conflict {
		t.Fatal("the delivery handler bound twice")
	}
}

// The policy state and every intent it produced commit in ONE transition. A
// replayed decision creates nothing twice; a conflicting body for a committed ID
// or a lost version race creates nothing at all.
func TestDeliveryEnqueueIsAtomicAndIdempotent(t *testing.T) {
	f := newDelFx(t)
	queue := f.intent(2, withDisposition(control.DeliveryDispositionDeliver, control.DeliveryRouteQueue, ""), withRecipient(nil))
	snoozed := f.intent(3, withDisposition(control.DeliveryDispositionSuppressed, control.DeliveryRouteImmediate, "snoozed"))
	missing := f.intent(4, withDisposition(control.DeliveryDispositionFailed, control.DeliveryRouteImmediate, "no_destination"), withRecipient(nil))
	first := f.intent(1)
	enq := f.enqueueBody(0, first, queue, snoozed, missing)
	id := model.NewID()
	res, err := f.enqueueWith(id, f.lease(), enq)
	if err != nil || res.Phase != "enqueued" || len(res.AffectedIDs) != 4 {
		t.Fatalf("first enqueue: %+v %v", res, err)
	}
	want := map[byte]string{1: control.DeliveryPending, 2: control.DeliveryQueued, 3: control.DeliverySuppressed, 4: control.DeliveryFailed}
	for seed, phase := range want {
		r := f.rec(model.ID{0xe0, seed})
		if r.Phase != phase || len(r.Attempts) != 0 || r.Org != f.org || r.Project != f.project {
			t.Fatalf("intent %d: %+v", seed, r)
		}
	}
	if r := f.rec(model.ID{0xe0, 3}); r.Code != "snoozed" {
		t.Fatalf("a suppressed intent lost its reason: %+v", r)
	}
	if r := f.rec(model.ID{0xe0, 4}); r.Code != "no_destination" {
		t.Fatalf("a missing destination is not visible as failed: %+v", r)
	}
	pol, ok, err := f.store.PolicyRecord(f.ctx, f.adminScope(), f.project, f.policy, f.subject)
	if err != nil || !ok || pol.Version != 1 || string(pol.State) != string(enq.State) {
		t.Fatalf("policy record: %+v %v %v", pol, ok, err)
	}
	// The visible failed intent is also audited and outlives the record.
	if f.auditCount("notify.delivery.failed") != 1 {
		t.Fatal("a failed delivery left no audit entry")
	}

	// Same command ID: the original result, no new transition of the deliveries.
	again, err := f.enqueueWith(id, f.lease(), enq)
	if err != nil || again.Revision != res.Revision || again.Phase != "enqueued" || len(again.AffectedIDs) != 4 {
		t.Fatalf("command replay changed state: %+v %v", again, err)
	}
	// A new decision that repeats intent 1 byte for byte and adds intent 5: intent 1
	// is not duplicated or reset, intent 5 is created, the policy version advances.
	r1 := f.rec(first.ID)
	res2, err := f.enqueueWith(model.NewID(), f.lease(), f.enqueueBody(1, first, f.intent(5)))
	if err != nil || len(res2.AffectedIDs) != 1 || res2.AffectedIDs[0] != (model.ID{0xe0, 5}) {
		t.Fatalf("second enqueue: %+v %v", res2, err)
	}
	if got := f.rec(first.ID); fmt.Sprint(got) != fmt.Sprint(r1) {
		t.Fatalf("a repeated intent was rewritten:\n%+v\n%+v", r1, got)
	}
	if n := len(f.all("")); n != 5 {
		t.Fatalf("%d deliveries after a replayed intent, want 5", n)
	}
	// A different body for a committed ID is a conflict, and the policy state it
	// rode with is not advanced either.
	other := f.intent(1, withBody(`{"seed":99}`))
	_, err = f.enqueueWith(model.NewID(), f.lease(), f.enqueueBody(2, other, f.intent(6)))
	if code(err) != model.Conflict || detail(err) != control.DeliveryIdentityConflict {
		t.Fatalf("conflicting body accepted: %v", err)
	}
	if _, found, _ := f.store.Delivery(f.ctx, f.adminScope(), f.project, model.ID{0xe0, 6}, 0); found {
		t.Fatal("a rejected command left an intent behind")
	}
	if pol, _, _ = f.store.PolicyRecord(f.ctx, f.adminScope(), f.project, f.policy, f.subject); pol.Version != 2 {
		t.Fatalf("a rejected command advanced the policy: %+v", pol)
	}
	// Two decisions computed from the same version: exactly one wins, the loser
	// is a conflict and creates none of its intents.
	if _, err = f.enqueue(2, f.intent(7)); err != nil {
		t.Fatal(err)
	}
	_, err = f.enqueue(2, f.intent(8))
	if code(err) != model.Conflict || detail(err) != control.DeliveryPolicyConflict {
		t.Fatalf("a lost version race committed: %v", err)
	}
	if _, found, _ := f.store.Delivery(f.ctx, f.adminScope(), f.project, model.ID{0xe0, 8}, 0); found {
		t.Fatal("the loser of a version race created its intent")
	}
	// A missing record only matches expected version 0.
	_, err = f.enqueueWith(model.NewID(), f.lease(), func() control.DeliveryEnqueue {
		e := f.enqueueBody(4, f.intent(9))
		e.Subject = "incident:" + model.ID{0xa2}.String()
		return e
	}())
	if code(err) != model.NotFound {
		t.Fatalf("a version against a missing policy state committed: %v", err)
	}
}

func TestDeliveryEnqueueRejectsMalformedCommands(t *testing.T) {
	f := newDelFx(t)
	lease := f.lease()
	good := f.intent(1)
	bad := func(m func(*control.DeliveryEnqueue)) control.DeliveryEnqueue {
		e := f.enqueueBody(0, good)
		m(&e)
		return e
	}
	cases := map[string]control.DeliveryEnqueue{
		"digest mismatch":     bad(func(e *control.DeliveryEnqueue) { e.Digest = model.Hash{1} }),
		"version skip":        bad(func(e *control.DeliveryEnqueue) { e.NewVersion = 5 }),
		"bad subject":         bad(func(e *control.DeliveryEnqueue) { e.Subject = "Incident Upper" }),
		"state not an object": bad(func(e *control.DeliveryEnqueue) { e.State = json.RawMessage(`[1]`); e.Digest = digest(e.State) }),
		"duplicate ID":        bad(func(e *control.DeliveryEnqueue) { e.Intents = []control.DeliveryIntent{good, good} }),
		"body digest": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, func(i *control.DeliveryIntent) { i.Digest = model.Hash{2} })}
		}),
		"unknown disposition": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withDisposition("sent", "immediate", ""))}
		}),
		"unknown route": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withDisposition("deliver", "pigeon", ""))}
		}),
		"deliver nowhere": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withRecipient(nil))}
		}),
		"suppressed no code": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withDisposition("suppressed", "immediate", ""))}
		}),
		"unsafe code": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withDisposition("suppressed", "immediate", "Has Space"))}
		}),
		"origin reversed": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withOrigin(50, 10))}
		}),
		"zero time": bad(func(e *control.DeliveryEnqueue) { e.Intents = []control.DeliveryIntent{f.intent(1, withAt(0))} }),
		"huge body": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = []control.DeliveryIntent{f.intent(1, withBody(`"`+strings.Repeat("a", 17<<10)+`"`))}
		}),
		"huge state": bad(func(e *control.DeliveryEnqueue) {
			e.State = json.RawMessage(`"` + strings.Repeat("a", 300<<10) + `"`)
			e.Digest = digest(e.State)
		}),
		"too many intents": bad(func(e *control.DeliveryEnqueue) {
			e.Intents = nil
			for i := range 65 {
				e.Intents = append(e.Intents, f.intent(byte(i+1)))
			}
		}),
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		before := f.revision()
		if _, err := f.enqueueWith(model.NewID(), lease, cases[name]); code(err) != model.Invalid && code(err) != model.TooLarge {
			t.Errorf("%s: got %v", name, err)
		}
		if f.revision() != before {
			t.Errorf("%s: a rejected command changed state", name)
		}
	}
	// A zero ID cannot even be encoded by the DTOs; a hand-written payload that
	// carries one is refused all the same.
	zeros := strings.Repeat("0", 32)
	e0 := f.enqueueBody(0, good)
	for name, replace := range map[string][2]string{
		"zero policy":    {`"policy":"` + f.policy.String() + `"`, `"policy":"` + zeros + `"`},
		"zero project":   {`"project":"` + f.project.String() + `"`, `"project":"` + zeros + `"`},
		"zero intent ID": {`"id":"` + good.ID.String() + `"`, `"id":"` + zeros + `"`},
	} {
		raw, err := json.Marshal(control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e0})
		if err != nil {
			t.Fatal(err)
		}
		mutated := strings.Replace(string(raw), replace[0], replace[1], 1)
		if mutated == string(raw) {
			t.Fatalf("%s: the payload has no %s", name, replace[0])
		}
		before := f.revision()
		if _, err = f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: before, Kind: string(control.KindClaimDelivery), Payload: json.RawMessage(mutated)}); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
		if f.revision() != before {
			t.Errorf("%s: a rejected command changed state", name)
		}
	}
	// A missing lease, a zero term and another group's lease are invalid.
	for name, l := range map[string]*replica.FenceToken{"missing": nil, "zero term": {Group: lease.Group, Revision: lease.Revision}, "foreign group": {Group: model.ID{0xee}, Term: 1}} {
		e := f.enqueueBody(0, good)
		if _, err := f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: l, Enqueue: &e}); code(err) != model.Invalid {
			t.Errorf("%s lease: %v", name, err)
		}
	}
	// One kind and one operation: an arm of another kind, two arms and no arm.
	e := f.enqueueBody(0, good)
	for name, c := range map[string]struct {
		kind control.CommandKind
		cmd  control.DeliveryCommand
	}{
		"enqueue under complete kind": {control.KindCompleteDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e}},
		"complete under claim kind":   {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease, Complete: &control.DeliveryComplete{Project: f.project, Delivery: good.ID, Attempt: 1, At: 5, Outcome: "terminal", Code: "x"}}},
		"operation arm mismatch":      {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Enqueue: &e}},
		"two arms":                    {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e, Claim: &control.DeliveryClaim{Project: f.project}}},
		"no arm":                      {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease}},
		"unknown operation":           {control.KindClaimDelivery, control.DeliveryCommand{Operation: "drop", Lease: &lease, Enqueue: &e}},
	} {
		if _, err := f.send(c.kind, model.NewID(), c.cmd); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.all("")) != 0 {
		t.Fatal("a rejected command created a delivery")
	}
}

// Scope and grants come before any lookup: a foreign project, a read-only scope
// and another organization all look like an absent target, for every arm.
func TestDeliveryScopeIsCheckedBeforeLookup(t *testing.T) {
	f := newDelFx(t)
	f.mustEnqueue(0, f.intent(1))
	lease := f.lease()
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	cmds := func(project model.ID) map[string]struct {
		kind control.CommandKind
		cmd  control.DeliveryCommand
	} {
		e := f.enqueueBody(1, f.intent(2))
		e.Project = project
		return map[string]struct {
			kind control.CommandKind
			cmd  control.DeliveryCommand
		}{
			"enqueue":  {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e}},
			"claim":    {control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Claim: &control.DeliveryClaim{Project: project, Now: 200, Expires: 300, Limit: 1}}},
			"complete": {control.KindCompleteDelivery, control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease, Complete: &control.DeliveryComplete{Project: project, Delivery: model.ID{0xe0, 1}, Attempt: 1, At: 150, Outcome: "terminal", Code: "x"}}},
			"cancel":   {control.KindCompleteDelivery, control.DeliveryCommand{Operation: control.DeliveryOpCancel, Lease: &lease, Cancel: &control.DeliveryCancel{Project: project, Delivery: model.ID{0xe0, 1}, At: 150, Reason: "deleted"}}},
		}
	}
	deliveries := func() string {
		var out []string
		for _, r := range f.all("") {
			raw, _ := json.Marshal(r)
			out = append(out, string(raw))
		}
		return strings.Join(out, "\n")
	}
	before := deliveries()
	for name, c := range cmds(model.NewID()) { // a project of nobody
		if _, err := f.send(c.kind, model.NewID(), c.cmd); code(err) != model.NotFound {
			t.Errorf("%s on a foreign project: %v", name, err)
		}
	}
	for name, c := range cmds(f.otherProject) { // a project of this org the delivery is not in
		_, err := f.send(c.kind, model.NewID(), c.cmd)
		switch name {
		case "enqueue": // creates the new project's own state: allowed, not under test
		case "claim": // nothing of this project is due: an empty claim, and never the other project's delivery
			if err != nil {
				t.Errorf("claim on the other project: %v", err)
			}
		default:
			if code(err) != model.NotFound {
				t.Errorf("%s of a delivery through the wrong project: %v", name, err)
			}
		}
	}
	if r := f.rec(model.ID{0xe0, 1}); r.Phase != control.DeliveryPending || len(r.Attempts) != 0 {
		t.Fatalf("another project's command touched the delivery: %+v", r)
	}
	for name, c := range cmds(f.project) {
		if _, err := f.store.Transact(f.ctx, read, f.cmd(c.kind, model.NewID(), c.cmd)); code(err) != model.Forbidden {
			t.Errorf("%s with a read-only scope: %v", name, err)
		}
	}
	// Reads: a project the scope does not name is indistinguishable from absent.
	if _, _, err := f.store.Delivery(f.ctx, read, f.otherProject, model.ID{0xe0, 1}, 0); code(err) != model.NotFound {
		t.Fatalf("read of an unnamed project: %v", err)
	}
	if _, found, err := f.store.Delivery(f.ctx, f.adminScope(), f.otherProject, model.ID{0xe0, 1}, 0); err != nil || found {
		t.Fatalf("a delivery answered under another project: %v %v", found, err)
	}
	if _, err := f.store.Deliveries(f.ctx, read, f.otherProject, "", 0, 0); code(err) != model.NotFound {
		t.Fatalf("list of an unnamed project: %v", err)
	}
	if after := deliveries(); !strings.HasPrefix(after, strings.Split(before, "\n")[0]) {
		t.Fatalf("a refused command changed the first project's deliveries:\n%s\n%s", before, after)
	}
}

// Due deliveries are leased in (eligible time, ID) order, up to the limit, one
// attempt each, and a live claim is not leased again.
func TestDeliveryClaimLeasesDueDeliveriesOnce(t *testing.T) {
	f := newDelFx(t)
	late := f.intent(1, withAt(500))
	b := f.intent(3, withAt(100))
	a := f.intent(2, withAt(100))
	f.mustEnqueue(0, late, b, a)
	lease := f.lease()
	if got := f.mustClaim(lease, 99, 100, 5); len(got) != 0 {
		t.Fatalf("a delivery before its eligibility was claimed: %v", got)
	}
	got := f.mustClaim(lease, 200, 1000, 1)
	if len(got) != 1 || got[0] != a.ID {
		t.Fatalf("limit 1 at 200 claimed %v, want the earliest ID %v", got, a.ID)
	}
	r := f.rec(a.ID)
	if r.Phase != control.DeliveryClaimed || len(r.Attempts) != 1 {
		t.Fatalf("claimed record: %+v", r)
	}
	at := r.Attempts[0]
	if at.Number != 1 || at.Fence != lease || at.ClaimedAt != 200 || at.Expires != 1200 || at.Outcome != "" || at.ClosedAt != 0 {
		t.Fatalf("attempt identity: %+v", at)
	}
	got = f.mustClaim(lease, 201, 1000, 5)
	if len(got) != 1 || got[0] != b.ID {
		t.Fatalf("second claim: %v, want only the next due delivery (the first is leased)", got)
	}
	if got = f.mustClaim(lease, 202, 1000, 5); len(got) != 0 {
		t.Fatalf("live claims were leased again: %v", got)
	}
	if got = f.mustClaim(lease, 600, 1000, 5); len(got) != 1 || got[0] != late.ID {
		t.Fatalf("the late delivery: %v", got)
	}
	// Bad claims.
	for name, c := range map[string]control.DeliveryClaim{
		"zero limit":      {Project: f.project, Now: 700, Expires: 800, Limit: 0},
		"huge limit":      {Project: f.project, Now: 700, Expires: 800, Limit: 65},
		"no expiry":       {Project: f.project, Now: 700, Expires: 700, Limit: 1},
		"zero now":        {Project: f.project, Now: 0, Expires: 10, Limit: 1},
		"unbounded lease": {Project: f.project, Now: 700, Expires: 700 + control.DeliveryMaxClaimTTL + 1, Limit: 1},
	} {
		c := c
		if _, err := f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Claim: &c}); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Many claimers at once never share a delivery: the control revision serializes
// them, and a claimed delivery is not claimable until its lease lapses.
func TestDeliverySimultaneousClaimersAreDisjoint(t *testing.T) {
	f := newDelFx(t)
	var intents []control.DeliveryIntent
	for i := range 12 {
		intents = append(intents, f.intent(byte(i+1)))
	}
	f.mustEnqueue(0, intents...)
	lease := f.lease()
	var mu sync.Mutex
	got := map[model.ID]int{}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := retryRevision(func() (control.Result, error) { return f.claim(lease, 200, 1000, 3) })
			if err != nil {
				errs <- fmt.Errorf("claimer %d: %w", w, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range res.AffectedIDs {
				got[id]++
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("%d of 12 deliveries claimed", len(got))
	}
	for id, n := range got {
		if n != 1 {
			t.Fatalf("delivery %s was claimed %d times", id, n)
		}
		if r := f.rec(id); r.Phase != control.DeliveryClaimed || len(r.Attempts) != 1 {
			t.Fatalf("%s: %+v", id, r)
		}
	}
}

// A claim whose lease lapsed may have reached the provider. The next claim
// closes that attempt as unknown, never as success, and retries the SAME
// delivery ID; the closed attempt is immutable from then on.
func TestDeliveryLapsedClaimIsUnknownAndRetriedWithTheSameID(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d)
	old := f.lease()
	f.mustClaim(old, 200, 100, 1)
	newer := f.newer(old)
	if got := f.mustClaim(newer, 299, 100, 1); len(got) != 0 {
		t.Fatalf("a claim before its expiry was taken over by a newer leader: %v", got)
	}
	if r := f.rec(d.ID); r.Phase != control.DeliveryClaimed || r.Attempts[0].Outcome != "" {
		t.Fatalf("an unexpired claim changed: %+v", r)
	}
	got := f.mustClaim(newer, 300, 100, 1)
	if len(got) != 1 || got[0] != d.ID {
		t.Fatalf("the lapsed delivery was not retried: %v", got)
	}
	r := f.rec(d.ID)
	if r.ID != d.ID || r.Phase != control.DeliveryClaimed || len(r.Attempts) != 2 || !r.Uncertain {
		t.Fatalf("after the retry: %+v", r)
	}
	first, second := r.Attempts[0], r.Attempts[1]
	if first.Outcome != control.DeliveryOutcomeUnknown || first.Code != control.DeliveryCodeClaimExpired || first.ClosedBy != "system" || first.ClosedAt != 300 || first.Fence != old {
		t.Fatalf("the lapsed attempt: %+v", first)
	}
	if second.Number != 2 || second.Fence != newer || second.Outcome != "" {
		t.Fatalf("the new attempt: %+v", second)
	}
	firstJSON, _ := json.Marshal(first)
	// Completing attempt 2 never edits attempt 1.
	f.mustComplete(newer, f.completeCmd(d.ID, 2, 350, control.DeliveryOutcomeAccepted, "msg-1", "", 0))
	done := f.rec(d.ID)
	if again, _ := json.Marshal(done.Attempts[0]); string(again) != string(firstJSON) {
		t.Fatalf("a closed attempt changed:\n%s\n%s", firstJSON, again)
	}
	// Accepted after an unknown attempt is accepted WITH provider evidence, and
	// is flagged as a possible duplicate: never exactly-once.
	if done.Phase != control.DeliveryAccepted || done.Provider != "msg-1" || !done.PossibleDuplicate || !done.Uncertain {
		t.Fatalf("accepted after unknown: %+v", done)
	}
	if f.auditCount("notify.delivery.unknown") != 1 || f.auditCount("notify.delivery.accepted") != 1 {
		t.Fatal("the unknown attempt or the acceptance left no audit entry")
	}
}

// Complete names the claim it closes: the attempt and the lease. A deposed
// worker can never close an attempt another lease holds, and nobody closes an
// attempt they did not open.
func TestDeliveryCompleteVerifiesAttemptAndFence(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d)
	old := f.lease()
	f.mustClaim(old, 200, 100, 1)
	ok := func(l replica.FenceToken) control.DeliveryComplete {
		return f.completeCmd(d.ID, 1, 210, "accepted", "p1", "", 0)
	}
	before := f.stateJSON()

	// The wrong attempt number.
	for _, n := range []uint32{2, 9} {
		if _, err := f.complete(old, f.completeCmd(d.ID, n, 210, "accepted", "p1", "", 0)); code(err) != model.Invalid && code(err) != model.Conflict {
			t.Errorf("attempt %d of a delivery with one attempt: %v", n, err)
		}
	}
	// A lease that is not the claim's: a newer leader did not open this attempt.
	if _, err := f.complete(f.newer(old), ok(old)); code(err) != model.Conflict || detail(err) != control.DeliveryClaimNotHeld {
		t.Fatalf("a newer lease closed an attempt it did not open: %v", err)
	}
	// Before that, a lease that is older than the claim's is stale.
	older := old
	older.Term--
	if older.Term > 0 {
		if _, err := f.complete(older, ok(old)); code(err) != model.Stale || detail(err) != control.DeliveryLeaseStale {
			t.Fatalf("a deposed leader's lease closed an attempt: %v", err)
		}
	}
	if f.stateJSON() != before {
		t.Fatal("a rejected completion changed state")
	}
	// A newer leader commits anything (here: an empty claim) and the old holder
	// is fenced out for good, though its claim is still stored.
	newer := f.newer(old)
	f.mustClaim(newer, 205, 100, 1)
	if _, err := f.complete(old, ok(old)); code(err) != model.Stale || detail(err) != control.DeliveryLeaseStale {
		t.Fatalf("an old leader completed after a newer lease committed: %v", err)
	}
	if r := f.rec(d.ID); r.Phase != control.DeliveryClaimed || r.Attempts[0].Outcome != "" || r.Provider != "" {
		t.Fatalf("a fenced completion left a mark: %+v", r)
	}
	// And the same fence applies to every other arm.
	if _, err := f.enqueueWith(model.NewID(), old, f.enqueueBody(1, f.intent(2))); code(err) != model.Stale {
		t.Fatalf("a deposed leader enqueued: %v", err)
	}
	if _, err := f.claim(old, 210, 100, 1); code(err) != model.Stale {
		t.Fatalf("a deposed leader claimed: %v", err)
	}
	if _, err := f.cancel(old, control.DeliveryCancel{Project: f.project, Delivery: d.ID, At: 210, Reason: "deleted"}); code(err) != model.Stale {
		t.Fatalf("a deposed leader cancelled: %v", err)
	}
	// The lease holder itself still completes, with the newer lease it holds
	// being exactly the claim's.
	f.mustClaim(newer, 400, 100, 1) // the lapsed attempt is closed unknown, attempt 2 is opened under newer
	if r := f.rec(d.ID); len(r.Attempts) != 2 || r.Attempts[1].Fence != newer {
		t.Fatalf("takeover: %+v", r)
	}
	// Stale Complete after a newer attempt: attempt 1 is closed and stays closed.
	if _, err := f.complete(newer, f.completeCmd(d.ID, 1, 410, "accepted", "p1", "", 0)); code(err) != model.Conflict || detail(err) != control.DeliveryAttemptClosed {
		t.Fatalf("a stale completion of a closed attempt: %v", err)
	}
	res := f.mustComplete(newer, f.completeCmd(d.ID, 2, 410, "accepted", "p2", "", 0))
	if res.Phase != control.DeliveryAccepted {
		t.Fatalf("holder completion: %+v", res)
	}
}

func TestDeliveryCompleteValidatesOutcomes(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d)
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 1)
	before := f.stateJSON()
	cases := map[string]control.DeliveryComplete{
		"accepted without provider evidence": f.completeCmd(d.ID, 1, 210, "accepted", "", "", 0),
		"accepted with a code":               f.completeCmd(d.ID, 1, 210, "accepted", "p", "ok", 0),
		"accepted with unsafe provider":      f.completeCmd(d.ID, 1, 210, "accepted", "has space", "", 0),
		"accepted with a schedule":           f.completeCmd(d.ID, 1, 210, "accepted", "p", "", 300),
		"retry without code":                 f.completeCmd(d.ID, 1, 210, "retry", "", "", 300),
		"retry without schedule":             f.completeCmd(d.ID, 1, 210, "retry", "", "rate_limited", 0),
		"retry in the past":                  f.completeCmd(d.ID, 1, 210, "retry", "", "rate_limited", 209),
		"retry beyond the budget horizon":    f.completeCmd(d.ID, 1, 210, "retry", "", "rate_limited", 210+control.DeliveryMaxAge+1),
		"retry with provider":                f.completeCmd(d.ID, 1, 210, "retry", "p", "rate_limited", 300),
		"unknown without code":               f.completeCmd(d.ID, 1, 210, "unknown", "", "", 300),
		"terminal without code":              f.completeCmd(d.ID, 1, 210, "terminal", "", "", 0),
		"terminal with a schedule":           f.completeCmd(d.ID, 1, 210, "terminal", "", "rejected", 300),
		"unsafe code":                        f.completeCmd(d.ID, 1, 210, "terminal", "", "Provider said: boom", 0),
		"unknown outcome kind":               f.completeCmd(d.ID, 1, 210, "delivered", "p", "", 0),
		"zero time":                          f.completeCmd(d.ID, 1, 0, "terminal", "", "rejected", 0),
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := f.complete(lease, cases[name]); code(err) != model.Invalid {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if f.stateJSON() != before {
		t.Fatal("a rejected completion changed state")
	}
}

// A definite retry keeps the delivery ID, schedules the next attempt and
// is not eligible before it; unknown acceptance is distinct from it and sticks;
// terminal and exhausted deliveries stay visibly failed or uncertain.
func TestDeliveryRetryUnknownAndTerminalAreDistinct(t *testing.T) {
	f := newDelFx(t)
	a, b, c := f.intent(1), f.intent(2), f.intent(3)
	f.mustEnqueue(0, a, b, c)
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 3)

	// retry: definite non-acceptance.
	res := f.mustComplete(lease, f.completeCmd(a.ID, 1, 210, "retry", "", "rate_limited", 400))
	ra := f.rec(a.ID)
	if res.Phase != control.DeliveryPending || ra.Phase != control.DeliveryPending || ra.Next != 400 || ra.Uncertain || ra.ID != a.ID || ra.Attempts[0].Outcome != "retry" || ra.Attempts[0].Code != "rate_limited" {
		t.Fatalf("after a definite retry: %+v", ra)
	}
	// unknown: possible acceptance, sticky.
	f.mustComplete(lease, f.completeCmd(b.ID, 1, 210, "unknown", "", "timeout_after_send", 400))
	rb := f.rec(b.ID)
	if rb.Phase != control.DeliveryPending || !rb.Uncertain || rb.Attempts[0].Outcome != "unknown" || rb.Attempts[0].ClosedBy != "worker" {
		t.Fatalf("after an unknown outcome: %+v", rb)
	}
	// terminal: failed, with the safe code.
	f.mustComplete(lease, f.completeCmd(c.ID, 1, 210, "terminal", "", "recipient_rejected", 0))
	rc := f.rec(c.ID)
	if rc.Phase != control.DeliveryFailed || rc.Code != "recipient_rejected" || rc.Provider != "" || rc.Uncertain {
		t.Fatalf("after a terminal outcome: %+v", rc)
	}
	// Not eligible before the schedule; eligible after, with the same ID.
	if got := f.mustClaim(lease, 399, 100, 5); len(got) != 0 {
		t.Fatalf("a retry was claimed before its schedule: %v", got)
	}
	got := f.mustClaim(lease, 400, 100, 5)
	if len(got) != 2 {
		t.Fatalf("both retries should be due at 400: %v", got)
	}
	// Attempt 2 of the unknown delivery finally fails terminally: a failure that
	// may still have been delivered once is uncertain, not plainly failed.
	f.mustComplete(lease, f.completeCmd(b.ID, 2, 410, "terminal", "", "recipient_rejected", 0))
	if rb = f.rec(b.ID); rb.Phase != control.DeliveryUncertain || rb.Code != "recipient_rejected" || !rb.Uncertain {
		t.Fatalf("terminal after unknown: %+v", rb)
	}
	// Attempt 2 of the definite-retry delivery is accepted: no duplicate possible.
	f.mustComplete(lease, f.completeCmd(a.ID, 2, 410, "accepted", "msg-a", "", 0))
	if ra = f.rec(a.ID); ra.Phase != control.DeliveryAccepted || ra.PossibleDuplicate || ra.Provider != "msg-a" || len(ra.Attempts) != 2 {
		t.Fatalf("accepted after definite retry: %+v", ra)
	}
	// A settled delivery is never claimed or completed again.
	if got := f.mustClaim(lease, 100000, 100, 5); len(got) != 0 {
		t.Fatalf("settled deliveries were claimed: %v", got)
	}
}

// The retry budget is 12 attempts or 24 hours from first eligibility. Exhaustion
// is a terminal reason that preserves uncertainty and keeps the attempt audit.
func TestDeliveryRetryBudgetIsBounded(t *testing.T) {
	t.Run("twelve definite retries fail visibly", func(t *testing.T) {
		f := newDelFx(t)
		d := f.intent(1)
		f.mustEnqueue(0, d)
		lease := f.lease()
		now := model.UnixNano(1000)
		for n := uint32(1); n <= control.DeliveryMaxAttempts; n++ {
			if got := f.mustClaim(lease, now, 100, 1); len(got) != 1 {
				t.Fatalf("attempt %d was not claimable: %v", n, got)
			}
			res := f.mustComplete(lease, f.completeCmd(d.ID, n, now+1, "retry", "", "unavailable", now+2))
			if n < control.DeliveryMaxAttempts && res.Phase != control.DeliveryPending {
				t.Fatalf("attempt %d settled early: %+v", n, res)
			}
			now += 10
		}
		r := f.rec(d.ID)
		if r.Phase != control.DeliveryFailed || r.Code != control.DeliveryReasonExhausted || len(r.Attempts) != control.DeliveryMaxAttempts || r.Uncertain {
			t.Fatalf("after the budget: %+v", r)
		}
		for _, a := range r.Attempts {
			if a.Outcome != "retry" || a.Code != "unavailable" {
				t.Fatalf("the attempt audit was altered: %+v", a)
			}
		}
		if f.auditCount("notify.delivery.failed") != 1 {
			t.Fatal("the exhaustion left no audit entry")
		}
		if got := f.mustClaim(lease, now+1000, 100, 1); len(got) != 0 {
			t.Fatalf("an exhausted delivery was claimed: %v", got)
		}
	})
	t.Run("unknown stays uncertain when the budget runs out", func(t *testing.T) {
		f := newDelFx(t)
		d := f.intent(1)
		f.mustEnqueue(0, d)
		lease := f.lease()
		now := model.UnixNano(1000)
		for n := uint32(1); n <= control.DeliveryMaxAttempts; n++ {
			f.mustClaim(lease, now, 100, 1)
			outcome, code := "retry", "unavailable"
			if n == 3 {
				outcome, code = "unknown", "timeout_after_send"
			}
			f.mustComplete(lease, f.completeCmd(d.ID, n, now+1, outcome, "", code, now+2))
			now += 10
		}
		if r := f.rec(d.ID); r.Phase != control.DeliveryUncertain || r.Code != control.DeliveryReasonExhausted || !r.Uncertain {
			t.Fatalf("exhaustion after an unknown attempt: %+v", r)
		}
	})
	t.Run("a lapsed twelfth attempt is uncertain", func(t *testing.T) {
		f := newDelFx(t)
		d := f.intent(1)
		f.mustEnqueue(0, d)
		lease := f.lease()
		now := model.UnixNano(1000)
		for n := uint32(1); n < control.DeliveryMaxAttempts; n++ {
			f.mustClaim(lease, now, 100, 1)
			f.mustComplete(lease, f.completeCmd(d.ID, n, now+1, "retry", "", "unavailable", now+2))
			now += 10
		}
		f.mustClaim(lease, now, 5, 1) // the twelfth attempt, never completed
		if got := f.mustClaim(f.newer(lease), now+5, 5, 1); len(got) != 0 {
			t.Fatalf("a thirteenth attempt was claimed: %v", got)
		}
		if r := f.rec(d.ID); r.Phase != control.DeliveryUncertain || r.Code != control.DeliveryReasonExhausted || len(r.Attempts) != 12 || r.Attempts[11].Outcome != "unknown" {
			t.Fatalf("the lapsed last attempt: %+v", r)
		}
	})
	t.Run("a retry scheduled past 24 hours exhausts at once", func(t *testing.T) {
		f := newDelFx(t)
		d := f.intent(1, withAt(1000))
		f.mustEnqueue(0, d)
		lease := f.lease()
		f.mustClaim(lease, 1000, 100, 1)
		// The provider asked to wait beyond the budget: honored within it or not at all.
		f.mustComplete(lease, f.completeCmd(d.ID, 1, 1001, "retry", "", "rate_limited", 1000+control.DeliveryMaxAge))
		if r := f.rec(d.ID); r.Phase != control.DeliveryFailed || r.Code != control.DeliveryReasonExhausted {
			t.Fatalf("a Retry-After beyond the budget: %+v", r)
		}
		// One nanosecond inside the horizon is still a retry.
		e := f.intent(2, withAt(1000))
		f.mustEnqueue(1, e)
		f.mustClaim(lease, 1000, 100, 1)
		f.mustComplete(lease, f.completeCmd(e.ID, 1, 1001, "retry", "", "rate_limited", 1000+control.DeliveryMaxAge-1))
		if r := f.rec(e.ID); r.Phase != control.DeliveryPending || r.Next != 1000+control.DeliveryMaxAge-1 {
			t.Fatalf("a Retry-After inside the budget: %+v", r)
		}
	})
	t.Run("a delivery never attempted for 24 hours expires", func(t *testing.T) {
		f := newDelFx(t)
		d := f.intent(1, withAt(1000))
		e := f.intent(2, withAt(1000))
		f.mustEnqueue(0, d, e)
		lease := f.lease()
		if got := f.mustClaim(lease, 1000+control.DeliveryMaxAge-1, 100, 1); len(got) != 1 {
			t.Fatalf("a delivery inside the budget was not claimable: %v", got)
		}
		if got := f.mustClaim(lease, 1000+control.DeliveryMaxAge, 100, 1); len(got) != 0 {
			t.Fatalf("a delivery past the budget was claimed: %v", got)
		}
		settled := 0
		for _, r := range f.all("") {
			if r.Phase == control.DeliveryCancelled && r.Code == control.DeliveryReasonExpired && len(r.Attempts) == 0 {
				settled++
			}
		}
		if settled != 1 {
			t.Fatalf("%d never-attempted deliveries expired, want the one still pending", settled)
		}
	})
}

// A repeat of an applied completion is a no-op; a different outcome for a
// closed attempt is a conflict and never rewrites it.
func TestDeliveryCompleteIsIdempotentAndImmutable(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d)
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 1)
	c := f.completeCmd(d.ID, 1, 210, "accepted", "msg-1", "", 0)
	first := f.mustComplete(lease, c)
	closed, _ := json.Marshal(f.rec(d.ID).Attempts[0])
	// Same outcome under a new command ID (a lost response, a restarted worker).
	repeat, err := f.complete(lease, c)
	if err != nil || repeat.Phase != "unchanged" || f.rec(d.ID).Phase != control.DeliveryAccepted {
		t.Fatalf("an identical completion: %+v %v (first %+v)", repeat, err, first)
	}
	// A different time for the same outcome is still the same completion.
	c2 := c
	c2.At = 215
	if res, err := f.complete(lease, c2); err != nil || res.Phase != "unchanged" {
		t.Fatalf("the same outcome at another instant: %+v %v", res, err)
	}
	// A different outcome for the closed attempt never overwrites it.
	for name, other := range map[string]control.DeliveryComplete{
		"other provider": f.completeCmd(d.ID, 1, 210, "accepted", "msg-2", "", 0),
		"other kind":     f.completeCmd(d.ID, 1, 210, "terminal", "", "rejected", 0),
	} {
		if _, err := f.complete(lease, other); code(err) != model.Conflict || detail(err) != control.DeliveryAttemptClosed {
			t.Errorf("%s: %v", name, err)
		}
	}
	if again, _ := json.Marshal(f.rec(d.ID).Attempts[0]); string(again) != string(closed) {
		t.Fatalf("a closed attempt changed:\n%s\n%s", closed, again)
	}
	if r := f.rec(d.ID); r.Provider != "msg-1" {
		t.Fatalf("the accepted evidence was overwritten: %+v", r)
	}
}

// Cancel settles a delivery that must not be sent. A pending one needs no
// attempt; a claimed one is cancelled only by its own holder, who thereby closes
// its attempt as a definite non-send.
func TestDeliveryCancelSettlesWithASafeReason(t *testing.T) {
	f := newDelFx(t)
	a, b, c := f.intent(1), f.intent(2), f.intent(3)
	f.mustEnqueue(0, a, b, c)
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 1) // a is claimed
	if res, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: b.ID, At: 210, Reason: control.DeliveryReasonDeleted}); err != nil || res.Phase != control.DeliveryCancelled {
		t.Fatalf("cancel a pending delivery: %+v %v", res, err)
	}
	if r := f.rec(b.ID); r.Phase != control.DeliveryCancelled || r.Code != "deleted" || len(r.Attempts) != 0 {
		t.Fatalf("cancelled pending: %+v", r)
	}
	// A claimed delivery needs its attempt named, and only the holder cancels it.
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: a.ID, At: 210, Reason: "deleted"}); code(err) != model.Conflict {
		t.Fatalf("cancelled a claimed delivery without naming its attempt: %v", err)
	}
	if _, err := f.cancel(f.newer(lease), control.DeliveryCancel{Project: f.project, Delivery: a.ID, Attempt: 1, At: 210, Reason: "deleted"}); code(err) != model.Conflict || detail(err) != control.DeliveryClaimNotHeld {
		t.Fatalf("a non-holder cancelled a claimed delivery: %v", err)
	}
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: a.ID, Attempt: 2, At: 210, Reason: "deleted"}); code(err) != model.Conflict && code(err) != model.Invalid {
		t.Fatalf("cancelled an attempt that does not exist: %v", err)
	}
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: a.ID, Attempt: 1, At: 210, Reason: "deleted"}); err != nil {
		t.Fatalf("the holder's cancel: %v", err)
	}
	r := f.rec(a.ID)
	at := r.Attempts[0]
	if r.Phase != control.DeliveryCancelled || r.Code != "deleted" || at.Outcome != "terminal" || at.Code != "deleted" || at.ClosedBy != "worker" || at.Provider != "" || r.Uncertain {
		t.Fatalf("holder cancel: %+v", r)
	}
	// A reason outside the closed set and a settled delivery are refused.
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: c.ID, At: 210, Reason: "because I said so"}); code(err) != model.Invalid {
		t.Fatalf("a free-text cancel reason: %v", err)
	}
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: b.ID, At: 220, Reason: "deleted"}); err != nil {
		t.Fatalf("a repeated identical cancel: %v", err)
	}
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: b.ID, At: 220, Reason: "expired"}); code(err) != model.Conflict {
		t.Fatalf("re-cancelling a settled delivery for another reason: %v", err)
	}
	// A missing channel is a visible failed delivery, not a cancellation.
	if _, err := f.cancel(lease, control.DeliveryCancel{Project: f.project, Delivery: c.ID, At: 230, Reason: control.DeliveryReasonNoDestination}); err != nil {
		t.Fatal(err)
	}
	if r = f.rec(c.ID); r.Phase != control.DeliveryFailed || r.Code != "no_destination" {
		t.Fatalf("a missing channel: %+v", r)
	}
	if f.auditCount("notify.delivery.cancelled") != 2 || f.auditCount("notify.delivery.failed") != 1 {
		t.Fatal("settlements left no audit trail")
	}
}

// Destination state is revalidated inside the claim: a removed channel is a
// visible failed delivery (terminal, no attempt), a disabled one is cancelled
// with a safe reason, and a delivery to the shared queue is never sent.
func TestDeliveryClaimRevalidatesTheDestination(t *testing.T) {
	f := newDelFx(t)
	gone := model.ID{0xd9} // never configured
	disabled := model.ID{0xd2}
	f.setDestination(disabled, true)
	ok := f.intent(1)
	missing := f.intent(2, withRecipient(&gone))
	off := f.intent(3, withRecipient(&disabled))
	f.mustEnqueue(0, ok, missing, off)
	f.setDestination(disabled, false)
	lease := f.lease()
	if r := f.recAt(missing.ID, 200); r.Hold != "no_destination" {
		t.Fatalf("hold of a missing channel: %q", r.Hold)
	}
	if r := f.recAt(off.ID, 200); r.Hold != "destination_disabled" {
		t.Fatalf("hold of a disabled channel: %q", r.Hold)
	}
	got := f.mustClaim(lease, 200, 100, 5)
	if len(got) != 1 || got[0] != ok.ID {
		t.Fatalf("claimed %v, want only the deliverable one", got)
	}
	m, d := f.rec(missing.ID), f.rec(off.ID)
	if m.Phase != control.DeliveryFailed || m.Code != "no_destination" || len(m.Attempts) != 0 {
		t.Fatalf("missing channel: %+v", m)
	}
	if d.Phase != control.DeliveryCancelled || d.Code != "destination_disabled" || len(d.Attempts) != 0 {
		t.Fatalf("disabled channel: %+v", d)
	}
	// The sealed destination secret never reaches a delivery record or an audit.
	for _, raw := range f.delBooks() {
		if strings.Contains(raw, destSecret) || strings.Contains(raw, "hooks.example.test") {
			t.Fatal("destination configuration reached the delivery state")
		}
	}
}

// C12: a closing deletion pauses deliveries derived from its origin at once, and
// completing it cancels them as deleted; a deletion elsewhere changes nothing.
func TestDeliveryDeletionPausesThenCancelsDerivedSends(t *testing.T) {
	f := newDelFx(t)
	inside := f.intent(1, withOrigin(10, 50))
	straddle := f.intent(2, withOrigin(90, 150))
	unknown := f.intent(3) // origin unknown: covered
	outside := f.intent(4, withOrigin(200, 300))
	f.mustEnqueue(0, inside, straddle, unknown, outside)
	lease := f.lease()
	id, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []control.DeliveryIntent{inside, straddle, unknown} {
		if r := f.recAt(d.ID, 1000); r.Hold != control.DeliveryHoldPaused || r.Phase != control.DeliveryPending {
			t.Fatalf("a delivery derived from the closing range is not paused: %+v", r)
		}
	}
	if r := f.recAt(outside.ID, 1000); r.Hold != "" {
		t.Fatalf("a delivery outside the range is held: %+v", r)
	}
	got := f.mustClaim(lease, 1000, 100, 10)
	if len(got) != 1 || got[0] != outside.ID {
		t.Fatalf("claimed %v while the deletion was closing, want only the unaffected delivery", got)
	}
	for _, d := range []control.DeliveryIntent{inside, straddle, unknown} {
		if r := f.rec(d.ID); r.Phase != control.DeliveryPending || len(r.Attempts) != 0 {
			t.Fatalf("a paused delivery changed: %+v", r)
		}
	}
	// Completing the deletion settles them as deleted, with an audit entry.
	if _, err = f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), nil); err != nil {
		t.Fatal(err)
	}
	if got = f.mustClaim(lease, 1001, 100, 10); len(got) != 0 {
		t.Fatalf("claimed %v after the deletion completed", got)
	}
	for _, d := range []control.DeliveryIntent{inside, straddle, unknown} {
		if r := f.rec(d.ID); r.Phase != control.DeliveryCancelled || r.Code != "deleted" || len(r.Attempts) != 0 {
			t.Fatalf("a delivery derived from deleted data: %+v", r)
		}
	}
	if r := f.rec(outside.ID); r.Phase != control.DeliveryClaimed {
		t.Fatalf("an unrelated delivery was touched: %+v", r)
	}
	if f.auditCount("notify.delivery.cancelled") != 3 {
		t.Fatal("deleted-origin cancellations left no audit trail")
	}
}

// A deletion that is held or failed never pauses sends, and a deletion of another
// project or signal-free entity root does not either.
func TestDeliveryDeletionOfOtherDataDoesNotPause(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1, withOrigin(10, 50))
	f.mustEnqueue(0, d)
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.otherProject}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 100, End: 200}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}, Signals: []model.Kind{model.Replay}}); err != nil {
		t.Fatal(err)
	}
	if r := f.recAt(d.ID, 1000); r.Hold != "" {
		t.Fatalf("an unrelated deletion holds the delivery: %+v", r)
	}
	if got := f.mustClaim(f.lease(), 1000, 100, 5); len(got) != 1 {
		t.Fatalf("claimed %v", got)
	}
}

// The evidence interval of a delivery is CLOSED, a historical range is half-open:
// a delivery is covered exactly when they share an instant. An unknown interval is
// covered.
func TestDeliveryDeletionOverlapBoundaries(t *testing.T) {
	f := newDelFx(t)
	cases := []struct {
		seed     byte
		from, to model.UnixNano
		covered  bool
		why      string
	}{
		{1, 10, 49, false, "ends the instant before the range starts"},
		{2, 10, 50, true, "its last instant is the range's first"},
		{3, 99, 150, true, "starts at the range's last instant"},
		{4, 100, 150, false, "starts where the range ends (exclusive)"},
		{5, 60, 60, true, "a single instant inside the range"},
		{6, 0, 0, true, "an unknown interval"},
		{7, 1, 1000, true, "an interval that spans the whole range"},
	}
	var intents []control.DeliveryIntent
	for _, c := range cases {
		intents = append(intents, f.intent(c.seed, withOrigin(c.from, c.to)))
	}
	f.mustEnqueue(0, intents...)
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 50, End: 100}); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		hold := f.recAt(model.ID{0xe0, c.seed}, 1000).Hold
		if (hold == control.DeliveryHoldPaused) != c.covered {
			t.Errorf("origin [%d,%d] (%s): hold %q, covered want %v", c.from, c.to, c.why, hold, c.covered)
		}
	}
}

// A retired project is unreachable for every arm; its deliveries stay as
// tombstoned audit and nothing can be sent for it.
func TestDeliveryOfARetiredProjectIsUnreachable(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d)
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 1)
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.claim(lease, 300, 100, 1); code(err) != model.NotFound {
		t.Fatalf("claim for a retired project: %v", err)
	}
	if _, err := f.complete(lease, f.completeCmd(d.ID, 1, 250, "accepted", "p", "", 0)); code(err) != model.NotFound {
		t.Fatalf("completion for a retired project: %v", err)
	}
	if _, err := f.enqueueWith(model.NewID(), lease, f.enqueueBody(1, f.intent(2))); code(err) != model.NotFound {
		t.Fatalf("enqueue for a retired project: %v", err)
	}
}

// The outbox never holds a destination secret, telemetry text or a free-text
// reason: its state is typed fields, and its audit entries name IDs and codes.
func TestDeliveryStateAndAuditStaySafe(t *testing.T) {
	f := newDelFx(t)
	d := f.intent(1)
	f.mustEnqueue(0, d, f.intent(2, withDisposition("failed", "immediate", "no_destination"), withRecipient(nil)))
	lease := f.lease()
	f.mustClaim(lease, 200, 100, 1)
	f.mustComplete(lease, f.completeCmd(d.ID, 1, 210, "terminal", "", "recipient_rejected", 0))
	var books map[string]json.RawMessage
	var audits []control.Audit
	if err := f.store.View(f.ctx, func(st control.State) error {
		books, audits = st.DeliveryBooks, st.Audits
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(books)
	if strings.Contains(string(raw), destSecret) || strings.Contains(string(raw), "hooks.example.test") {
		t.Fatalf("the outbox holds destination configuration: %s", raw)
	}
	found := 0
	for _, a := range audits {
		if !strings.HasPrefix(a.Action, "notify.delivery.") {
			continue
		}
		found++
		line, _ := json.Marshal(a)
		if strings.Contains(string(line), destSecret) || strings.Contains(a.Reason, " ") || a.Principal != f.user || a.Org != f.org.String() || len(a.Targets) == 0 {
			t.Fatalf("unsafe or unbound audit entry: %s", line)
		}
	}
	if found != 2 {
		t.Fatalf("%d delivery audit entries, want 2 (the failed intent and the terminal failure)", found)
	}
}

// Settled history and open deliveries are bounded: settled records are pruned
// oldest first (benign ones before failures), open ones never, and a pruned
// record's audit entry stays.
func TestDeliveryHistoryIsBounded(t *testing.T) {
	f := newDelFx(t)
	failed := f.intent(1, withDisposition("failed", "immediate", "no_destination"), withRecipient(nil), withAt(1))
	f.mustEnqueue(0, failed)
	open := f.intent(2, withAt(2))
	version := uint64(1)
	f.mustEnqueue(version, open)
	version++
	next := uint16(10)
	for batch := 0; batch < 17; batch++ {
		var intents []control.DeliveryIntent
		for range 64 {
			next++
			in := f.intent(0, withDisposition("deliver", "queue", ""), withRecipient(nil), withAt(model.UnixNano(next)))
			in.ID = model.ID{0xc0, byte(next >> 8), byte(next)}
			intents = append(intents, in)
		}
		f.mustEnqueue(version, intents...)
		version++
	}
	var queued, openCount, failedCount int
	for _, r := range f.all("") {
		switch r.Phase {
		case control.DeliveryQueued:
			queued++
		case control.DeliveryPending:
			openCount++
		case control.DeliveryFailed:
			failedCount++
		}
	}
	if queued != 1024-1 || openCount != 1 || failedCount != 1 {
		t.Fatalf("after 1088 queued entries: queued=%d open=%d failed=%d, want 1023/1/1 (settled bound 1024, benign pruned first)", queued, openCount, failedCount)
	}
	if f.auditCount("notify.delivery.failed") != 1 {
		t.Fatal("the audit entry of a kept failure is gone")
	}
}

func TestDeliveryOpenDeliveriesAreBounded(t *testing.T) {
	f := newDelFx(t)
	version := uint64(0)
	n := uint16(0)
	push := func(count int) error {
		var intents []control.DeliveryIntent
		for range count {
			n++
			in := f.intent(0, withBody(`{}`))
			in.ID = model.ID{0xc1, byte(n >> 8), byte(n)}
			intents = append(intents, in)
		}
		_, err := f.enqueue(version, intents...)
		if err == nil {
			version++
		}
		return err
	}
	for range 64 {
		if err := push(64); err != nil {
			t.Fatalf("enqueue under the bound: %v", err)
		}
	}
	if err := push(1); code(err) != model.Quota {
		t.Fatalf("the 4097th open delivery was accepted: %v", err)
	}
}

// The committed state is the same whatever order retried and duplicated commands
// arrive in: every command is idempotent or a conflict, never a merge.
func TestDeliveryDeterministicUnderReorderedRetries(t *testing.T) {
	d := func(f *delFx) control.DeliveryIntent { return f.intent(1) }
	run := func(order []int) string {
		f := newDelFx(t)
		lease := f.lease()
		cmdIDs := []model.ID{{1}, {2}, {3}, {4}}
		steps := []func() error{
			func() error {
				_, err := f.enqueueWith(cmdIDs[0], lease, f.enqueueBody(0, d(f), f.intent(2)))
				return err
			},
			func() error {
				_, err := f.send(control.KindClaimDelivery, cmdIDs[1], control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Claim: &control.DeliveryClaim{Project: f.project, Now: 200, Expires: 300, Limit: 1}})
				return err
			},
			func() error {
				c := f.completeCmd(model.ID{0xe0, 1}, 1, 210, "accepted", "msg", "", 0)
				_, err := f.send(control.KindCompleteDelivery, cmdIDs[2], control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease, Complete: &c})
				return err
			},
			func() error {
				_, err := f.send(control.KindCompleteDelivery, cmdIDs[3], control.DeliveryCommand{Operation: control.DeliveryOpCancel, Lease: &lease, Cancel: &control.DeliveryCancel{Project: f.project, Delivery: model.ID{0xe0, 2}, At: 220, Reason: "deleted"}})
				return err
			},
		}
		for _, i := range order {
			// A step that arrives before its predecessor, or twice, may be refused;
			// it must never change what a correct order commits.
			_ = steps[i]()
		}
		var out string
		_ = f.store.View(f.ctx, func(st control.State) error {
			var recs []control.DeliveryRecord
			for key, raw := range st.DeliveryBooks {
				if !strings.HasPrefix(key, "delivery:") {
					continue
				}
				var r control.DeliveryRecord
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				r.Org, r.Project, r.Policy, r.Created = model.ID{1}, model.ID{2}, model.ID{3}, 0
				for i := range r.Attempts {
					r.Attempts[i].Fence = replica.FenceToken{Group: model.ID{1}}
				}
				recs = append(recs, r)
			}
			sort.Slice(recs, func(i, j int) bool { return recs[i].ID.String() < recs[j].ID.String() })
			raw, _ := json.Marshal(recs)
			out = string(raw)
			return nil
		})
		return out
	}
	ordered := run([]int{0, 1, 2, 3})
	reordered := run([]int{0, 0, 1, 1, 0, 2, 2, 3, 3, 1, 2, 0, 3})
	if ordered != reordered || !strings.Contains(ordered, `"phase":"accepted"`) || !strings.Contains(ordered, `"phase":"cancelled"`) {
		t.Fatalf("state depends on retry order:\n%s\n%s", ordered, reordered)
	}
	// Steps that arrive too early are refused, not applied out of order.
	early := run([]int{2, 3, 1, 0})
	if strings.Contains(early, `"phase":"accepted"`) {
		t.Fatalf("a completion before its enqueue and claim was applied:\n%s", early)
	}
}

// Deliveries, attempts, fences and policy states survive a restart and a control
// snapshot import, and a restarted store still answers a committed command once.
func TestDeliveryOutboxSurvivesRestartAndSnapshotImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	open := func() (*control.Store, *auth.Service) {
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.BindDeliveryOutbox(); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, svc
	}
	store, svc := open()
	boot, _ := store.BootstrapToken()
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, policy := model.NewID(), model.NewID(), model.ID{0xf1}
	subject := "incident:" + model.ID{0xa1}.String()
	admin := func(kind string, p auth.AdminPayload) {
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(p)
		if _, err := svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	admin("create_org", auth.AdminPayload{Name: "restart", Reason: "fixture"})
	admin("create_project", auth.AdminPayload{ID: project, Name: "p1", Reason: "fixture"})
	dest := model.ID{0xd1}
	admin("destination", auth.AdminPayload{ID: dest, Config: json.RawMessage(`{"type":"webhook","enabled":true}`), Secret: destSecret, Reason: "fixture"})
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, id model.ID, kind control.CommandKind, c control.DeliveryCommand) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(c)
		return store.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(kind), Payload: raw})
	}
	lease, err := store.ReplicaGroup().Fence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body := json.RawMessage(`{"seed":1}`)
	stateRaw := json.RawMessage(fmt.Sprintf(`{"org_id":%q}`, org.String()))
	in := control.DeliveryIntent{ID: model.ID{0xe0, 1}, Kind: "open", Disposition: "deliver", Route: "immediate", Recipient: &dest, At: 100, Body: body, Digest: digest(body)}
	enq := control.DeliveryEnqueue{Project: project, Policy: policy, Subject: subject, NewVersion: 1, At: 100, State: stateRaw, Digest: digest(stateRaw), Intents: []control.DeliveryIntent{in}}
	enqID := model.NewID()
	first, err := send(store, svc, cred, enqID, control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &enq})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = send(store, svc, cred, model.NewID(), control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease, Claim: &control.DeliveryClaim{Project: project, Now: 200, Expires: 300, Limit: 1}}); err != nil {
		t.Fatal(err)
	}
	snapshot := func(st control.State) string {
		raw, _ := json.Marshal(st.DeliveryBooks)
		return string(raw)
	}
	var before string
	if err = store.View(ctx, func(st control.State) error { before = snapshot(st); return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, `"attempts"`) || !strings.Contains(before, `"fence:`) || !strings.Contains(before, `"policy:`) {
		t.Fatalf("the outbox state is incomplete: %s", before)
	}
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var restored string
	if err = imported.View(ctx, func(st control.State) error { restored = snapshot(st); return nil }); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	if restored != before {
		t.Fatalf("snapshot import changed the outbox:\n%s\n%s", before, restored)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, svc = open()
	defer store.Close()
	if cred, err = svc.Authenticate(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = store.View(ctx, func(st control.State) error { after = snapshot(st); return nil }); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restart changed the outbox:\n%s\n%s", before, after)
	}
	// The restarted leader has a newer term; the committed enqueue answers once.
	newLease, err := store.ReplicaGroup().Fence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newLease.Term <= lease.Term {
		t.Fatalf("restart did not move the election term: %d -> %d", lease.Term, newLease.Term)
	}
	again, err := send(store, svc, cred, enqID, control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &newLease, Enqueue: &enq})
	if err != nil || again.Revision != first.Revision {
		t.Fatalf("committed enqueue not recognized after restart: %+v vs %+v (%v)", again, first, err)
	}
	// The pre-restart lease is stale for the restarted outbox once the new leader commits.
	if _, err = send(store, svc, cred, model.NewID(), control.KindClaimDelivery, control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &newLease, Claim: &control.DeliveryClaim{Project: project, Now: 250, Expires: 350, Limit: 1}}); err != nil {
		t.Fatal(err)
	}
	c := control.DeliveryComplete{Project: project, Delivery: in.ID, Attempt: 1, At: 260, Outcome: "accepted", Provider: "p"}
	if _, err = send(store, svc, cred, model.NewID(), control.KindCompleteDelivery, control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &lease, Complete: &c}); code(err) != model.Stale {
		t.Fatalf("the pre-restart lease completed after restart: %v", err)
	}
}
