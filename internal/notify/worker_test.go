// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
)

// call is one provider send as the provider saw it.
type call struct {
	ID      model.ID
	Attempt uint32
	Secret  string
}

// provider is the fake notify.Sender the worker tests drive: a stand-in for the
// provider adapters of task 06.08, which do not exist yet. It records every send,
// dedups by delivery ID the way a provider with an idempotency key does (the same
// ID gets the same message identity), and can be scripted per call.
type provider struct {
	mu      sync.Mutex
	calls   []call
	script  func(nth int, d notify.Delivery) (notify.Outcome, error)
	onSend  func(d notify.Delivery)
	observe func() string // the destination secret the sender would resolve now
}

func (p *provider) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	p.mu.Lock()
	nth := 1
	for _, c := range p.calls {
		if c.ID == d.ID {
			nth++
		}
	}
	secret := ""
	if p.observe != nil {
		secret = p.observe()
	}
	p.calls = append(p.calls, call{ID: d.ID, Attempt: d.Attempt, Secret: secret})
	script, onSend := p.script, p.onSend
	p.mu.Unlock()
	if onSend != nil {
		onSend(d)
	}
	if script != nil {
		return script(nth, d)
	}
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-" + d.ID.String()[:8]}, nil
}

func (p *provider) count(id model.ID) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		if c.ID == id {
			n++
		}
	}
	return n
}
func (p *provider) total() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.calls) }

// hookQueue wraps the outbox the worker drives so a test can act between the
// worker's steps, or kill the "process" at one of them.
type hookQueue struct {
	notify.Queue
	afterClaim func([]notify.Delivery)
	onComplete func(id model.ID, attempt uint32, o notify.Outcome) error
	// afterComplete runs after a completion committed.
	afterComplete func()
	// afterDue runs after a timer decision (a policy checkpoint) committed.
	afterDue func()
}

func (q *hookQueue) Due(ctx context.Context, scope auth.Scope, lease notify.FenceToken, at model.UnixNano, limit int) (int, error) {
	fired, err := q.Queue.Due(ctx, scope, lease, at, limit)
	if err == nil && fired > 0 && q.afterDue != nil {
		q.afterDue()
	}
	return fired, err
}

func (q *hookQueue) Claim(ctx context.Context, scope auth.Scope, now model.UnixNano, lease notify.FenceToken, limit int) ([]notify.Delivery, error) {
	d, err := q.Queue.Claim(ctx, scope, now, lease, limit)
	if err == nil && q.afterClaim != nil {
		q.afterClaim(d)
	}
	return d, err
}

func (q *hookQueue) Complete(ctx context.Context, scope auth.Scope, id model.ID, attempt uint32, o notify.Outcome) error {
	if q.onComplete != nil {
		if err := q.onComplete(id, attempt, o); err != nil {
			return err
		}
	}
	err := q.Queue.Complete(ctx, scope, id, attempt, o)
	if err == nil && q.afterComplete != nil {
		q.afterComplete()
	}
	return err
}

var errCrash = errors.New("process died")

// crash runs fn and reports whether the "process" died in it (a panic stops
// everything after it, as a dead process does; nothing the worker does can
// recover from it).
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

func (n *node) worker(q notify.Queue, p notify.Sender, opts ...notify.WorkerOption) *notify.Worker {
	n.t.Helper()
	w, err := notify.NewWorker(q, p, n.group(), opts...)
	if err != nil {
		n.t.Fatal(err)
	}
	return w
}

// run is one RunOnce at the given instant under the current leader's lease.
func (n *node) run(w *notify.Worker, at model.UnixNano) (notify.RunReport, error) {
	n.t.Helper()
	n.clock.set(at)
	return w.RunOnce(n.ctx, n.scope(), at, n.lease())
}

func (n *node) mustRun(w *notify.Worker, at model.UnixNano) notify.RunReport {
	n.t.Helper()
	r, err := n.run(w, at)
	if err != nil {
		n.t.Fatalf("run at %d: %v", at-base, err)
	}
	return r
}

func has(ids []model.ID, id model.ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func (n *node) record(ob *notify.Outbox, id model.ID) notify.Record {
	n.t.Helper()
	r, ok, err := ob.Record(n.ctx, n.scope(), id, n.clock.Now())
	if err != nil || !ok {
		n.t.Fatalf("record %s: %v %v", id, ok, err)
	}
	return r
}

func (n *node) beginDeletion(from, to model.UnixNano) model.ID {
	n.t.Helper()
	scope, err := n.svc.Authorize(n.ctx, n.cred, n.org, nil, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	id := model.NewID()
	at := n.clock.Now()
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{n.project}, Signals: []model.Kind{model.Metric}, Start: from, End: to,
		Reason: "fixture deletion", At: at, PhysicalDeadline: at + model.UnixNano(24*time.Hour), BackupDeadline: at + model.UnixNano(30*24*time.Hour)}
	raw, _ := json.Marshal(req)
	if _, err = n.store.Transact(n.ctx, scope, control.Command{CommandID: id, ExpectedRevision: n.revision(), Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		n.t.Fatal("begin deletion:", err)
	}
	return id
}

func (n *node) completeDeletion(id model.ID) {
	n.t.Helper()
	barriers := make([]model.Cursor, model.DeleteSlots)
	for i := range barriers {
		barriers[i] = model.Cursor{Group: model.NewID(), Index: model.Uint64(i + 1)}
	}
	if _, err := n.store.RecordBarriers(n.ctx, id, barriers); err != nil {
		n.t.Fatal(err)
	}
	if _, err := n.store.CompleteDeletion(n.ctx, id, n.clock.Now(), nil); err != nil {
		n.t.Fatal(err)
	}
}

// openSecret is what a real sender does at every attempt: resolve the
// destination's current sealed secret fresh from control.
func (n *node) openSecret() string {
	var sealed string
	if err := n.store.View(n.ctx, func(st control.State) error {
		sealed = st.Orgs[n.org.String()].Secrets["destination:"+n.dest.String()]
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
	if sealed == "" {
		return ""
	}
	secret, err := n.store.OpenSecret(sealed)
	if err != nil {
		n.t.Fatal(err)
	}
	return secret
}

// stateText is the whole committed control state as text, for "never stored"
// assertions.
func (n *node) stateText() string {
	var out string
	_ = n.store.View(n.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.DeliveryBooks)
		audits, _ := json.Marshal(st.Audits)
		out = string(raw) + string(audits)
		return nil
	})
	return out
}

func (n *node) auditCount(action string) int {
	c := 0
	_ = n.store.View(n.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				c++
			}
		}
		return nil
	})
	return c
}

// auditFor lists the delivery audit entries that name one delivery.
func (n *node) auditFor(id model.ID, action string) []control.Audit {
	var out []control.Audit
	_ = n.store.View(n.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action != action {
				continue
			}
			for _, target := range a.Targets {
				if target == id {
					out = append(out, a)
				}
			}
		}
		return nil
	})
	return out
}

func TestWorkerSendsOnceAndRecordsAcceptanceWithProviderEvidence(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	p := &provider{}
	w := n.worker(ob, p)
	open := n.openRecord(ob)
	report := n.mustRun(w, base+sec)
	if len(report.Claimed) != 1 || !has(report.Accepted, open.ID) || len(report.Errors) != 0 {
		t.Fatalf("report: %+v", report)
	}
	rec := n.record(ob, open.ID)
	if rec.Phase != control.DeliveryAccepted || rec.Provider != "msg-"+open.ID.String()[:8] || len(rec.Attempts) != 1 || rec.PossibleDuplicate || rec.Uncertain {
		t.Fatalf("record: %+v", rec)
	}
	if a := rec.Attempts[0]; a.Outcome != control.DeliveryOutcomeAccepted || a.Provider != rec.Provider || a.ClosedBy != "worker" || a.Number != 1 {
		t.Fatalf("attempt: %+v", a)
	}
	if p.total() != 1 || p.calls[0].ID != open.ID || p.calls[0].Attempt != 1 {
		t.Fatalf("provider calls: %+v (the queue entry must never be sent)", p.calls)
	}
	// A second run finds nothing: an accepted delivery is never sent again.
	if r := n.mustRun(w, base+10*60*sec); len(r.Claimed) != 0 || p.total() != 1 {
		t.Fatalf("a settled delivery was run again: %+v", r)
	}
}

// A definite retry and an unknown acceptance are different outcomes with the
// same stable ID; a retry waits for its schedule and the provider's Retry-After.
func TestWorkerRetryAndUnknownAreDistinct(t *testing.T) {
	n := newNode(t)
	ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	p := &provider{script: func(nth int, d notify.Delivery) (notify.Outcome, error) {
		switch nth {
		case 1:
			return notify.Outcome{Kind: notify.OutcomeRetry, Code: "rate_limited", RetryAfter: 30 * sec}, nil
		case 2:
			return notify.Outcome{}, context.DeadlineExceeded // timeout after the request was written
		}
		return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-final"}, nil
	}}
	w := n.worker(ob, p)

	r1 := n.mustRun(w, base+sec)
	if !has(r1.Retried, open.ID) || has(r1.Unknown, open.ID) {
		t.Fatalf("a definite retry: %+v", r1)
	}
	rec := n.record(ob, open.ID)
	if rec.Uncertain || rec.Next != base+sec+30*sec {
		t.Fatalf("after the retry: next %d uncertain %v", rec.Next-base, rec.Uncertain)
	}
	if r := n.mustRun(w, base+sec+29*sec); len(r.Claimed) != 0 {
		t.Fatalf("a retry ran before the provider's Retry-After: %+v", r)
	}
	r2 := n.mustRun(w, base+sec+30*sec)
	if !has(r2.Unknown, open.ID) || has(r2.Retried, open.ID) {
		t.Fatalf("a timeout after the request was sent must be unknown, not a retry: %+v", r2)
	}
	rec = n.record(ob, open.ID)
	if !rec.Uncertain || rec.Attempts[1].Outcome != control.DeliveryOutcomeUnknown || rec.Attempts[1].Code != "timeout" || rec.Phase != control.DeliveryPending {
		t.Fatalf("after the timeout: %+v", rec)
	}
	r3 := n.mustRun(w, rec.Next)
	if !has(r3.Accepted, open.ID) {
		t.Fatalf("the third attempt: %+v", r3)
	}
	rec = n.record(ob, open.ID)
	if rec.ID != open.ID || rec.Phase != control.DeliveryAccepted || !rec.PossibleDuplicate || len(rec.Attempts) != 3 || rec.Provider != "msg-final" {
		t.Fatalf("final: %+v", rec)
	}
	for i, c := range p.calls {
		if c.ID != open.ID || c.Attempt != uint32(i+1) {
			t.Fatalf("the provider saw %+v: the ID and attempt numbers must be stable and ordered", p.calls)
		}
	}
}

// Only an accepted outcome with observed provider evidence is accepted: anything
// else the sender claims is recorded as unknown or failed, never as success.
func TestWorkerNeverLabelsAcceptedWithoutEvidence(t *testing.T) {
	cases := map[string]struct {
		outcome notify.Outcome
		err     error
		kind    string
		code    string
	}{
		"accepted without a provider ID": {notify.Outcome{Kind: notify.OutcomeAccepted}, nil, control.DeliveryOutcomeUnknown, "accepted_without_evidence"},
		"accepted with an unsafe ID":     {notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "id with spaces\nand lines"}, nil, control.DeliveryOutcomeUnknown, "accepted_without_evidence"},
		"an invalid outcome kind":        {notify.Outcome{Kind: "delivered", ProviderID: "x"}, nil, control.DeliveryOutcomeUnknown, "invalid_outcome"},
		"a sender error":                 {notify.Outcome{}, errors.New("dial tcp: i/o timeout to https://hooks.example.test/secret-path"), control.DeliveryOutcomeUnknown, "sender_error"},
		"a cancelled context":            {notify.Outcome{}, context.Canceled, control.DeliveryOutcomeUnknown, "cancelled"},
		"an unsafe failure code":         {notify.Outcome{Kind: notify.OutcomeTerminal, Code: "HTTP 500: stack trace for " + "secret"}, nil, control.DeliveryOutcomeTerminal, "unspecified"},
		"a retry without a code":         {notify.Outcome{Kind: notify.OutcomeRetry}, nil, control.DeliveryOutcomeRetry, "unspecified"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			ob := n.outbox()
			if _, err := n.openAndQueue(ob); err != nil {
				t.Fatal(err)
			}
			open := n.openRecord(ob)
			w := n.worker(ob, &provider{script: func(int, notify.Delivery) (notify.Outcome, error) { return tc.outcome, tc.err }})
			n.mustRun(w, base+sec)
			rec := n.record(ob, open.ID)
			a := rec.Attempts[0]
			if rec.Phase == control.DeliveryAccepted || rec.Provider != "" || a.Outcome != tc.kind || a.Code != tc.code {
				t.Fatalf("recorded %+v (attempt %+v), want outcome %s code %s and never accepted", rec, a, tc.kind, tc.code)
			}
			// Nothing a provider said or a transport printed is stored.
			for _, banned := range []string{"secret-path", "hooks.example.test", "stack trace", "i/o timeout", "id with spaces"} {
				if strings.Contains(n.stateText(), banned) {
					t.Fatalf("provider text %q reached control state", banned)
				}
			}
		})
	}
}

func TestWorkerTerminalOutcomeFailsAndIsNotRetried(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	p := &provider{script: func(int, notify.Delivery) (notify.Outcome, error) {
		return notify.Outcome{Kind: notify.OutcomeTerminal, Code: "recipient_rejected"}, nil
	}}
	w := n.worker(ob, p)
	if r := n.mustRun(w, base+sec); !has(r.Failed, open.ID) {
		t.Fatalf("report: %+v", r)
	}
	if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryFailed || rec.Code != "recipient_rejected" || rec.Provider != "" {
		t.Fatalf("record: %+v", rec)
	}
	if r := n.mustRun(w, base+2*3600*sec); has(r.Claimed, open.ID) || p.count(open.ID) != 1 {
		t.Fatalf("a failed delivery was retried: %+v", r)
	}
}

// A destination that is gone is a visible failed delivery and nothing is sent,
// whether it vanished before the claim or between the claim and the send.
func TestWorkerMissingChannelIsTerminalAndNeverSent(t *testing.T) {
	t.Run("before the claim", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		n.removeDestination(n.dest)
		p := &provider{}
		w := n.worker(ob, p)
		n.mustRun(w, base+sec)
		rec := n.record(ob, open.ID)
		if rec.Phase != control.DeliveryFailed || rec.Code != "no_destination" || len(rec.Attempts) != 0 || p.total() != 0 {
			t.Fatalf("record %+v, provider calls %d", rec, p.total())
		}
	})
	t.Run("between the claim and the send", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		p := &provider{}
		q := &hookQueue{Queue: ob, afterClaim: func([]notify.Delivery) { n.removeDestination(n.dest) }}
		w := n.worker(q, p)
		report := n.mustRun(w, base+sec)
		rec := n.record(ob, open.ID)
		if !has(report.Failed, open.ID) || rec.Phase != control.DeliveryFailed || rec.Code != "no_destination" || p.total() != 0 {
			t.Fatalf("report %+v record %+v provider calls %d", report, rec, p.total())
		}
		if a := rec.Attempts[0]; a.Outcome != control.DeliveryOutcomeTerminal || a.Code != "no_destination" {
			t.Fatalf("the unsent attempt: %+v", a)
		}
	})
	t.Run("a policy with no recipient at all", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		// No destination event: the policy has nobody to tell.
		if _, err := ob.Submit(n.ctx, n.scope(), n.lease(), incident, n.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
			t.Fatal(err)
		}
		recs := n.records(ob, control.DeliveryFailed)
		if len(recs) != 1 || recs[0].Code != "no_destination" || recs[0].Kind != string(notify.KindOpen) {
			t.Fatalf("a missing channel is not a visible failed delivery: %+v", n.records(ob, ""))
		}
		p := &provider{}
		n.mustRun(n.worker(ob, p), base+sec)
		if p.total() != 0 {
			t.Fatal("something was sent with no destination")
		}
	})
}

// Destination secret rotation: the secret is resolved fresh at every attempt and
// never stored; the delivery ID is the same across the rotation.
func TestWorkerDestinationSecretRotation(t *testing.T) {
	n := newNode(t)
	ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	p := &provider{observe: n.openSecret, script: func(nth int, d notify.Delivery) (notify.Outcome, error) {
		if nth == 1 {
			return notify.Outcome{Kind: notify.OutcomeRetry, Code: "unauthorized"}, nil
		}
		return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-2"}, nil
	}}
	w := n.worker(ob, p)
	n.mustRun(w, base+sec)
	n.setDestination(n.dest, true, "ROTATED-SECRET-TEXT-e5d0")
	rec := n.record(ob, open.ID)
	n.mustRun(w, rec.Next)
	if len(p.calls) != 2 || p.calls[0].Secret != "SECRET-DESTINATION-TEXT-71c2" || p.calls[1].Secret != "ROTATED-SECRET-TEXT-e5d0" {
		t.Fatalf("the sender did not resolve the rotated secret: %+v", p.calls)
	}
	if p.calls[0].ID != open.ID || p.calls[1].ID != open.ID {
		t.Fatalf("the delivery ID changed across the rotation: %+v", p.calls)
	}
	if rec = n.record(ob, open.ID); rec.Phase != control.DeliveryAccepted || rec.ID != open.ID {
		t.Fatalf("record: %+v", rec)
	}
	for _, secret := range []string{"SECRET-DESTINATION-TEXT-71c2", "ROTATED-SECRET-TEXT-e5d0"} {
		if strings.Contains(n.stateText(), secret) {
			t.Fatalf("destination secret %q reached the outbox or its audit", secret)
		}
	}
}

// Deletion and revocation before the send: a closing C12 deletion pauses the
// derived send (nothing is sent, the delivery keeps its ID), a failed or
// finished deletion resolves it, a disabled destination cancels it, and an
// external request already in flight is still recorded.
func TestWorkerDeletionAndRevocationBeforeSend(t *testing.T) {
	t.Run("a closing deletion pauses and its completion cancels", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		p := &provider{}
		w := n.worker(ob, p)
		n.clock.set(base + sec)
		deletion := n.beginDeletion(0, 2*base)
		if r := n.mustRun(w, base+2*sec); len(r.Claimed) != 0 || p.total() != 0 {
			t.Fatalf("a delivery derived from a closing deletion was claimed: %+v", r)
		}
		if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryPending || rec.Hold != control.DeliveryHoldPaused {
			t.Fatalf("a paused delivery: %+v", rec)
		}
		n.completeDeletion(deletion)
		if r := n.mustRun(w, base+3*sec); len(r.Claimed) != 0 || p.total() != 0 {
			t.Fatalf("a delivery derived from deleted data was claimed: %+v", r)
		}
		if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryCancelled || rec.Code != "deleted" || len(rec.Attempts) != 0 {
			t.Fatalf("after the deletion completed: %+v", rec)
		}
		if n.auditCount("notify.delivery.cancelled") != 1 {
			t.Fatal("the cancellation left no audit entry")
		}
	})
	t.Run("a deletion that begins between the claim and the send", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		p := &provider{}
		var deletion model.ID
		q := &hookQueue{Queue: ob, afterClaim: func([]notify.Delivery) {
			if deletion == (model.ID{}) {
				deletion = n.beginDeletion(0, 2*base)
			}
		}}
		w := n.worker(q, p)
		report := n.mustRun(w, base+sec)
		if !has(report.Paused, open.ID) || p.total() != 0 {
			t.Fatalf("report %+v provider calls %d", report, p.total())
		}
		rec := n.record(ob, open.ID)
		if rec.Phase != control.DeliveryPending || rec.Attempts[0].Outcome != control.DeliveryOutcomeRetry || rec.Attempts[0].Code != control.DeliveryHoldPaused || rec.Uncertain {
			t.Fatalf("a released claim is a definite non-send: %+v", rec)
		}
		n.completeDeletion(deletion)
		n.mustRun(w, rec.Next)
		if rec = n.record(ob, open.ID); rec.Phase != control.DeliveryCancelled || rec.Code != "deleted" || p.total() != 0 {
			t.Fatalf("after completion: %+v, provider calls %d", rec, p.total())
		}
	})
	t.Run("a disabled destination cancels before the send", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		p := &provider{}
		q := &hookQueue{Queue: ob, afterClaim: func([]notify.Delivery) { n.disableDestination(n.dest) }}
		report := n.mustRun(n.worker(q, p), base+sec)
		rec := n.record(ob, open.ID)
		if !has(report.Cancelled, open.ID) || rec.Phase != control.DeliveryCancelled || rec.Code != "destination_disabled" || p.total() != 0 {
			t.Fatalf("report %+v record %+v provider calls %d", report, rec, p.total())
		}
	})
	t.Run("an external request already in flight is still recorded", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		open := n.openRecord(ob)
		started := false
		p := &provider{onSend: func(notify.Delivery) {
			if !started {
				started = true
				n.beginDeletion(0, 2*base) // begins while the request is on the wire
			}
		}}
		report := n.mustRun(n.worker(ob, p), base+sec)
		rec := n.record(ob, open.ID)
		if !has(report.Accepted, open.ID) || rec.Phase != control.DeliveryAccepted || rec.Provider == "" {
			t.Fatalf("an accepted in-flight request was not kept: report %+v record %+v", report, rec)
		}
		// The record holds only typed fields: nothing derived from deleted content.
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "message") || strings.Contains(string(raw), "stack") {
			t.Fatalf("free text in an accepted record: %s", raw)
		}
	})
	t.Run("a retired project cannot be run at all", func(t *testing.T) {
		n := newNode(t)
		ob := n.outbox()
		if _, err := n.openAndQueue(ob); err != nil {
			t.Fatal(err)
		}
		scope, err := n.svc.Authorize(n.ctx, n.cred, n.org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		worker := n.scope() // the worker's own, project-scoped principal, minted before the retirement
		at := n.clock.Now()
		req := control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{n.project}, Reason: "retire", At: at, PhysicalDeadline: at + 1, BackupDeadline: at + 2}
		raw, _ := json.Marshal(req)
		if _, err = n.store.Transact(n.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: n.revision(), Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
			t.Fatal(err)
		}
		p := &provider{}
		w := n.worker(ob, p)
		if _, err = w.RunOnce(n.ctx, worker, base+sec, n.lease()); err == nil {
			t.Fatal("a worker of a retired project ran")
		}
		if p.total() != 0 {
			t.Fatal("something was sent for a retired project")
		}
	})
}

// flipFencer is a fencer whose leadership can be revoked between the claim and
// the send.
type flipFencer struct {
	notify.Fencer
	stale bool
	mu    sync.Mutex
}

func (f *flipFencer) ValidateFence(ctx context.Context, t notify.FenceToken) error {
	f.mu.Lock()
	stale := f.stale
	f.mu.Unlock()
	if stale {
		return replica.ErrStale
	}
	return f.Fencer.ValidateFence(ctx, t)
}

// The lease is validated against a fresh quorum observation immediately before
// every send, not only at the claim.
func TestWorkerRevalidatesTheFenceBeforeEverySend(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	fencer := &flipFencer{Fencer: n.group()}
	p := &provider{}
	q := &hookQueue{Queue: ob, afterClaim: func([]notify.Delivery) { fencer.mu.Lock(); fencer.stale = true; fencer.mu.Unlock() }}
	w, err := notify.NewWorker(q, p, fencer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.run(w, base+sec)
	if c, det := faultOf(err); c != model.Stale || det != control.DeliveryLeaseStale {
		t.Fatalf("a deposed worker kept running: %v", err)
	}
	if p.total() != 0 {
		t.Fatal("a deposed worker sent")
	}
	// Its claim is not silently released: it stays visible until it lapses, then
	// is recorded as a possible acceptance, because the worker cannot prove it did
	// not send.
	if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryClaimed {
		t.Fatalf("record: %+v", rec)
	}
}

// TestAcceptedBeforeCrash: the provider accepts, the process dies before it can
// record that, and the next leader retries the SAME delivery ID. The record says
// possible duplicate and unknown, never exactly-once success.
func TestAcceptedBeforeCrash(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	p := &provider{}
	dies := &hookQueue{Queue: ob, onComplete: func(model.ID, uint32, notify.Outcome) error { panic(errCrash) }}
	w1 := n.worker(dies, p)
	lease1 := n.lease()
	n.clock.set(base + sec)
	if !crash(func() { _, _ = w1.RunOnce(n.ctx, n.scope(), base+sec, lease1) }) {
		t.Fatal("the worker survived the injected process death")
	}
	if p.count(open.ID) != 1 {
		t.Fatalf("the provider saw %d sends before the crash", p.count(open.ID))
	}
	// The provider accepted, but nothing durable says so: the claim is open.
	if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryClaimed || rec.Provider != "" || rec.Attempts[0].Outcome != "" {
		t.Fatalf("after the crash: %+v", rec)
	}

	n.restart() // the next leader
	ob2 := n.outbox()
	w2 := n.worker(ob2, p)
	if r := n.mustRun(w2, base+10*sec); len(r.Claimed) != 0 || p.count(open.ID) != 1 {
		t.Fatalf("the next leader took over a live claim: %+v", r)
	}
	later := base + 5*60*sec // past the 2-minute lease
	report := n.mustRun(w2, later)
	if !has(report.Accepted, open.ID) || p.count(open.ID) != 2 {
		t.Fatalf("the next leader did not retry: %+v (provider sends %d)", report, p.count(open.ID))
	}
	if p.calls[0].ID != open.ID || p.calls[1].ID != open.ID || p.calls[1].Attempt != 2 {
		t.Fatalf("the retry changed the delivery identity: %+v", p.calls)
	}
	rec := n.record(ob2, open.ID)
	first, second := rec.Attempts[0], rec.Attempts[1]
	if first.Outcome != control.DeliveryOutcomeUnknown || first.Code != control.DeliveryCodeClaimExpired || first.ClosedBy != "system" || second.Outcome != control.DeliveryOutcomeAccepted {
		t.Fatalf("attempts: %+v", rec.Attempts)
	}
	if rec.ID != open.ID || rec.Phase != control.DeliveryAccepted || !rec.PossibleDuplicate || !rec.Uncertain {
		t.Fatalf("the record claims more than it knows: %+v", rec)
	}
	if n.auditCount("notify.delivery.unknown") != 1 {
		t.Fatal("the unknown attempt left no audit entry")
	}
}

// If the completion merely fails (not a crash), the worker reports it safely and
// the attempt is left open: it can only become unknown later, never success.
func TestWorkerCompleteFailureLeavesTheAttemptOpen(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	open := n.openRecord(ob)
	p := &provider{}
	q := &hookQueue{Queue: ob, onComplete: func(model.ID, uint32, notify.Outcome) error { return errLost }}
	report := n.mustRun(n.worker(q, p), base+sec)
	if len(report.Errors) != 1 || report.Errors[0].Delivery != open.ID || report.Errors[0].Stage != "complete" || has(report.Accepted, open.ID) {
		t.Fatalf("report: %+v", report)
	}
	if strings.Contains(fmt.Sprint(report), "connection lost") {
		t.Fatalf("a raw error text leaked into the report: %+v", report)
	}
	if rec := n.record(ob, open.ID); rec.Phase != control.DeliveryClaimed || rec.Provider != "" {
		t.Fatalf("record: %+v", rec)
	}
}

// Two workers running at once never send the same delivery twice.
func TestWorkerSimultaneousClaimersSendEachDeliveryOnce(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	// Five more destinations: five recipients, five opening deliveries.
	dests := []model.ID{n.dest}
	for i := range 4 {
		id := model.ID{0xd2, byte(i)}
		n.setDestination(id, true, "s")
		dests = append(dests, id)
	}
	scope, lease := n.scope(), n.lease()
	for _, id := range dests {
		ev := n.event(notify.EventDestination)
		ev.Destination = &notify.DestinationChange{Recipient: id, Enabled: true}
		if _, err := ob.Submit(n.ctx, scope, lease, incident, ev, base); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ob.Submit(n.ctx, scope, lease, incident, n.incidentEvent(1, notify.SeverityMajor, 1), base); err != nil {
		t.Fatal(err)
	}
	if got := len(n.records(ob, control.DeliveryPending)); got != 5 {
		t.Fatalf("%d pending deliveries, want 5", got)
	}
	p := &provider{}
	n.clock.set(base + sec)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := n.worker(ob, p, notify.WithBatch(2))
			if _, err := w.RunOnce(n.ctx, scope, base+sec, lease); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, r := range n.records(ob, "") {
		if r.Kind != string(notify.KindOpen) {
			continue
		}
		if c := p.count(r.ID); c > 1 {
			t.Fatalf("delivery %s was sent %d times by simultaneous workers", r.ID, c)
		}
	}
	// A further run finishes whatever the batch limit left.
	n.mustRun(n.worker(ob, p), base+2*sec)
	if p.total() != 5 {
		t.Fatalf("%d sends for 5 deliveries", p.total())
	}
	for _, r := range n.records(ob, "") {
		if r.Kind == string(notify.KindOpen) && r.Phase != control.DeliveryAccepted {
			t.Fatalf("delivery %s: %+v", r.ID, r)
		}
	}
}

// Bounded retry: after 12 attempts a delivery that kept failing definitely is
// failed with a terminal reason; one that was ever unknown is uncertain. The
// same ID is used throughout and the whole attempt audit stays.
func TestWorkerRetryExhaustionIsVisibleAndKeepsTheAudit(t *testing.T) {
	for name, unknownAt := range map[string]int{"definite failures": 0, "one unknown attempt": 4} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			ob := n.outbox(notify.WithJitter(func(model.ID, uint32) float64 { return 0 }))
			if _, err := n.openAndQueue(ob); err != nil {
				t.Fatal(err)
			}
			open := n.openRecord(ob)
			p := &provider{script: func(nth int, d notify.Delivery) (notify.Outcome, error) {
				if nth == unknownAt {
					return notify.Outcome{}, context.DeadlineExceeded
				}
				return notify.Outcome{Kind: notify.OutcomeRetry, Code: "unavailable"}, nil
			}}
			w := n.worker(ob, p)
			at := base + sec
			for i := 1; i <= 12; i++ {
				n.mustRun(w, at)
				rec := n.record(ob, open.ID)
				if i < 12 {
					if rec.Phase != control.DeliveryPending || len(rec.Attempts) != i {
						t.Fatalf("after attempt %d: %+v", i, rec)
					}
					at = rec.Next
				}
			}
			rec := n.record(ob, open.ID)
			want := control.DeliveryFailed
			if unknownAt != 0 {
				want = control.DeliveryUncertain
			}
			if rec.Phase != want || rec.Code != control.DeliveryReasonExhausted || len(rec.Attempts) != 12 || rec.ID != open.ID || rec.Uncertain != (unknownAt != 0) {
				t.Fatalf("after the budget: %+v", rec)
			}
			if p.count(open.ID) != 12 {
				t.Fatalf("%d sends, want exactly the budget", p.count(open.ID))
			}
			// Time passes, reminders fire and are sent; the exhausted delivery is never
			// claimed or sent again.
			if r := n.mustRun(w, at+24*3600*sec); has(r.Claimed, open.ID) || p.count(open.ID) != 12 {
				t.Fatalf("an exhausted delivery was sent again: %+v", r)
			}
			// The audit trail outlives the record's own history: the settlement of THIS
			// delivery is an audit entry naming it, with the safe reason.
			if got := n.auditFor(open.ID, "notify.delivery."+want); len(got) != 1 || got[0].Reason != control.DeliveryReasonExhausted {
				t.Fatalf("audit entries for the %s settlement of %s: %+v", want, open.ID, got)
			}
			for i, a := range rec.Attempts {
				if a.Number != uint32(i+1) || a.Outcome == "" {
					t.Fatalf("attempt %d lost its identity: %+v", i+1, a)
				}
			}
		})
	}
}

// Timers are part of the run: a due reminder is decided, enqueued under its own
// stable key and sent, and a repeated run does not decide it again.
func TestWorkerFiresDueTimersOnce(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	p := &provider{}
	w := n.worker(ob, p)
	n.mustRun(w, base+sec) // the opening
	countKind := func(kind notify.Kind) int {
		c := 0
		for _, r := range n.records(ob, "") {
			if r.Kind == string(kind) {
				c++
			}
		}
		return c
	}
	if countKind(notify.KindReminder) != 0 {
		t.Fatal("a reminder before it was due")
	}
	if r := n.mustRun(w, base+14*60*sec); r.Fired != 0 {
		t.Fatalf("a timer fired early: %+v", r)
	}
	r := n.mustRun(w, base+16*60*sec)
	if r.Fired != 1 || countKind(notify.KindReminder) != 1 || len(r.Accepted) != 1 {
		t.Fatalf("the 15-minute reminder: %+v reminders %d", r, countKind(notify.KindReminder))
	}
	if again := n.mustRun(w, base+16*60*sec+sec); again.Fired != 0 || countKind(notify.KindReminder) != 1 {
		t.Fatalf("a reminder was decided twice: %+v", again)
	}
	// Restart: still once.
	n.restart()
	ob = n.outbox() // the new process's outbox: the old one points at the closed store
	w2 := n.worker(ob, p)
	n.mustRun(w2, base+17*60*sec)
	if countKind(notify.KindReminder) != 1 {
		t.Fatal("a restart decided the reminder again")
	}
}
