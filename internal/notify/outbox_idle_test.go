// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
)

// commands is how many applied commands the control state remembers (the bounded dedup window): an idle claim must not add one.
func (n *node) commands() int {
	n.t.Helper()
	var c int
	if err := n.store.View(n.ctx, func(st control.State) error { c = len(st.Commands); return nil }); err != nil {
		n.t.Fatal(err)
	}
	return c
}

// quiet claims for the project and requires that nothing was leased and that no control transition was committed: the revision and the command window
// are unchanged. A claim that changes nothing is not a reason for a client command that names the global revision to be refused.
func (n *node) quiet(ob *notify.Outbox, at model.UnixNano, lease replica.FenceToken, why string) {
	n.t.Helper()
	revision, commands := n.revision(), n.commands()
	got, err := ob.Claim(n.ctx, n.scope(), at, lease, 5)
	if err != nil || len(got) != 0 {
		n.t.Fatalf("%s: claim = %v, %v; want nothing leased", why, got, err)
	}
	if after := n.revision(); after != revision {
		n.t.Fatalf("%s: a claim that changed nothing moved the control revision %d -> %d", why, revision, after)
	}
	if after := n.commands(); after != commands {
		n.t.Fatalf("%s: a claim that changed nothing stored %d command record(s)", why, after-commands)
	}
}

// TestOutboxAClaimThatChangesNothingCommitsNothing: the runner claims once per project on every pass. A claim with nothing due, nothing lapsed,
// nothing to settle and the fence already raised to this lease is answered from the read that proved it; every claim that does something still commits.
func TestOutboxAClaimThatChangesNothingCommitsNothing(t *testing.T) {
	n := newNode(t)
	zero := func(model.ID, uint32) float64 { return 0 }
	ob := n.outbox(notify.WithJitter(zero), notify.WithLeaseTTL(90*time.Second))
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()

	// The first claim of this lease leases the due delivery and raises the project's fence: it commits.
	before := n.revision()
	got, err := ob.Claim(n.ctx, n.scope(), base+5*sec, lease, 5)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim of a due delivery: %v %v", got, err)
	}
	if n.revision() == before {
		t.Fatal("leasing a due delivery committed nothing")
	}
	d := got[0]

	// 1. A live claim is not touched, and the fence already equals the lease.
	n.quiet(ob, base+6*sec, lease, "a live claim")

	// 2. A retry that is not due yet is not touched.
	n.clock.set(base + 6*sec)
	if err = ob.Complete(n.ctx, n.scope(), d.ID, d.Attempt, notify.Outcome{Kind: notify.OutcomeRetry, Code: "unavailable"}); err != nil {
		t.Fatal(err)
	}
	rec, _, _ := ob.Record(n.ctx, n.scope(), d.ID, base+6*sec)
	if rec.Next <= base+6*sec {
		t.Fatalf("the retry is due at %d, not in the future", rec.Next)
	}
	n.quiet(ob, rec.Next-1, lease, "a retry scheduled for later")

	// 3. When it is due, the claim leases it and commits again.
	before = n.revision()
	retry, err := ob.Claim(n.ctx, n.scope(), rec.Next, lease, 5)
	if err != nil || len(retry) != 1 || retry[0].ID != d.ID || retry[0].Attempt != 2 {
		t.Fatalf("the retry when due: %v %v", retry, err)
	}
	if n.revision() == before {
		t.Fatal("leasing a retry committed nothing")
	}

	// 4. A claim that lapsed without a completion is closed as unknown by the next claim: that is a change, so it commits.
	lapsed := rec.Next + 10*60*sec
	before = n.revision()
	again, err := ob.Claim(n.ctx, n.scope(), lapsed, lease, 5)
	if err != nil || len(again) != 1 || again[0].Attempt != 3 {
		t.Fatalf("the lapsed claim was not retried as attempt 3: %v %v", again, err)
	}
	if n.revision() == before {
		t.Fatal("closing a lapsed claim committed nothing")
	}
	n.clock.set(lapsed)
	if err = ob.Complete(n.ctx, n.scope(), d.ID, 3, notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "msg-1"}); err != nil {
		t.Fatal(err)
	}

	// 5. Nothing is open any more.
	n.quiet(ob, lapsed+sec, lease, "no open delivery")
}

// TestOutboxTheFirstClaimOfANewLeaderTermStillCommits: the fence raise is what makes a deposed leader's later commit stale, and a new leader's
// first claim (empty or not) is what raises it. After that the claim is idle again.
func TestOutboxTheFirstClaimOfANewLeaderTermStillCommits(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease1 := n.lease()
	got, err := ob.Claim(n.ctx, n.scope(), base+sec, lease1, 5)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim under the first term: %v %v", got, err)
	}
	n.quiet(ob, base+2*sec, lease1, "the same term")

	n.restart()
	ob2 := n.outbox()
	lease2 := n.lease()
	if lease2.Term <= lease1.Term {
		t.Fatalf("leadership did not move: term %d -> %d", lease1.Term, lease2.Term)
	}
	before := n.revision()
	if live, err := ob2.Claim(n.ctx, n.scope(), base+3*sec, lease2, 5); err != nil || len(live) != 0 {
		t.Fatalf("the new leader took over an unexpired claim: %v %v", live, err)
	}
	if n.revision() == before {
		t.Fatal("the new leader's first claim committed nothing, so the deposed leader's lease is still current at the outbox")
	}
	n.quiet(ob2, base+4*sec, lease2, "the second claim of the new term")
}

// TestOutboxAClaimThatSettlesADeliveryCommits: a delivery whose destination was disabled is settled by the claim, and the claim after that is idle.
func TestOutboxAClaimThatSettlesADeliveryCommits(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	n.disableDestination(n.dest)
	before := n.revision()
	got, err := ob.Claim(n.ctx, n.scope(), base+5*sec, lease, 5)
	if err != nil || len(got) != 0 {
		t.Fatalf("a delivery to a disabled destination was leased: %v %v", got, err)
	}
	if n.revision() == before {
		t.Fatal("settling a delivery committed nothing")
	}
	if rec := n.openRecord(ob); rec.Open() {
		t.Fatalf("the delivery was not settled: %+v", rec)
	}
	n.quiet(ob, base+6*sec, lease, "after the settle")
}

// TestOutboxAnUnauthorizedClaimIsRefusedNotAnsweredEmpty: an idle project must not turn a scope that may not claim into a quiet empty answer.
func TestOutboxAnUnauthorizedClaimIsRefusedNotAnsweredEmpty(t *testing.T) {
	n := newNode(t)
	ob := n.outbox()
	if _, err := n.openAndQueue(ob); err != nil {
		t.Fatal(err)
	}
	lease := n.lease()
	if _, err := ob.Claim(n.ctx, n.scope(), base+sec, lease, 5); err != nil {
		t.Fatal(err)
	}
	n.admin("membership", auth.AdminPayload{UserID: n.user, Enabled: true})
	n.admin("grant", auth.AdminPayload{UserID: n.user, ProjectID: n.project, Permissions: []string{string(auth.Read)}, Enabled: true})
	n.authenticate()
	reader, err := n.svc.Authorize(n.ctx, n.cred, n.org, []model.ID{n.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ob.Claim(n.ctx, reader, base+2*sec, lease, 5); err == nil {
		t.Fatalf("a read-only scope claimed on an idle project and got %v", got)
	}
	// A scope whose session ended after it was derived is not authorized any more: the claim is refused even though nothing is due.
	scope := n.scope()
	if err = n.svc.Logout(n.ctx, n.token); err != nil {
		t.Fatal(err)
	}
	if got, err := ob.Claim(n.ctx, scope, base+3*sec, lease, 5); err == nil {
		t.Fatalf("a scope of a logged-out session claimed on an idle project and got %v", got)
	}
}
