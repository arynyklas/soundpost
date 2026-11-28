// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// TestPolicyClockThroughControlOutboxAndWorker is the smoke leg of
// TestPolicyDurableClockAndPromotion (06.06 criterion 8) through the real
// control store, the real Outbox and the Worker the served node runs: opening,
// reminder, ACK, a queued issue, the 09:00 digest, a worse impact
// despite the ACK, snooze and its exact expiry, each with a process restart
// (control closed and reopened from disk) between steps. Every send is counted
// per delivery ID: one decision, one delivery, never two.
func TestPolicyClockThroughControlOutboxAndWorker(t *testing.T) {
	n := newNode(t)
	queued := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x51}}
	ob := n.outbox()
	p := &provider{}
	w := n.worker(ob, p)
	live := func(ev notify.PolicyEvent, subject notify.Entity) notify.PolicyEvent {
		ev.Entity, ev.Mode = &subject, notify.ModeLive
		return ev
	}
	submit := func(subject notify.Entity, ev notify.PolicyEvent, at model.UnixNano) {
		t.Helper()
		n.clock.set(at)
		if _, err := ob.Submit(n.ctx, n.scope(), n.lease(), subject, ev, at); err != nil {
			t.Fatalf("%s at +%ds: %v", ev.Kind, (at-base)/sec, err)
		}
	}
	restart := func() {
		t.Helper()
		n.restart()
		ob = n.outbox()
		w = n.worker(ob, p)
	}
	sent := func() map[string]int {
		t.Helper()
		out := map[string]int{}
		for _, r := range n.records(ob, "") {
			if got := p.count(r.ID); got != 1 && got != 0 {
				t.Fatalf("delivery %s of kind %s was sent %d times", r.ID, r.Kind, got)
			} else if got == 1 {
				out[r.Kind]++
			}
		}
		return out
	}
	expect := func(step string, want map[string]int) {
		t.Helper()
		got := sent()
		for _, k := range []notify.Kind{notify.KindOpen, notify.KindReminder, notify.KindDigest, notify.KindWorseImpact, notify.KindCurrent} {
			if got[string(k)] != want[string(k)] {
				t.Fatalf("%s: sent %v, want %v", step, got, want)
			}
		}
	}
	min := 60 * sec

	// 08:00Z. The recipient has no zone, so the digest is 09:00 UTC. The major
	// incident opens (committed through the real incident handler); the issue below the
	// urgent rate is only queued.
	n.commitIncident(1)
	submit(incident, live(n.destinationEvent(), incident), base)
	submit(queued, live(n.destinationEvent(), queued), base)
	submit(incident, n.incidentEvent(1, notify.SeverityMajor, 1), base)
	issue := n.event(notify.EventIssue)
	at := base + 5*min
	window := at - at%notify.ErrorWindow
	issue.Issue = &notify.IssueEvidence{WindowStart: window, Occurrences: occ(5, 1), Freshness: notify.FreshnessFresh,
		Denominator: &notify.Denominator{Name: "http_requests_total", WindowStart: window, Operations: 101, Complete: true}} // 5 of 101: below the urgent rate, so queued
	submit(queued, live(issue, queued), at)
	n.mustRun(w, base+sec)
	expect("opening", map[string]int{"open": 1})
	restart()

	// +16 minutes: the first reminder, once.
	if r := n.mustRun(w, base+16*min); r.Fired != 1 {
		t.Fatalf("the reminder timer: %+v", r)
	}
	expect("reminder", map[string]int{"open": 1, "reminder": 1})
	restart()

	// ACK at +20 minutes pauses reminders: two hours of timers send nothing more
	// that is a reminder, yet the 09:00 digest (+60 minutes) of the queued issue is delivered exactly once, and not again after a restart.
	ack := n.event(notify.EventAction)
	ack.Action = &notify.HumanAction{Type: notify.ActionAck, Actor: n.user, Version: 2, ImpactRevision: 1}
	submit(incident, live(ack, incident), base+20*min)
	n.mustRun(w, base+40*min)
	expect("acked, before the digest", map[string]int{"open": 1, "reminder": 1})
	restart()
	n.mustRun(w, base+61*min)
	expect("digest", map[string]int{"open": 1, "reminder": 1, "digest": 1})
	restart()
	n.mustRun(w, base+62*min)
	n.mustRun(w, base+2*60*min)
	expect("no second digest, no reminder while acked", map[string]int{"open": 1, "reminder": 1, "digest": 1})

	// A worse impact notifies despite the ACK.
	submit(incident, n.incidentEvent(3, notify.SeverityCritical, 2), base+130*min)
	n.mustRun(w, base+131*min)
	expect("worse impact despite the ACK", map[string]int{"open": 1, "reminder": 1, "digest": 1, "worse_impact": 1})
	restart()

	// Snooze, quiet until its exact expiry, then one current-state update that a
	// replay after a restart does not repeat.
	until := base + 4*60*min
	snooze := n.event(notify.EventAction)
	snooze.Action = &notify.HumanAction{Type: notify.ActionSnooze, Actor: n.user, Version: 4, Reason: "waiting for vendor", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: until}
	submit(incident, live(snooze, incident), base+132*min)
	n.mustRun(w, base+3*60*min)
	expect("snoozed", map[string]int{"open": 1, "reminder": 1, "digest": 1, "worse_impact": 1})
	n.mustRun(w, until)
	want := map[string]int{"open": 1, "reminder": 1, "digest": 1, "worse_impact": 1, "current_state": 1}
	expect("snooze expiry", want)
	restart()
	n.mustRun(w, until)
	n.mustRun(w, until+sec)
	expect("expiry replayed after a restart", want)

	// The next local date's 09:00 passes with the queue unchanged: no second
	// digest. The worse impact made the ACK stale (it covered revision 1), so the
	// reminder cadence is back: the second reminder is due, and only that.
	n.mustRun(w, base+26*60*min)
	want["reminder"] = 2
	expect("next day, queue unchanged", want)
}
