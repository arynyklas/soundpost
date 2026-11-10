// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/notify"
)

var (
	org, project, pol = model.ID{0x01}, model.ID{0x02}, model.ID{0x03}
	issueE            = notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x51}}
	condE             = notify.Entity{Kind: notify.EntityCondition, ID: model.ID{0x52}}
	incE              = notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
	rcptA, rcptB      = model.ID{0xa1}, model.ID{0xa2}
	alice             = model.ID{0xb1}
	svcA, svcB        = model.ID{0xd1}, model.ID{0xd2}
	epOne, epTwo      = model.ID{0xe1}, model.ID{0xe2}
)

const (
	min1 = model.UnixNano(time.Minute)
	hour = model.UnixNano(time.Hour)
	// t0 is aligned to the 5-minute window.
	t0 = model.UnixNano(1773144000 * int64(time.Second)) // 2026-03-10T12:00:00Z
)

func occ(n int, salt byte) []model.ID {
	out := make([]model.ID, n)
	for i := range out {
		out[i] = model.ID{0x70, salt, byte(i >> 8), byte(i)}
	}
	return out
}

type harness struct {
	t   *testing.T
	s   notify.PolicyState
	cfg notify.Config
	rev model.Revision
	n   uint16
}

func newHarness(t *testing.T, subject notify.Entity) *harness {
	t.Helper()
	s, err := notify.NewState(org, project, pol, subject)
	if err != nil {
		t.Fatal(err)
	}
	cfg := notify.DefaultConfig()
	cfg.CriticalCodes = []string{"payment_failed"}
	return &harness{t: t, s: s, cfg: cfg, rev: 1}
}

func (h *harness) ev(kind notify.EventKind) notify.PolicyEvent {
	h.n++
	cfg := h.cfg
	return notify.PolicyEvent{
		Kind: kind, Command: model.ID{0xc0, byte(h.n >> 8), byte(h.n)}, Org: org, Project: project, Policy: pol,
		PolicyRef: notify.PolicyRef{Revision: h.rev, Config: &cfg}, OwnerRevision: h.s.OwnerRevision,
	}
}

func (h *harness) try(ev notify.PolicyEvent, at model.UnixNano) ([]notify.Intent, error) {
	h.t.Helper()
	next, in, err := notify.Decide(h.s, ev, at)
	if err == nil {
		h.s = next
	}
	return in, err
}

func (h *harness) do(ev notify.PolicyEvent, at model.UnixNano) []notify.Intent {
	h.t.Helper()
	in, err := h.try(ev, at)
	if err != nil {
		h.t.Fatalf("%s: %v", ev.Kind, err)
	}
	return in
}

func (h *harness) dest(id model.ID, zone string, at model.UnixNano) {
	h.t.Helper()
	ev := h.ev(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: id, Enabled: true, Zone: zone}
	h.do(ev, at)
}

func (h *harness) issue(e notify.Entity, at model.UnixNano, ids []model.ID, mod func(*notify.IssueEvidence)) []notify.Intent {
	h.t.Helper()
	ev := h.ev(notify.EventIssue)
	ev.Entity = &e
	ev.Issue = &notify.IssueEvidence{WindowStart: at - at%notify.ErrorWindow, Occurrences: ids, Freshness: notify.FreshnessFresh}
	if mod != nil {
		mod(ev.Issue)
	}
	return h.do(ev, at)
}

func (h *harness) timer(at model.UnixNano) []notify.Intent {
	h.t.Helper()
	ev := h.ev(notify.EventTimer)
	ev.Timer = &notify.Timer{}
	return h.do(ev, at)
}

func (h *harness) action(e notify.Entity, a notify.HumanAction, at model.UnixNano) ([]notify.Intent, error) {
	ev := h.ev(notify.EventAction)
	ev.Entity = &e
	ev.Action = &a
	return h.try(ev, at)
}

func (h *harness) mustAction(e notify.Entity, a notify.HumanAction, at model.UnixNano) []notify.Intent {
	h.t.Helper()
	in, err := h.action(e, a, at)
	if err != nil {
		h.t.Fatalf("%s: %v", a.Type, err)
	}
	return in
}

func withDenominator(ops uint64, complete bool) func(*notify.IssueEvidence) {
	return func(e *notify.IssueEvidence) {
		e.Denominator = &notify.Denominator{Name: "http_requests_total", WindowStart: e.WindowStart, Operations: model.Uint64(ops), Complete: complete}
	}
}

func kinds(in []notify.Intent) []string {
	var out []string
	for _, i := range in {
		out = append(out, string(i.Key.Kind))
	}
	return out
}

func of(in []notify.Intent, k notify.Kind) []notify.Intent {
	var out []notify.Intent
	for _, i := range in {
		if i.Key.Kind == k {
			out = append(out, i)
		}
	}
	return out
}

func sameStrings(t *testing.T, got, want []string, what string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s: got %v want %v", what, got, want)
	}
}

func stateJSON(t *testing.T, s notify.PolicyState) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// restart simulates persisting the state as opaque control state and loading
// it again in a new process.
func (h *harness) restart() {
	h.t.Helper()
	var back notify.PolicyState
	if err := json.Unmarshal([]byte(stateJSON(h.t, h.s)), &back); err != nil {
		h.t.Fatal(err)
	}
	if !reflect.DeepEqual(back, h.s) {
		h.t.Fatalf("state does not survive a JSON round trip:\n%s\n%s", stateJSON(h.t, h.s), stateJSON(h.t, back))
	}
	h.s = back
}

func TestUrgencyThresholds(t *testing.T) {
	cases := []struct {
		name  string
		ids   []model.ID
		mod   func(*notify.IssueEvidence)
		tier  notify.Tier
		basis notify.Basis
		rate  notify.RateState
		bp    uint32
	}{
		{"20 ops 5 unique failures is urgent", occ(5, 1), withDenominator(20, true), notify.TierUrgent, notify.BasisErrorRate, notify.RateKnown, 2500},
		{"100 ops 5 failures is urgent at exactly 5 percent", occ(5, 1), withDenominator(100, true), notify.TierUrgent, notify.BasisErrorRate, notify.RateKnown, 500},
		{"101 ops 5 failures is queue", occ(5, 1), withDenominator(101, true), notify.TierQueue, notify.BasisCount, notify.RateKnown, 495},
		{"19 ops 5 failures is queue", occ(5, 1), withDenominator(19, true), notify.TierQueue, notify.BasisCount, notify.RateKnown, 2631},
		{"20 ops 4 failures is queue", occ(4, 1), withDenominator(20, true), notify.TierQueue, notify.BasisCount, notify.RateKnown, 2000},
		{"1000 ops 50 failures is urgent at 5 percent", occ(50, 1), withDenominator(1000, true), notify.TierUrgent, notify.BasisErrorRate, notify.RateKnown, 500},
		{"huge denominator never overflows", occ(60, 1), withDenominator(math.MaxUint64, true), notify.TierQueue, notify.BasisCount, notify.RateKnown, 0},
		{"missing denominator is rate unknown and queue", occ(500, 1), nil, notify.TierQueue, notify.BasisCount, notify.RateNoDenominator, 0},
		{"incomplete denominator is rate unknown and queue", occ(25, 1), withDenominator(100, false), notify.TierQueue, notify.BasisCount, notify.RateIncomplete, 0},
		{"stale source is rate unknown even with a complete denominator", occ(25, 1), func(e *notify.IssueEvidence) {
			withDenominator(100, true)(e)
			e.Freshness = notify.FreshnessStale
		}, notify.TierQueue, notify.BasisCount, notify.RateStale, 0},
		{"unknown freshness is rate unknown", occ(25, 1), func(e *notify.IssueEvidence) {
			withDenominator(100, true)(e)
			e.Freshness = notify.FreshnessUnknown
		}, notify.TierQueue, notify.BasisCount, notify.RateStale, 0},
		{"denominator for another window is rate unknown", occ(25, 1), func(e *notify.IssueEvidence) {
			withDenominator(100, true)(e)
			e.Denominator.WindowStart -= notify.ErrorWindow
		}, notify.TierQueue, notify.BasisCount, notify.RateWindowMismatch, 0},
		{"failures above operations is inconsistent, not a rate", occ(30, 1), withDenominator(10, true), notify.TierQueue, notify.BasisCount, notify.RateInconsistent, 0},
		{"critical approved code is urgent without a denominator", occ(1, 1), func(e *notify.IssueEvidence) { e.Code = "payment_failed" }, notify.TierUrgent, notify.BasisCriticalCode, notify.RateNoDenominator, 0},
		{"critical code is urgent even with stale data", occ(1, 1), func(e *notify.IssueEvidence) {
			e.Code = "payment_failed"
			e.Freshness = notify.FreshnessStale
		}, notify.TierUrgent, notify.BasisCriticalCode, notify.RateStale, 0},
		{"unapproved code is not critical", occ(1, 1), func(e *notify.IssueEvidence) { e.Code = "timeout" }, notify.TierQueue, notify.BasisCount, notify.RateNoDenominator, 0},
		{"qualifying regression with 5 occurrences is urgent", occ(5, 1), func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{Eligible: true, Occurrences: 5, AncestryKnown: true}
		}, notify.TierUrgent, notify.BasisRegression, notify.RateNoDenominator, 0},
		{"qualifying regression with 4 occurrences is queue", occ(4, 1), func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{Eligible: true, Occurrences: 4, AncestryKnown: true}
		}, notify.TierQueue, notify.BasisRegression, notify.RateNoDenominator, 0},
		{"non-qualifying regression with many occurrences is only count", occ(9, 1), func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{AncestryKnown: false}
		}, notify.TierQueue, notify.BasisCount, notify.RateNoDenominator, 0},
		{"no occurrences is no tier", nil, nil, notify.TierNone, notify.BasisNone, notify.RateNoDenominator, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, issueE)
			h.dest(rcptA, "", t0)
			in := h.issue(issueE, t0+min1, c.ids, c.mod)
			if h.s.Tier != c.tier || h.s.Explanation.Basis != c.basis || h.s.Explanation.Rate != c.rate || h.s.Explanation.RateBasisPoints != c.bp {
				t.Fatalf("tier=%s basis=%s rate=%s bp=%d, want %s %s %s %d", h.s.Tier, h.s.Explanation.Basis, h.s.Explanation.Rate, h.s.Explanation.RateBasisPoints, c.tier, c.basis, c.rate, c.bp)
			}
			if c.rate != notify.RateKnown && (h.s.Explanation.Operations != 0 || h.s.Explanation.RateBasisPoints != 0) {
				t.Fatalf("an unknown rate must not carry operations or a percentage: %+v", h.s.Explanation)
			}
			opens := of(in, notify.KindOpen)
			if (c.tier == notify.TierUrgent) != (len(opens) == 1) {
				t.Fatalf("tier %s but opening intents=%d (%v)", c.tier, len(opens), kinds(in))
			}
		})
	}
}

func TestUrgencyDuplicateOccurrencesNeverRaiseCounts(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	four := occ(4, 1)
	// The same four IDs, repeated inside one event and across several events.
	dup := slices.Concat(four, four, four)
	for range 3 {
		h.issue(issueE, t0+min1, dup, withDenominator(100, true))
	}
	if h.s.Tier != notify.TierQueue || h.s.Explanation.Failures != 4 {
		t.Fatalf("4 distinct failures repeated must stay 4 and queue: tier=%s failures=%d", h.s.Tier, h.s.Explanation.Failures)
	}
	// A fifth distinct ID crosses the threshold exactly once.
	in := h.issue(issueE, t0+2*min1, occ(5, 1), withDenominator(100, true))
	if h.s.Tier != notify.TierUrgent || h.s.Explanation.Failures != 5 || len(of(in, notify.KindOpen)) != 1 {
		t.Fatalf("5 distinct failures at 5%% must open once: tier=%s failures=%d %v", h.s.Tier, h.s.Explanation.Failures, kinds(in))
	}
	// Re-sending everything creates nothing new.
	in = h.issue(issueE, t0+3*min1, occ(5, 1), withDenominator(100, true))
	if len(in) != 0 {
		t.Fatalf("replayed evidence produced intents %v", kinds(in))
	}
}

func TestUrgencyQueueIsImmediateNotDigest(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	in := h.issue(issueE, t0+min1, occ(2, 1), nil)
	q := of(in, notify.KindQueue)
	if len(q) != 1 || q[0].Route != notify.RouteQueue || !q[0].Eligible() || q[0].Key.Recipient != nil {
		t.Fatalf("a queue change must reach the shared queue at once, got %+v", in)
	}
	if len(of(in, notify.KindDigest)) != 0 || len(of(in, notify.KindOpen)) != 0 {
		t.Fatalf("queue-tier evidence must not open or digest immediately: %v", kinds(in))
	}
	// More occurrences with the same queue summary are not a new queue change.
	in = h.issue(issueE, t0+2*min1, occ(3, 1), nil)
	if len(in) != 0 {
		t.Fatalf("a count change inside the same queue state produced %v", kinds(in))
	}
}

func TestUrgencyWindowsAreIndependentOfArrivalOrder(t *testing.T) {
	// Evidence is merged per 5-minute window; the worst retained window wins.
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	h.issue(issueE, t0+min1, occ(5, 1), withDenominator(100, true))
	if h.s.Tier != notify.TierUrgent {
		t.Fatal("first window should be urgent")
	}
	// A quiet later window does not erase the urgent one or re-open.
	in := h.issue(issueE, t0+6*min1, occ(1, 2), nil)
	if h.s.Tier != notify.TierUrgent || len(of(in, notify.KindOpen)) != 0 {
		t.Fatalf("tier=%s %v", h.s.Tier, kinds(in))
	}
}

func TestPolicyOpeningRemindersAndAck(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	h.dest(rcptB, "", t0)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	open := h.do(ev, t0)
	if got := of(open, notify.KindOpen); len(got) != 2 {
		t.Fatalf("one opening per recipient, got %v", kinds(open))
	}
	// One opening per episode: repeated routine evidence stays grouped.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 2, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if in := h.do(ev, t0+min1); len(in) != 0 {
		t.Fatalf("a routine repeat produced %v", kinds(in))
	}
	// Reminders at +15 minutes, then every 60 minutes.
	if in := h.timer(t0 + 15*min1 - 1); len(in) != 0 {
		t.Fatalf("early reminder %v", kinds(in))
	}
	r1 := h.timer(t0 + 15*min1)
	if got := of(r1, notify.KindReminder); len(got) != 2 || got[0].Key.Ordinal != 1 || got[0].Template.Reminder != 1 {
		t.Fatalf("first reminder wrong: %+v", r1)
	}
	if in := h.timer(t0 + 74*min1); len(in) != 0 {
		t.Fatalf("second reminder is due at +75 minutes, got %v", kinds(in))
	}
	r2 := h.timer(t0 + 75*min1)
	if got := of(r2, notify.KindReminder); len(got) != 2 || got[0].Key.Ordinal != 2 {
		t.Fatalf("second reminder wrong: %+v", r2)
	}
	// Catching up after downtime sends one reminder for the latest slot only.
	late := h.timer(t0 + 400*min1)
	if got := of(late, notify.KindReminder); len(got) != 2 || got[0].Key.Ordinal != 3 {
		t.Fatalf("catch-up must send exactly one reminder, got %v", kinds(late))
	}
	if h.s.Reminders.Next != t0+435*min1 {
		t.Fatalf("schedule must resume on the 60-minute grid, next=%d", (h.s.Reminders.Next-t0)/min1)
	}
	// ACK pauses reminders only.
	ack := h.mustAction(incE, notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 3, ImpactRevision: 1}, t0+401*min1)
	if len(ack) != 0 {
		t.Fatalf("ACK must not itself notify: %v", kinds(ack))
	}
	if in := h.timer(t0 + 500*min1); len(in) != 0 {
		t.Fatalf("an acknowledged impact must not remind: %v", kinds(in))
	}
	if due, ok := h.s.NextDue(); ok && due == h.s.Reminders.Next {
		t.Fatalf("an acknowledged impact has no reminder due: %v", h.s.Reminders)
	}
	// A worse impact notifies despite the ACK and has its own revision.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 4, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	worse := h.do(ev, t0+510*min1)
	w := of(worse, notify.KindWorseImpact)
	if len(w) != 2 || !w[0].Eligible() || w[0].Key.ImpactRevision != 2 || w[0].Key.Entity != incE {
		t.Fatalf("worse impact must notify despite ACK with impact revision 2: %+v", worse)
	}
	if w[0].Template.Acknowledged {
		t.Fatal("the new impact revision is not acknowledged")
	}
	// The new revision is unacknowledged, so reminders resume 15 minutes later.
	if in := h.timer(t0 + 525*min1); len(of(in, notify.KindReminder)) != 2 {
		t.Fatalf("reminders must resume after a worse impact: %v", kinds(in))
	}
	// ACK of the new revision pauses again.
	h.mustAction(incE, notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 5, ImpactRevision: 2}, t0+526*min1)
	if in := h.timer(t0 + 700*min1); len(in) != 0 {
		t.Fatalf("reminders after the second ACK: %v", kinds(in))
	}
}

func TestPolicyAckBeforeEvidenceCoversTheRevision(t *testing.T) {
	// Out-of-order delivery: the ACK for revision 1 arrives before the
	// incident snapshot that carries revision 1.
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	h.mustAction(incE, notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 2, ImpactRevision: 1}, t0)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	in := h.do(ev, t0+min1)
	if len(of(in, notify.KindOpen)) != 1 {
		t.Fatalf("an ACK never suppresses the opening: %v", kinds(in))
	}
	if in := h.timer(t0 + 30*min1); len(in) != 0 {
		t.Fatalf("revision 1 is acknowledged, no reminder: %v", kinds(in))
	}
}

func TestPolicySuppressionAndAck(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t, incE)
		h.dest(rcptA, "", t0)
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
		if in := h.do(ev, t0); len(of(in, notify.KindOpen)) != 1 {
			t.Fatalf("setup: %v", kinds(in))
		}
		return h
	}
	snooze := func(version model.Revision, until model.UnixNano) notify.HumanAction {
		return notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: version, Reason: "known issue, vendor notified", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: until}
	}
	maint := func(version model.Revision, until model.UnixNano) notify.HumanAction {
		return notify.HumanAction{Type: notify.ActionMaintenance, Actor: alice, Version: version, Reason: "planned database upgrade", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: until}
	}
	incident := func(h *harness, v model.Revision, sev notify.Severity, impact uint64, src notify.SourceState, at model.UnixNano) []notify.Intent {
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: v, Status: notify.HumanOpen, Severity: sev, ImpactRevision: impact, Episode: epOne, Source: src, Freshness: notify.FreshnessFresh}
		return h.do(ev, at)
	}

	t.Run("snooze pauses reminders and routine updates but never a worse impact", func(t *testing.T) {
		h := setup(t)
		until := t0 + 3*hour
		h.mustAction(incE, snooze(2, until), t0+min1)
		if in := h.timer(t0 + 20*min1); len(in) != 0 {
			t.Fatalf("snoozed reminder: %v", kinds(in))
		}
		worse := incident(h, 3, notify.SeverityCritical, 2, notify.SourceFiring, t0+30*min1)
		if w := of(worse, notify.KindWorseImpact); len(w) != 1 || !w[0].Eligible() {
			t.Fatalf("a worse impact must notify during a snooze: %+v", worse)
		}
		rec := incident(h, 4, notify.SeverityCritical, 2, notify.SourceRecovered, t0+40*min1)
		r := of(rec, notify.KindRecovery)
		if len(r) != 1 || r[0].Eligible() || r[0].Code != notify.CodeSnoozed {
			t.Fatalf("a recovery update is suppressed with a code while snoozed: %+v", rec)
		}
		// Queue and evidence are never suppressed.
		if q := of(rec, notify.KindQueue); len(q) != 1 || !q[0].Eligible() {
			t.Fatalf("queue evidence must stay visible: %+v", rec)
		}
		if h.s.Source != notify.SourceRecovered {
			t.Fatal("evidence must still be evaluated during a snooze")
		}
		// Exact expiry: one current-state update.
		if in := h.timer(until - 1); len(in) != 0 {
			t.Fatalf("one nanosecond early: %v", kinds(in))
		}
		exp := h.timer(until)
		cur := of(exp, notify.KindCurrent)
		if len(exp) != 1 || len(cur) != 1 || !cur[0].Eligible() || cur[0].Template.Source != notify.SourceRecovered {
			t.Fatalf("expiry must emit exactly one current-state update, got %+v", exp)
		}
		// A replayed timer emits nothing, even after a restart.
		before := stateJSON(t, h.s)
		if in := h.timer(until); len(in) != 0 {
			t.Fatalf("replayed expiry timer: %v", kinds(in))
		}
		h.restart()
		if in := h.timer(until + min1); len(in) != 0 || stateJSON(t, h.s) != before {
			t.Fatalf("restart replay changed state or emitted: %v", kinds(in))
		}
	})

	t.Run("maintenance suppresses delivery with a code while the revision advances", func(t *testing.T) {
		h := setup(t)
		until := t0 + 2*hour
		h.mustAction(incE, maint(2, until), t0+min1)
		worse := incident(h, 3, notify.SeverityCritical, 2, notify.SourceFiring, t0+10*min1)
		w := of(worse, notify.KindWorseImpact)
		if len(w) != 1 || w[0].Eligible() || w[0].Code != notify.CodeMaintenance || w[0].Key.ImpactRevision != 2 {
			t.Fatalf("worse impact in maintenance: ineligible with a code, revision still advances: %+v", worse)
		}
		if h.s.ImpactRevision != 2 {
			t.Fatalf("impact revision must advance during maintenance, got %d", h.s.ImpactRevision)
		}
		if q := of(worse, notify.KindQueue); len(q) != 1 || !q[0].Eligible() {
			t.Fatalf("maintenance must not hide the queue: %+v", worse)
		}
		if in := h.timer(t0 + 30*min1); len(in) != 0 {
			t.Fatalf("a reminder during maintenance: %v", kinds(in))
		}
		exp := h.timer(until)
		if cur := of(exp, notify.KindCurrent); len(exp) != 1 || len(cur) != 1 || !cur[0].Eligible() || cur[0].Template.Severity != notify.SeverityCritical || cur[0].Key.ImpactRevision != 2 {
			t.Fatalf("expiry must send one current update with the worse impact: %+v", exp)
		}
		// Reminders resume 60 minutes after the update.
		if due, _ := h.s.NextDue(); due != until+hour {
			t.Fatalf("next reminder %d minutes after expiry, want 60", (due-until)/min1)
		}
		if in := h.timer(until + 30*min1); len(in) != 0 {
			t.Fatalf("a second current update: %v", kinds(in))
		}
	})

	t.Run("a suppressed opening is delivered as one current update afterwards", func(t *testing.T) {
		h := newHarness(t, incE)
		h.dest(rcptA, "", t0)
		h.mustAction(incE, maint(1, t0+hour), t0)
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
		in := h.do(ev, t0+min1)
		o := of(in, notify.KindOpen)
		if len(o) != 1 || o[0].Eligible() || o[0].Code != notify.CodeMaintenance {
			t.Fatalf("opening in maintenance: %+v", in)
		}
		exp := h.timer(t0 + hour)
		if cur := of(exp, notify.KindCurrent); len(cur) != 1 || !cur[0].Eligible() {
			t.Fatalf("after maintenance the recipient must learn the current state once: %+v", exp)
		}
	})

	t.Run("explicit end reevaluates once and the old expiry timer is then a no-op", func(t *testing.T) {
		h := setup(t)
		h.mustAction(incE, maint(2, t0+hour), t0+min1)
		incident(h, 3, notify.SeverityCritical, 2, notify.SourceFiring, t0+2*min1)
		end := h.mustAction(incE, notify.HumanAction{Type: notify.ActionMaintenanceEnd, Actor: alice, Version: 3, Reason: "done"}, t0+3*min1)
		if cur := of(end, notify.KindCurrent); len(end) != 1 || len(cur) != 1 {
			t.Fatalf("ending maintenance emits one current update: %+v", end)
		}
		if in := h.timer(t0 + hour); len(of(in, notify.KindCurrent)) != 0 {
			t.Fatalf("the original expiry must not emit again: %v", kinds(in))
		}
	})

	t.Run("snooze and maintenance expiring together emit at most one update", func(t *testing.T) {
		h := setup(t)
		h.mustAction(incE, snooze(2, t0+hour), t0+min1)
		h.mustAction(incE, maint(3, t0+hour), t0+min1)
		incident(h, 4, notify.SeverityCritical, 2, notify.SourceFiring, t0+2*min1)
		exp := h.timer(t0 + hour)
		if cur := of(exp, notify.KindCurrent); len(cur) != 1 || !cur[0].Eligible() {
			t.Fatalf("exactly one deliverable current update: %+v", exp)
		}
	})

	t.Run("a longer window ends later; the earlier expiry is silent while still suppressed", func(t *testing.T) {
		h := setup(t)
		h.mustAction(incE, snooze(2, t0+hour), t0+min1)
		h.mustAction(incE, maint(3, t0+2*hour), t0+min1)
		incident(h, 4, notify.SeverityCritical, 2, notify.SourceFiring, t0+2*min1)
		if in := h.timer(t0 + hour); len(of(in, notify.KindCurrent)) != 0 {
			t.Fatalf("still in maintenance, no deliverable update: %v", kinds(in))
		}
		if in := h.timer(t0 + 2*hour); len(of(in, notify.KindCurrent)) != 1 {
			t.Fatalf("one update when the last suppression ends: %v", kinds(in))
		}
	})

	t.Run("windows need a reason, a future expiry within the maximum and an applicable scope", func(t *testing.T) {
		h := setup(t)
		bad := []notify.HumanAction{
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Reason = ""; return a }(),
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Reason = "bad\x00reason"; return a }(),
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Reason = strings.Repeat("x", 513); return a }(),
			snooze(2, t0+8*24*hour),
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Actor = model.ID{}; return a }(),
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Scope = notify.Scope{Kind: "galaxy"}; return a }(),
			func() notify.HumanAction {
				a := snooze(2, t0+hour)
				a.Scope = notify.Scope{Kind: notify.ScopeService}
				return a
			}(),
			func() notify.HumanAction { a := snooze(2, t0+hour); a.Version = 0; return a }(),
		}
		for i, a := range bad {
			before := stateJSON(t, h.s)
			if _, err := h.action(incE, a, t0+min1); err == nil {
				t.Fatalf("case %d: invalid window accepted", i)
			}
			if stateJSON(t, h.s) != before {
				t.Fatalf("case %d: rejected window changed state", i)
			}
		}
		// Exactly the 7-day maximum is allowed.
		h.mustAction(incE, snooze(2, t0+min1+7*24*hour), t0+min1)
		// A service scope for another service is not applicable: no-op.
		other := model.ID{0xdd}
		a := maint(3, t0+hour)
		a.Scope = notify.Scope{Kind: notify.ScopeService, Service: &other}
		h.mustAction(incE, a, t0+min1)
		if h.s.Maintenance != nil {
			t.Fatal("a window for another service must not apply")
		}
	})

	t.Run("a late snooze older than its end never starts", func(t *testing.T) {
		h := setup(t)
		h.mustAction(incE, notify.HumanAction{Type: notify.ActionUnsnooze, Actor: alice, Version: 5, Reason: "back"}, t0+min1)
		h.mustAction(incE, snooze(4, t0+hour), t0+2*min1)
		if h.s.Snooze != nil {
			t.Fatal("a snooze older than a recorded unsnooze must be ignored")
		}
		h.mustAction(incE, snooze(6, t0+hour), t0+3*min1)
		if h.s.Snooze == nil {
			t.Fatal("a newer snooze must start")
		}
		// A stale unsnooze (older than the window) does not end it.
		h.mustAction(incE, notify.HumanAction{Type: notify.ActionUnsnooze, Actor: alice, Version: 5, Reason: "stale"}, t0+4*min1)
		if h.s.Snooze == nil {
			t.Fatal("a stale unsnooze must not end a newer snooze")
		}
		// A snooze with exactly the version of a recorded end never starts.
		h.mustAction(incE, notify.HumanAction{Type: notify.ActionUnsnooze, Actor: alice, Version: 8, Reason: "back"}, t0+5*min1)
		h.mustAction(incE, snooze(8, t0+hour), t0+6*min1)
		if h.s.Snooze != nil {
			t.Fatal("a snooze at the version of its end must not start")
		}
	})

	t.Run("project scope applies and service scope matches the affected service", func(t *testing.T) {
		h := setup(t)
		a := maint(2, t0+hour)
		a.Scope = notify.Scope{Kind: notify.ScopeProject}
		h.mustAction(incE, a, t0+min1)
		if h.s.Maintenance == nil {
			t.Fatal("project scope applies")
		}
	})
}

func TestPolicyOwnerCutoverAndPromotion(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	in := h.issue(issueE, t0+min1, occ(5, 1), withDenominator(100, true))
	if len(of(in, notify.KindOpen)) != 1 || h.s.Owner != issueE {
		t.Fatalf("issue opens as the canonical owner: %v", kinds(in))
	}
	// The incident is not linked yet: it cannot send anything.
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	before := stateJSON(t, h.s)
	if _, err := h.try(ev, t0+2*min1); !errors.Is(err, &notify.Error{Reason: notify.ReasonNotLinked}) {
		t.Fatalf("unlinked entity must fail closed, got %v", err)
	}
	if stateJSON(t, h.s) != before {
		t.Fatal("a refused event changed state")
	}
	// Cutover with a stale expected owner revision fails closed.
	cut := h.ev(notify.EventCutover)
	cut.Entity = &issueE
	cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 1}, To: incE}
	cut.OwnerRevision = 7
	if _, err := h.try(cut, t0+3*min1); !errors.Is(err, &notify.Error{Reason: notify.ReasonOwnerRevision}) {
		t.Fatalf("wrong owner revision: %v", err)
	}
	cut.OwnerRevision = h.s.OwnerRevision
	cq := h.do(cut, t0+3*min1)
	if h.s.Owner != incE || h.s.OwnerRevision != 2 || len(of(cq, notify.KindOpen)) != 0 {
		t.Fatalf("promotion transfers ownership without a second opening: owner=%v rev=%d %v", h.s.Owner, h.s.OwnerRevision, kinds(cq))
	}
	// A replayed cutover is a no-op, not a revision conflict.
	snap := stateJSON(t, h.s)
	if in := h.do(cut, t0+4*min1); len(in) != 0 || stateJSON(t, h.s) != snap {
		t.Fatalf("replayed cutover: %v", kinds(in))
	}
	// The old issue still feeds provenance but no longer decides or sends.
	in = h.issue(issueE, t0+5*min1, occ(40, 3), withDenominator(100, true))
	if len(of(in, notify.KindOpen))+len(of(in, notify.KindWorseImpact))+len(of(in, notify.KindReminder)) != 0 {
		t.Fatalf("a linked non-owner must not send: %v", kinds(in))
	}
	// The incident's first snapshot adopts the open episode: no second opening.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if in := h.do(ev, t0+6*min1); len(of(in, notify.KindOpen))+len(of(in, notify.KindWorseImpact)) != 0 {
		t.Fatalf("no duplicate normal owner on promotion: %v", kinds(in))
	}
	if h.s.Episode != 1 {
		t.Fatalf("one episode across the promotion, got %d", h.s.Episode)
	}
	// A real worse impact now comes from the incident, keyed by the incident.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 2, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	w := of(h.do(ev, t0+7*min1), notify.KindWorseImpact)
	if len(w) != 1 || w[0].Key.Entity != incE {
		t.Fatalf("worse impact after promotion: %+v", w)
	}
	// Reminders after the promotion are keyed by the new owner, exactly once.
	rem := h.timer(t0 + 30*min1)
	if r := of(rem, notify.KindReminder); len(r) != 1 || r[0].Key.Entity != incE {
		t.Fatalf("reminder after promotion: %+v", rem)
	}
	// Rolling back is one owner at a time: owner is the issue again.
	rb := h.ev(notify.EventCutover)
	rb.Entity = &incE
	rb.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 2}, To: issueE}
	h.do(rb, t0+31*min1)
	if h.s.Owner != issueE || h.s.OwnerRevision != 3 {
		t.Fatalf("rollback: owner=%v rev=%d", h.s.Owner, h.s.OwnerRevision)
	}
	// An event that names the previous owner revision is refused.
	stale := h.ev(notify.EventTimer)
	stale.Timer = &notify.Timer{}
	stale.OwnerRevision = 2
	if _, err := h.try(stale, t0+32*min1); !errors.Is(err, &notify.Error{Reason: notify.ReasonOwnerRevision}) {
		t.Fatalf("stale owner revision on a timer: %v", err)
	}
}

func TestPolicyShadowModeSendsNothing(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	sh := h.ev(notify.EventCutover)
	sh.Entity = &issueE
	sh.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 1}, To: issueE, Mode: notify.ModeShadow}
	h.do(sh, t0)
	in := h.issue(issueE, t0+min1, occ(5, 1), withDenominator(100, true))
	o := of(in, notify.KindOpen)
	if len(o) != 1 || o[0].Eligible() || o[0].Code != notify.CodeShadow {
		t.Fatalf("shadow decisions are recorded but never delivered: %+v", in)
	}
	if q := of(in, notify.KindQueue); len(q) != 1 || !q[0].Eligible() {
		t.Fatalf("the queue is a read model, not a send: %+v", in)
	}
	if in := h.timer(t0 + 30*min1); len(in) != 0 {
		t.Fatalf("shadow reminders: %v", kinds(in))
	}
	// Activating reevaluates once: one current update, no second opening.
	act := h.ev(notify.EventCutover)
	act.Entity = &issueE
	act.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 2}, To: issueE, Mode: notify.ModeActive}
	in = h.do(act, t0+31*min1)
	if cur := of(in, notify.KindCurrent); len(in) != 1 || len(cur) != 1 || !cur[0].Eligible() {
		t.Fatalf("activation: %+v", in)
	}
}

func TestPolicyFailClosed(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	h.issue(issueE, t0+min1, occ(2, 1), nil)
	h.rev = 2 // the state adopts revision 2; revision 1 is then stale
	h.issue(issueE, t0+min1, occ(1, 2), nil)
	good := func() notify.PolicyEvent {
		ev := h.ev(notify.EventIssue)
		ev.Entity = &issueE
		ev.Issue = &notify.IssueEvidence{WindowStart: t0, Occurrences: occ(1, 9), Freshness: notify.FreshnessFresh}
		return ev
	}
	cases := []struct {
		name   string
		mutate func(*notify.PolicyEvent)
		reason notify.Reason
		code   model.Code
	}{
		{"owner revision behind", func(e *notify.PolicyEvent) { e.OwnerRevision-- }, notify.ReasonOwnerRevision, model.Conflict},
		{"owner revision ahead", func(e *notify.PolicyEvent) { e.OwnerRevision++ }, notify.ReasonOwnerRevision, model.Conflict},
		{"stale policy revision", func(e *notify.PolicyEvent) { e.PolicyRef = notify.PolicyRef{Revision: 1} }, notify.ReasonPolicyStale, model.Stale},
		{"newer policy revision without config", func(e *notify.PolicyEvent) { e.PolicyRef = notify.PolicyRef{Revision: 9} }, notify.ReasonPolicyConfig, model.Invalid},
		{"same revision different config", func(e *notify.PolicyEvent) {
			c := notify.DefaultConfig()
			c.MinFailures = 99
			e.PolicyRef.Config = &c
		}, notify.ReasonPolicyConflict, model.Conflict},
		{"another org", func(e *notify.PolicyEvent) { e.Org = model.ID{0x99} }, notify.ReasonScope, model.Invalid},
		{"another project", func(e *notify.PolicyEvent) { e.Project = model.ID{0x99} }, notify.ReasonScope, model.Invalid},
		{"another policy", func(e *notify.PolicyEvent) { e.Policy = model.ID{0x99} }, notify.ReasonScope, model.Invalid},
		{"unlinked incident", func(e *notify.PolicyEvent) { e.Entity = &incE }, notify.ReasonNotLinked, model.Forbidden},
		{"unlinked issue", func(e *notify.PolicyEvent) {
			o := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x99}}
			e.Entity = &o
		}, notify.ReasonNotLinked, model.Forbidden},
		{"no entity", func(e *notify.PolicyEvent) { e.Entity = nil }, notify.ReasonInvalidEvent, model.Invalid},
		{"two payloads", func(e *notify.PolicyEvent) { e.Timer = &notify.Timer{} }, notify.ReasonInvalidEvent, model.Invalid},
		{"payload does not match kind", func(e *notify.PolicyEvent) { e.Kind = notify.EventTimer }, notify.ReasonInvalidEvent, model.Invalid},
		{"unknown kind", func(e *notify.PolicyEvent) { e.Kind = "mystery" }, notify.ReasonInvalidEvent, model.Invalid},
		{"no command id", func(e *notify.PolicyEvent) { e.Command = model.ID{} }, notify.ReasonScope, model.Invalid},
		{"unknown mode", func(e *notify.PolicyEvent) { e.Mode = "turbo" }, notify.ReasonInvalidEvent, model.Invalid},
		{"unaligned window", func(e *notify.PolicyEvent) { e.Issue.WindowStart++ }, notify.ReasonInvalidEvent, model.Invalid},
		{"window in the far future", func(e *notify.PolicyEvent) { e.Issue.WindowStart = t0 + 10*hour }, notify.ReasonInvalidEvent, model.Invalid},
		{"zero occurrence id", func(e *notify.PolicyEvent) { e.Issue.Occurrences = []model.ID{{}} }, notify.ReasonInvalidEvent, model.Invalid},
		{"too many occurrences", func(e *notify.PolicyEvent) { e.Issue.Occurrences = occ(notify.MaxEventOccurrences+1, 4) }, notify.ReasonInvalidEvent, model.Invalid},
		{"code without occurrences", func(e *notify.PolicyEvent) { e.Issue.Occurrences = nil; e.Issue.Code = "payment_failed" }, notify.ReasonInvalidEvent, model.Invalid},
		{"free-text code", func(e *notify.PolicyEvent) { e.Issue.Code = "token=abc def" }, notify.ReasonInvalidEvent, model.Invalid},
		{"unknown freshness", func(e *notify.PolicyEvent) { e.Issue.Freshness = "maybe" }, notify.ReasonInvalidEvent, model.Invalid},
		{"denominator without a safe name", func(e *notify.PolicyEvent) {
			e.Issue.Denominator = &notify.Denominator{Name: "has space", WindowStart: t0, Complete: true}
		}, notify.ReasonInvalidEvent, model.Invalid},
		{"cursor without group", func(e *notify.PolicyEvent) { e.Cursor = &model.Cursor{} }, notify.ReasonInvalidEvent, model.Invalid},
		{"condition evidence from an issue entity", func(e *notify.PolicyEvent) {
			e.Kind = notify.EventCondition
			e.Issue = nil
			e.Condition = &notify.ConditionEvidence{Seq: 1, State: notify.SourceFiring, Freshness: notify.FreshnessFresh, Severity: notify.SeverityMajor, Episode: epOne}
		}, notify.ReasonInvalidEvent, model.Invalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := good()
			c.mutate(&ev)
			before := stateJSON(t, h.s)
			next, in, err := notify.Decide(h.s, ev, t0+2*min1)
			if err == nil {
				t.Fatalf("event accepted: %v", kinds(in))
			}
			reason, ok := notify.ReasonOf(err)
			if !ok || reason != c.reason {
				t.Fatalf("reason %q (ok=%v) want %q: %v", reason, ok, c.reason, err)
			}
			var f *model.Fault
			if !errors.As(err, &f) || f.Code != c.code {
				t.Fatalf("code %v want %v", f, c.code)
			}
			if in != nil || stateJSON(t, next) != before || stateJSON(t, h.s) != before {
				t.Fatal("a refusal must return the original state and no intents")
			}
		})
	}
}

func TestPolicyDoesNotMutateItsArgument(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	h.issue(issueE, t0+min1, occ(3, 1), withDenominator(50, true))
	before := stateJSON(t, h.s)
	ev := h.ev(notify.EventIssue)
	ev.Entity = &issueE
	ev.Issue = &notify.IssueEvidence{WindowStart: t0, Occurrences: occ(9, 2), Freshness: notify.FreshnessFresh, Code: "payment_failed", Service: &notify.ServiceRef{ID: svcA, Critical: true}}
	next, _, err := notify.Decide(h.s, ev, t0+2*min1)
	if err != nil {
		t.Fatal(err)
	}
	if stateJSON(t, h.s) != before {
		t.Fatal("Decide modified the state it was given")
	}
	if stateJSON(t, next) == before {
		t.Fatal("the returned state should differ")
	}
}

func TestPolicyMissingChannelIsVisibleFailure(t *testing.T) {
	h := newHarness(t, issueE)
	in := h.issue(issueE, t0+min1, occ(1, 1), func(e *notify.IssueEvidence) { e.Code = "payment_failed" })
	o := of(in, notify.KindOpen)
	if len(o) != 1 || o[0].Disposition != notify.DispositionFailed || o[0].Code != notify.CodeNoDestination || o[0].Eligible() || o[0].Key.Recipient != nil {
		t.Fatalf("no destination must be a visible failed intent, never success: %+v", in)
	}
	// A disabled recipient is not a destination.
	ev := h.ev(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: rcptA, Enabled: false}
	h.do(ev, t0+2*min1)
	if rem := h.timer(t0 + 16*min1); len(of(rem, notify.KindReminder)) != 1 || rem[0].Disposition != notify.DispositionFailed {
		t.Fatalf("reminder without a destination: %+v", rem)
	}
	h.dest(rcptA, "", t0+17*min1)
	rem := h.timer(t0 + 76*min1)
	if r := of(rem, notify.KindReminder); len(r) != 1 || !r[0].Eligible() || r[0].Key.Recipient == nil || *r[0].Key.Recipient != rcptA {
		t.Fatalf("a configured destination receives the next reminder: %+v", rem)
	}
	// Removing the recipient makes the failure visible again.
	rm := h.ev(notify.EventDestination)
	rm.Destination = &notify.DestinationChange{Recipient: rcptA, Remove: true}
	h.do(rm, t0+77*min1)
	if rem := h.timer(t0 + 136*min1); len(rem) != 1 || rem[0].Disposition != notify.DispositionFailed {
		t.Fatalf("after removal: %+v", rem)
	}
}

func TestPolicyRecoveryIsNotResolution(t *testing.T) {
	h := newHarness(t, condE)
	h.dest(rcptA, "", t0)
	cond := func(seq uint64, st notify.SourceState, fr notify.Freshness, sev notify.Severity, ep model.ID, at model.UnixNano) []notify.Intent {
		ev := h.ev(notify.EventCondition)
		ev.Entity = &condE
		ev.Condition = &notify.ConditionEvidence{Seq: seq, State: st, Freshness: fr, Severity: sev, Episode: ep}
		return h.do(ev, at)
	}
	in := cond(1, notify.SourceFiring, notify.FreshnessFresh, notify.SeverityMajor, epOne, t0)
	if len(of(in, notify.KindOpen)) != 1 {
		t.Fatalf("firing major condition opens: %v", kinds(in))
	}
	// Unknown and stale data never recover.
	if in := cond(2, notify.SourceUnknown, notify.FreshnessUnknown, notify.SeverityMajor, epOne, t0+min1); len(of(in, notify.KindRecovery)) != 0 || h.s.Source != notify.SourceFiring {
		t.Fatalf("unknown must not recover: %v source=%s", kinds(in), h.s.Source)
	}
	if in := cond(3, notify.SourceRecovered, notify.FreshnessStale, notify.SeverityMajor, epOne, t0+2*min1); len(of(in, notify.KindRecovery)) != 0 || h.s.Source != notify.SourceFiring {
		t.Fatalf("a stale recovered claim must not recover: %v source=%s", kinds(in), h.s.Source)
	}
	if in := cond(4, notify.SourceRecovered, notify.FreshnessUnknown, notify.SeverityMajor, epOne, t0+3*min1); len(of(in, notify.KindRecovery)) != 0 {
		t.Fatalf("an unknown-freshness recovered claim must not recover: %v", kinds(in))
	}
	// A late (older sequence) firing cannot overwrite the newer state, and a
	// late recovery cannot appear either.
	if in := cond(2, notify.SourceRecovered, notify.FreshnessFresh, notify.SeverityMajor, epOne, t0+4*min1); len(in) != 0 || h.s.Source != notify.SourceFiring {
		t.Fatalf("an older sequence is late history: %v source=%s", kinds(in), h.s.Source)
	}
	if h.s.Late != 1 {
		t.Fatalf("late history must be counted, got %d", h.s.Late)
	}
	rec := cond(5, notify.SourceRecovered, notify.FreshnessFresh, notify.SeverityMajor, epOne, t0+5*min1)
	r := of(rec, notify.KindRecovery)
	if len(r) != 1 || r[0].Template.Source != notify.SourceRecovered || r[0].Template.Human != notify.HumanOpen {
		t.Fatalf("source recovery is a recovery, not a resolution: %+v", rec)
	}
	if len(of(rec, notify.KindResolution)) != 0 {
		t.Fatal("recovery must not look like a human resolution")
	}
	if in := h.timer(t0 + 30*min1); len(in) != 0 {
		t.Fatalf("recovered source has nothing to remind: %v", kinds(in))
	}
	// Recovery does not resolve: the human state is still open.
	if h.s.Human != notify.HumanOpen {
		t.Fatal("alert recovery must not resolve")
	}
	// A new episode opens again with a distinct impact revision.
	n := cond(6, notify.SourceFiring, notify.FreshnessFresh, notify.SeverityMajor, epTwo, t0+hour)
	o := of(n, notify.KindOpen)
	if len(o) != 1 || o[0].Key.ImpactRevision <= r[0].Key.ImpactRevision {
		t.Fatalf("new episode: %+v", n)
	}
}

func TestPolicyResolutionKeepsSourceEvidence(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	h.do(ev, t0)
	res := h.mustAction(incE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 2, Reason: "mitigated"}, t0+min1)
	r := of(res, notify.KindResolution)
	if len(r) != 1 || r[0].Template.Human != notify.HumanResolved || r[0].Template.Source != notify.SourceFiring {
		t.Fatalf("resolution while the source is firing must say so: %+v", res)
	}
	if len(of(res, notify.KindRecovery)) != 0 {
		t.Fatal("resolution must not look like source recovery")
	}
	// A replay and a late snapshot saying "open" cannot reopen or re-notify.
	if in := h.mustAction(incE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 2, Reason: "mitigated"}, t0+2*min1); len(in) != 0 {
		t.Fatalf("replayed resolve: %v", kinds(in))
	}
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 2, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if in := h.do(ev, t0+3*min1); len(of(in, notify.KindOpen))+len(of(in, notify.KindWorseImpact))+len(of(in, notify.KindReminder)) != 0 || h.s.Human != notify.HumanResolved {
		t.Fatalf("an incident resolution is final: %v human=%s", kinds(in), h.s.Human)
	}
	if in := h.timer(t0 + 5*hour); len(in) != 0 {
		t.Fatalf("reminder after resolution: %v", kinds(in))
	}
	// An alert recovery after resolution is only source evidence, not a notice.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 3, Status: notify.HumanResolved, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceRecovered, Freshness: notify.FreshnessFresh}
	if in := h.do(ev, t0+4*min1); len(of(in, notify.KindRecovery)) != 0 {
		t.Fatalf("recovery after resolution: %v", kinds(in))
	}
}

func TestPolicyBackfillAndLateEvidenceNeverInterrupt(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	critical := func(e *notify.IssueEvidence) { e.Code = "payment_failed" }
	// Backfill is recorded, never notified.
	ev := h.ev(notify.EventIssue)
	ev.Entity = &issueE
	ev.Mode = notify.ModeBackfill
	ev.Issue = &notify.IssueEvidence{WindowStart: t0, Occurrences: occ(50, 1), Freshness: notify.FreshnessFresh, Code: "payment_failed"}
	if in := h.do(ev, t0+min1); len(in) != 0 || h.s.Backfilled != 1 || h.s.Tier != notify.TierNone {
		t.Fatalf("backfill: %v backfilled=%d tier=%s", kinds(in), h.s.Backfilled, h.s.Tier)
	}
	// A live event for a window that closed long ago is late history too.
	old := t0 - 2*hour
	in := h.issue(issueE, t0+min1, occ(5, 1), func(e *notify.IssueEvidence) {
		critical(e)
		e.WindowStart = old - old%notify.ErrorWindow
	})
	if len(in) != 0 || h.s.Late != 1 || h.s.Tier != notify.TierNone {
		t.Fatalf("late live evidence: %v late=%d", kinds(in), h.s.Late)
	}
	// The same late evidence in explicit operator replay mode is processed.
	ev = h.ev(notify.EventIssue)
	ev.Entity = &issueE
	ev.Mode = notify.ModeOperatorReplay
	ev.Issue = &notify.IssueEvidence{WindowStart: old - old%notify.ErrorWindow, Occurrences: occ(1, 1), Freshness: notify.FreshnessFresh, Code: "payment_failed"}
	if in := h.do(ev, t0+2*min1); len(of(in, notify.KindOpen)) != 1 {
		t.Fatalf("operator replay is live evidence: %v", kinds(in))
	}
	// Late history after resolution never reopens by itself.
	h.mustAction(issueE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 1}, t0+3*min1)
	in = h.issue(issueE, t0+hour, occ(30, 8), func(e *notify.IssueEvidence) { critical(e) })
	if len(of(in, notify.KindOpen)) != 0 || h.s.Human != notify.HumanResolved {
		t.Fatalf("evidence after resolution: %v human=%s", kinds(in), h.s.Human)
	}
	// A qualifying reopen is a new episode with a new revision.
	prev := h.s.ImpactRevision
	in = h.issue(issueE, t0+2*hour, occ(6, 9), func(e *notify.IssueEvidence) {
		e.Regression = &notify.Regression{Eligible: true, Occurrences: 6, Reopened: true, AncestryKnown: true}
	})
	o := of(in, notify.KindOpen)
	if len(o) != 1 || o[0].Key.ImpactRevision <= prev || h.s.Human != notify.HumanOpen {
		t.Fatalf("reopen: %v prev=%d", kinds(in), prev)
	}
}

func TestPolicyConditionSeverityAndOrdering(t *testing.T) {
	h := newHarness(t, condE)
	h.dest(rcptA, "", t0)
	cond := func(seq uint64, sev notify.Severity, at model.UnixNano, svc *notify.ServiceRef) []notify.Intent {
		ev := h.ev(notify.EventCondition)
		ev.Entity = &condE
		ev.Condition = &notify.ConditionEvidence{Seq: seq, State: notify.SourceFiring, Freshness: notify.FreshnessFresh, Severity: sev, Episode: epOne, Service: svc}
		return h.do(ev, at)
	}
	in := cond(1, notify.SeverityMinor, t0, nil)
	if len(of(in, notify.KindOpen)) != 0 || len(of(in, notify.KindQueue)) != 1 || h.s.Tier != notify.TierQueue {
		t.Fatalf("a minor condition is a queue entry: %v", kinds(in))
	}
	in = cond(2, notify.SeverityMajor, t0+min1, nil)
	if o := of(in, notify.KindOpen); len(o) != 1 || o[0].Key.ImpactRevision != 1 {
		t.Fatalf("major opens at revision 1: %v", kinds(in))
	}
	// A newly affected critical service is a material impact even at the same
	// severity, once per service.
	in = cond(3, notify.SeverityMajor, t0+2*min1, &notify.ServiceRef{ID: svcA, Critical: true})
	if w := of(in, notify.KindWorseImpact); len(w) != 1 || w[0].Key.ImpactRevision != 2 || w[0].Template.Service == nil || w[0].Template.Service.ID != svcA {
		t.Fatalf("new critical service: %v", kinds(in))
	}
	if in := cond(4, notify.SeverityMajor, t0+3*min1, &notify.ServiceRef{ID: svcA, Critical: true}); len(of(in, notify.KindWorseImpact)) != 0 {
		t.Fatalf("the same critical service again is a routine repeat: %v", kinds(in))
	}
	if in := cond(5, notify.SeverityMajor, t0+4*min1, &notify.ServiceRef{ID: svcB, Critical: true}); len(of(in, notify.KindWorseImpact)) != 1 {
		t.Fatalf("a second critical service is a new material impact: %v", kinds(in))
	}
	// A non-critical service never is.
	if in := cond(6, notify.SeverityMajor, t0+5*min1, &notify.ServiceRef{ID: model.ID{0xd9}}); len(of(in, notify.KindWorseImpact)) != 0 {
		t.Fatalf("non-critical service: %v", kinds(in))
	}
	// A severity increase beyond the peak is material; a decrease is not.
	if in := cond(7, notify.SeverityCritical, t0+6*min1, nil); len(of(in, notify.KindWorseImpact)) != 1 {
		t.Fatalf("severity increase: %v", kinds(in))
	}
	if in := cond(8, notify.SeverityMajor, t0+7*min1, nil); len(of(in, notify.KindWorseImpact)) != 0 {
		t.Fatalf("severity decrease must not notify as worse: %v", kinds(in))
	}
	if in := cond(9, notify.SeverityCritical, t0+8*min1, nil); len(of(in, notify.KindWorseImpact)) != 0 {
		t.Fatalf("returning to the peak is not worse: %v", kinds(in))
	}
}

func TestPolicyDigestScheduleAndIdentity(t *testing.T) {
	// 2026-03-10 is a Tuesday; the digest is due at 09:00 recipient time.
	day := func(d int, hh int) model.UnixNano {
		return model.UnixNano(time.Date(2026, 3, d, hh, 0, 0, 0, time.UTC).UnixNano())
	}
	t.Run("UTC fallback with no zone configured", func(t *testing.T) {
		h := newHarness(t, issueE)
		h.dest(rcptA, "", day(10, 8)) // before 09:00: the first digest is today's
		if h.s.Recipients[0].DigestNext != day(10, 9) {
			t.Fatalf("first digest %v", time.Unix(0, int64(h.s.Recipients[0].DigestNext)).UTC())
		}
		in := h.issue(issueE, day(10, 8)+min1, occ(2, 1), nil)
		if len(of(in, notify.KindDigest)) != 0 {
			t.Fatal("a queue change must not wait for or trigger a digest")
		}
		if in := h.timer(day(10, 9) - 1); len(in) != 0 {
			t.Fatalf("digest before 09:00: %v", kinds(in))
		}
		d := h.timer(day(10, 9))
		g := of(d, notify.KindDigest)
		if len(g) != 1 || !g[0].Eligible() || g[0].Route != notify.RouteDigest || g[0].Template.Digest.LocalDate != 20260310 {
			t.Fatalf("digest: %+v", d)
		}
		want := notify.DigestID(org, pol, rcptA, 20260310, 1)
		if g[0].Template.Digest.ID != want {
			t.Fatal("digest identity must be (recipient, local date, policy revision)")
		}
		// Replay and restart: no duplicate digest.
		snap := stateJSON(t, h.s)
		if in := h.timer(day(10, 9)); len(in) != 0 || stateJSON(t, h.s) != snap {
			t.Fatalf("replayed digest timer: %v", kinds(in))
		}
		h.restart()
		if in := h.timer(day(10, 9) + hour); len(in) != 0 {
			t.Fatalf("digest after restart: %v", kinds(in))
		}
		// The next day has nothing new: no digest, but the schedule advances.
		if in := h.timer(day(11, 9)); len(in) != 0 {
			t.Fatalf("an unchanged queue is not re-sent: %v", kinds(in))
		}
		if h.s.Recipients[0].DigestNext != day(12, 9) {
			t.Fatalf("next digest %v", time.Unix(0, int64(h.s.Recipients[0].DigestNext)).UTC())
		}
		// A reopened issue is a queue change: it is in the next digest.
		h.mustAction(issueE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 1, Reason: "fixed"}, day(11, 12))
		h.issue(issueE, day(11, 13), occ(1, 5), func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{Eligible: true, Occurrences: 1, Reopened: true, AncestryKnown: true}
		})
		if in := h.timer(day(12, 9)); len(of(in, notify.KindDigest)) != 1 {
			t.Fatalf("a changed queue appears in the next digest: %v", kinds(in))
		}
	})

	t.Run("configured recipient zone and the installation default", func(t *testing.T) {
		h := newHarness(t, issueE)
		h.cfg.DefaultZone = "Asia/Tokyo" // +09:00, so 09:00 local is 00:00Z
		h.dest(rcptA, "", day(10, 1))
		h.dest(rcptB, "Asia/Kolkata", day(10, 1)) // +05:30, 09:00 local is 03:30Z
		if h.s.Recipients[0].DigestNext != day(11, 0) {
			t.Fatalf("default-zone recipient: %v", time.Unix(0, int64(h.s.Recipients[0].DigestNext)).UTC())
		}
		if want := day(10, 3) + 30*min1; h.s.Recipients[1].DigestNext != want {
			t.Fatalf("kolkata recipient: %v", time.Unix(0, int64(h.s.Recipients[1].DigestNext)).UTC())
		}
		h.issue(issueE, day(10, 2), occ(2, 1), nil)
		d := h.timer(day(10, 3) + 30*min1)
		g := of(d, notify.KindDigest)
		if len(g) != 1 || *g[0].Key.Recipient != rcptB || g[0].Template.Digest.LocalDate != 20260310 {
			t.Fatalf("only the Kolkata recipient is due: %+v", d)
		}
	})

	t.Run("an invalid zone is a typed refusal and never stored", func(t *testing.T) {
		h := newHarness(t, issueE)
		ev := h.ev(notify.EventDestination)
		ev.Destination = &notify.DestinationChange{Recipient: rcptA, Enabled: true, Zone: "Mars/Olympus"}
		before := stateJSON(t, h.s)
		_, err := h.try(ev, t0)
		if r, _ := notify.ReasonOf(err); r != notify.ReasonInvalidZone || stateJSON(t, h.s) != before {
			t.Fatalf("invalid zone: %v", err)
		}
		// A disabled recipient must not smuggle an invalid zone into the state
		// either: it would break the moment it is enabled.
		ev.Destination = &notify.DestinationChange{Recipient: rcptA, Enabled: false, Zone: "../../etc/passwd"}
		if _, err = h.try(ev, t0); !errors.Is(err, &notify.Error{Reason: notify.ReasonInvalidZone}) || stateJSON(t, h.s) != before {
			t.Fatalf("invalid zone on a disabled recipient: %v", err)
		}
		h.cfg.DefaultZone = "Mars/Olympus"
		ev = h.ev(notify.EventTimer)
		ev.Timer = &notify.Timer{}
		if _, err = h.try(ev, t0); !errors.Is(err, &notify.Error{Reason: notify.ReasonInvalidZone}) {
			t.Fatalf("invalid default zone in a policy: %v", err)
		}
	})

	t.Run("maintenance skips a digest without consuming its content", func(t *testing.T) {
		h := newHarness(t, issueE)
		h.dest(rcptA, "", day(10, 1))
		h.issue(issueE, day(10, 2), occ(2, 1), nil)
		h.mustAction(issueE, notify.HumanAction{Type: notify.ActionMaintenance, Actor: alice, Version: 1, Reason: "upgrade", Scope: notify.Scope{Kind: notify.ScopeProject}, Until: day(10, 20)}, day(10, 3))
		if in := h.timer(day(10, 9)); len(in) != 0 {
			t.Fatalf("digest during maintenance: %v", kinds(in))
		}
		if in := h.timer(day(11, 9)); len(of(in, notify.KindDigest)) != 1 {
			t.Fatalf("the content is in the first digest after maintenance: %v", kinds(in))
		}
	})

	t.Run("urgent entities are not digest items", func(t *testing.T) {
		h := newHarness(t, issueE)
		h.dest(rcptA, "", day(10, 1))
		h.issue(issueE, day(10, 2), occ(5, 1), withDenominator(100, true))
		if in := h.timer(day(10, 9)); len(of(in, notify.KindDigest)) != 0 {
			t.Fatalf("an urgent entity was notified immediately: %v", kinds(in))
		}
	})

	t.Run("policy revision is part of the digest identity", func(t *testing.T) {
		a := notify.DigestID(org, pol, rcptA, 20260310, 1)
		for name, other := range map[string]model.ID{
			"revision":  notify.DigestID(org, pol, rcptA, 20260310, 2),
			"date":      notify.DigestID(org, pol, rcptA, 20260311, 1),
			"recipient": notify.DigestID(org, pol, rcptB, 20260310, 1),
			"policy":    notify.DigestID(org, model.ID{0x77}, rcptA, 20260310, 1),
			"org":       notify.DigestID(model.ID{0x77}, pol, rcptA, 20260310, 1),
		} {
			if other == a {
				t.Fatalf("digest identity ignores %s", name)
			}
		}
		if a != notify.DigestID(org, pol, rcptA, 20260310, 1) || a == (model.ID{}) {
			t.Fatal("digest identity must be stable and nonzero")
		}
	})
}

func TestPolicyReorderedEvidenceIsDeterministic(t *testing.T) {
	// Batches of one window applied in every order: the merged windows, tier,
	// explanation, revision and the single opening (or none) are identical.
	type batch struct {
		ids []model.ID
		mod func(*notify.IssueEvidence)
		at  model.UnixNano
	}
	reg := func(n uint32, reopened bool) func(*notify.IssueEvidence) {
		return func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{Eligible: true, Occurrences: n, Reopened: reopened, AncestryKnown: n != 2}
		}
	}
	both := func(fs ...func(*notify.IssueEvidence)) func(*notify.IssueEvidence) {
		return func(e *notify.IssueEvidence) {
			for _, f := range fs {
				f(e)
			}
		}
	}
	base := []batch{
		{occ(2, 1), nil, t0 + min1},
		{occ(2, 1), withDenominator(100, false), t0 + min1},
		{occ(3, 2), both(withDenominator(100, true), reg(3, false)), t0 + min1},
		{occ(1, 3), reg(2, false), t0 + min1},
		{occ(1, 4), withDenominator(100, false), t0 + min1},
		{occ(2, 5), nil, t0 + 2*min1},
	}
	stale := batch{occ(1, 6), func(e *notify.IssueEvidence) { e.Freshness = notify.FreshnessStale }, t0 + min1}
	scenarios := []struct {
		name    string
		batches []batch
		// opens is the exact number of openings in every order, or -1 when
		// whether the threshold was crossed before the stale batch arrived
		// legitimately depends on the order (the final window state does not).
		opens    int
		tier     notify.Tier
		rate     notify.RateState
		failures uint32
		perms    int
	}{
		{"fresh, complete denominator: 9 of 100 is urgent", base, 1, notify.TierUrgent, notify.RateKnown, 9, 720},
		{"one stale batch makes the window's rate unknown whatever the order", append(slices.Clone(base[:6]), stale), -1, notify.TierQueue, notify.RateStale, 10, 5040},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			var want, wantOpen string
			perm := make([]int, len(sc.batches))
			for i := range perm {
				perm[i] = i
			}
			count := 0
			var visit func(k int)
			visit = func(k int) {
				if k == len(perm) {
					count++
					h := newHarness(t, issueE)
					h.dest(rcptA, "", t0)
					opens := 0
					var openKey string
					for _, i := range perm {
						in := h.issue(issueE, sc.batches[i].at, sc.batches[i].ids, sc.batches[i].mod)
						for _, o := range of(in, notify.KindOpen) {
							opens++
							openKey = fmt.Sprintf("%s/%d/%d", o.Key.Entity.ID, o.Key.ImpactRevision, o.Key.Ordinal)
						}
					}
					wj, _ := json.Marshal(h.s.Windows)
					ej, _ := json.Marshal(h.s.Explanation)
					got := fmt.Sprintf("%s|%s|%s", wj, h.s.Tier, ej)
					if sc.opens >= 0 {
						got += fmt.Sprintf("|%d|%d", h.s.ImpactRevision, h.s.Episode)
						if opens != sc.opens {
							t.Fatalf("order %v opened %d times, want %d", perm, opens, sc.opens)
						}
					} else if opens > 1 {
						t.Fatalf("order %v opened %d times", perm, opens)
					}
					if want == "" {
						want, wantOpen = got, openKey
					}
					if got != want || (sc.opens >= 0 && openKey != wantOpen) {
						t.Fatalf("order %v diverged:\n%s\n%s", perm, got, want)
					}
					return
				}
				for i := k; i < len(perm); i++ {
					perm[k], perm[i] = perm[i], perm[k]
					visit(k + 1)
					perm[k], perm[i] = perm[i], perm[k]
				}
			}
			visit(0)
			if count != sc.perms {
				t.Fatalf("ran %d permutations", count)
			}
			h := newHarness(t, issueE)
			for _, b := range sc.batches {
				h.issue(issueE, b.at, b.ids, b.mod)
			}
			if h.s.Explanation.Failures != sc.failures || h.s.Tier != sc.tier || h.s.Explanation.Rate != sc.rate {
				t.Fatalf("failures=%d tier=%s rate=%s", h.s.Explanation.Failures, h.s.Tier, h.s.Explanation.Rate)
			}
			// The merged regression keeps the largest count and the least certain
			// ancestry, whatever order it arrived in.
			if g := h.s.Windows[0].Regression; g == nil || g.Occurrences != 3 || g.AncestryKnown {
				t.Fatalf("merged regression %+v", g)
			}
		})
	}
}

func TestPolicyLatenessBoundary(t *testing.T) {
	// A live window is processed until LateAfter after it closed.
	end := t0 + notify.ErrorWindow // the window starting at t0 closes here
	cases := []struct {
		name string
		at   model.UnixNano
		late bool
	}{
		{"while the window is open", t0 + min1, false},
		{"exactly at the lateness limit", end + notify.LateAfter, false},
		{"one nanosecond past the limit", end + notify.LateAfter + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, issueE)
			h.dest(rcptA, "", t0)
			in := h.issue(issueE, c.at, occ(1, 1), func(e *notify.IssueEvidence) {
				e.WindowStart = t0
				e.Code = "payment_failed"
			})
			if c.late != (h.s.Late == 1) || c.late != (len(of(in, notify.KindOpen)) == 0) {
				t.Fatalf("late=%d intents=%v", h.s.Late, kinds(in))
			}
		})
	}
	// A window may start at most one window ahead of the decision time.
	h := newHarness(t, issueE)
	ahead := t0 + notify.ErrorWindow
	ev := h.ev(notify.EventIssue)
	ev.Entity = &issueE
	ev.Issue = &notify.IssueEvidence{WindowStart: ahead, Occurrences: occ(1, 1), Freshness: notify.FreshnessFresh}
	if _, err := h.try(ev, t0); err != nil {
		t.Fatalf("a window starting exactly one window ahead is allowed: %v", err)
	}
	ev.Issue = &notify.IssueEvidence{WindowStart: ahead + notify.ErrorWindow, Occurrences: occ(1, 1), Freshness: notify.FreshnessFresh}
	if _, err := h.try(ev, t0); err == nil {
		t.Fatal("a window starting beyond one window ahead is a future window")
	}
}

func TestPolicyConflictingDenominatorsAreRateUnknown(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	h.issue(issueE, t0+min1, occ(10, 1), withDenominator(100, true))
	if h.s.Explanation.Rate != notify.RateKnown {
		t.Fatal("setup")
	}
	h.issue(issueE, t0+2*min1, nil, withDenominator(200, true))
	if h.s.Explanation.Rate != notify.RateConflict || h.s.Explanation.RateBasisPoints != 0 {
		t.Fatalf("two different complete denominators for one window cannot give a rate: %+v", h.s.Explanation)
	}
	// Counts still work: the earlier decision stands and nothing is hidden.
	if h.s.Explanation.Failures != 10 {
		t.Fatalf("failures=%d", h.s.Explanation.Failures)
	}
}

func TestPolicyIdempotentReplay(t *testing.T) {
	// Every event kind applied twice gives the same state and no second batch
	// of intents.
	h := newHarness(t, condE)
	h.dest(rcptA, "Asia/Kolkata", t0)
	steps := []struct {
		name string
		ev   func() notify.PolicyEvent
		at   model.UnixNano
	}{
		{"condition fires", func() notify.PolicyEvent {
			ev := h.ev(notify.EventCondition)
			ev.Entity = &condE
			ev.Cursor = &model.Cursor{Group: model.ID{0x9a}, Index: 5}
			ev.Condition = &notify.ConditionEvidence{Seq: 1, State: notify.SourceFiring, Freshness: notify.FreshnessFresh, Severity: notify.SeverityMajor, Episode: epOne, Service: &notify.ServiceRef{ID: svcA, Critical: true}}
			return ev
		}, t0 + min1},
		{"ack", func() notify.PolicyEvent {
			ev := h.ev(notify.EventAction)
			ev.Entity = &condE
			ev.Action = &notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 2, ImpactRevision: 2}
			return ev
		}, t0 + 2*min1},
		{"snooze", func() notify.PolicyEvent {
			ev := h.ev(notify.EventAction)
			ev.Entity = &condE
			ev.Action = &notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 3, Reason: "known", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: t0 + hour}
			return ev
		}, t0 + 3*min1},
		{"maintenance", func() notify.PolicyEvent {
			ev := h.ev(notify.EventAction)
			ev.Entity = &condE
			ev.Action = &notify.HumanAction{Type: notify.ActionMaintenance, Actor: alice, Version: 4, Reason: "upgrade", Scope: notify.Scope{Kind: notify.ScopeProject}, Until: t0 + 2*hour}
			return ev
		}, t0 + 4*min1},
		{"worse condition", func() notify.PolicyEvent {
			ev := h.ev(notify.EventCondition)
			ev.Entity = &condE
			ev.Condition = &notify.ConditionEvidence{Seq: 2, State: notify.SourceFiring, Freshness: notify.FreshnessFresh, Severity: notify.SeverityCritical, Episode: epOne}
			return ev
		}, t0 + 5*min1},
		{"timer at snooze end", func() notify.PolicyEvent { ev := h.ev(notify.EventTimer); ev.Timer = &notify.Timer{}; return ev }, t0 + hour},
		{"timer at maintenance end", func() notify.PolicyEvent { ev := h.ev(notify.EventTimer); ev.Timer = &notify.Timer{}; return ev }, t0 + 2*hour},
		{"timer reminder", func() notify.PolicyEvent { ev := h.ev(notify.EventTimer); ev.Timer = &notify.Timer{}; return ev }, t0 + 4*hour},
		{"resolve", func() notify.PolicyEvent {
			ev := h.ev(notify.EventAction)
			ev.Entity = &condE
			ev.Action = &notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 6, Reason: "done"}
			return ev
		}, t0 + 5*hour},
		{"destination", func() notify.PolicyEvent {
			ev := h.ev(notify.EventDestination)
			ev.Destination = &notify.DestinationChange{Recipient: rcptB, Enabled: true, Zone: "Europe/Berlin"}
			return ev
		}, t0 + 6*hour},
		{"cutover", func() notify.PolicyEvent {
			ev := h.ev(notify.EventCutover)
			ev.Entity = &condE
			ev.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 9}, To: incE, Mode: notify.ModeShadow}
			return ev
		}, t0 + 7*hour},
	}
	for _, s := range steps {
		ev := s.ev()
		first := h.do(ev, s.at)
		snap := stateJSON(t, h.s)
		next, again, err := notify.Decide(h.s, ev, s.at)
		if err != nil {
			// A replay that the first application made stale (owner revision)
			// is a typed refusal, never a second effect.
			if r, _ := notify.ReasonOf(err); r != notify.ReasonOwnerRevision {
				t.Fatalf("%s: replay: %v", s.name, err)
			}
			continue
		}
		if len(again) != 0 || stateJSON(t, next) != snap {
			t.Fatalf("%s: replay produced %v (first %v) or changed state\n%s\n%s", s.name, kinds(again), kinds(first), snap, stateJSON(t, next))
		}
	}
}

func TestPolicyIntentIdentityIsStable(t *testing.T) {
	base := notify.IntentKey{Org: org, Policy: pol, Entity: incE, ImpactRevision: 3, Kind: notify.KindWorseImpact, Recipient: &rcptA, Ordinal: 2}
	id := notify.KeyID(base)
	if id == (model.ID{}) || id != notify.KeyID(base) {
		t.Fatal("key identity must be stable and nonzero")
	}
	other := rcptB
	mut := map[string]func(k *notify.IntentKey){
		"org":            func(k *notify.IntentKey) { k.Org = model.ID{0x44} },
		"policy":         func(k *notify.IntentKey) { k.Policy = model.ID{0x44} },
		"entity":         func(k *notify.IntentKey) { k.Entity.ID = model.ID{0x44} },
		"kind of entity": func(k *notify.IntentKey) { k.Entity.Kind = notify.EntityIssue },
		"impact":         func(k *notify.IntentKey) { k.ImpactRevision++ },
		"kind":           func(k *notify.IntentKey) { k.Kind = notify.KindReminder },
		"recipient":      func(k *notify.IntentKey) { k.Recipient = &other },
		"no recipient":   func(k *notify.IntentKey) { k.Recipient = nil },
		"ordinal":        func(k *notify.IntentKey) { k.Ordinal++ },
	}
	seen := map[model.ID]string{id: "base"}
	for name, f := range mut {
		k := base
		f(&k)
		got := notify.KeyID(k)
		if prev, dup := seen[got]; dup {
			t.Fatalf("%s collides with %s", name, prev)
		}
		seen[got] = name
	}
	// Intents emitted by the reducer carry the identity of their own key.
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	in := h.issue(issueE, t0+min1, occ(1, 1), func(e *notify.IssueEvidence) { e.Code = "payment_failed" })
	if len(in) < 2 {
		t.Fatal("setup")
	}
	for _, i := range in {
		if i.ID != notify.KeyID(i.Key) || i.Key.Org != org || i.Key.Policy != pol || i.Key.Entity != issueE {
			t.Fatalf("intent identity %+v", i)
		}
	}
	// Two replicas with the same inputs produce byte-identical intents.
	a, b := newHarness(t, issueE), newHarness(t, issueE)
	a.dest(rcptA, "", t0)
	b.dest(rcptA, "", t0)
	x := a.issue(issueE, t0+min1, occ(7, 1), withDenominator(100, true))
	y := b.issue(issueE, t0+min1, occ(7, 1), withDenominator(100, true))
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	if !bytes.Equal(xb, yb) || len(x) == 0 {
		t.Fatalf("not deterministic:\n%s\n%s", xb, yb)
	}
}

func TestPolicyIntentsCarryOnlyTypedFields(t *testing.T) {
	const secret = "SECRET-TOKEN-do-not-leak"
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	all := h.do(ev, t0)
	all = append(all, h.mustAction(incE, notify.HumanAction{Type: notify.ActionMaintenance, Actor: alice, Version: 2, Reason: secret, Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: t0 + hour}, t0+min1)...)
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 2, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	all = append(all, h.do(ev, t0+2*min1)...)
	all = append(all, h.timer(t0+hour)...)
	b, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 4 || strings.Contains(string(b), secret) {
		t.Fatalf("intents must carry no human or telemetry text (n=%d)", len(all))
	}
	// And the template type itself has no free-text field.
	var check func(rt reflect.Type, path string)
	check = func(rt reflect.Type, path string) {
		switch rt.Kind() {
		case reflect.Pointer, reflect.Slice:
			check(rt.Elem(), path)
		case reflect.Struct:
			if rt == reflect.TypeOf(model.ID{}) {
				return
			}
			for i := range rt.NumField() {
				check(rt.Field(i).Type, path+"."+rt.Field(i).Name)
			}
		case reflect.String:
			if rt == reflect.TypeOf("") {
				t.Fatalf("Template has a raw string field at %s", path)
			}
		}
	}
	check(reflect.TypeOf(notify.Template{}), "Template")
}

func TestPolicyStateIsBounded(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	// Thousands of distinct failures across many events and windows.
	for w := range 10 {
		for b := range 8 {
			ids := make([]model.ID, 500)
			for i := range ids {
				ids[i] = model.ID{0x70, byte(w), byte(b), byte(i >> 8), byte(i)}
			}
			h.issue(issueE, t0+model.UnixNano(w)*notify.ErrorWindow+min1, ids, withDenominator(1_000_000, true))
		}
	}
	if len(h.s.Windows) != notify.MaxWindows {
		t.Fatalf("windows=%d", len(h.s.Windows))
	}
	for _, w := range h.s.Windows {
		if len(w.Occurrences) != notify.MaxWindowOccurrences || !w.Saturated {
			t.Fatalf("window %d holds %d saturated=%v", w.Start, len(w.Occurrences), w.Saturated)
		}
		if !slices.IsSortedFunc(w.Occurrences, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) }) {
			t.Fatal("window occurrences must stay sorted")
		}
	}
	if !h.s.Explanation.Saturated || h.s.Explanation.Failures != notify.MaxWindowOccurrences {
		t.Fatalf("a saturated count is flagged as a lower bound: %+v", h.s.Explanation)
	}
	// Saturation keeps the smallest IDs whatever the order: a smaller ID that
	// arrives later displaces a larger one, a larger one is ignored.
	a, b := newHarness(t, issueE), newHarness(t, issueE)
	small := occ(MaxIDs(), 1)
	large := occ(MaxIDs(), 200)
	feed := func(h *harness, ids []model.ID) {
		for len(ids) > 0 {
			n := min(len(ids), notify.MaxEventOccurrences)
			h.issue(issueE, t0+min1, ids[:n], nil)
			ids = ids[n:]
		}
	}
	feed(a, small)
	feed(a, large)
	feed(b, large)
	feed(b, small)
	aj, _ := json.Marshal(a.s.Windows)
	bj, _ := json.Marshal(b.s.Windows)
	if string(aj) != string(bj) {
		t.Fatal("saturation depends on arrival order")
	}
	if !slices.Equal(a.s.Windows[0].Occurrences, small) || !a.s.Windows[0].Saturated {
		t.Fatal("the smallest identifiers must be the ones kept")
	}
	// The sent ledger, recipients and cursors are bounded and refuse overflow.
	h2 := newHarness(t, incE)
	for i := range notify.MaxRecipients {
		h2.dest(model.ID{0xa0, byte(i + 1)}, "", t0)
	}
	ev := h2.ev(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: model.ID{0xa9, 9}, Enabled: true}
	before := stateJSON(t, h2.s)
	if _, err := h2.try(ev, t0); !errors.Is(err, &notify.Error{Reason: notify.ReasonQuota}) || stateJSON(t, h2.s) != before {
		t.Fatalf("recipient overflow: %v", err)
	}
	for i := range 200 {
		ev := h2.ev(notify.EventIncident)
		ev.Entity = &incE
		sev := notify.SeverityMajor
		if i%2 == 0 {
			sev = notify.SeverityCritical
		}
		ev.Incident = &notify.IncidentEvidence{Version: model.Revision(i + 1), Status: notify.HumanOpen, Severity: sev, ImpactRevision: uint64(i/2 + 1), Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
		h2.do(ev, t0+model.UnixNano(i)*min1)
		if len(h2.s.Sent) > notify.MaxSentMarks {
			t.Fatalf("ledger grew to %d", len(h2.s.Sent))
		}
	}
	for i := range notify.MaxCursors + 1 {
		ev := h2.ev(notify.EventTimer)
		ev.Timer = &notify.Timer{}
		ev.Cursor = &model.Cursor{Group: model.ID{0xcd, byte(i + 1)}, Index: 1}
		_, err := h2.try(ev, t0+hour)
		if (i == notify.MaxCursors) != (err != nil) {
			t.Fatalf("cursor %d: %v", i, err)
		}
	}
	// A tampered, oversized state is refused instead of processed.
	big := h.s
	big.Windows = append(slices.Clone(big.Windows), big.Windows...)
	tm := h.ev(notify.EventTimer)
	tm.Timer = &notify.Timer{}
	if _, _, err := notify.Decide(big, tm, t0); !errors.Is(err, &notify.Error{Reason: notify.ReasonInvalidState}) {
		t.Fatalf("oversized state: %v", err)
	}
}

func MaxIDs() int { return notify.MaxWindowOccurrences }

func TestPolicyTimeArithmeticCannotOverflow(t *testing.T) {
	near := model.UnixNano(math.MaxInt64) - 5*min1
	h := newHarness(t, incE)
	// Destination at the end of time: the next digest does not fit.
	ev := h.ev(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: rcptA, Enabled: true}
	if _, err := h.try(ev, near); !errors.Is(err, &notify.Error{Reason: notify.ReasonTimeRange}) {
		t.Fatalf("digest past the end of time: %v", err)
	}
	// Opening near the end of time: the first reminder time does not fit.
	open := h.ev(notify.EventIncident)
	open.Entity = &incE
	open.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	before := stateJSON(t, h.s)
	if _, in, err := notify.Decide(h.s, open, near+4*min1+59*model.UnixNano(time.Second)); !errors.Is(err, &notify.Error{Reason: notify.ReasonTimeRange}) || in != nil {
		t.Fatalf("reminder schedule overflow: %v", err)
	}
	if stateJSON(t, h.s) != before {
		t.Fatal("state changed")
	}
	// A snooze whose window arithmetic would overflow is refused, not wrapped.
	h2 := newHarness(t, incE)
	h2.do(func() notify.PolicyEvent {
		e := h2.ev(notify.EventIncident)
		e.Entity = &incE
		e.Incident = open.Incident
		return e
	}(), t0)
	a := notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 2, Reason: "r", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: math.MaxInt64}
	if _, err := h2.action(incE, a, t0+min1); err == nil {
		t.Fatal("a snooze to the end of time exceeds the maximum window")
	}
	// Non-positive decision times and absurd windows are refused.
	for _, at := range []model.UnixNano{0, -1, math.MinInt64} {
		tm := h2.ev(notify.EventTimer)
		tm.Timer = &notify.Timer{}
		if _, err := h2.try(tm, at); err == nil {
			t.Fatalf("decision time %d accepted", at)
		}
	}
	i := newHarness(t, issueE)
	e2 := i.ev(notify.EventIssue)
	e2.Entity = &issueE
	e2.Issue = &notify.IssueEvidence{WindowStart: model.UnixNano(math.MaxInt64 - math.MaxInt64%int64(notify.ErrorWindow)), Freshness: notify.FreshnessFresh}
	if _, err := i.try(e2, near); err == nil {
		t.Fatal("a window that cannot close is refused")
	}
	// Reminder catch-up with the largest gap stays in range.
	h3 := newHarness(t, incE)
	h3.dest(rcptA, "", t0)
	h3.do(func() notify.PolicyEvent {
		e := h3.ev(notify.EventIncident)
		e.Entity = &incE
		e.Incident = open.Incident
		return e
	}(), t0)
	far := model.UnixNano(math.MaxInt64 - 1)
	tm := h3.ev(notify.EventTimer)
	tm.Timer = &notify.Timer{}
	next, _, err := notify.Decide(h3.s, tm, far)
	switch {
	case err != nil:
		if !errors.Is(err, &notify.Error{Reason: notify.ReasonTimeRange}) {
			t.Fatalf("unexpected error %v", err)
		}
	case next.Reminders.Next <= far:
		t.Fatalf("a wrapped reminder time %d", next.Reminders.Next)
	}
}

// TestPolicyDurableClockAndPromotion advances an injected clock through ACK,
// impact, snooze expiry and digest, persisting and reloading the state
// between steps like a restarted control apply. It drives the pure reducer:
// the real control service and outbox are later work (06.07), so this does
// not claim to be the end-to-end smoke.
func TestPolicyDurableClockAndPromotion(t *testing.T) {
	h := newHarness(t, issueE)
	h.cfg.DefaultZone = "Europe/Berlin"
	h.dest(rcptA, "", t0) // 12:00Z = 13:00 CET: next digest is 09:00 CET on the 11th
	step := func(name string, in []notify.Intent, want ...string) {
		t.Helper()
		sameStrings(t, kinds(in), want, name)
		h.restart()
	}
	// 1. An issue crosses the urgency threshold: opening + queue entry.
	in := h.issue(issueE, t0+min1, occ(5, 1), withDenominator(100, true))
	step("issue opens", in, "open", "queue")
	// 2. Promotion: the incident takes over; no second opening.
	cut := h.ev(notify.EventCutover)
	cut.Entity = &issueE
	cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 1}, To: incE}
	in = h.do(cut, t0+2*min1)
	step("promotion", in, "queue")
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	step("incident adopts the episode", h.do(ev, t0+3*min1))
	// 3. First reminder at the original opening + 15 minutes.
	step("reminder one", h.timer(t0+16*min1), "reminder")
	// 4. ACK pauses reminders.
	step("ack", h.mustAction(incE, notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 2, ImpactRevision: 1}, t0+20*min1))
	step("paused", h.timer(t0+2*hour))
	// 5. A worse impact notifies despite the ACK.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 3, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	step("worse impact", h.do(ev, t0+3*hour), "worse_impact", "queue")
	// 6. Snooze, then exact expiry: one current-state update.
	until := t0 + 5*hour
	step("snooze", h.mustAction(incE, notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 4, Reason: "waiting for vendor", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: until}, t0+3*hour+min1))
	step("quiet while snoozed", h.timer(t0+4*hour))
	step("expiry", h.timer(until), "current_state")
	step("expiry replay after restart", h.timer(until))
	// 7. Recovery of the source, then the daily digest for the queue.
	ev = h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 5, Status: notify.HumanOpen, Severity: notify.SeverityCritical, ImpactRevision: 2, Episode: epOne, Source: notify.SourceRecovered, Freshness: notify.FreshnessFresh}
	step("recovery", h.do(ev, until+min1), "recovery", "queue")
	digest := model.UnixNano(time.Date(2026, 3, 11, 8, 0, 0, 0, time.UTC).UnixNano()) // 09:00 CET
	step("no digest for a resolved-away urgent entity", h.timer(digest))
	// 8. Final counts: exactly one opening, one worse impact, one reminder.
	counts := map[notify.Kind]int{}
	for _, m := range h.s.Sent {
		counts[m.Kind]++
	}
	if counts[notify.KindOpen] != 1 || counts[notify.KindWorseImpact] != 1 || counts[notify.KindReminder] != 1 || counts[notify.KindCurrent] != 1 || counts[notify.KindRecovery] != 1 {
		t.Fatalf("exact kinds and counts: %v", counts)
	}
}

func TestPolicyNextDueDrivesTimers(t *testing.T) {
	h := newHarness(t, incE)
	if _, ok := h.s.NextDue(); ok {
		t.Fatal("an empty state has nothing due")
	}
	h.dest(rcptA, "", t0)
	due, ok := h.s.NextDue()
	if !ok || due != model.UnixNano(time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC).UnixNano()) {
		t.Fatalf("digest due %v", due)
	}
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	h.do(ev, t0)
	if due, _ := h.s.NextDue(); due != t0+15*min1 {
		t.Fatalf("reminder due %d", (due-t0)/min1)
	}
	h.mustAction(incE, notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 2, Reason: "r", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: t0 + 10*min1}, t0+min1)
	if due, _ := h.s.NextDue(); due != t0+10*min1 {
		t.Fatalf("snooze expiry due %d", (due-t0)/min1)
	}
}

// promoted returns a harness whose issue opened and then handed ownership to
// an incident that adopted the episode.
func promoted(t *testing.T) *harness {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	h.issue(issueE, t0+min1, occ(5, 1), withDenominator(100, true))
	cut := h.ev(notify.EventCutover)
	cut.Entity = &issueE
	cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 1}, To: incE}
	h.do(cut, t0+2*min1)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceFiring, Freshness: notify.FreshnessFresh}
	if in := h.do(ev, t0+3*min1); len(of(in, notify.KindOpen)) != 0 {
		t.Fatalf("setup: %v", kinds(in))
	}
	return h
}

func TestPolicyNonOwnerActionsDoNotChangeTheOwner(t *testing.T) {
	h := promoted(t)
	// A human resolving or acknowledging the old issue is not an incident
	// resolution or ACK: the owner keeps reminding.
	if in := h.mustAction(issueE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 1, Reason: "issue fixed"}, t0+4*min1); len(in) != 0 || h.s.Human != notify.HumanOpen {
		t.Fatalf("issue resolution leaked into the incident: %v human=%s", kinds(in), h.s.Human)
	}
	h.mustAction(issueE, notify.HumanAction{Type: notify.ActionAck, Actor: alice, Version: 2, ImpactRevision: 1}, t0+5*min1)
	if h.s.Ack != nil {
		t.Fatal("an ACK of the old issue must not pause the incident")
	}
	h.mustAction(issueE, notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 3, Reason: "issue snoozed", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: t0 + hour}, t0+6*min1)
	if h.s.Snooze != nil {
		t.Fatal("an entity-scoped snooze of the old issue must not snooze the incident")
	}
	if in := h.timer(t0 + 16*min1); len(of(in, notify.KindReminder)) != 1 {
		t.Fatalf("the incident must keep reminding: %v", kinds(in))
	}
	// An entity-scoped window of the owner cannot be ended by the issue.
	h.mustAction(incE, notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: 4, Reason: "incident snoozed", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: t0 + hour}, t0+17*min1)
	h.mustAction(issueE, notify.HumanAction{Type: notify.ActionUnsnooze, Actor: alice, Version: 9, Reason: "x"}, t0+18*min1)
	if h.s.Snooze == nil {
		t.Fatal("a non-owner cannot end the owner's snooze")
	}
	// Project scope reaches every linked entity.
	pm := notify.HumanAction{Type: notify.ActionMaintenance, Actor: alice, Version: 5, Reason: "db upgrade", Scope: notify.Scope{Kind: notify.ScopeProject}, Until: t0 + hour}
	h.mustAction(issueE, pm, t0+19*min1)
	if h.s.Maintenance == nil {
		t.Fatal("a project-scoped window applies whichever linked entity carried it")
	}
	// Evidence kind must match the entity kind.
	ev := h.ev(notify.EventIssue)
	ev.Entity = &incE
	ev.Issue = &notify.IssueEvidence{WindowStart: t0, Occurrences: occ(1, 7), Freshness: notify.FreshnessFresh}
	if _, err := h.try(ev, t0+20*min1); !errors.Is(err, &notify.Error{Reason: notify.ReasonInvalidEvent}) {
		t.Fatalf("issue evidence from an incident entity: %v", err)
	}
}

func TestPolicyOutOfOrderSnapshotsNeverRegress(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	snap := func(v model.Revision, sev notify.Severity, impact uint64, src notify.SourceState, at model.UnixNano) []notify.Intent {
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: v, Status: notify.HumanOpen, Severity: sev, ImpactRevision: impact, Episode: epOne, Source: src, Freshness: notify.FreshnessFresh}
		return h.do(ev, at)
	}
	snap(1, notify.SeverityMajor, 1, notify.SourceFiring, t0)
	snap(3, notify.SeverityCritical, 2, notify.SourceFiring, t0+min1)
	// Version 2 arrives late: it can neither lower the severity nor repeat an
	// impact notice, and it cannot manufacture a recovery.
	for _, v := range []struct {
		sev notify.Severity
		src notify.SourceState
	}{{notify.SeverityMinor, notify.SourceFiring}, {notify.SeverityMajor, notify.SourceRecovered}} {
		if in := snap(2, v.sev, 1, v.src, t0+2*min1); len(in) != 0 {
			t.Fatalf("late snapshot produced %v", kinds(in))
		}
	}
	if h.s.Severity != notify.SeverityCritical || h.s.Source != notify.SourceFiring || h.s.Late != 2 || h.s.IncidentVersion != 3 {
		t.Fatalf("late snapshot changed state: sev=%d source=%s late=%d version=%d", h.s.Severity, h.s.Source, h.s.Late, h.s.IncidentVersion)
	}
}

func TestPolicyIncidentOpenedWithRecoveredSourceStillOpens(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	ev := h.ev(notify.EventIncident)
	ev.Entity = &incE
	ev.Incident = &notify.IncidentEvidence{Version: 1, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: notify.SourceRecovered, Freshness: notify.FreshnessFresh}
	in := h.do(ev, t0)
	if len(of(in, notify.KindOpen)) != 1 || len(of(in, notify.KindRecovery)) != 0 {
		t.Fatalf("a human incident is a human response even if the source already recovered: %v", kinds(in))
	}
	if in := h.timer(t0 + 16*min1); len(in) != 0 {
		t.Fatalf("a recovered source has nothing to remind: %v", kinds(in))
	}
}

func TestPolicyDoesNotRetainEventMemory(t *testing.T) {
	h := newHarness(t, issueE)
	h.dest(rcptA, "", t0)
	svc := svcA
	cfg := h.cfg
	ev := h.ev(notify.EventIssue)
	ev.PolicyRef.Config = &cfg
	ev.Entity = &issueE
	ev.Cursor = &model.Cursor{Group: model.ID{0x9a}, Index: 5}
	ev.Issue = &notify.IssueEvidence{
		WindowStart: t0, Occurrences: occ(3, 1), Freshness: notify.FreshnessFresh,
		Denominator: &notify.Denominator{Name: "http_requests_total", WindowStart: t0, Operations: 50, Complete: true},
		Regression:  &notify.Regression{Eligible: true, Occurrences: 3, AncestryKnown: true},
		Service:     &notify.ServiceRef{ID: svc, Critical: true},
	}
	h.do(ev, t0+min1)
	snap := stateJSON(t, h.s)
	// Scribbling over the caller's event afterwards must not reach the state.
	ev.Issue.Denominator.Operations = 1
	ev.Issue.Regression.Occurrences = 99
	ev.Issue.Service.ID = model.ID{0xee}
	ev.Issue.Occurrences[0] = model.ID{0xff}
	ev.Cursor.Index = 1 << 40
	cfg.CriticalCodes = append(cfg.CriticalCodes, "zzz")
	cfg.MinFailures = 1
	if stateJSON(t, h.s) != snap {
		t.Fatal("the state aliases memory of the event it was built from")
	}
	// And mutating a returned intent does not reach the state either.
	h2 := newHarness(t, issueE)
	h2.dest(rcptA, "", t0)
	in := h2.issue(issueE, t0+min1, occ(5, 1), func(e *notify.IssueEvidence) {
		withDenominator(100, true)(e)
		e.Regression = &notify.Regression{Eligible: true, Occurrences: 5, AncestryKnown: true}
		e.Service = &notify.ServiceRef{ID: svcA}
	})
	snap = stateJSON(t, h2.s)
	for i := range in {
		if in[i].Template.Explanation.Regression != nil {
			in[i].Template.Explanation.Regression.Occurrences = 77
		}
		if in[i].Template.Service != nil {
			in[i].Template.Service.ID = model.ID{0xee}
		}
	}
	if stateJSON(t, h2.s) != snap {
		t.Fatal("an intent aliases the state")
	}
}

func TestPolicyCursorsAreHighWaterMarks(t *testing.T) {
	h := newHarness(t, issueE)
	g1, g2 := model.ID{0x91}, model.ID{0x92}
	feed := func(group model.ID, idx uint64, at model.UnixNano) {
		ev := h.ev(notify.EventTimer)
		ev.Timer = &notify.Timer{}
		ev.Cursor = &model.Cursor{Group: group, Index: model.Uint64(idx)}
		h.do(ev, at)
	}
	feed(g2, 7, t0)
	feed(g1, 5, t0+min1)
	feed(g1, 3, t0+2*min1) // a lower cursor never moves the mark back
	feed(g1, 9, t0+3*min1)
	want := []model.Cursor{{Group: g1, Index: 9}, {Group: g2, Index: 7}}
	if !reflect.DeepEqual(h.s.Cursors, want) {
		t.Fatalf("cursors %+v want %+v", h.s.Cursors, want)
	}
}

func TestPolicyDestinationAndPolicyZoneChangesReschedule(t *testing.T) {
	day := func(d, hh int) model.UnixNano {
		return model.UnixNano(time.Date(2026, 3, d, hh, 0, 0, 0, time.UTC).UnixNano())
	}
	h := newHarness(t, issueE)
	h.dest(rcptA, "", day(10, 1))
	h.dest(rcptB, "Asia/Kolkata", day(10, 1))
	// Re-sending the same destination changes nothing.
	snap := stateJSON(t, h.s)
	h.dest(rcptA, "", day(10, 2))
	if stateJSON(t, h.s) != snap {
		t.Fatal("an unchanged destination must not reschedule its digest")
	}
	// A zone change moves the next digest and keeps what the recipient has seen.
	h.s.Recipients[0].DigestSeen = 4
	h.dest(rcptA, "Asia/Tokyo", day(10, 2))
	if got := h.s.Recipients[0]; got.DigestNext != day(11, 0) || got.DigestSeen != 4 {
		t.Fatalf("zone change: %+v", got)
	}
	// Disabling clears the schedule; re-enabling computes a new one.
	ev := h.ev(notify.EventDestination)
	ev.Destination = &notify.DestinationChange{Recipient: rcptA, Enabled: false, Zone: "Asia/Tokyo"}
	h.do(ev, day(10, 3))
	if h.s.Recipients[0].DigestNext != 0 {
		t.Fatal("a disabled recipient has no digest schedule")
	}
	h.dest(rcptA, "Asia/Tokyo", day(10, 4))
	if h.s.Recipients[0].DigestNext != day(11, 0) {
		t.Fatalf("re-enabled: %v", h.s.Recipients[0].DigestNext)
	}
	// A new policy revision with another default zone moves the recipients that
	// use the default and leaves the others alone.
	h.dest(model.ID{0xa3}, "", day(10, 4))
	before := h.s.Recipients[1].DigestNext // rcptB (Kolkata), explicit zone
	h.rev = 2
	h.cfg.DefaultZone = "Asia/Tokyo"
	h.dest(rcptA, "Asia/Tokyo", day(10, 5))
	for _, r := range h.s.Recipients {
		switch r.ID {
		case rcptB:
			if r.DigestNext != before {
				t.Fatalf("an explicit zone must not follow the default: %v", r.DigestNext)
			}
		case model.ID{0xa3}:
			if r.DigestNext != day(11, 0) {
				t.Fatalf("default-zone recipient must follow the new default: %v", r.DigestNext)
			}
		}
	}
}

func TestPolicyLinkedEntitiesAreBounded(t *testing.T) {
	h := newHarness(t, issueE)
	for i := 1; i < notify.MaxLinked; i++ {
		cut := h.ev(notify.EventCutover)
		owner := h.s.Owner
		cut.Entity = &owner
		cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, byte(i)}, To: notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x60, byte(i)}}}
		h.do(cut, t0+model.UnixNano(i)*min1)
	}
	cut := h.ev(notify.EventCutover)
	owner := h.s.Owner
	cut.Entity = &owner
	cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 0xff}, To: notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x60, 0xff}}}
	before := stateJSON(t, h.s)
	if _, err := h.try(cut, t0+hour); !errors.Is(err, &notify.Error{Reason: notify.ReasonQuota}) || stateJSON(t, h.s) != before {
		t.Fatalf("a ninth linked entity: %v", err)
	}
	// Handing back to an already linked entity needs no new slot.
	cut.Cutover = &notify.OwnerCutover{Command: model.ID{0xcc, 0xfe}, To: issueE}
	h.do(cut, t0+hour)
	if h.s.Owner != issueE {
		t.Fatal("rollback to a linked entity")
	}
}

func TestPolicyWorseImpactWhileSourceRecoveredStillNotifies(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	snap := func(v model.Revision, sev notify.Severity, impact uint64, src notify.SourceState, at model.UnixNano) []notify.Intent {
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: v, Status: notify.HumanOpen, Severity: sev, ImpactRevision: impact, Episode: epOne, Source: src, Freshness: notify.FreshnessFresh}
		return h.do(ev, at)
	}
	snap(1, notify.SeverityMajor, 1, notify.SourceFiring, t0)
	if in := snap(2, notify.SeverityMajor, 1, notify.SourceRecovered, t0+min1); len(of(in, notify.KindRecovery)) != 1 {
		t.Fatalf("recovery: %v", kinds(in))
	}
	// The human incident is still open; a worse impact reported while the source
	// is recovered is still a material impact change.
	w := of(snap(3, notify.SeverityCritical, 2, notify.SourceRecovered, t0+2*min1), notify.KindWorseImpact)
	if len(w) != 1 || w[0].Key.ImpactRevision != 2 || w[0].Template.Source != notify.SourceRecovered {
		t.Fatalf("worse impact while recovered: %+v", w)
	}
	if in := h.timer(t0 + hour); len(in) != 0 {
		t.Fatalf("a recovered source never reminds: %v", kinds(in))
	}
}

func TestPolicyDigestExcludesAnAlreadyOpenedEpisode(t *testing.T) {
	day := func(hh, mm int) model.UnixNano {
		return model.UnixNano(time.Date(2026, 3, 10, hh, mm, 0, 0, time.UTC).UnixNano())
	}
	h := newHarness(t, issueE)
	h.dest(rcptA, "", day(8, 0))
	h.issue(issueE, day(8, 1), occ(5, 1), withDenominator(100, true))
	// Three quiet windows later the urgent one is no longer retained: the
	// current tier is queue, but the episode was opened and announced.
	for i, at := range []model.UnixNano{day(8, 6), day(8, 11), day(8, 16)} {
		h.issue(issueE, at, occ(1, byte(10+i)), nil)
	}
	if h.s.Tier != notify.TierQueue || !h.s.EpisodeOpen {
		t.Fatalf("setup: tier=%s open=%v", h.s.Tier, h.s.EpisodeOpen)
	}
	if in := h.timer(day(9, 0)); len(of(in, notify.KindDigest)) != 0 {
		t.Fatalf("an announced episode is not a digest item: %v", kinds(in))
	}
}

func TestPolicyRepeatedExpiriesEachGetTheirOwnUpdate(t *testing.T) {
	h := newHarness(t, incE)
	h.dest(rcptA, "", t0)
	snap := func(v model.Revision, src notify.SourceState, at model.UnixNano) []notify.Intent {
		ev := h.ev(notify.EventIncident)
		ev.Entity = &incE
		ev.Incident = &notify.IncidentEvidence{Version: v, Status: notify.HumanOpen, Severity: notify.SeverityMajor, ImpactRevision: 1, Episode: epOne, Source: src, Freshness: notify.FreshnessFresh}
		return h.do(ev, at)
	}
	snooze := func(v model.Revision, until model.UnixNano, at model.UnixNano) {
		h.mustAction(incE, notify.HumanAction{Type: notify.ActionSnooze, Actor: alice, Version: v, Reason: "quiet", Scope: notify.Scope{Kind: notify.ScopeEntity}, Until: until}, at)
	}
	snap(1, notify.SourceFiring, t0)
	snooze(2, t0+hour, t0+min1)
	if in := snap(3, notify.SourceRecovered, t0+2*min1); len(of(in, notify.KindRecovery)) != 1 || of(in, notify.KindRecovery)[0].Eligible() {
		t.Fatalf("recovery during a snooze: %v", kinds(in))
	}
	first := of(h.timer(t0+hour), notify.KindCurrent)
	if len(first) != 1 || !first[0].Eligible() {
		t.Fatalf("first expiry: %+v", first)
	}
	// Same impact revision, a second suppression and a second held-back change.
	snooze(4, t0+3*hour, t0+hour+min1)
	if in := snap(5, notify.SourceFiring, t0+hour+2*min1); len(of(in, notify.KindCurrent)) != 0 {
		t.Fatalf("a snoozed re-fire must not send: %v", kinds(in))
	}
	h.mustAction(incE, notify.HumanAction{Type: notify.ActionResolve, Actor: alice, Version: 6, Reason: "done"}, t0+hour+3*min1)
	second := of(h.timer(t0+3*hour), notify.KindCurrent)
	if len(second) != 1 || !second[0].Eligible() || second[0].ID == first[0].ID || second[0].Template.Human != notify.HumanResolved {
		t.Fatalf("second expiry must produce its own update: %+v", second)
	}
}
