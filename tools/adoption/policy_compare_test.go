// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/notify"
)

const (
	policyT0  = model.UnixNano(1773144000 * int64(time.Second))
	policyMin = model.UnixNano(time.Minute)
)

var (
	policyOrg, policyProject, policyID = model.ID{0x01}, model.ID{0x02}, model.ID{0x03}
	policyInc                          = notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
	policyIss                          = notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x51}}
	policyRcptA, policyRcptB           = model.ID{0xa1}, model.ID{0xa2}
	policyActor                        = model.ID{0xb1}
)

type policyFixture struct {
	t   *testing.T
	cfg notify.Config
	n   int
}

func newPolicyFixture(t *testing.T) *policyFixture {
	cfg := notify.DefaultConfig()
	cfg.CriticalCodes = []string{"payment_failed"}
	return &policyFixture{t: t, cfg: cfg}
}

func (f *policyFixture) event(kind notify.EventKind) notify.PolicyEvent {
	f.n++
	c := f.cfg
	return notify.PolicyEvent{Kind: kind, Command: model.ID{0xc0, byte(f.n >> 8), byte(f.n)}, Org: policyOrg, Project: policyProject, Policy: policyID,
		PolicyRef: notify.PolicyRef{Revision: 1, Config: &c}, OwnerRevision: 1}
}

func (f *policyFixture) dest(r model.ID, at model.UnixNano) PolicyStep {
	e := f.event(notify.EventDestination)
	e.Destination = &notify.DestinationChange{Recipient: r, Enabled: true}
	return PolicyStep{Event: e, At: at}
}

func (f *policyFixture) incident(at model.UnixNano, version model.Revision, sev notify.Severity, impact uint64, src notify.SourceState) PolicyStep {
	e := f.event(notify.EventIncident)
	ent := policyInc
	e.Entity = &ent
	e.Mode = notify.ModeLive
	e.Incident = &notify.IncidentEvidence{Version: version, Status: notify.HumanOpen, Severity: sev, ImpactRevision: impact, Episode: model.ID{0xe1}, Source: src, Freshness: notify.FreshnessFresh}
	return PolicyStep{Event: e, At: at}
}

func (f *policyFixture) issue(at model.UnixNano, salt byte, code string, ids int, mod func(*notify.IssueEvidence)) PolicyStep {
	e := f.event(notify.EventIssue)
	ent := policyIss
	e.Entity = &ent
	occ := make([]model.ID, ids)
	for i := range occ {
		occ[i] = model.ID{0x70, salt, byte(i)}
	}
	e.Issue = &notify.IssueEvidence{WindowStart: at - at%notify.ErrorWindow, Occurrences: occ, Code: code, Freshness: notify.FreshnessFresh}
	if mod != nil {
		mod(e.Issue)
	}
	return PolicyStep{Event: e, At: at}
}

func (f *policyFixture) timer(at model.UnixNano) PolicyStep {
	e := f.event(notify.EventTimer)
	e.Timer = &notify.Timer{}
	return PolicyStep{Event: e, At: at}
}

func (f *policyFixture) action(at model.UnixNano, a notify.HumanAction) PolicyStep {
	e := f.event(notify.EventAction)
	ent := policyInc
	e.Entity = &ent
	a.Actor = policyActor
	e.Action = &a
	return PolicyStep{Event: e, At: at}
}

// journey: open, two reminders, ACK, a skipped reminder, a worse impact, a source
// recovery and a separate human resolution.
func (f *policyFixture) journey() PolicyReplay {
	m := policyMin
	return PolicyReplay{Subject: policyInc, Steps: []PolicyStep{
		f.dest(policyRcptA, policyT0),
		f.incident(policyT0, 1, notify.SeverityMajor, 1, notify.SourceFiring),
		f.timer(policyT0 + 15*m),
		f.timer(policyT0 + 75*m),
		f.action(policyT0+80*m, notify.HumanAction{Type: notify.ActionAck, Version: 2, ImpactRevision: 1}),
		f.timer(policyT0 + 140*m),
		f.incident(policyT0+150*m, 3, notify.SeverityCritical, 2, notify.SourceFiring),
		f.incident(policyT0+160*m, 4, notify.SeverityCritical, 2, notify.SourceRecovered),
		f.action(policyT0+170*m, notify.HumanAction{Type: notify.ActionResolve, Version: 5, Reason: "mitigated"}),
	}}
}

func policyJourneyFacts() (acks []PolicyAck, life []PolicyLifecycle) {
	m := policyMin
	return []PolicyAck{{Entity: policyInc, ImpactRevision: 1, At: policyT0 + 80*m}},
		[]PolicyLifecycle{{Entity: policyInc, Type: policyLifecycleRecovered, At: policyT0 + 160*m}, {Entity: policyInc, Type: policyLifecycleResolved, At: policyT0 + 170*m}}
}

// issueGroup: three batches of the same critical-code exception in one group.
func (f *policyFixture) issueGroup() PolicyReplay {
	m := policyMin
	return PolicyReplay{Subject: policyIss, Steps: []PolicyStep{
		f.dest(policyRcptA, policyT0),
		f.issue(policyT0, 1, "payment_failed", 1, nil),
		f.issue(policyT0+m, 2, "payment_failed", 1, nil),
		f.issue(policyT0+2*m, 3, "payment_failed", 1, nil),
	}}
}

func (f *policyFixture) canonical(r ...PolicyReplay) CanonicalShadowEvidence {
	return CanonicalShadowEvidence{Org: policyOrg, Project: policyProject, Policy: policyID, Replays: r}
}

func (f *policyFixture) approved() ApprovedPolicy {
	return ApprovedPolicy{Revision: 1, Config: f.cfg}
}

// policyDecisions replays the canonical evidence exactly as an operator's own
// shadow window would have recorded it.
func policyDecisions(t *testing.T, c CanonicalShadowEvidence) []PolicyDecisionAt {
	t.Helper()
	var out []PolicyDecisionAt
	for _, r := range c.Replays {
		ev, err := notify.NewShadowEvaluator(c.Org, c.Project, c.Policy, r.Subject)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range r.Steps {
			ds, err := ev.Apply(s.Event, s.At)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			for _, d := range ds {
				out = append(out, PolicyDecisionAt{Decision: d, At: s.At})
			}
		}
	}
	return out
}

func policyTriggerOf(k notify.Kind) LedgerTrigger {
	switch k {
	case notify.KindReminder:
		return ledgerTriggerReminderTimer
	case notify.KindWorseImpact:
		return ledgerTriggerImpact
	case notify.KindRecovery:
		return ledgerTriggerSourceRecovery
	case notify.KindResolution:
		return ledgerTriggerIncidentResolve
	case notify.KindOpen:
		return ledgerTriggerCriticalCode
	}
	return ledgerTriggerOther
}

// policyLegacy turns canonical decisions into the legacy ledger of an old owner
// that behaved identically.
func policyLegacy(ds []PolicyDecisionAt) []LedgerEntry {
	out := make([]LedgerEntry, 0, len(ds))
	for i, d := range ds {
		e := LedgerEntry{Entity: d.Decision.Entity, Kind: d.Decision.Kind, ImpactRevision: d.Decision.ImpactRevision, Ordinal: d.Decision.Ordinal, Recipient: d.Decision.Recipient,
			AttemptID: fmt.Sprintf("legacy-%d", i), Attempt: 1, EventTime: d.At, SourceVersion: d.Decision.SourceVersion, Trigger: policyTriggerOf(d.Decision.Kind)}
		if d.Decision.Suppression == notify.CodeNone {
			e.Outcome, e.DeliveredAt = ledgerDelivered, d.At+1
		} else {
			e.Outcome, e.Suppression = ledgerSuppressed, d.Decision.Suppression
		}
		out = append(out, e)
	}
	return out
}

func policyWithout(entries []LedgerEntry, drop func(LedgerEntry) bool) []LedgerEntry {
	var out []LedgerEntry
	for _, e := range entries {
		if !drop(e) {
			out = append(out, e)
		}
	}
	return out
}

func policyKindIs(k ...notify.Kind) func(LedgerEntry) bool {
	return func(e LedgerEntry) bool {
		for _, v := range k {
			if e.Kind == v {
				return true
			}
		}
		return false
	}
}

func policyAdd(entries []LedgerEntry, e LedgerEntry) []LedgerEntry {
	if e.AttemptID == "" {
		e.AttemptID = fmt.Sprintf("added-%d", len(entries))
	}
	if e.Attempt == 0 {
		e.Attempt = 1
	}
	if e.Outcome == "" {
		e.Outcome = ledgerDelivered
	}
	if e.Outcome == ledgerDelivered && e.DeliveredAt == 0 {
		e.DeliveredAt = e.EventTime + 1
	}
	if e.Trigger == "" {
		e.Trigger = policyTriggerOf(e.Kind)
	}
	return append(entries, e)
}

func policyCompare(t *testing.T, l LegacyEvidence, c CanonicalShadowEvidence, a ApprovedPolicy) PolicyReport {
	t.Helper()
	r, err := ComparePolicy(context.Background(), l, c, a)
	if err != nil {
		t.Fatalf("ComparePolicy: %v", err)
	}
	return r
}

func policyAllDiffs(r PolicyReport) []PolicyDifference {
	var out []PolicyDifference
	out = append(out, r.MissingUrgency...)
	out = append(out, r.Noise...)
	out = append(out, r.Intentional...)
	out = append(out, r.Inert...)
	return out
}

func policyReasons(ds []PolicyDifference) map[PolicyReason]int {
	out := map[PolicyReason]int{}
	for _, d := range ds {
		out[d.Reason]++
	}
	return out
}

func policyStatus(r PolicyReport, name string) PolicyCheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "absent"
}

func policyHasFinding(r PolicyReport, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func policyBlockerFindings(r PolicyReport) int {
	n := 0
	for _, f := range r.Findings {
		if f.Blocker {
			n++
		}
	}
	return n
}

func policyApproval(id string, reason PolicyReason, effect PolicyEffect, max uint32) PolicyApproval {
	return PolicyApproval{ID: id, Difference: reason, OwnerReason: "owner reviewed the legacy behaviour as noise", ApprovedBy: "owner-1", PolicyRevision: 1,
		Expected: PolicyExpectedImpact{Effect: effect, MaxDecisions: max}}
}

func policyWantReasons(t *testing.T, got []PolicyDifference, want map[PolicyReason]int) {
	t.Helper()
	g := policyReasons(got)
	if !reflect.DeepEqual(g, want) && !(len(g) == 0 && len(want) == 0) {
		t.Fatalf("reasons = %v, want %v", g, want)
	}
}

func TestComparisonDistinguishesIntentionalChangeFromMissingUrgency(t *testing.T) {
	m := policyMin
	t.Run("repeated exception occurrences group and the legacy page storm is noise not urgency", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.issueGroup())
		ds := policyDecisions(t, c)
		var opens int
		for _, d := range ds {
			if d.Decision.Kind == notify.KindOpen {
				opens++
			}
		}
		if opens != 1 {
			t.Fatalf("the canonical engine must group three occurrence batches into one opening, got %d", opens)
		}
		legacy := policyLegacy(ds)
		for i, ord := range []uint64{2, 3} {
			legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: ord, Recipient: &policyRcptA, EventTime: policyT0 + model.UnixNano(i+1)*m, Trigger: ledgerTriggerPerOccurrence})
		}
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Ownership: policyOwnership()}, c, f.approved())
		if len(r.MissingUrgency) != 0 {
			t.Fatalf("a legacy per-occurrence repeat of an already opened group is not lost urgency: %+v", r.MissingUrgency)
		}
		policyWantReasons(t, r.Noise, map[PolicyReason]int{policyReasonRepeatOccurrence: 2})
		if len(r.Intentional) != 0 || r.Verdict != policyVerdictUnresolved {
			t.Fatalf("unapproved noise must stay unresolved, got %s with %d intentional", r.Verdict, len(r.Intentional))
		}
		if policyStatus(r, policyCheckGrouping) != policyPass {
			t.Fatalf("grouping check = %s", policyStatus(r, policyCheckGrouping))
		}
		// An owner-approved, revisioned, bounded change makes it intentional.
		a := f.approved()
		a.Approvals = []PolicyApproval{policyApproval("group-pages", policyReasonRepeatOccurrence, policyEffectFewer, 2)}
		r = policyCompare(t, LegacyEvidence{Ledger: legacy, Ownership: policyOwnership()}, c, a)
		policyWantReasons(t, r.Intentional, map[PolicyReason]int{policyReasonRepeatOccurrence: 2})
		if len(r.Noise) != 0 || len(r.MissingUrgency) != 0 {
			t.Fatalf("approved difference still reported as noise/blocker: %+v %+v", r.Noise, r.MissingUrgency)
		}
		if r.Intentional[0].Approval != "group-pages" || len(r.Approvals) != 1 || r.Approvals[0].Matched != 2 {
			t.Fatalf("observed impact not recorded: %+v %+v", r.Intentional, r.Approvals)
		}
	})

	t.Run("impact rate and regression urgency lost by canonical is a blocker", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		// Legacy interrupted on three bases the canonical stream did not.
		legacy := policyLegacy(ds)
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 3, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0 + 155*m, SourceVersion: 3, Trigger: ledgerTriggerImpact})
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0, Trigger: ledgerTriggerRate})
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 2, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0 + m, Trigger: ledgerTriggerRegression})
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		policyWantReasons(t, r.MissingUrgency, map[PolicyReason]int{policyReasonUrgentLost: 3})
		if r.Verdict != policyVerdictBlocked || policyStatus(r, policyCheckInterrupts) != policyFail {
			t.Fatalf("verdict %s, interrupt check %s", r.Verdict, policyStatus(r, policyCheckInterrupts))
		}
		// Approving the loss does not make it intentional.
		a := f.approved()
		a.Approvals = []PolicyApproval{policyApproval("waive", policyReasonUrgentLost, policyEffectFewer, 10)}
		r = policyCompare(t, LegacyEvidence{Ledger: legacy}, c, a)
		if len(r.MissingUrgency) != 3 || len(r.Intentional) != 0 || r.Verdict != policyVerdictBlocked || !policyHasFinding(r, "approval_blocker_class") {
			t.Fatalf("a blocker was waived: %d blockers, %d intentional, %s", len(r.MissingUrgency), len(r.Intentional), r.Verdict)
		}
	})

	t.Run("a rate from an unknown denominator is never faked", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(PolicyReplay{Subject: policyIss, Steps: []PolicyStep{
			f.dest(policyRcptA, policyT0),
			// Six deduplicated failures, no denominator at all: no rate, no urgency.
			f.issue(policyT0, 1, "", 6, nil),
		}})
		ds := policyDecisions(t, c)
		for _, d := range ds {
			if d.Decision.Kind != notify.KindQueue {
				t.Fatalf("an unknown denominator must not interrupt, canonical produced %s", d.Decision.Kind)
			}
		}
		legacy := policyLegacy(ds)
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0, Trigger: ledgerTriggerRateNoDenominator})
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		if len(r.MissingUrgency) != 0 {
			t.Fatalf("a rate nobody could compute is not urgency: %+v", r.MissingUrgency)
		}
		policyWantReasons(t, r.Noise, map[PolicyReason]int{policyReasonFakeRate: 1})
		if policyStatus(r, policyCheckDenominator) != policyPass {
			t.Fatalf("denominator check = %s", policyStatus(r, policyCheckDenominator))
		}
	})

	t.Run("ACK suppresses reminders but not worsened impact", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		acks, life := policyJourneyFacts()
		// The old owner kept reminding after the ACK and stayed silent on the
		// worsened impact because its ACK muted the whole incident.
		legacy := policyWithout(policyLegacy(ds), policyKindIs(notify.KindWorseImpact))
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, Recipient: &policyRcptA, EventTime: policyT0 + 140*m, SourceVersion: 1})
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
		if len(r.MissingUrgency) != 0 {
			t.Fatalf("unexpected blockers: %+v", r.MissingUrgency)
		}
		want := map[PolicyReason]int{policyReasonReminderAfterAck: 1, policyReasonWorseAfterAck: 1}
		var noise []PolicyDifference
		for _, d := range r.Noise {
			if d.Reason != policyReasonQueueCadence {
				noise = append(noise, d)
			}
		}
		policyWantReasons(t, noise, want)
		if policyStatus(r, policyCheckAck) != policyPass {
			t.Fatalf("ack check = %s", policyStatus(r, policyCheckAck))
		}
		// The reverse is the dangerous one: legacy told the humans about the
		// worsened impact and the canonical stream did not.
		short := f.journey()
		short.Steps = append(append([]PolicyStep{}, short.Steps[:6]...), short.Steps[7:]...)
		c2 := f.canonical(short)
		legacy = policyLegacy(ds)
		r = policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c2, f.approved())
		if reasons := policyReasons(r.MissingUrgency); reasons[policyReasonUrgentLost] == 0 || r.Verdict != policyVerdictBlocked {
			t.Fatalf("a worsened impact lost after ACK must block: %v %s", reasons, r.Verdict)
		}
		if policyStatus(r, policyCheckAck) != policyFail {
			t.Fatalf("ack check = %s", policyStatus(r, policyCheckAck))
		}
	})

	t.Run("source recovery and incident resolve are separate events", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: life}, c, f.approved())
		if policyStatus(r, policyCheckRecovery) != policyPass {
			t.Fatalf("recovery/resolve check = %s", policyStatus(r, policyCheckRecovery))
		}
		// A canonical stream that announces a resolution for a mere source
		// recovery conflates the two lifecycles.
		var conflated []PolicyDecisionAt
		for _, d := range ds {
			if d.Decision.Kind == notify.KindResolution {
				continue
			}
			if d.Decision.Kind == notify.KindRecovery {
				x := d
				x.Decision.Kind = notify.KindResolution
				d = x
			}
			conflated = append(conflated, d)
		}
		r = policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: life}, CanonicalShadowEvidence{Decisions: conflated}, f.approved())
		if policyStatus(r, policyCheckRecovery) != policyFail {
			t.Fatalf("conflated lifecycles passed: %s", policyStatus(r, policyCheckRecovery))
		}
		if r.Verdict != policyVerdictBlocked {
			t.Fatalf("verdict %s", r.Verdict)
		}
	})
}

// policyGroupScenario is the grouped issue with two legacy per-occurrence pages.
func policyGroupScenario(t *testing.T) (*policyFixture, LegacyEvidence, CanonicalShadowEvidence) {
	f := newPolicyFixture(t)
	c := f.canonical(f.issueGroup())
	legacy := policyLegacy(policyDecisions(t, c))
	for i, ord := range []uint64{2, 3} {
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: ord, Recipient: &policyRcptA, EventTime: policyT0 + model.UnixNano(i+1)*policyMin, Trigger: ledgerTriggerPerOccurrence})
	}
	return f, LegacyEvidence{Ledger: legacy, Ownership: policyOwnership()}, c
}

func TestComparisonIncompleteApprovalIsNotIntentional(t *testing.T) {
	other := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x99}}
	cases := []struct {
		name    string
		mutate  func(*PolicyApproval)
		finding string
		blocker bool
	}{
		{"no identifier", func(a *PolicyApproval) { a.ID = "" }, "approval_incomplete", true},
		{"no owner reason", func(a *PolicyApproval) { a.OwnerReason = "" }, "approval_incomplete", true},
		{"no approving owner", func(a *PolicyApproval) { a.ApprovedBy = "" }, "approval_incomplete", true},
		{"no policy revision", func(a *PolicyApproval) { a.PolicyRevision = 0 }, "approval_incomplete", true},
		{"no expected impact", func(a *PolicyApproval) { a.Expected = PolicyExpectedImpact{} }, "approval_incomplete", true},
		{"zero impact bound", func(a *PolicyApproval) { a.Expected.MaxDecisions = 0 }, "approval_incomplete", true},
		{"other policy revision", func(a *PolicyApproval) { a.PolicyRevision = 2 }, "approval_revision_mismatch", true},
		{"wrong impact direction", func(a *PolicyApproval) { a.Expected.Effect = policyEffectMore }, "approval_effect_mismatch", true},
		{"unknown difference", func(a *PolicyApproval) { a.Difference = "made_up" }, "approval_unknown_difference", true},
		{"approval for an inert reason", func(a *PolicyApproval) { a.Difference = policyReasonLegacySuppressedOnly }, "approval_not_needed", false},
		{"other entity scope", func(a *PolicyApproval) { a.Entity = &other }, "approval_unused", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, legacy, c := policyGroupScenario(t)
			a := f.approved()
			ap := policyApproval("ap-1", policyReasonRepeatOccurrence, policyEffectFewer, 2)
			tc.mutate(&ap)
			a.Approvals = []PolicyApproval{ap}
			r := policyCompare(t, legacy, c, a)
			if len(r.Intentional) != 0 {
				t.Fatalf("an approval with %s made a difference intentional: %+v", tc.name, r.Intentional)
			}
			policyWantReasons(t, r.Noise, map[PolicyReason]int{policyReasonRepeatOccurrence: 2})
			found := false
			for _, fd := range r.Findings {
				if fd.Code == tc.finding {
					found = true
					if fd.Blocker != tc.blocker {
						t.Fatalf("finding %s blocker=%v, want %v", fd.Code, fd.Blocker, tc.blocker)
					}
				}
			}
			if !found {
				t.Fatalf("no %s finding: %+v", tc.finding, r.Findings)
			}
			want := policyVerdictUnresolved
			if tc.blocker {
				want = policyVerdictBlocked
			}
			if r.Verdict != want {
				t.Fatalf("verdict %s, want %s", r.Verdict, want)
			}
		})
	}
	t.Run("impact beyond the approved bound", func(t *testing.T) {
		f, legacy, c := policyGroupScenario(t)
		a := f.approved()
		a.Approvals = []PolicyApproval{policyApproval("tight", policyReasonRepeatOccurrence, policyEffectFewer, 1)}
		r := policyCompare(t, legacy, c, a)
		if len(r.Intentional) != 1 || len(r.Noise) != 1 || !policyHasFinding(r, "approval_impact_exceeded") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("observed impact beyond MaxDecisions must not be silently absorbed: %d/%d %v %s", len(r.Intentional), len(r.Noise), r.Findings, r.Verdict)
		}
		if r.Approvals[0].Matched != 2 || r.Approvals[0].Max != 1 {
			t.Fatalf("approval use = %+v", r.Approvals)
		}
	})
	t.Run("duplicate approval identifiers", func(t *testing.T) {
		f, legacy, c := policyGroupScenario(t)
		a := f.approved()
		a.Approvals = []PolicyApproval{policyApproval("same", policyReasonRepeatOccurrence, policyEffectFewer, 2), policyApproval("same", policyReasonRepeatOccurrence, policyEffectFewer, 9)}
		r := policyCompare(t, legacy, c, a)
		if !policyHasFinding(r, "approval_ambiguous") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("ambiguous approvals accepted: %v %s", r.Findings, r.Verdict)
		}
	})
	t.Run("entity scope selects only its entity", func(t *testing.T) {
		f, legacy, c := policyGroupScenario(t)
		a := f.approved()
		ap := policyApproval("scoped", policyReasonRepeatOccurrence, policyEffectFewer, 2)
		ent := policyIss
		ap.Entity = &ent
		a.Approvals = []PolicyApproval{ap}
		r := policyCompare(t, legacy, c, a)
		if len(r.Intentional) != 2 {
			t.Fatalf("scoped approval did not apply to its own entity: %+v", r.Noise)
		}
	})
}

func TestComparisonMissingUrgencyKindsAreBlockers(t *testing.T) {
	f := newPolicyFixture(t)
	m := policyMin
	t.Run("reminders lost while unacknowledged", func(t *testing.T) {
		rep := f.journey()
		// No timer is ever replayed: the canonical stream never reminds.
		var steps []PolicyStep
		for _, s := range rep.Steps {
			if s.Event.Kind != notify.EventTimer {
				steps = append(steps, s)
			}
		}
		rep.Steps = steps
		full := policyLegacy(policyDecisions(t, f.canonical(f.journey())))
		_, life := policyJourneyFacts()
		// Drop the ACK so nothing excuses the legacy reminders.
		r := policyCompare(t, LegacyEvidence{Ledger: full, Lifecycle: life}, f.canonical(rep), f.approved())
		if policyReasons(r.MissingUrgency)[policyReasonReminderLost] == 0 || r.Verdict != policyVerdictBlocked {
			t.Fatalf("lost reminders = %v verdict %s", policyReasons(r.MissingUrgency), r.Verdict)
		}
	})
	t.Run("an ACKed reminder the canonical stream rightly dropped is noise", func(t *testing.T) {
		c := f.canonical(f.journey())
		acks, life := policyJourneyFacts()
		legacy := policyAdd(policyLegacy(policyDecisions(t, c)), LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, Recipient: &policyRcptA, EventTime: policyT0 + 140*m, SourceVersion: 1})
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonReminderAfterAck] != 1 {
			t.Fatalf("ack-covered reminder misclassified: %+v %+v", r.MissingUrgency, r.Noise)
		}
		// The very same legacy reminder without a recorded ACK is lost urgency
		// only when the canonical stream stopped reminding that impact at all;
		// here it only has a different cadence.
		r = policyCompare(t, LegacyEvidence{Ledger: legacy, Lifecycle: life}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonReminderCadence] != 1 {
			t.Fatalf("cadence difference misclassified: %+v %+v", r.MissingUrgency, r.Noise)
		}
	})
	t.Run("recovery and resolution notices lost", func(t *testing.T) {
		rep := f.journey()
		rep.Steps = rep.Steps[:7]
		c := f.canonical(rep)
		legacy := policyLegacy(policyDecisions(t, f.canonical(f.journey())))
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
		if policyReasons(r.MissingUrgency)[policyReasonUrgentLost] != 2 {
			t.Fatalf("lost recovery+resolution = %v", policyReasons(r.MissingUrgency))
		}
		if policyStatus(r, policyCheckRecovery) != policyFail {
			t.Fatalf("recovery check = %s", policyStatus(r, policyCheckRecovery))
		}
	})
	t.Run("canonical suppressed what legacy delivered with no recorded window", func(t *testing.T) {
		c := f.canonical(f.maintenanceReplay())
		ds := policyDecisions(t, c)
		legacy := policyLegacy(ds)
		for i := range legacy {
			if legacy[i].Kind == notify.KindWorseImpact {
				legacy[i].Outcome, legacy[i].Suppression, legacy[i].DeliveredAt = ledgerDelivered, notify.CodeNone, legacy[i].EventTime+1
			}
		}
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		if policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 || r.Verdict != policyVerdictBlocked {
			t.Fatalf("a silence without a recorded window passed: %v %s", policyReasons(r.MissingUrgency), r.Verdict)
		}
	})
}

// maintenanceReplay: open, a project maintenance window, a worse impact inside it.
func (f *policyFixture) maintenanceReplay() PolicyReplay {
	m := policyMin
	return PolicyReplay{Subject: policyInc, Steps: []PolicyStep{
		f.dest(policyRcptA, policyT0),
		f.incident(policyT0, 1, notify.SeverityMajor, 1, notify.SourceFiring),
		f.action(policyT0+5*m, notify.HumanAction{Type: notify.ActionMaintenance, Version: 2, Scope: notify.Scope{Kind: notify.ScopeProject}, Reason: "planned work", Until: policyT0 + 60*m}),
		f.incident(policyT0+10*m, 3, notify.SeverityCritical, 2, notify.SourceFiring),
	}}
}

func TestComparisonMaintenanceAndSnoozeNeedReasonAndExpiry(t *testing.T) {
	m := policyMin
	build := func(t *testing.T) (*policyFixture, CanonicalShadowEvidence, []LedgerEntry) {
		f := newPolicyFixture(t)
		c := f.canonical(f.maintenanceReplay())
		ds := policyDecisions(t, c)
		suppressed := 0
		for _, d := range ds {
			if d.Decision.Suppression == notify.CodeMaintenance {
				suppressed++
			}
		}
		if suppressed == 0 {
			t.Fatal("the canonical engine did not suppress anything inside the maintenance window")
		}
		legacy := policyLegacy(ds)
		for i := range legacy {
			// The old owner paged straight through its own window.
			if legacy[i].Suppression == notify.CodeMaintenance {
				legacy[i].Outcome, legacy[i].Suppression, legacy[i].DeliveredAt = ledgerDelivered, notify.CodeNone, legacy[i].EventTime+1
			}
		}
		return f, c, legacy
	}
	valid := PolicyWindow{Type: notify.ActionMaintenance, Reason: "planned work", From: policyT0 + 5*m, Until: policyT0 + 60*m}
	t.Run("recorded window with reason and expiry makes the legacy page noise", func(t *testing.T) {
		f, c, legacy := build(t)
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{valid}}, c, f.approved())
		if len(r.MissingUrgency) != 0 {
			t.Fatalf("blockers %+v", r.MissingUrgency)
		}
		if policyReasons(r.Noise)[policyReasonIgnoredWindow] == 0 || policyStatus(r, policyCheckWindows) != policyPass {
			t.Fatalf("noise %v windows %s", policyReasons(r.Noise), policyStatus(r, policyCheckWindows))
		}
	})
	t.Run("window without a reason", func(t *testing.T) {
		f, c, legacy := build(t)
		w := valid
		w.Reason = ""
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{w}}, c, f.approved())
		if !policyHasFinding(r, "window_missing_reason") || policyStatus(r, policyCheckWindows) != policyFail || r.Verdict != policyVerdictBlocked {
			t.Fatalf("reasonless window accepted: %v %s", r.Findings, policyStatus(r, policyCheckWindows))
		}
		if policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
			t.Fatalf("a reasonless window must not excuse a silence: %v", policyReasons(r.MissingUrgency))
		}
	})
	t.Run("window without an expiry", func(t *testing.T) {
		f, c, legacy := build(t)
		for _, until := range []model.UnixNano{0, valid.From, valid.From - 1} {
			w := valid
			w.Until = until
			r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{w}}, c, f.approved())
			if !policyHasFinding(r, "window_missing_expiry") || policyStatus(r, policyCheckWindows) != policyFail {
				t.Fatalf("until=%d accepted: %v", until, r.Findings)
			}
		}
	})
	t.Run("expiry boundary is half open", func(t *testing.T) {
		f, c, legacy := build(t)
		w := valid
		for i := range legacy {
			if legacy[i].Kind == notify.KindWorseImpact {
				w.Until = legacy[i].EventTime // the window ended at the instant of the event
			}
		}
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{w}}, c, f.approved())
		if policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
			t.Fatalf("a window that ended at the event time still excused the silence: %v", policyReasons(r.Noise))
		}
	})
	t.Run("legacy silent while canonical interrupts is canonical-extra", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		legacy := policyLegacy(policyDecisions(t, c))
		for i := range legacy {
			if legacy[i].Kind == notify.KindWorseImpact {
				legacy[i].Outcome, legacy[i].Suppression, legacy[i].DeliveredAt = ledgerSuppressed, notify.CodeSnoozed, 0
			}
		}
		_, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Lifecycle: life}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonExtraInterrupt] != 1 {
			t.Fatalf("snooze that expired: %+v %+v", r.MissingUrgency, r.Noise)
		}
	})
}

func TestComparisonRecipientDifferences(t *testing.T) {
	t.Run("canonical reaches a recipient legacy did not", func(t *testing.T) {
		f := newPolicyFixture(t)
		rep := f.journey()
		rep.Steps = append([]PolicyStep{f.dest(policyRcptB, policyT0)}, rep.Steps...)
		c := f.canonical(rep)
		ds := policyDecisions(t, c)
		legacy := policyLegacy(ds)
		legacy = policyWithout(legacy, func(e LedgerEntry) bool { return e.Recipient != nil && *e.Recipient == policyRcptB })
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
		if len(r.MissingUrgency) != 0 {
			t.Fatalf("an added recipient lost urgency? %+v", r.MissingUrgency)
		}
		if policyReasons(r.Noise)[policyReasonRecipientAdded] == 0 {
			t.Fatalf("recipient addition not reported: %v", policyReasons(r.Noise))
		}
	})
	t.Run("legacy reached a recipient canonical dropped", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		legacy := policyLegacy(ds)
		n := 0
		for _, e := range policyLegacy(ds) {
			if e.Recipient != nil {
				x := e
				b := policyRcptB
				x.Recipient = &b
				x.AttemptID = "b-" + e.AttemptID
				legacy = append(legacy, x)
				n++
			}
		}
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
		if policyReasons(r.MissingUrgency)[policyReasonRecipientDropped] != n || r.Verdict != policyVerdictBlocked {
			t.Fatalf("dropped recipients = %v, want %d", policyReasons(r.MissingUrgency), n)
		}
	})
}

func policyDigest(r model.ID, ord uint64, at model.UnixNano, suppressed notify.Code) PolicyDecisionAt {
	return PolicyDecisionAt{At: at, Decision: notify.ShadowDecision{Entity: policyInc, Kind: notify.KindDigest, ImpactRevision: 1, Ordinal: ord, Recipient: &r, DedupID: model.ID{0xd9, byte(ord)}, Suppression: suppressed, Route: notify.RouteDigest}}
}

func TestComparisonQueueAndDigestCadence(t *testing.T) {
	f := newPolicyFixture(t)
	t.Run("canonical digest the legacy tool never sent", func(t *testing.T) {
		c := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(policyRcptA, 20260310, policyT0, notify.CodeNone)}}
		var legacy []LedgerEntry
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		if policyReasons(r.Noise)[policyReasonDigestCadence] != 1 {
			t.Fatalf("digest cadence not reported: %+v", r.Noise)
		}
		a := f.approved()
		a.Approvals = []PolicyApproval{policyApproval("digest", policyReasonDigestCadence, policyEffectRetimed, 1)}
		r = policyCompare(t, LegacyEvidence{Ledger: legacy}, c, a)
		if policyReasons(r.Intentional)[policyReasonDigestCadence] != 1 || policyStatus(r, policyCheckCadence) != policyPass {
			t.Fatalf("approved cadence: %+v %s", r.Intentional, policyStatus(r, policyCheckCadence))
		}
	})
	t.Run("legacy digest the canonical stream does not reproduce", func(t *testing.T) {
		c := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(policyRcptA, 20260310, policyT0, notify.CodeNone)}}
		legacy := []LedgerEntry{
			{Entity: policyInc, Kind: notify.KindDigest, ImpactRevision: 1, Ordinal: 20260310, Recipient: &policyRcptA, AttemptID: "d1", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerOther},
			{Entity: policyInc, Kind: notify.KindDigest, ImpactRevision: 1, Ordinal: 20260311, Recipient: &policyRcptA, AttemptID: "d2", Attempt: 1, EventTime: policyT0 + 24*60*policyMin, DeliveredAt: policyT0 + 24*60*policyMin + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerOther},
		}
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonDigestCadence] != 1 {
			t.Fatalf("a digest is not an interrupt: %+v %+v", r.MissingUrgency, r.Noise)
		}
	})
	t.Run("suppressed or unsent decisions are inert", func(t *testing.T) {
		c := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(policyRcptA, 20260310, policyT0, notify.CodeNone)}}
		legacy := []LedgerEntry{{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 2, Ordinal: 1, Recipient: &policyRcptA, AttemptID: "w", Attempt: 1, EventTime: policyT0, Outcome: ledgerSuppressed, Suppression: notify.CodeSnoozed, Trigger: ledgerTriggerImpact},
			{Entity: policyInc, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &policyRcptA, AttemptID: "f", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerFailed, Trigger: ledgerTriggerCount}}
		r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
		if policyReasons(r.Inert)[policyReasonLegacySuppressedOnly] != 2 || len(r.MissingUrgency) != 0 {
			t.Fatalf("inert = %v blockers %v", policyReasons(r.Inert), r.MissingUrgency)
		}
	})
}

func policyControls() []PolicyControl {
	return []PolicyControl{
		{ID: "c-ops", Kind: policyControlMinOperations, Value: 20},
		{ID: "c-fail", Kind: policyControlMinFailures, Value: 5},
		{ID: "c-rate", Kind: policyControlRateBP, Value: 500},
		{ID: "c-reg", Kind: policyControlRegressionMin, Value: 5},
		{ID: "c-codes", Kind: policyControlCriticalCodes, Codes: []string{"payment_failed"}},
		{ID: "c-first", Kind: policyControlFirstReminder, Value: uint64(15 * time.Minute)},
		{ID: "c-every", Kind: policyControlReminderEvery, Value: uint64(60 * time.Minute)},
		{ID: "c-max", Kind: policyControlMaxSuppress, Value: uint64(7 * 24 * time.Hour)},
		{ID: "c-zone", Kind: policyControlDigestZone},
		{ID: "c-schedule", Kind: policyControlOther},
	}
}

func policyDispositions() []PolicyControlDisposition {
	var out []PolicyControlDisposition
	for _, c := range policyControls() {
		switch c.ID {
		case "c-schedule":
			out = append(out, PolicyControlDisposition{Control: c.ID, Disposition: policyDispSuperseded, Reason: "customer paging rota is replaced by the canonical digest", ApprovedBy: "owner-1", PolicyRevision: 1})
		case "c-max":
			out = append(out, PolicyControlDisposition{Control: c.ID, Disposition: policyDispRetained, Reason: "customer tool keeps its own long maintenance cap", ApprovedBy: "owner-1", PolicyRevision: 1})
		default:
			out = append(out, PolicyControlDisposition{Control: c.ID, Disposition: policyDispPreserved})
		}
	}
	return out
}

func policyOwnership() []PolicyClassOwner {
	var out []PolicyClassOwner
	for _, c := range []string{policyClassUrgent, policyClassReminder, policyClassRecovery, policyClassQueue, policyClassDigest} {
		out = append(out, PolicyClassOwner{Class: c, Owner: policyOwnerSoundpost})
	}
	return out
}

// policyFullWindow builds the complete synthetic shadow window: every behaviour
// the plan lists, every difference approved, every semantic check exercised.
func policyFullWindow(t *testing.T) (LegacyEvidence, CanonicalShadowEvidence, ApprovedPolicy) {
	f := newPolicyFixture(t)
	m := policyMin
	c := f.canonical(f.journey(), f.issueGroup())
	ds := policyDecisions(t, c)
	// The old owner has no shared queue.
	legacy := policyWithout(policyLegacy(ds), policyKindIs(notify.KindQueue))
	for i, ord := range []uint64{2, 3} {
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: ord, Recipient: &policyRcptA, EventTime: policyT0 + model.UnixNano(i+1)*m, Trigger: ledgerTriggerPerOccurrence})
	}
	legacy = policyAdd(legacy, LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 7, Recipient: &policyRcptA, EventTime: policyT0 + 3*m, Trigger: ledgerTriggerRateNoDenominator})
	legacy = policyAdd(legacy, LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, Recipient: &policyRcptA, EventTime: policyT0 + 140*m, SourceVersion: 1})
	for i, e := range legacy {
		switch {
		case e.Entity == policyInc && e.Kind == notify.KindOpen:
			dup := e
			dup.AttemptID = "dup-delivery"
			dup.DeliveredAt = e.DeliveredAt + 1
			legacy = append(legacy, dup, e) // a second delivery and an exact record replay
		case e.Entity == policyInc && e.Kind == notify.KindRecovery:
			failed := e
			failed.Outcome, failed.DeliveredAt = ledgerFailed, e.EventTime
			legacy[i].Attempt, legacy[i].DeliveredAt = 2, e.EventTime+2
			legacy = append(legacy, failed) // job retry: attempt 1 failed, attempt 2 delivered
		}
	}
	legacy = policyAdd(legacy, LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 9, Recipient: &policyRcptA, EventTime: policyT0 + 155*m, SourceVersion: 1, AttemptID: "late-1"})
	acks, life := policyJourneyFacts()
	l := LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life, Ownership: policyOwnership(), Controls: policyControls(),
		Windows: []PolicyWindow{{Type: notify.ActionMaintenance, Reason: "planned database maintenance", From: policyT0 + 400*m, Until: policyT0 + 500*m}}}
	a := f.approved()
	a.Controls = policyDispositions()
	a.Approvals = []PolicyApproval{
		policyApproval("ap-group", policyReasonRepeatOccurrence, policyEffectFewer, 2),
		policyApproval("ap-rate", policyReasonFakeRate, policyEffectFewer, 1),
		policyApproval("ap-ack", policyReasonReminderAfterAck, policyEffectFewer, 1),
		policyApproval("ap-queue", policyReasonQueueCadence, policyEffectRetimed, 6),
		policyApproval("ap-dup", policyReasonDuplicateDelivery, policyEffectFewer, 1),
		policyApproval("ap-late", policyReasonLateDelivery, policyEffectFewer, 1),
	}
	return l, c, a
}

func TestComparisonReconciledOnlyWhenEveryDifferenceIsResolvedAndEveryCheckIsExercised(t *testing.T) {
	l, c, a := policyFullWindow(t)
	r := policyCompare(t, l, c, a)
	if r.Verdict != policyVerdictReconciled {
		t.Fatalf("verdict %s; blockers %+v noise %+v findings %+v checks %+v", r.Verdict, r.MissingUrgency, r.Noise, r.Findings, r.Checks)
	}
	policyWantReasons(t, r.Intentional, map[PolicyReason]int{policyReasonRepeatOccurrence: 2, policyReasonFakeRate: 1, policyReasonReminderAfterAck: 1, policyReasonQueueCadence: 5, policyReasonDuplicateDelivery: 1, policyReasonLateDelivery: 1})
	if r.Ledger.Retries != 1 || r.Ledger.Duplicates != 1 || r.Ledger.DuplicateDeliveries != 1 || r.Ledger.Late != 1 {
		t.Fatalf("ledger stats %+v", r.Ledger)
	}
	for _, ck := range r.Checks {
		if ck.Status != policyPass {
			t.Fatalf("check %s = %s", ck.Name, ck.Status)
		}
	}
	if r.Controls != (PolicyControlCounts{Recorded: 10, Preserved: 8, Superseded: 1, RetainedExternal: 1}) {
		t.Fatalf("controls %+v", r.Controls)
	}
	if r.Identical == 0 || r.Compared < r.Identical {
		t.Fatalf("compared/identical %d/%d", r.Compared, r.Identical)
	}
	if PolicyPublic(r).CustomerAcceptance {
		t.Fatal("a synthetic reconciliation is not customer acceptance")
	}
	// Each defect re-opens the verdict.
	t.Run("a missing approval leaves noise unresolved", func(t *testing.T) {
		a2 := a
		a2.Approvals = a.Approvals[1:]
		if r := policyCompare(t, l, c, a2); r.Verdict != policyVerdictUnresolved || len(r.Noise) != 2 {
			t.Fatalf("%s %d", r.Verdict, len(r.Noise))
		}
	})
	t.Run("an unexercised check is incomplete coverage", func(t *testing.T) {
		l2 := l
		l2.Windows = nil
		if r := policyCompare(t, l2, c, a); r.Verdict != policyVerdictIncomplete || policyStatus(r, policyCheckWindows) != policyNotExercised {
			t.Fatalf("%s %s", r.Verdict, policyStatus(r, policyCheckWindows))
		}
	})
	t.Run("an unapproved lost page blocks everything", func(t *testing.T) {
		l2 := l
		l2.Ledger = policyAdd(append([]LedgerEntry{}, l.Ledger...), LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 9, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0 + 200*policyMin, SourceVersion: 9})
		if r := policyCompare(t, l2, c, a); r.Verdict != policyVerdictBlocked {
			t.Fatalf("%s", r.Verdict)
		}
	})
}

func TestComparisonControlsAreNeverSilentlyDiscarded(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	acks, life := policyJourneyFacts()
	run := func(t *testing.T, controls []PolicyControl, disp []PolicyControlDisposition) PolicyReport {
		a := f.approved()
		a.Controls = disp
		return policyCompare(t, LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c)), Acks: acks, Lifecycle: life, Controls: controls}, c, a)
	}
	without := func(id string) []PolicyControlDisposition {
		var out []PolicyControlDisposition
		for _, d := range policyDispositions() {
			if d.Control != id {
				out = append(out, d)
			}
		}
		return out
	}
	t.Run("a control with no disposition is a blocker", func(t *testing.T) {
		r := run(t, policyControls(), without("c-rate"))
		if !policyHasFinding(r, "control_silently_discarded") || r.Controls.Unresolved != 1 || policyStatus(r, policyCheckControls) != policyFail || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v %+v %s", r.Findings, r.Controls, r.Verdict)
		}
	})
	t.Run("preserved must equal the canonical value", func(t *testing.T) {
		ctl := policyControls()
		ctl[0].Value = 50 // customer's min operations differs from the canonical 20
		r := run(t, ctl, policyDispositions())
		if !policyHasFinding(r, "control_preserved_mismatch") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v", r.Findings)
		}
	})
	t.Run("critical codes compare as sets", func(t *testing.T) {
		ctl := policyControls()
		ctl[4].Codes = []string{"payment_failed", "outage"}
		if r := run(t, ctl, policyDispositions()); !policyHasFinding(r, "control_preserved_mismatch") {
			t.Fatalf("a missing critical code was preserved: %v", r.Findings)
		}
		ctl[4].Codes = []string{"payment_failed"}
		if r := run(t, ctl, policyDispositions()); policyHasFinding(r, "control_preserved_mismatch") {
			t.Fatalf("equal code sets flagged: %v", r.Findings)
		}
	})
	t.Run("a control the canonical config cannot hold cannot be preserved", func(t *testing.T) {
		d := policyDispositions()
		d[len(d)-1] = PolicyControlDisposition{Control: "c-schedule", Disposition: policyDispPreserved}
		r := run(t, policyControls(), d)
		if !policyHasFinding(r, "control_preserved_mismatch") {
			t.Fatalf("%v", r.Findings)
		}
	})
	for _, tc := range []struct {
		name string
		mut  func(*PolicyControlDisposition)
	}{
		{"no reason", func(d *PolicyControlDisposition) { d.Reason = "" }},
		{"no approving owner", func(d *PolicyControlDisposition) { d.ApprovedBy = "" }},
		{"no policy revision", func(d *PolicyControlDisposition) { d.PolicyRevision = 0 }},
		{"other policy revision", func(d *PolicyControlDisposition) { d.PolicyRevision = 7 }},
	} {
		t.Run("supersession with "+tc.name, func(t *testing.T) {
			d := policyDispositions()
			tc.mut(&d[len(d)-1])
			r := run(t, policyControls(), d)
			if !policyHasFinding(r, "control_supersession_incomplete") || r.Controls.Superseded != 0 || r.Controls.Unresolved != 1 {
				t.Fatalf("%v %+v", r.Findings, r.Controls)
			}
		})
	}
	t.Run("a disposition for a control nobody recorded is reported", func(t *testing.T) {
		d := append(policyDispositions(), PolicyControlDisposition{Control: "c-ghost", Disposition: policyDispPreserved})
		r := run(t, policyControls(), d)
		for _, fd := range r.Findings {
			if fd.Code == "control_disposition_orphan" && !fd.Blocker {
				return
			}
		}
		t.Fatalf("%v", r.Findings)
	})
	t.Run("malformed controls are refused", func(t *testing.T) {
		for _, ctl := range [][]PolicyControl{{{ID: "x", Kind: "nope"}}, {{ID: "", Kind: policyControlMinFailures}}, {{ID: "d", Kind: policyControlMinFailures}, {ID: "d", Kind: policyControlMinOperations}}} {
			if _, err := ComparePolicy(context.Background(), LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c)), Controls: ctl}, c, f.approved()); err == nil {
				t.Fatalf("accepted %+v", ctl)
			}
		}
		if _, err := ComparePolicy(context.Background(), LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c))}, c, ApprovedPolicy{Revision: 1, Config: f.cfg, Controls: []PolicyControlDisposition{{Control: "c", Disposition: "keep"}}}); err == nil {
			t.Fatal("accepted an unknown disposition")
		}
	})
}

func TestComparisonOwnershipBoundaries(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	acks, life := policyJourneyFacts()
	run := func(own []PolicyClassOwner) PolicyReport {
		return policyCompare(t, LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c)), Acks: acks, Lifecycle: life, Ownership: own}, c, f.approved())
	}
	if r := run(policyOwnership()); policyStatus(r, policyCheckOwnership) != policyPass || policyBlockerFindings(r) != 0 {
		t.Fatalf("one owner per class: %v", r.Findings)
	}
	if r := run(nil); !policyHasFinding(r, "ownership_unspecified") || policyStatus(r, policyCheckOwnership) != policyFail || r.Verdict != policyVerdictBlocked {
		t.Fatalf("no declared owner accepted: %v", r.Findings)
	}
	t.Run("a retained customer sender plus a delivering canonical class is two normal senders", func(t *testing.T) {
		own := policyOwnership()
		own[1].Owner = policyOwnerCustomer // reminders stay with the customer tool
		r := run(own)
		if !policyHasFinding(r, "dual_normal_sender") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v", r.Findings)
		}
	})
	t.Run("two owners for one class", func(t *testing.T) {
		own := append(policyOwnership(), PolicyClassOwner{Class: policyClassUrgent, Owner: policyOwnerCustomer})
		if r := run(own); !policyHasFinding(r, "ownership_ambiguous") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v", r.Findings)
		}
	})
	t.Run("unknown class or owner is refused", func(t *testing.T) {
		for _, own := range [][]PolicyClassOwner{{{Class: "pager", Owner: policyOwnerSoundpost}}, {{Class: policyClassUrgent, Owner: "both"}}} {
			if _, err := ComparePolicy(context.Background(), LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c)), Ownership: own}, c, f.approved()); err == nil {
				t.Fatalf("accepted %+v", own)
			}
		}
	})
}

func TestComparisonLedgerOrdersByAttemptEventTimeAndSourceVersion(t *testing.T) {
	rcpt := policyRcptA
	e := func(id string, attempt uint32, out LedgerOutcome, sv uint64, ev, at model.UnixNano) LedgerEntry {
		x := LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, AttemptID: id, Attempt: attempt, EventTime: ev, SourceVersion: sv, Outcome: out, Trigger: ledgerTriggerReminderTimer}
		if out == ledgerDelivered || out == ledgerFailed || out == ledgerUnknown {
			x.DeliveredAt = at
		} else {
			x.Suppression = notify.CodeSnoozed
		}
		return x
	}
	t.Run("retry keeps one delivery and a delivered attempt wins", func(t *testing.T) {
		red, err := ledgerReduce([]LedgerEntry{e("a", 1, ledgerFailed, 1, 10, 11), e("a", 2, ledgerDelivered, 1, 10, 12), e("a", 3, ledgerFailed, 1, 10, 13)})
		if err != nil {
			t.Fatal(err)
		}
		if len(red.Records) != 1 || red.Records[0].Entry.Outcome != ledgerDelivered || red.Stats.Retries != 2 || red.Stats.Deliveries != 1 {
			t.Fatalf("%+v", red)
		}
		red, _ = ledgerReduce([]LedgerEntry{e("a", 1, ledgerFailed, 1, 10, 11), e("a", 2, ledgerFailed, 1, 10, 12)})
		if len(red.Records) != 1 || red.Records[0].Entry.Outcome != ledgerFailed || red.Records[0].Entry.Attempt != 2 {
			t.Fatalf("all attempts failed: %+v", red.Records)
		}
	})
	t.Run("an exact replay is a duplicate record not a second delivery", func(t *testing.T) {
		red, err := ledgerReduce([]LedgerEntry{e("a", 1, ledgerDelivered, 1, 10, 11), e("a", 1, ledgerDelivered, 1, 10, 11)})
		if err != nil || len(red.Records) != 1 || red.Stats.Duplicates != 1 || len(red.DuplicateDeliveries) != 0 {
			t.Fatalf("%v %+v", err, red)
		}
	})
	t.Run("two delivery attempts of one decision keep the newest source version", func(t *testing.T) {
		red, err := ledgerReduce([]LedgerEntry{e("a", 1, ledgerDelivered, 1, 10, 11), e("b", 1, ledgerDelivered, 3, 10, 12)})
		if err != nil || len(red.Records) != 1 || red.Records[0].Entry.SourceVersion != 3 || len(red.DuplicateDeliveries) != 1 || red.Stats.DuplicateDeliveries != 1 {
			t.Fatalf("%v %+v", err, red)
		}
		// A suppressed twin is not a second delivery.
		red, _ = ledgerReduce([]LedgerEntry{e("a", 1, ledgerDelivered, 1, 10, 11), e("b", 1, ledgerSuppressed, 1, 10, 0)})
		if len(red.DuplicateDeliveries) != 0 || len(red.Records) != 1 || red.Records[0].Entry.Outcome != ledgerDelivered {
			t.Fatalf("%+v", red)
		}
	})
	t.Run("late delivery of older source evidence is excluded and never current", func(t *testing.T) {
		newer := e("n", 1, ledgerDelivered, 5, 20, 21)
		newer.Kind, newer.Ordinal = notify.KindWorseImpact, 1
		late := e("l", 1, ledgerDelivered, 2, 15, 30)
		red, err := ledgerReduce([]LedgerEntry{late, newer})
		if err != nil || len(red.Late) != 1 || red.Late[0].Entry.AttemptID != "l" || len(red.Records) != 1 || red.Records[0].Entry.AttemptID != "n" || red.Stats.Late != 1 {
			t.Fatalf("%v %+v", err, red)
		}
		// Delivery order matters: the same entries delivered the other way round
		// (older first, newer after) are both current.
		late.DeliveredAt = 10
		red, _ = ledgerReduce([]LedgerEntry{late, newer})
		if len(red.Late) != 0 || len(red.Records) != 2 {
			t.Fatalf("%+v", red)
		}
		// An undelivered stale record is not a late delivery.
		late.Outcome, late.DeliveredAt, late.Suppression = ledgerSuppressed, 0, notify.CodeSnoozed
		late.AttemptID = "l2"
		red, _ = ledgerReduce([]LedgerEntry{newer, late})
		if red.Stats.Late != 0 {
			t.Fatalf("%+v", red)
		}
	})
	t.Run("one attempt identifier for two decisions is a conflict finding", func(t *testing.T) {
		x, y := e("a", 1, ledgerDelivered, 1, 10, 11), e("a", 1, ledgerDelivered, 1, 10, 11)
		y.Ordinal = 9
		red, err := ledgerReduce([]LedgerEntry{x, y})
		if err != nil || len(red.Findings) != 1 || red.Findings[0].Code != "ledger_attempt_conflict" || !red.Findings[0].Blocker {
			t.Fatalf("%v %+v", err, red.Findings)
		}
		z := e("a", 1, ledgerFailed, 1, 10, 11)
		red, _ = ledgerReduce([]LedgerEntry{x, z})
		if len(red.Findings) != 1 || red.Findings[0].Code != "ledger_attempt_conflict" {
			t.Fatalf("two outcomes for one attempt: %+v", red.Findings)
		}
	})
	t.Run("delivery before its event is a clock inversion finding", func(t *testing.T) {
		red, err := ledgerReduce([]LedgerEntry{e("a", 1, ledgerDelivered, 1, 100, 50)})
		if err != nil || len(red.Findings) != 1 || red.Findings[0].Code != "ledger_time_inversion" || !red.Findings[0].Blocker {
			t.Fatalf("%v %+v", err, red.Findings)
		}
	})
	t.Run("input order never changes the reduction", func(t *testing.T) {
		in := []LedgerEntry{e("a", 1, ledgerFailed, 1, 10, 11), e("a", 2, ledgerDelivered, 1, 10, 12), e("b", 1, ledgerDelivered, 3, 10, 14), e("c", 1, ledgerDelivered, 1, 5, 40)}
		want, _ := ledgerReduce(in)
		rng := rand.New(rand.NewPCG(7, 11))
		for i := 0; i < 25; i++ {
			sh := append([]LedgerEntry{}, in...)
			rng.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
			got, _ := ledgerReduce(sh)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("order dependent:\n%+v\n%+v", got, want)
			}
		}
	})
	t.Run("malformed entries are refused", func(t *testing.T) {
		good := e("a", 1, ledgerDelivered, 1, 10, 11)
		zero := model.ID{}
		for name, mut := range map[string]func(*LedgerEntry){
			"kind":             func(x *LedgerEntry) { x.Kind = "page" },
			"entity":           func(x *LedgerEntry) { x.Entity.ID = model.ID{} },
			"entity kind":      func(x *LedgerEntry) { x.Entity.Kind = "host" },
			"outcome":          func(x *LedgerEntry) { x.Outcome = "sent" },
			"trigger":          func(x *LedgerEntry) { x.Trigger = "cron" },
			"attempt zero":     func(x *LedgerEntry) { x.Attempt = 0 },
			"attempt id":       func(x *LedgerEntry) { x.AttemptID = "has space" },
			"empty attempt id": func(x *LedgerEntry) { x.AttemptID = "" },
			"event time":       func(x *LedgerEntry) { x.EventTime = 0 },
			"zero recipient":   func(x *LedgerEntry) { x.Recipient = &zero },
			"delivered no time": func(x *LedgerEntry) {
				x.DeliveredAt = 0
			},
			"suppressed no code": func(x *LedgerEntry) { x.Outcome, x.DeliveredAt, x.Suppression = ledgerSuppressed, 0, "" },
			"delivered with suppression": func(x *LedgerEntry) {
				x.Suppression = notify.CodeMaintenance
			},
			"unknown suppression": func(x *LedgerEntry) { x.Outcome, x.DeliveredAt, x.Suppression = ledgerSuppressed, 0, "paused" },
		} {
			x := good
			mut(&x)
			if _, err := ledgerReduce([]LedgerEntry{x}); err == nil {
				t.Fatalf("%s accepted", name)
			}
		}
		if _, err := ledgerReduce([]LedgerEntry{good}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("an older canonical source version after a late legacy delivery fails the ordering check", func(t *testing.T) {
		f := newPolicyFixture(t)
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		for i := range ds {
			if ds[i].At >= policyT0+160*policyMin {
				ds[i].Decision.SourceVersion = 1 // canonical never saw the newest source versions
			}
		}
		legacy := policyLegacy(policyDecisions(t, c))
		legacy = policyAdd(legacy, LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 9, Recipient: &policyRcptA, EventTime: policyT0 + 155*policyMin, SourceVersion: 1, AttemptID: "late-1"})
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, CanonicalShadowEvidence{Decisions: ds}, f.approved())
		if policyStatus(r, policyCheckLate) != policyFail || policyReasons(r.Noise)[policyReasonSourceSkew] == 0 {
			t.Fatalf("late check %s noise %v", policyStatus(r, policyCheckLate), policyReasons(r.Noise))
		}
	})
}

func TestComparisonUnknownDenominatorNeverFakesRate(t *testing.T) {
	f := newPolicyFixture(t)
	rcpt := policyRcptA
	canonicalWith := func(basis notify.Basis, rate notify.RateState) CanonicalShadowEvidence {
		return CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{{At: policyT0, Basis: basis, Rate: rate, Decision: notify.ShadowDecision{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, DedupID: model.ID{0xd1}, Route: notify.RouteImmediate}}}}
	}
	legacy := func(trigger LedgerTrigger) LegacyEvidence {
		return LegacyEvidence{Ledger: []LedgerEntry{{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, AttemptID: "o", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: trigger}}}
	}
	if r := policyCompare(t, legacy(ledgerTriggerRateNoDenominator), canonicalWith(notify.BasisErrorRate, notify.RateNoDenominator), f.approved()); policyStatus(r, policyCheckDenominator) != policyFail {
		t.Fatalf("canonical adopted a rate with no denominator: %s", policyStatus(r, policyCheckDenominator))
	}
	if r := policyCompare(t, legacy(ledgerTriggerCount), canonicalWith(notify.BasisErrorRate, notify.RateStale), f.approved()); policyStatus(r, policyCheckDenominator) != policyFail {
		t.Fatalf("an unknown rate state interrupted: %s", policyStatus(r, policyCheckDenominator))
	}
	if r := policyCompare(t, legacy(ledgerTriggerRateNoDenominator), canonicalWith(notify.BasisCount, notify.RateNoDenominator), f.approved()); policyStatus(r, policyCheckDenominator) != policyPass {
		t.Fatalf("a count basis never fakes a rate: %s", policyStatus(r, policyCheckDenominator))
	}
	if r := policyCompare(t, legacy(ledgerTriggerRateNoDenominator), canonicalWith(notify.BasisErrorRate, notify.RateKnown), f.approved()); policyStatus(r, policyCheckDenominator) != policyPass {
		t.Fatalf("a known rate is a rate: %s", policyStatus(r, policyCheckDenominator))
	}
	if r := policyCompare(t, legacy(ledgerTriggerRateNoDenominator), canonicalWith("", ""), f.approved()); policyStatus(r, policyCheckDenominator) != policyUnverified || r.Verdict == policyVerdictReconciled {
		t.Fatalf("a basis nobody recorded cannot be verified: %s %s", policyStatus(r, policyCheckDenominator), r.Verdict)
	}
	if r := policyCompare(t, legacy(ledgerTriggerCount), canonicalWith(notify.BasisCount, notify.RateNotApplicable), f.approved()); policyStatus(r, policyCheckDenominator) != policyNotExercised {
		t.Fatalf("nothing about denominators was exercised: %s", policyStatus(r, policyCheckDenominator))
	}
}

func TestComparisonLedgerRecipientsAreKeyedHashes(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	raw := "oncall.person@example.invalid"
	a, err := LedgerRecipientKey(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := LedgerRecipientKey(key, " "+raw+"\n"); a != b {
		t.Fatal("surrounding whitespace must not change the pseudonym")
	}
	if b, _ := LedgerRecipientKey(key, "other.person@example.invalid"); a == b {
		t.Fatal("different recipients collide")
	}
	if b, _ := LedgerRecipientKey([]byte("fedcba9876543210fedcba9876543210"), raw); a == b {
		t.Fatal("the pseudonym does not depend on the key")
	}
	if strings.Contains(a.String(), "oncall") || a == (model.ID{}) {
		t.Fatal("pseudonym leaks or is zero")
	}
	if _, err := LedgerRecipientKey([]byte("short"), raw); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := LedgerRecipientKey(key, "  "); err == nil {
		t.Fatal("an empty handle was accepted")
	}
	// A raw address cannot even be decoded into a ledger entry.
	var e LedgerEntry
	if err := json.Unmarshal([]byte(`{"recipient_key":"`+raw+`"}`), &e); err == nil {
		t.Fatal("raw address decoded into a recipient key")
	}
	// Reports and summaries carry the pseudonym and never the handle.
	f := newPolicyFixture(t)
	rep := f.journey()
	rep.Steps[0] = f.dest(a, policyT0) // the destination IS the keyed pseudonym
	c := f.canonical(rep)
	legacy := policyLegacy(policyDecisions(t, c))
	for i := range legacy {
		if legacy[i].Kind == notify.KindWorseImpact { // the old owner was snoozed, the canonical stream interrupts
			legacy[i].Outcome, legacy[i].Suppression, legacy[i].DeliveredAt = ledgerSuppressed, notify.CodeSnoozed, 0
		}
	}
	acks, life := policyJourneyFacts()
	r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
	private, _ := json.Marshal(r)
	public, _ := json.Marshal(PolicyPublic(r))
	if !strings.Contains(string(private), a.String()) {
		t.Fatal("the private report should name the keyed pseudonym")
	}
	for _, b := range [][]byte{private, public} {
		if strings.Contains(string(b), "oncall") || strings.Contains(string(b), "example.invalid") {
			t.Fatalf("raw handle in output: %s", b)
		}
	}
	if strings.Contains(string(public), a.String()) {
		t.Fatal("the public summary carries a recipient key")
	}
}

func TestComparisonPublicProjectionIsClosedAllowlist(t *testing.T) {
	typ := reflect.TypeOf(PolicyPublicSummary{})
	var walk func(reflect.Type, string)
	walk = func(ty reflect.Type, path string) {
		switch ty.Kind() {
		case reflect.Int, reflect.Bool:
		case reflect.String:
			if ty != reflect.TypeOf(PolicyVerdict("")) {
				t.Errorf("%s: free-form string field", path)
			}
		case reflect.Map:
			if ty.Key().Kind() != reflect.String || ty.Elem().Kind() != reflect.Int {
				t.Errorf("%s: map is not enum->count", path)
			}
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				walk(ty.Field(i).Type, path+"."+ty.Field(i).Name)
			}
		default:
			t.Errorf("%s: kind %s is not allowlisted", path, ty.Kind())
		}
	}
	walk(typ, "PolicyPublicSummary")
	l, c, a := policyFullWindow(t)
	r := policyCompare(t, l, c, a)
	s := PolicyPublic(r)
	if s.SchemaVersion != 1 || s.Verdict != r.Verdict || s.Intentional != len(r.Intentional) || s.Compared != r.Compared || s.ChecksPassed != len(r.Checks) || s.CustomerAcceptance {
		t.Fatalf("%+v", s)
	}
	for reason := range s.ByReason {
		if _, ok := policyReasonTable[PolicyReason(reason)]; !ok {
			t.Fatalf("reason key %q is not in the closed table", reason)
		}
	}
	if s.ByReason[string(policyReasonQueueCadence)] != 5 {
		t.Fatalf("by reason %v", s.ByReason)
	}
	b, _ := json.Marshal(s)
	for _, id := range []string{policyInc.ID.String(), policyIss.ID.String(), policyRcptA.String(), "owner-1", "planned database"} {
		if strings.Contains(string(b), id) {
			t.Fatalf("public summary contains %q", id)
		}
	}
	// The private report must not carry human reason text either.
	pb, _ := json.Marshal(r)
	for _, text := range []string{"planned database maintenance", "owner reviewed", "customer paging rota"} {
		if strings.Contains(string(pb), text) {
			t.Fatalf("private report echoes reason text %q", text)
		}
	}
}

func TestComparisonEmptyOrRefusedEvidenceNeverLooksLikeParity(t *testing.T) {
	f := newPolicyFixture(t)
	if r := policyCompare(t, LegacyEvidence{}, CanonicalShadowEvidence{}, f.approved()); r.Verdict != policyVerdictInsufficient {
		t.Fatalf("empty vs empty = %s", r.Verdict)
	}
	if _, err := ComparePolicy(context.Background(), LegacyEvidence{}, CanonicalShadowEvidence{}, ApprovedPolicy{Config: f.cfg}); err == nil {
		t.Fatal("a zero policy revision was accepted")
	}
	bad := f.cfg
	bad.RateBasisPoints = 20000
	if _, err := ComparePolicy(context.Background(), LegacyEvidence{}, CanonicalShadowEvidence{}, ApprovedPolicy{Revision: 1, Config: bad}); err == nil {
		t.Fatal("an impossible threshold was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ComparePolicy(ctx, LegacyEvidence{}, CanonicalShadowEvidence{}, f.approved()); err == nil {
		t.Fatal("cancelled context ignored")
	}
	t.Run("a refused canonical event is a blocker not silence", func(t *testing.T) {
		rep := f.journey()
		rep.Steps[1].Event.Org = model.ID{0x77} // an event of another organization
		c := f.canonical(rep)
		r := policyCompare(t, LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, f.canonical(f.journey())))}, c, f.approved())
		if !policyHasFinding(r, "canonical_event_refused") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v %s", r.Findings, r.Verdict)
		}
	})
	t.Run("shadow replay under another policy revision or config", func(t *testing.T) {
		rep := f.journey()
		rep.Steps[1].Event.PolicyRef.Revision = 2
		cfg := f.cfg
		cfg.MinFailures = 9
		rep.Steps[2].Event.PolicyRef.Config = &cfg
		r := policyCompare(t, LegacyEvidence{}, f.canonical(rep), f.approved())
		if !policyHasFinding(r, "policy_revision_mismatch") || !policyHasFinding(r, "policy_config_mismatch") || r.Verdict != policyVerdictBlocked {
			t.Fatalf("%v", r.Findings)
		}
	})
	t.Run("a replay without its identity is refused", func(t *testing.T) {
		c := f.canonical(f.journey())
		c.Org = model.ID{}
		if _, err := ComparePolicy(context.Background(), LegacyEvidence{}, c, f.approved()); err == nil {
			t.Fatal("replay without org accepted")
		}
	})
}

func TestComparisonRecordedDecisionsEqualReplayedDecisions(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	ds := policyDecisions(t, c)
	acks, life := policyJourneyFacts()
	l := LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: life}
	a, err := ComparePolicy(context.Background(), l, c, f.approved())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComparePolicy(context.Background(), l, CanonicalShadowEvidence{Decisions: ds}, f.approved())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || a.Compared == 0 || a.Identical != a.Compared || len(policyAllDiffs(a)) != 0 {
		t.Fatalf("replay and recorded disagree or differ from identical legacy:\n%+v\n%+v", a, b)
	}
	if a.Verdict == policyVerdictReconciled || PolicyPublic(a).CustomerAcceptance {
		t.Fatalf("parity with unexercised checks claimed more: %s", a.Verdict)
	}
	// Replay and recorded evidence may be combined; a decision seen twice is one.
	both := c
	both.Decisions = ds
	if r, err := ComparePolicy(context.Background(), l, both, f.approved()); err != nil || !reflect.DeepEqual(r, a) {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestComparisonReportIsDeterministicUnderReordering(t *testing.T) {
	l, c, a := policyFullWindow(t)
	want, _ := json.Marshal(policyCompare(t, l, c, a))
	rng := rand.New(rand.NewPCG(3, 5))
	ds := policyDecisions(t, c)
	for i := 0; i < 15; i++ {
		l2 := l
		l2.Ledger = append([]LedgerEntry{}, l.Ledger...)
		rng.Shuffle(len(l2.Ledger), func(x, y int) { l2.Ledger[x], l2.Ledger[y] = l2.Ledger[y], l2.Ledger[x] })
		c2 := CanonicalShadowEvidence{Decisions: append([]PolicyDecisionAt{}, ds...)}
		rng.Shuffle(len(c2.Decisions), func(x, y int) { c2.Decisions[x], c2.Decisions[y] = c2.Decisions[y], c2.Decisions[x] })
		a2 := a
		a2.Approvals = append([]PolicyApproval{}, a.Approvals...)
		rng.Shuffle(len(a2.Approvals), func(x, y int) { a2.Approvals[x], a2.Approvals[y] = a2.Approvals[y], a2.Approvals[x] })
		got, _ := json.Marshal(policyCompare(t, l2, c2, a2))
		if string(got) != string(want) {
			t.Fatalf("order dependent report:\n%s\n%s", got, want)
		}
	}
}

func TestComparisonCommand(t *testing.T) {
	// privateDirectory (shared with intake) needs a valid local Git context.
	targets, _ := fixture(t)
	t.Chdir(targets.Targets[0].Repository)
	l, c, a := policyFullWindow(t)
	inputs := t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(inputs, name)
		if err := writeExclusive(p, v); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lp, cp, ap := write("legacy.json", l), write("canonical.json", c), write("approved.json", a)
	run := func(private, summary string, extra ...string) error {
		args := []string{"--legacy", lp, "--canonical", cp, "--approved-policy", ap, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
		return runPolicyCompare(context.Background(), append(args, extra...))
	}
	t.Run("reconciled window writes private report and closed summary", func(t *testing.T) {
		private := privateTempDir(t)
		summary := filepath.Join(inputs, "summary.json")
		if err := run(private, summary); err != nil {
			t.Fatal(err)
		}
		var got PolicyPublicSummary
		if err := readInput(summary, &got); err != nil {
			t.Fatal(err)
		}
		if got.Verdict != policyVerdictReconciled || got.CustomerAcceptance || got.Intentional != 11 {
			t.Fatalf("%+v", got)
		}
		var rep PolicyReport
		if err := readInput(filepath.Join(private, "policy-report.json"), &rep); err != nil || rep.Verdict != policyVerdictReconciled {
			t.Fatalf("%v %+v", err, rep.Verdict)
		}
		if err := run(private, filepath.Join(inputs, "summary2.json")); err == nil {
			t.Fatal("overwrote the private report")
		}
	})
	t.Run("an unreconciled window still writes evidence and fails the command", func(t *testing.T) {
		l2 := l
		l2.Ledger = policyAdd(append([]LedgerEntry{}, l.Ledger...), LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 9, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0 + 200*policyMin, SourceVersion: 9})
		blocked := write("legacy-blocked.json", l2)
		private := privateTempDir(t)
		summary := filepath.Join(inputs, "blocked-summary.json")
		args := []string{"--legacy", blocked, "--canonical", cp, "--approved-policy", ap, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
		if err := runPolicyCompare(context.Background(), args); err == nil || !strings.Contains(err.Error(), string(policyVerdictBlocked)) {
			t.Fatalf("blocked comparison exited cleanly: %v", err)
		}
		var got PolicyPublicSummary
		if err := readInput(summary, &got); err != nil || got.Verdict != policyVerdictBlocked || got.MissingUrgency == 0 {
			t.Fatalf("%v %+v", err, got)
		}
	})
	t.Run("refuses bad invocations", func(t *testing.T) {
		private := privateTempDir(t)
		if err := runPolicyCompare(context.Background(), nil); err == nil {
			t.Fatal("no flags accepted")
		}
		if err := runPolicyCompare(context.Background(), []string{"--legacy", lp}); err == nil {
			t.Fatal("partial flags accepted")
		}
		if err := run(private, filepath.Join(inputs, "s3.json"), "--timeout", "0s"); err == nil {
			t.Fatal("zero timeout accepted")
		}
		if err := run(private, filepath.Join(inputs, "s3.json"), "--timeout", "2h"); err == nil {
			t.Fatal("excessive timeout accepted")
		}
		if err := run(private, filepath.Join(inputs, "s3.json"), "stray"); err == nil {
			t.Fatal("stray argument accepted")
		}
		if err := run(filepath.Join(inputs, "missing-dir"), filepath.Join(inputs, "s3.json")); err == nil {
			t.Fatal("missing private directory accepted")
		}
		junk := filepath.Join(inputs, "junk.json")
		if err := os.WriteFile(junk, []byte(`{"ledger": 1, "unknown": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--legacy", junk, "--canonical", cp, "--approved-policy", ap, "--private-output", private, "--public-summary", filepath.Join(inputs, "s4.json"), "--private-directory-acl-confirmed"}
		if err := runPolicyCompare(context.Background(), args); err == nil {
			t.Fatal("malformed input accepted")
		}
		if _, err := os.Stat(filepath.Join(private, "policy-report.json")); err == nil {
			t.Fatal("a refused invocation left a private report")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		args = []string{"--legacy", lp, "--canonical", cp, "--approved-policy", ap, "--private-output", private, "--public-summary", filepath.Join(inputs, "s5.json"), "--private-directory-acl-confirmed"}
		if err := runPolicyCompare(ctx, args); err == nil {
			t.Fatal("cancelled context ignored")
		}
		if _, err := os.Stat(filepath.Join(inputs, "s5.json")); err == nil {
			t.Fatal("a cancelled run wrote a summary")
		}
	})
}

// policyMaintenanceCase: canonical suppresses the worse impact inside a window
// the old owner paged straight through.
func policyMaintenanceCase(t *testing.T) (*policyFixture, CanonicalShadowEvidence, []LedgerEntry, model.UnixNano) {
	f := newPolicyFixture(t)
	c := f.canonical(f.maintenanceReplay())
	legacy := policyLegacy(policyDecisions(t, c))
	var at model.UnixNano
	for i := range legacy {
		if legacy[i].Suppression == notify.CodeMaintenance {
			legacy[i].Outcome, legacy[i].Suppression, legacy[i].DeliveredAt = ledgerDelivered, notify.CodeNone, legacy[i].EventTime+1
			at = legacy[i].EventTime
		}
	}
	if at == 0 {
		t.Fatal("no suppressed decision to flip")
	}
	return f, c, legacy, at
}

func TestComparisonWindowBoundariesAndTypes(t *testing.T) {
	f, c, legacy, at := policyMaintenanceCase(t)
	win := func(typ notify.ActionType, from, until model.UnixNano) PolicyReport {
		return policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{{Type: typ, Reason: "planned work", From: from, Until: until}}}, c, f.approved())
	}
	if r := win(notify.ActionMaintenance, at, at+policyMin); policyReasons(r.Noise)[policyReasonIgnoredWindow] == 0 || len(r.MissingUrgency) != 0 {
		t.Fatalf("a window that starts at the decision time covers it: %v %v", policyReasons(r.Noise), policyReasons(r.MissingUrgency))
	}
	if r := win(notify.ActionMaintenance, at+1, at+policyMin); policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
		t.Fatal("a window that starts after the decision excused it")
	}
	if r := win(notify.ActionMaintenance, at-policyMin, at); policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
		t.Fatal("a window that ended at the decision time excused it")
	}
	if r := win(notify.ActionSnooze, at-policyMin, at+policyMin); policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
		t.Fatal("a snooze record excused a maintenance suppression")
	}
	other := notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x99}}
	r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{{Type: notify.ActionMaintenance, Entity: &other, Reason: "planned work", From: at - policyMin, Until: at + policyMin}}}, c, f.approved())
	if policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
		t.Fatal("a window scoped to another entity excused the silence")
	}
	ent := policyInc
	r = policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{{Type: notify.ActionMaintenance, Entity: &ent, Reason: "planned work", From: at - policyMin, Until: at + policyMin}}}, c, f.approved())
	if len(r.MissingUrgency) != 0 {
		t.Fatalf("an entity-scoped window of this entity did not excuse the silence: %v", r.MissingUrgency)
	}
	if r.Identical != r.Compared-1 {
		t.Fatalf("exactly one compared decision differs: identical %d of %d", r.Identical, r.Compared)
	}
}

func TestComparisonSnoozeSuppressionNeedsASnoozeRecord(t *testing.T) {
	f := newPolicyFixture(t)
	m := policyMin
	ent := policyInc
	rcpt := policyRcptA
	// A recorded canonical decision suppressed by a snooze; the old owner paged.
	c := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{{At: policyT0 + 15*m, Decision: notify.ShadowDecision{Entity: policyInc, Kind: notify.KindRecovery, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt,
		SourceVersion: 2, DedupID: model.ID{0xa7}, Suppression: notify.CodeSnoozed, Route: notify.RouteImmediate}}}}
	legacy := []LedgerEntry{{Entity: policyInc, Kind: notify.KindRecovery, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, AttemptID: "r", Attempt: 1, EventTime: policyT0 + 15*m, DeliveredAt: policyT0 + 15*m + 1,
		SourceVersion: 2, Outcome: ledgerDelivered, Trigger: ledgerTriggerSourceRecovery}}
	snooze := PolicyWindow{Type: notify.ActionSnooze, Entity: &ent, Reason: "waiting for the vendor", From: policyT0 + 5*m, Until: policyT0 + 60*m}
	if r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{snooze}}, c, f.approved()); len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonIgnoredWindow] != 1 {
		t.Fatalf("recorded snooze: %v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise))
	}
	maint := snooze
	maint.Type = notify.ActionMaintenance
	if r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{maint}}, c, f.approved()); policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] != 1 {
		t.Fatal("a maintenance record excused a snooze")
	}
	if r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved()); policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] != 1 {
		t.Fatal("a snooze nobody recorded excused a silence")
	}
	// A decision suppressed because no destination exists is not a window.
	c.Decisions[0].Decision.Suppression = notify.CodeNoDestination
	if r := policyCompare(t, LegacyEvidence{Ledger: legacy, Windows: []PolicyWindow{snooze}}, c, f.approved()); policyReasons(r.MissingUrgency)[policyReasonUrgentLost] != 1 {
		t.Fatalf("a missing destination was excused by a window: %v", policyReasons(r.MissingUrgency))
	}
}

func TestComparisonEveryControlKindIsComparedAgainstItsOwnConfigField(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	acks, life := policyJourneyFacts()
	for i, ctl := range policyControls() {
		if ctl.Kind == policyControlOther {
			continue
		}
		t.Run(ctl.Kind, func(t *testing.T) {
			controls := policyControls()
			switch ctl.Kind {
			case policyControlCriticalCodes:
				controls[i].Codes = append(controls[i].Codes, "other_code")
			case policyControlDigestZone:
				controls[i].Zone = "Europe/Berlin"
			default:
				controls[i].Value++
			}
			disp := policyDispositions()
			for j := range disp {
				if disp[j].Control == ctl.ID {
					disp[j] = PolicyControlDisposition{Control: ctl.ID, Disposition: policyDispPreserved}
				}
			}
			a := f.approved()
			a.Controls = disp
			r := policyCompare(t, LegacyEvidence{Ledger: policyLegacy(policyDecisions(t, c)), Acks: acks, Lifecycle: life, Controls: controls}, c, a)
			mismatches := 0
			for _, fd := range r.Findings {
				if fd.Code == "control_preserved_mismatch" && fd.Subject == ctl.ID {
					mismatches++
				}
			}
			if mismatches != 1 {
				t.Fatalf("%s differing from the configuration was preserved: %v", ctl.Kind, r.Findings)
			}
		})
	}
}

func TestComparisonCanonicalReminderAfterAckFailsAndOrderingEdges(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	ds := policyDecisions(t, c)
	acks, life := policyJourneyFacts()
	// A recorded canonical reminder for the acknowledged impact after the ACK.
	extra := PolicyDecisionAt{At: policyT0 + 140*policyMin, Decision: notify.ShadowDecision{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, Recipient: &policyRcptA, SourceVersion: 1, DedupID: model.ID{0xee}, Route: notify.RouteImmediate}}
	r := policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: life}, CanonicalShadowEvidence{Decisions: append(append([]PolicyDecisionAt{}, ds...), extra)}, f.approved())
	if policyStatus(r, policyCheckAck) != policyFail {
		t.Fatalf("a canonical reminder after the ACK passed: %s", policyStatus(r, policyCheckAck))
	}
	// Before the ACK the same reminder is fine.
	extra.At = policyT0 + 79*policyMin
	r = policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: life}, CanonicalShadowEvidence{Decisions: append(append([]PolicyDecisionAt{}, ds...), extra)}, f.approved())
	if policyStatus(r, policyCheckAck) != policyPass {
		t.Fatalf("a reminder before the ACK failed: %s", policyStatus(r, policyCheckAck))
	}
	// A worse impact the ACK did not cover is not a post-ACK reminder either way.
	rcpt := policyRcptA
	e := func(id string, k notify.Kind, ord uint64, sv uint64, at model.UnixNano) LedgerEntry {
		return LedgerEntry{Entity: policyInc, Kind: k, ImpactRevision: 1, Ordinal: ord, Recipient: &rcpt, AttemptID: id, Attempt: 1, EventTime: at, DeliveredAt: at, SourceVersion: sv, Outcome: ledgerDelivered, Trigger: ledgerTriggerOther}
	}
	t.Run("equal source versions are both current", func(t *testing.T) {
		red, err := ledgerReduce([]LedgerEntry{e("a", notify.KindReminder, 1, 2, 10), e("b", notify.KindWorseImpact, 1, 2, 20)})
		if err != nil || len(red.Late) != 0 || len(red.Records) != 2 {
			t.Fatalf("%v %+v", err, red)
		}
	})
	t.Run("an unknown outcome may have been delivered", func(t *testing.T) {
		x := e("u", notify.KindWorseImpact, 1, 2, 20)
		x.Outcome = ledgerUnknown
		red, err := ledgerReduce([]LedgerEntry{x})
		if err != nil || red.Stats.Deliveries != 1 || len(red.Records) != 1 {
			t.Fatalf("%v %+v", err, red)
		}
		g := newPolicyFixture(t)
		cc := g.canonical(PolicyReplay{Subject: policyInc, Steps: []PolicyStep{g.dest(policyRcptA, policyT0), g.incident(policyT0, 1, notify.SeverityMajor, 1, notify.SourceFiring)}})
		legacy := policyAdd(policyLegacy(policyDecisions(t, cc)), LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 7, Ordinal: 1, Recipient: &rcpt, EventTime: policyT0 + 20, SourceVersion: 1, Outcome: ledgerUnknown, DeliveredAt: policyT0 + 21})
		if r := policyCompare(t, LegacyEvidence{Ledger: legacy}, cc, g.approved()); policyReasons(r.MissingUrgency)[policyReasonUrgentLost] != 1 {
			t.Fatalf("an unknown outcome was not treated as an interrupt: %v", policyReasons(r.MissingUrgency))
		}
		// A failed attempt that never reached the provider interrupted nobody.
		legacy[len(legacy)-1].Outcome = ledgerFailed
		if r := policyCompare(t, LegacyEvidence{Ledger: legacy}, cc, g.approved()); len(r.MissingUrgency) != 0 || policyReasons(r.Inert)[policyReasonLegacySuppressedOnly] != 1 {
			t.Fatalf("a failed delivery counted as urgency: %v %v", r.MissingUrgency, policyReasons(r.Inert))
		}
	})
	t.Run("an unknown attempt beats a later failed one", func(t *testing.T) {
		x, y := e("u", notify.KindWorseImpact, 1, 2, 20), e("u", notify.KindWorseImpact, 1, 2, 20)
		x.Outcome = ledgerUnknown
		y.Attempt, y.Outcome, y.DeliveredAt = 2, ledgerFailed, 22
		red, err := ledgerReduce([]LedgerEntry{x, y})
		if err != nil || len(red.Records) != 1 || red.Records[0].Entry.Outcome != ledgerUnknown {
			t.Fatalf("%v %+v", err, red.Records)
		}
	})
}

func TestComparisonUngroupedCanonicalOpeningsFailTheGroupingCheck(t *testing.T) {
	f := newPolicyFixture(t)
	rcpt := policyRcptA
	open := func(ord uint64, id byte) PolicyDecisionAt {
		return PolicyDecisionAt{At: policyT0, Decision: notify.ShadowDecision{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: ord, Recipient: &rcpt, DedupID: model.ID{0xf0, id}, Route: notify.RouteImmediate}}
	}
	legacy := LegacyEvidence{Ledger: []LedgerEntry{
		{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, AttemptID: "o1", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerPerOccurrence},
		{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 2, Recipient: &rcpt, AttemptID: "o2", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerPerOccurrence},
	}}
	// The canonical owner paged once per occurrence too: it did not group.
	r := policyCompare(t, legacy, CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{open(1, 1), open(2, 2)}}, f.approved())
	if policyStatus(r, policyCheckGrouping) != policyFail {
		t.Fatalf("ungrouped canonical openings passed: %s", policyStatus(r, policyCheckGrouping))
	}
	// One opening for the same group is grouped, and the legacy repeat is noise.
	r = policyCompare(t, legacy, CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{open(1, 1)}}, f.approved())
	if policyStatus(r, policyCheckGrouping) != policyPass || policyReasons(r.Noise)[policyReasonRepeatOccurrence] != 1 {
		t.Fatalf("%s %v", policyStatus(r, policyCheckGrouping), policyReasons(r.Noise))
	}
	// Openings of different impact revisions are different notifications.
	o3 := open(1, 3)
	o3.Decision.ImpactRevision = 2
	r = policyCompare(t, legacy, CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{open(1, 1), o3}}, f.approved())
	if policyStatus(r, policyCheckGrouping) != policyPass {
		t.Fatalf("distinct impact revisions are not ungrouped: %s", policyStatus(r, policyCheckGrouping))
	}
}

func TestComparisonVerdictNeedsEvidenceOnBothSides(t *testing.T) {
	f := newPolicyFixture(t)
	rcpt := policyRcptA
	canon := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(rcpt, 20260310, policyT0, notify.CodeNone)}}
	legacyOnly := LegacyEvidence{Ledger: []LedgerEntry{{Entity: policyInc, Kind: notify.KindDigest, ImpactRevision: 1, Ordinal: 20260310, Recipient: &rcpt, AttemptID: "d", Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerOther}}}
	own := policyOwnership()
	canonOnly := policyCompare(t, LegacyEvidence{Ownership: own}, canon, f.approved())
	if canonOnly.Verdict != policyVerdictInsufficient {
		t.Fatalf("canonical decisions against an empty legacy ledger = %s", canonOnly.Verdict)
	}
	legacyOnly.Ownership = own
	if r := policyCompare(t, legacyOnly, CanonicalShadowEvidence{}, f.approved()); r.Verdict != policyVerdictInsufficient {
		t.Fatalf("a legacy ledger against no canonical decisions = %s", r.Verdict)
	}
	if r := policyCompare(t, legacyOnly, canon, f.approved()); r.Verdict == policyVerdictInsufficient {
		t.Fatalf("both sides present = %s", r.Verdict)
	}
}

func TestComparisonPublicSummaryCountsEveryClassAndStatus(t *testing.T) {
	f := newPolicyFixture(t)
	c := f.canonical(f.journey())
	ds := policyDecisions(t, c)
	acks, life := policyJourneyFacts()
	legacy := policyAdd(policyLegacy(ds), LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 8, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0 + 200*policyMin, SourceVersion: 8})
	r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
	s := PolicyPublic(r)
	var failed, unverified, notExercised, passed int
	for _, ck := range r.Checks {
		switch ck.Status {
		case policyFail:
			failed++
		case policyUnverified:
			unverified++
		case policyNotExercised:
			notExercised++
		case policyPass:
			passed++
		}
	}
	blockers, others := 0, 0
	for _, fd := range r.Findings {
		if fd.Blocker {
			blockers++
		} else {
			others++
		}
	}
	if s.MissingUrgency != 1 || s.MissingUrgency != len(r.MissingUrgency) || s.ChecksFailed != failed || s.ChecksUnverified != unverified || s.ChecksNotExercised != notExercised || s.ChecksPassed != passed ||
		s.BlockerFindings != blockers || s.OtherFindings != others || s.Verdict != policyVerdictBlocked || s.Identical != r.Identical || s.ByReason[string(policyReasonUrgentLost)] != 1 {
		t.Fatalf("%+v vs %+v", s, r)
	}
	if failed == 0 && blockers == 0 {
		t.Fatal("the scenario should also fail something besides the lost page")
	}
}

func TestComparisonQueueDigestRecipientsAndSuppressionCodes(t *testing.T) {
	f := newPolicyFixture(t)
	a, b := policyRcptA, policyRcptB
	dig := func(r model.ID, id string) LedgerEntry {
		return LedgerEntry{Entity: policyInc, Kind: notify.KindDigest, ImpactRevision: 1, Ordinal: 20260310, Recipient: &r, AttemptID: id, Attempt: 1, EventTime: policyT0, DeliveredAt: policyT0 + 1, Outcome: ledgerDelivered, Trigger: ledgerTriggerOther}
	}
	t.Run("a digest recipient only one side reached is cadence not urgency", func(t *testing.T) {
		c := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(a, 20260310, policyT0, notify.CodeNone)}}
		r := policyCompare(t, LegacyEvidence{Ledger: []LedgerEntry{dig(a, "d1"), dig(b, "d2")}}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonDigestCadence] != 1 {
			t.Fatalf("%v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise))
		}
		db := policyDigest(b, 20260310, policyT0, notify.CodeNone)
		db.Decision.DedupID = model.ID{0xd8}
		c2 := CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{policyDigest(a, 20260310, policyT0, notify.CodeNone), db}}
		r = policyCompare(t, LegacyEvidence{Ledger: []LedgerEntry{dig(a, "d1")}}, c2, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonDigestCadence] != 1 {
			t.Fatalf("%v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise))
		}
	})
	t.Run("both sides suppressed", func(t *testing.T) {
		canon := func(code notify.Code) CanonicalShadowEvidence {
			return CanonicalShadowEvidence{Decisions: []PolicyDecisionAt{{At: policyT0, Decision: notify.ShadowDecision{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 2, Ordinal: 1, Recipient: &a, DedupID: model.ID{0xb7}, Suppression: code, Route: notify.RouteImmediate}}}}
		}
		legacy := func(out LedgerOutcome, code notify.Code) LegacyEvidence {
			e := LedgerEntry{Entity: policyInc, Kind: notify.KindWorseImpact, ImpactRevision: 2, Ordinal: 1, Recipient: &a, AttemptID: "w", Attempt: 1, EventTime: policyT0, Outcome: out, Suppression: code, Trigger: ledgerTriggerImpact}
			if out == ledgerFailed {
				e.DeliveredAt = policyT0 + 1
			}
			return LegacyEvidence{Ledger: []LedgerEntry{e}}
		}
		// Snoozed by the old owner, in maintenance for the canonical one: a different reason, same silence.
		r := policyCompare(t, legacy(ledgerSuppressed, notify.CodeSnoozed), canon(notify.CodeMaintenance), f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonSuppressionReason] != 1 {
			t.Fatalf("%v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise))
		}
		// The old owner's delivery failed and the canonical one is silenced: nobody was interrupted.
		r = policyCompare(t, legacy(ledgerFailed, ""), canon(notify.CodeMaintenance), f.approved())
		if len(r.MissingUrgency) != 0 || len(r.Noise) != 0 || policyReasons(r.Inert)[policyReasonCanonicalSuppressedOnly] != 1 {
			t.Fatalf("%v %v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise), policyReasons(r.Inert))
		}
	})
}

func TestComparisonLifecycleFactsAreNotInterchangeable(t *testing.T) {
	f := newPolicyFixture(t)
	rep := f.journey()
	rep.Steps = rep.Steps[:8] // ... through the source recovery, before any human resolution
	c := f.canonical(rep)
	ds := policyDecisions(t, c)
	recovered := []PolicyLifecycle{{Entity: policyInc, Type: policyLifecycleRecovered, At: policyT0 + 160*policyMin}}
	resolved := []PolicyLifecycle{{Entity: policyInc, Type: policyLifecycleResolved, At: policyT0 + 160*policyMin}}
	acks, _ := policyJourneyFacts()
	r := policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: recovered}, c, f.approved())
	if policyStatus(r, policyCheckRecovery) != policyNotExercised {
		t.Fatalf("a recovery announced for a recovery fact is consistent but not the whole separation: %s", policyStatus(r, policyCheckRecovery))
	}
	r = policyCompare(t, LegacyEvidence{Ledger: policyLegacy(ds), Acks: acks, Lifecycle: resolved}, c, f.approved())
	if policyStatus(r, policyCheckRecovery) != policyFail {
		t.Fatalf("a recovery announced for a resolution fact passed: %s", policyStatus(r, policyCheckRecovery))
	}
}

func TestComparisonRateAndRegressionInterruptOnlyWithTheirProvenance(t *testing.T) {
	f := newPolicyFixture(t)
	other := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x52}}
	rate := func(complete bool) PolicyReplay {
		return PolicyReplay{Subject: policyIss, Steps: []PolicyStep{f.dest(policyRcptA, policyT0),
			f.issue(policyT0, 1, "", 5, func(e *notify.IssueEvidence) {
				e.Denominator = &notify.Denominator{Name: "http_requests_total", WindowStart: e.WindowStart, Operations: model.Uint64(40), Complete: complete}
			})}}
	}
	regression := func() PolicyReplay {
		step := f.issue(policyT0, 2, "", 5, func(e *notify.IssueEvidence) {
			e.Regression = &notify.Regression{Eligible: true, Occurrences: 5, AncestryKnown: true}
		})
		step.Event.Entity = &other
		return PolicyReplay{Subject: other, Steps: []PolicyStep{f.dest(policyRcptA, policyT0), step}}
	}
	opens := func(ds []PolicyDecisionAt, e notify.Entity) int {
		n := 0
		for _, d := range ds {
			if d.Decision.Entity == e && d.Decision.Kind == notify.KindOpen && d.Decision.Suppression == notify.CodeNone {
				n++
			}
		}
		return n
	}
	c := f.canonical(rate(true), regression())
	ds := policyDecisions(t, c)
	if opens(ds, policyIss) != 1 || opens(ds, other) != 1 {
		t.Fatalf("a known rate and a qualifying regression must interrupt: %d %d", opens(ds, policyIss), opens(ds, other))
	}
	legacy := policyLegacy(ds)
	for i := range legacy {
		switch legacy[i].Entity {
		case policyIss:
			legacy[i].Trigger = ledgerTriggerRate
		case other:
			legacy[i].Trigger = ledgerTriggerRegression
		}
	}
	r := policyCompare(t, LegacyEvidence{Ledger: legacy, Ownership: policyOwnership()}, c, f.approved())
	if len(policyAllDiffs(r)) != 0 || policyStatus(r, policyCheckInterrupts) != policyPass {
		t.Fatalf("identical interrupting behaviour: %v %s", policyAllDiffs(r), policyStatus(r, policyCheckInterrupts))
	}
	// The same evidence with an incomplete denominator is no rate: the canonical owner stays quiet.
	c2 := f.canonical(rate(false))
	if got := opens(policyDecisions(t, c2), policyIss); got != 0 {
		t.Fatalf("an incomplete denominator produced a rate page: %d", got)
	}
	page := func(trigger LedgerTrigger) LegacyEvidence {
		return LegacyEvidence{Ledger: policyAdd(policyLegacy(policyDecisions(t, c2)), LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &policyRcptA, EventTime: policyT0, Trigger: trigger}), Ownership: policyOwnership()}
	}
	if r := policyCompare(t, page(ledgerTriggerRateNoDenominator), c2, f.approved()); len(r.MissingUrgency) != 0 || policyReasons(r.Noise)[policyReasonFakeRate] != 1 {
		t.Fatalf("a rate the legacy tool computed without a denominator: %v %v", policyReasons(r.MissingUrgency), policyReasons(r.Noise))
	}
	// If the operator normalizes the legacy rule as a real rate, silence is lost urgency.
	if r := policyCompare(t, page(ledgerTriggerRate), c2, f.approved()); policyReasons(r.MissingUrgency)[policyReasonUrgentLost] != 1 || policyStatus(r, policyCheckInterrupts) != policyFail {
		t.Fatalf("%v %s", policyReasons(r.MissingUrgency), policyStatus(r, policyCheckInterrupts))
	}
}

func TestComparisonAckFactsAreOrderedByEventTime(t *testing.T) {
	f := newPolicyFixture(t)
	m := policyMin
	c := f.canonical(f.journey())
	ds := policyDecisions(t, c)
	_, life := policyJourneyFacts()
	// A reminder legacy sent BEFORE the ACK is not an ACK-suppressed reminder.
	legacy := policyAdd(policyLegacy(ds), LedgerEntry{Entity: policyInc, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, Recipient: &policyRcptA, EventTime: policyT0 + 30*m, SourceVersion: 1})
	acks := []PolicyAck{{Entity: policyInc, ImpactRevision: 1, At: policyT0 + 80*m}}
	r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life}, c, f.approved())
	if policyReasons(r.Noise)[policyReasonReminderCadence] != 1 || policyReasons(r.Noise)[policyReasonReminderAfterAck] != 0 {
		t.Fatalf("a reminder before the ACK was excused by it: %v", policyReasons(r.Noise))
	}
	// A canonical-only worse impact BEFORE a late-recorded ACK is not a worse impact after ACK.
	legacy = policyWithout(policyLegacy(ds), policyKindIs(notify.KindWorseImpact))
	late := []PolicyAck{{Entity: policyInc, ImpactRevision: 1, At: policyT0 + 200*m}}
	r = policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: late, Lifecycle: life}, c, f.approved())
	if policyReasons(r.Noise)[policyReasonExtraInterrupt] != 1 || policyReasons(r.Noise)[policyReasonWorseAfterAck] != 0 {
		t.Fatalf("%v", policyReasons(r.Noise))
	}
	// An ACK of the SAME impact is not a worsened impact after ACK either.
	same := []PolicyAck{{Entity: policyInc, ImpactRevision: 2, At: policyT0 + 100*m}}
	r = policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: same, Lifecycle: life}, c, f.approved())
	if policyReasons(r.Noise)[policyReasonWorseAfterAck] != 0 {
		t.Fatalf("%v", policyReasons(r.Noise))
	}
}

func TestComparisonCustomerRetainedClassIsNotLostUrgency(t *testing.T) {
	f := newPolicyFixture(t)
	retain := func(class string) []PolicyClassOwner {
		own := policyOwnership()
		for i := range own {
			if own[i].Class == class {
				own[i].Owner = policyOwnerCustomer
			}
		}
		return own
	}
	t.Run("a class the canonical owner does not send stays with the customer tool", func(t *testing.T) {
		rep := f.journey()
		var steps []PolicyStep
		for _, s := range rep.Steps {
			if s.Event.Kind != notify.EventTimer {
				steps = append(steps, s)
			}
		}
		rep.Steps = steps
		full := policyLegacy(policyDecisions(t, f.canonical(f.journey())))
		_, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: full, Lifecycle: life, Ownership: retain(policyClassReminder)}, f.canonical(rep), f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Inert)[policyReasonCustomerRetained] != 2 {
			t.Fatalf("retained reminders: blockers %v inert %v", policyReasons(r.MissingUrgency), policyReasons(r.Inert))
		}
		if policyHasFinding(r, "dual_normal_sender") || policyStatus(r, policyCheckOwnership) != policyPass {
			t.Fatalf("no second sender exists: %v %s", r.Findings, policyStatus(r, policyCheckOwnership))
		}
	})
	t.Run("a retained class does not excuse a silence of another class", func(t *testing.T) {
		f2, c, legacy, _ := policyMaintenanceCase(t)
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Ownership: retain(policyClassReminder)}, c, f2.approved())
		if policyReasons(r.MissingUrgency)[policyReasonSilencedNoWindow] == 0 {
			t.Fatalf("a reminder-class retention excused an urgent-class silence: %v", policyReasons(r.Inert))
		}
		r = policyCompare(t, LegacyEvidence{Ledger: legacy, Ownership: retain(policyClassUrgent)}, c, f2.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Inert)[policyReasonCustomerRetained] == 0 {
			t.Fatalf("the customer keeps the urgent class: %v %v", policyReasons(r.MissingUrgency), policyReasons(r.Inert))
		}
	})
	t.Run("a recipient only legacy reached in a retained class", func(t *testing.T) {
		c := f.canonical(f.journey())
		ds := policyDecisions(t, c)
		legacy := policyLegacy(ds)
		for _, e := range policyLegacy(ds) {
			if e.Recipient != nil && e.Kind == notify.KindReminder {
				x := e
				b := policyRcptB
				x.Recipient, x.AttemptID = &b, "b-"+e.AttemptID
				legacy = append(legacy, x)
			}
		}
		acks, life := policyJourneyFacts()
		r := policyCompare(t, LegacyEvidence{Ledger: legacy, Acks: acks, Lifecycle: life, Ownership: retain(policyClassReminder)}, c, f.approved())
		if len(r.MissingUrgency) != 0 || policyReasons(r.Inert)[policyReasonCustomerRetained] != 2 {
			t.Fatalf("blockers %v inert %v", policyReasons(r.MissingUrgency), policyReasons(r.Inert))
		}
	})
}

func TestComparisonGroupingCheckFailsWhenAPerOccurrencePageIsLost(t *testing.T) {
	f := newPolicyFixture(t)
	rcpt := policyRcptA
	c := f.canonical(f.journey()) // the canonical stream never opened the issue at all
	legacy := policyAdd(policyLegacy(policyDecisions(t, c)), LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 2, Recipient: &rcpt, EventTime: policyT0, Trigger: ledgerTriggerPerOccurrence})
	r := policyCompare(t, LegacyEvidence{Ledger: legacy}, c, f.approved())
	if policyReasons(r.MissingUrgency)[policyReasonUrgentLost] != 1 || policyStatus(r, policyCheckGrouping) != policyFail {
		t.Fatalf("%v %s", policyReasons(r.MissingUrgency), policyStatus(r, policyCheckGrouping))
	}
}
