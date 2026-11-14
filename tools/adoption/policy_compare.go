// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// PolicyClass is the closed classification of one legacy/canonical difference.
type PolicyClass string

const (
	// policyIntentional: owner-approved reason, policy revision and observable
	// expected impact are all present and the observation stays inside them.
	policyIntentional PolicyClass = "intentional"
	// policyNoise: the difference loses no urgency but nobody approved it.
	policyNoise PolicyClass = "noise"
	// policyMissingUrgency: legacy interrupted and canonical did not (a blocker).
	policyMissingUrgency PolicyClass = "missing_urgency"
	// policyInert: no recipient would have been interrupted by either side.
	policyInert PolicyClass = "inert"
)

// PolicyReason is the closed reason a difference was classified the way it was.
type PolicyReason string

// PolicyEffect is the observable direction of an approved difference.
type PolicyEffect string

// PolicyVerdict is the closed outcome of one comparison. No verdict is
// customer acceptance.
type PolicyVerdict string

const (
	policyVerdictBlocked      PolicyVerdict = "blocked"
	policyVerdictInsufficient PolicyVerdict = "insufficient_evidence"
	policyVerdictUnresolved   PolicyVerdict = "unresolved"
	policyVerdictIncomplete   PolicyVerdict = "incomplete_coverage"
	policyVerdictReconciled   PolicyVerdict = "reconciled"
)

const (
	// Noise reasons: no urgency is lost, but the difference needs an approval.
	policyReasonRepeatOccurrence  PolicyReason = "repeat_occurrence_page"
	policyReasonFakeRate          PolicyReason = "legacy_fake_rate"
	policyReasonReminderAfterAck  PolicyReason = "reminder_after_ack"
	policyReasonReminderCadence   PolicyReason = "reminder_cadence"
	policyReasonIgnoredWindow     PolicyReason = "legacy_ignored_window"
	policyReasonDuplicateDelivery PolicyReason = "legacy_duplicate_delivery"
	policyReasonLateDelivery      PolicyReason = "legacy_late_delivery"
	policyReasonExtraInterrupt    PolicyReason = "canonical_extra_interrupt"
	policyReasonWorseAfterAck     PolicyReason = "worse_impact_after_ack"
	policyReasonRecipientAdded    PolicyReason = "recipient_added"
	policyReasonQueueCadence      PolicyReason = "queue_cadence"
	policyReasonDigestCadence     PolicyReason = "digest_cadence"
	policyReasonSourceSkew        PolicyReason = "source_version_skew"
	policyReasonSuppressionReason PolicyReason = "suppression_reason"
	policyReasonDedup             PolicyReason = "dedup_inconsistent"
	// Blocker reasons: legacy interrupted and canonical did not. An approval
	// can never waive one of them.
	policyReasonUrgentLost       PolicyReason = "urgent_not_delivered"
	policyReasonReminderLost     PolicyReason = "reminder_not_delivered"
	policyReasonRecipientDropped PolicyReason = "recipient_dropped"
	policyReasonSilencedNoWindow PolicyReason = "silenced_without_window"
	// Inert reasons: neither side would have interrupted anyone.
	policyReasonLegacySuppressedOnly    PolicyReason = "legacy_suppressed_only"
	policyReasonCanonicalSuppressedOnly PolicyReason = "canonical_suppressed_only"
	// The class stays with a customer tool by declared ownership.
	policyReasonCustomerRetained PolicyReason = "customer_retained_class"
)

const (
	policyEffectFewer     PolicyEffect = "fewer_interrupts"
	policyEffectMore      PolicyEffect = "more_interrupts"
	policyEffectRetimed   PolicyEffect = "re_timed"
	policyEffectUnchanged PolicyEffect = "no_interrupt_change"
)

const (
	policyPass         PolicyCheckStatus = "pass"
	policyFail         PolicyCheckStatus = "fail"
	policyUnverified   PolicyCheckStatus = "unverified"
	policyNotExercised PolicyCheckStatus = "not_exercised"
)

const (
	policyCheckGrouping    = "occurrence_grouping"
	policyCheckInterrupts  = "impact_rate_regression_interrupt"
	policyCheckDenominator = "unknown_denominator_no_rate"
	policyCheckAck         = "ack_semantics"
	policyCheckRecovery    = "recovery_resolve_separate"
	policyCheckLate        = "late_event_ordering"
	policyCheckDuplicate   = "duplicate_event_handling"
	policyCheckRetry       = "job_retry_handling"
	policyCheckCadence     = "queue_digest_cadence"
	policyCheckWindows     = "window_reason_expiry"
	policyCheckOwnership   = "ownership_boundary"
	policyCheckControls    = "control_preservation"

	policyLifecycleRecovered PolicyLifecycleType = "source_recovered"
	policyLifecycleResolved  PolicyLifecycleType = "incident_resolved"

	policyClassUrgent    = "urgent"
	policyClassReminder  = "reminder"
	policyClassRecovery  = "recovery"
	policyClassQueue     = "queue"
	policyClassDigest    = "digest"
	policyOwnerSoundpost = "soundpost"
	policyOwnerCustomer  = "customer_retained"

	policyControlMinOperations = "min_operations"
	policyControlMinFailures   = "min_failures"
	policyControlRateBP        = "rate_basis_points"
	policyControlRegressionMin = "regression_min"
	policyControlCriticalCodes = "critical_codes"
	policyControlFirstReminder = "first_reminder"
	policyControlReminderEvery = "reminder_every"
	policyControlMaxSuppress   = "max_suppression"
	policyControlDigestZone    = "digest_zone"
	policyControlOther         = "other"

	policyDispPreserved  = "preserved"
	policyDispSuperseded = "superseded"
	policyDispRetained   = "retained_external"
)

// PolicyDifference is one classified difference. It carries identifiers,
// enums and counts only: no recipient address, telemetry or human text.
type PolicyDifference struct {
	Entity         notify.Entity `json:"entity"`
	Kind           notify.Kind   `json:"kind"`
	ImpactRevision uint64        `json:"impact_revision"`
	Ordinal        uint64        `json:"ordinal"`
	Recipient      *model.ID     `json:"recipient_key,omitempty"`
	Field          string        `json:"field"`
	Class          PolicyClass   `json:"class"`
	Reason         PolicyReason  `json:"reason"`
	Trigger        LedgerTrigger `json:"trigger,omitempty"`
	Approval       string        `json:"approval,omitempty"`
}

// PolicyFinding is a ledger, control, ownership, approval or evidence defect.
type PolicyFinding struct {
	Code    string `json:"code"`
	Blocker bool   `json:"blocker"`
	Subject string `json:"subject,omitempty"`
}

// PolicyCheckStatus is the closed result of one semantic check.
type PolicyCheckStatus string

// PolicyCheck is one named semantic check with its closed status.
type PolicyCheck struct {
	Name   string            `json:"name"`
	Status PolicyCheckStatus `json:"status"`
}

// PolicyApprovalUse is the observed impact of one approval.
type PolicyApprovalUse struct {
	ID      string `json:"id"`
	Matched int    `json:"matched"`
	Max     uint32 `json:"max"`
}

// PolicyControlCounts count the legacy threshold controls by disposition.
type PolicyControlCounts struct {
	Recorded         int `json:"recorded"`
	Preserved        int `json:"preserved"`
	Superseded       int `json:"superseded"`
	RetainedExternal int `json:"retained_external"`
	Unresolved       int `json:"unresolved"`
}

// PolicyReport is the PRIVATE comparison record: it names entities and keyed
// recipient pseudonyms. Publish only PolicyPublic(report).
type PolicyReport struct {
	SchemaVersion  int                 `json:"schema_version"`
	PolicyRevision uint64              `json:"policy_revision"`
	Compared       int                 `json:"compared"`
	Identical      int                 `json:"identical"`
	MissingUrgency []PolicyDifference  `json:"missing_urgency"`
	Noise          []PolicyDifference  `json:"noise"`
	Intentional    []PolicyDifference  `json:"intentional"`
	Inert          []PolicyDifference  `json:"inert"`
	Findings       []PolicyFinding     `json:"findings"`
	Checks         []PolicyCheck       `json:"checks"`
	Approvals      []PolicyApprovalUse `json:"approvals"`
	Ledger         LedgerStats         `json:"ledger"`
	Controls       PolicyControlCounts `json:"controls"`
	Verdict        PolicyVerdict       `json:"verdict"`
}

// PolicyPublicSummary is the closed allowlisted projection: counts and enums
// only, no identifier, key, reason text or inventory.
type PolicyPublicSummary struct {
	SchemaVersion      int                 `json:"schema_version"`
	Compared           int                 `json:"compared"`
	Identical          int                 `json:"identical"`
	MissingUrgency     int                 `json:"missing_urgency"`
	Noise              int                 `json:"noise"`
	Intentional        int                 `json:"intentional"`
	Inert              int                 `json:"inert"`
	BlockerFindings    int                 `json:"blocker_findings"`
	OtherFindings      int                 `json:"other_findings"`
	ChecksPassed       int                 `json:"checks_passed"`
	ChecksFailed       int                 `json:"checks_failed"`
	ChecksUnverified   int                 `json:"checks_unverified"`
	ChecksNotExercised int                 `json:"checks_not_exercised"`
	ByReason           map[string]int      `json:"by_reason"`
	Ledger             LedgerStats         `json:"ledger"`
	Controls           PolicyControlCounts `json:"controls"`
	Verdict            PolicyVerdict       `json:"verdict"`
	CustomerAcceptance bool                `json:"customer_acceptance"`
}

// PolicyAck is one human acknowledgment: it covers the impact revision the
// human saw, at the event time it was given.
type PolicyAck struct {
	Entity         notify.Entity  `json:"entity"`
	ImpactRevision uint64         `json:"impact_revision"`
	At             model.UnixNano `json:"at_ns"`
}

// PolicyLifecycleType separates the source's own recovery from the human
// incident resolution: they are different events.
type PolicyLifecycleType string

// PolicyLifecycle is one observed source recovery or incident resolution.
type PolicyLifecycle struct {
	Entity notify.Entity       `json:"entity"`
	Type   PolicyLifecycleType `json:"type"`
	At     model.UnixNano      `json:"at_ns"`
}

// PolicyWindow is one recorded snooze or maintenance window of the old tooling.
// A window without a reason or an expiry cannot be adopted as it stands. Entity
// nil means project-wide. Reason is private human text and never reaches a
// report.
type PolicyWindow struct {
	Type   notify.ActionType `json:"type"`
	Entity *notify.Entity    `json:"entity,omitempty"`
	Reason string            `json:"reason"`
	From   model.UnixNano    `json:"from_ns"`
	Until  model.UnixNano    `json:"until_ns"`
}

// PolicyClassOwner says who normally sends one notification class after
// adoption: exactly one owner per class.
type PolicyClassOwner struct {
	Class string `json:"class"`
	Owner string `json:"owner"`
}

// PolicyControl is one threshold or routing control the customer tools hold
// today. Value is in the canonical unit of the control kind (a count, basis
// points or nanoseconds); Codes and Zone serve the two kinds that need them.
type PolicyControl struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	Value uint64   `json:"value,omitempty"`
	Codes []string `json:"codes,omitempty"`
	Zone  string   `json:"zone,omitempty"`
}

// LegacyEvidence is the normalized observation of the old owner's behaviour
// and the customer-side facts the comparison needs. It is private.
type LegacyEvidence struct {
	Ledger    []LedgerEntry      `json:"ledger"`
	Acks      []PolicyAck        `json:"acks,omitempty"`
	Lifecycle []PolicyLifecycle  `json:"lifecycle,omitempty"`
	Windows   []PolicyWindow     `json:"windows,omitempty"`
	Ownership []PolicyClassOwner `json:"ownership,omitempty"`
	Controls  []PolicyControl    `json:"controls,omitempty"`
}

// PolicyDecisionAt is one canonical shadow decision with its decision time.
// Basis and Rate are optional template facts of a recorded decision; a replayed
// decision leaves them empty and the checks that need them report unverified.
type PolicyDecisionAt struct {
	Decision notify.ShadowDecision `json:"decision"`
	At       model.UnixNano        `json:"at_ns"`
	Basis    notify.Basis          `json:"basis,omitempty"`
	Rate     notify.RateState      `json:"rate,omitempty"`
}

// PolicyStep is one event replayed at one time.
type PolicyStep struct {
	Event notify.PolicyEvent `json:"event"`
	At    model.UnixNano     `json:"at_ns"`
}

// PolicyReplay is the event stream of one notification subject. ComparePolicy
// replays it through notify.ShadowEvaluator: nothing is stored or sent.
type PolicyReplay struct {
	Subject notify.Entity `json:"subject"`
	Steps   []PolicyStep  `json:"steps"`
}

// CanonicalShadowEvidence is the canonical owner's no-send decision evidence:
// replayed event streams and/or recorded decisions.
type CanonicalShadowEvidence struct {
	Org       model.ID           `json:"org_id"`
	Project   model.ID           `json:"project_id"`
	Policy    model.ID           `json:"policy_id"`
	Replays   []PolicyReplay     `json:"replays,omitempty"`
	Decisions []PolicyDecisionAt `json:"decisions,omitempty"`
}

// PolicyExpectedImpact is the observable effect an approval promises: its
// direction and the most decisions it may touch.
type PolicyExpectedImpact struct {
	Effect       PolicyEffect `json:"effect"`
	MaxDecisions uint32       `json:"max_decisions"`
}

// PolicyApproval makes one class of difference intentional. The owner-approved
// reason (OwnerReason and ApprovedBy), the policy revision and the expected
// impact are all required; one missing and the difference is not intentional.
type PolicyApproval struct {
	ID             string               `json:"id"`
	Difference     PolicyReason         `json:"difference"`
	Entity         *notify.Entity       `json:"entity,omitempty"`
	OwnerReason    string               `json:"owner_reason"`
	ApprovedBy     string               `json:"approved_by"`
	PolicyRevision uint64               `json:"policy_revision"`
	Expected       PolicyExpectedImpact `json:"expected_impact"`
}

// PolicyControlDisposition records what adoption does with one legacy control:
// preserved (the canonical value equals it), superseded (replaced, with a
// reason) or retained_external (the customer tool keeps it, with a reason).
type PolicyControlDisposition struct {
	Control        string `json:"control"`
	Disposition    string `json:"disposition"`
	Reason         string `json:"reason,omitempty"`
	ApprovedBy     string `json:"approved_by,omitempty"`
	PolicyRevision uint64 `json:"policy_revision,omitempty"`
}

// ApprovedPolicy is the owner-approved policy revision under comparison, with
// its approved differences and the disposition of each delegated control.
type ApprovedPolicy struct {
	Revision  uint64                     `json:"revision"`
	Config    notify.Config              `json:"config"`
	Approvals []PolicyApproval           `json:"approvals,omitempty"`
	Controls  []PolicyControlDisposition `json:"controls,omitempty"`
}

// policyReasonInfo is what a reason means: the class it files a difference
// under and, for approvable reasons, the one effect an approval must promise.
type policyReasonInfo struct {
	Class  PolicyClass
	Effect PolicyEffect
}

// policyReasonTable is the closed vocabulary of difference reasons.
var policyReasonTable = map[PolicyReason]policyReasonInfo{
	policyReasonRepeatOccurrence:        {policyNoise, policyEffectFewer},
	policyReasonFakeRate:                {policyNoise, policyEffectFewer},
	policyReasonReminderAfterAck:        {policyNoise, policyEffectFewer},
	policyReasonReminderCadence:         {policyNoise, policyEffectFewer},
	policyReasonIgnoredWindow:           {policyNoise, policyEffectFewer},
	policyReasonDuplicateDelivery:       {policyNoise, policyEffectFewer},
	policyReasonLateDelivery:            {policyNoise, policyEffectFewer},
	policyReasonExtraInterrupt:          {policyNoise, policyEffectMore},
	policyReasonWorseAfterAck:           {policyNoise, policyEffectMore},
	policyReasonRecipientAdded:          {policyNoise, policyEffectMore},
	policyReasonQueueCadence:            {policyNoise, policyEffectRetimed},
	policyReasonDigestCadence:           {policyNoise, policyEffectRetimed},
	policyReasonSourceSkew:              {policyNoise, policyEffectUnchanged},
	policyReasonSuppressionReason:       {policyNoise, policyEffectUnchanged},
	policyReasonDedup:                   {policyNoise, policyEffectUnchanged},
	policyReasonUrgentLost:              {policyMissingUrgency, ""},
	policyReasonReminderLost:            {policyMissingUrgency, ""},
	policyReasonRecipientDropped:        {policyMissingUrgency, ""},
	policyReasonSilencedNoWindow:        {policyMissingUrgency, ""},
	policyReasonLegacySuppressedOnly:    {policyInert, ""},
	policyReasonCanonicalSuppressedOnly: {policyInert, ""},
	policyReasonCustomerRetained:        {policyInert, ""},
}

// ComparePolicy compares the old owner's behaviour with the canonical owner's
// shadow decisions and classifies EVERY difference. Parity is not blind
// cloning: a legacy decision the canonical owner does not reproduce is lost
// urgency (a blocker) only if it interrupted a person and nothing explains it;
// repeated pages of a grouped exception, rates no denominator supports,
// reminders after an ACK, pages through a recorded window and late or duplicate
// deliveries are noise, and become intentional only with an owner-approved
// reason, the policy revision and a bounded observable impact. The canonical
// decisions come from notify.ShadowEvaluator replays and/or recorded no-send
// decisions and are compared with notify.CompareParity; nothing is stored or
// sent.
func ComparePolicy(ctx context.Context, legacy LegacyEvidence, canonical CanonicalShadowEvidence, approved ApprovedPolicy) (PolicyReport, error) {
	if err := ctx.Err(); err != nil {
		return PolicyReport{}, err
	}
	if err := policyValidateApproved(approved); err != nil {
		return PolicyReport{}, err
	}
	if err := policyValidateLegacy(legacy); err != nil {
		return PolicyReport{}, err
	}
	red, err := ledgerReduce(legacy.Ledger)
	if err != nil {
		return PolicyReport{}, err
	}
	canon, findings, err := policyCanonical(ctx, canonical, approved)
	if err != nil {
		return PolicyReport{}, err
	}
	p := &policyRun{approved: approved, legacy: legacy, red: red, canon: canon, findings: append(findings, red.Findings...), owners: map[string]string{}}
	p.index()
	if err := p.compare(ctx); err != nil {
		return PolicyReport{}, err
	}
	return p.report(), nil
}

func policyTextOK(s string) bool {
	if s == "" || len(s) > notify.MaxReasonBytes || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// policyConfigRefused runs the approved configuration through the canonical
// reducer's own validation instead of restating its rules.
func policyConfigRefused(rev uint64, cfg notify.Config) error {
	subject := notify.Entity{Kind: notify.EntityIncident, ID: model.ID{1}}
	st, err := notify.NewState(model.ID{1}, model.ID{2}, model.ID{3}, subject)
	if err != nil {
		return err
	}
	c := cfg
	ev := notify.PolicyEvent{Kind: notify.EventDestination, Command: model.ID{4}, Org: model.ID{1}, Project: model.ID{2}, Policy: model.ID{3},
		PolicyRef: notify.PolicyRef{Revision: model.Revision(rev), Config: &c}, OwnerRevision: 1, Destination: &notify.DestinationChange{Recipient: model.ID{5}, Enabled: true}}
	if _, _, err := notify.Decide(st, ev, 1); err != nil {
		return errors.New("approved policy configuration is refused by the canonical reducer")
	}
	return nil
}

func policyValidateApproved(a ApprovedPolicy) error {
	if a.Revision == 0 {
		return errors.New("approved policy needs a revision")
	}
	if err := policyConfigRefused(a.Revision, a.Config); err != nil {
		return err
	}
	for _, d := range a.Controls {
		switch d.Disposition {
		case policyDispPreserved, policyDispSuperseded, policyDispRetained:
		default:
			return errors.New("control disposition is not preserved, superseded or retained_external")
		}
		if !ledgerSafeName(d.Control) {
			return errors.New("control disposition names an invalid control")
		}
	}
	return nil
}

func policyControlKindValid(k string) bool {
	switch k {
	case policyControlMinOperations, policyControlMinFailures, policyControlRateBP, policyControlRegressionMin, policyControlCriticalCodes,
		policyControlFirstReminder, policyControlReminderEvery, policyControlMaxSuppress, policyControlDigestZone, policyControlOther:
		return true
	}
	return false
}

func policyClassValid(c string) bool {
	switch c {
	case policyClassUrgent, policyClassReminder, policyClassRecovery, policyClassQueue, policyClassDigest:
		return true
	}
	return false
}

func policyValidateLegacy(l LegacyEvidence) error {
	for _, a := range l.Acks {
		if !ledgerEntityValid(a.Entity) || a.At <= 0 {
			return errors.New("invalid acknowledgment fact")
		}
	}
	for _, f := range l.Lifecycle {
		if !ledgerEntityValid(f.Entity) || f.At <= 0 || (f.Type != policyLifecycleRecovered && f.Type != policyLifecycleResolved) {
			return errors.New("invalid lifecycle fact")
		}
	}
	for _, w := range l.Windows {
		if (w.Type != notify.ActionMaintenance && w.Type != notify.ActionSnooze) || (w.Entity != nil && !ledgerEntityValid(*w.Entity)) || w.From <= 0 || w.Until < 0 || len(w.Reason) > notify.MaxReasonBytes {
			return errors.New("invalid window fact")
		}
	}
	for _, o := range l.Ownership {
		if !policyClassValid(o.Class) || (o.Owner != policyOwnerSoundpost && o.Owner != policyOwnerCustomer) {
			return errors.New("invalid ownership declaration")
		}
	}
	ids := map[string]bool{}
	for _, c := range l.Controls {
		if !ledgerSafeName(c.ID) || ids[c.ID] || !policyControlKindValid(c.Kind) || len(c.Codes) > notify.MaxCriticalCodes || len(c.Zone) > notify.MaxName {
			return errors.New("invalid control record")
		}
		ids[c.ID] = true
		for _, code := range c.Codes {
			if !ledgerSafeName(code) {
				return errors.New("invalid control record")
			}
		}
	}
	return nil
}

func policyConfigEqual(a, b notify.Config) bool {
	return a.MinOperations == b.MinOperations && a.MinFailures == b.MinFailures && a.RateBasisPoints == b.RateBasisPoints && a.RegressionMin == b.RegressionMin &&
		slices.Equal(a.CriticalCodes, b.CriticalCodes) && a.FirstReminder == b.FirstReminder && a.ReminderEvery == b.ReminderEvery &&
		a.MaxSuppression == b.MaxSuppression && a.DefaultZone == b.DefaultZone
}

// policyCanonical produces the canonical decisions: it replays every event
// stream through notify.ShadowEvaluator (a refused event decides nothing and is
// a blocker finding) and adds the recorded decisions.
func policyCanonical(ctx context.Context, c CanonicalShadowEvidence, approved ApprovedPolicy) ([]PolicyDecisionAt, []PolicyFinding, error) {
	var out []PolicyDecisionAt
	var findings []PolicyFinding
	seen := map[PolicyFinding]bool{}
	add := func(code string, blocker bool, subject string) {
		f := PolicyFinding{Code: code, Blocker: blocker, Subject: subject}
		if !seen[f] {
			seen[f] = true
			findings = append(findings, f)
		}
	}
	for _, r := range c.Replays {
		ev, err := notify.NewShadowEvaluator(c.Org, c.Project, c.Policy, r.Subject)
		if err != nil {
			return nil, nil, errors.New("canonical replay needs an organization, project, policy and a valid subject")
		}
		for _, s := range r.Steps {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			if uint64(s.Event.PolicyRef.Revision) != approved.Revision {
				add("policy_revision_mismatch", true, "")
			}
			if s.Event.PolicyRef.Config != nil && !policyConfigEqual(*s.Event.PolicyRef.Config, approved.Config) {
				add("policy_config_mismatch", true, "")
			}
			ds, err := ev.Apply(s.Event, s.At)
			if err != nil {
				reason := "other"
				if v, ok := notify.ReasonOf(err); ok {
					reason = string(v)
				}
				add("canonical_event_refused", true, reason)
				continue
			}
			for _, d := range ds {
				out = append(out, PolicyDecisionAt{Decision: d, At: s.At})
			}
		}
	}
	for _, d := range c.Decisions {
		x := d.Decision
		if !ledgerEntityValid(x.Entity) || !ledgerKindValid(x.Kind) || x.DedupID == (model.ID{}) || d.At <= 0 || (x.Recipient != nil && *x.Recipient == (model.ID{})) {
			return nil, nil, errors.New("invalid recorded canonical decision")
		}
		switch x.Suppression {
		case notify.CodeNone, notify.CodeMaintenance, notify.CodeSnoozed, notify.CodeNoDestination:
		default:
			return nil, nil, errors.New("recorded canonical decision has an unknown suppression code")
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ka, kb := policyDecisionKey(a.Decision), policyDecisionKey(b.Decision)
		switch {
		case ka != kb:
			return ledgerKeyLess(ka, kb)
		case a.At != b.At:
			return a.At < b.At
		case a.Decision.SourceVersion != b.Decision.SourceVersion:
			return a.Decision.SourceVersion < b.Decision.SourceVersion
		}
		return a.Decision.DedupID.String() < b.Decision.DedupID.String()
	})
	ledgerSortFindings(findings)
	return out, findings, nil
}

func policyDecisionKey(d notify.ShadowDecision) ledgerKey {
	k := ledgerKey{Entity: d.Entity, Kind: d.Kind, Impact: d.ImpactRevision, Ordinal: d.Ordinal}
	if d.Recipient != nil {
		k.Recipient, k.HasRecipient = *d.Recipient, true
	}
	return k
}

func policyLogical(k ledgerKey) ledgerKey {
	k.Recipient, k.HasRecipient = model.ID{}, false
	return k
}

func policyClassOf(k notify.Kind) string {
	switch k {
	case notify.KindReminder:
		return policyClassReminder
	case notify.KindRecovery, notify.KindResolution:
		return policyClassRecovery
	case notify.KindQueue:
		return policyClassQueue
	case notify.KindDigest:
		return policyClassDigest
	}
	return policyClassUrgent
}

type policyRun struct {
	approved ApprovedPolicy
	legacy   LegacyEvidence
	red      ledgerReduction
	canon    []PolicyDecisionAt
	owners   map[string]string
	windows  []PolicyWindow // recorded windows that carry a reason and an expiry

	lrec map[ledgerKey]ledgerRecord
	llog map[ledgerKey][]ledgerRecord
	crec map[ledgerKey]PolicyDecisionAt
	clog map[ledgerKey][]PolicyDecisionAt

	parity   notify.ParityReport
	findings []PolicyFinding
	diffs    []PolicyDifference
	uses     []PolicyApprovalUse
	controls PolicyControlCounts
}

func (p *policyRun) finding(code string, blocker bool, subject string) {
	for _, f := range p.findings {
		if f.Code == code && f.Subject == subject {
			return
		}
	}
	p.findings = append(p.findings, PolicyFinding{Code: code, Blocker: blocker, Subject: subject})
}

func (p *policyRun) index() {
	p.lrec, p.llog = map[ledgerKey]ledgerRecord{}, map[ledgerKey][]ledgerRecord{}
	p.crec, p.clog = map[ledgerKey]PolicyDecisionAt{}, map[ledgerKey][]PolicyDecisionAt{}
	for _, r := range p.red.Records {
		k := ledgerKeyOf(r.Entry)
		p.lrec[k] = r
		p.llog[policyLogical(k)] = append(p.llog[policyLogical(k)], r)
	}
	for _, d := range p.canon {
		k := policyDecisionKey(d.Decision)
		if _, ok := p.crec[k]; ok {
			continue
		}
		p.crec[k] = d
		p.clog[policyLogical(k)] = append(p.clog[policyLogical(k)], d)
	}
	for _, o := range p.legacy.Ownership {
		if prev, ok := p.owners[o.Class]; ok && prev != o.Owner {
			p.finding("ownership_ambiguous", true, o.Class)
			continue
		}
		p.owners[o.Class] = o.Owner
	}
	for _, w := range p.legacy.Windows {
		switch {
		case strings.TrimSpace(w.Reason) == "":
			p.finding("window_missing_reason", true, string(w.Type))
		case w.Until <= w.From:
			p.finding("window_missing_expiry", true, string(w.Type))
		default:
			p.windows = append(p.windows, w)
		}
	}
}

func (p *policyRun) delivers(d PolicyDecisionAt) bool {
	return d.Decision.Suppression == notify.CodeNone
}

func (p *policyRun) retained(k notify.Kind) bool {
	return p.owners[policyClassOf(k)] == policyOwnerCustomer
}

// covered: the canonical owner already interrupted for this entity at this
// impact revision or a worse one.
func (p *policyRun) covered(e notify.Entity, impact uint64) bool {
	for _, d := range p.canon {
		x := d.Decision
		if x.Entity == e && p.delivers(d) && x.ImpactRevision >= impact && (x.Kind == notify.KindOpen || x.Kind == notify.KindWorseImpact || x.Kind == notify.KindCurrent) {
			return true
		}
	}
	return false
}

func (p *policyRun) ackCovers(e notify.Entity, impact uint64, at model.UnixNano) bool {
	for _, a := range p.legacy.Acks {
		if a.Entity == e && a.ImpactRevision >= impact && a.At <= at {
			return true
		}
	}
	return false
}

// ackedBefore: a worse impact than the one acknowledged, after the ACK.
func (p *policyRun) ackedBefore(e notify.Entity, impact uint64, at model.UnixNano) bool {
	for _, a := range p.legacy.Acks {
		if a.Entity == e && a.ImpactRevision < impact && a.At <= at {
			return true
		}
	}
	return false
}

func (p *policyRun) windowCovers(e notify.Entity, at model.UnixNano, typ notify.ActionType) bool {
	for _, w := range p.windows {
		if w.Type == typ && (w.Entity == nil || *w.Entity == e) && w.From <= at && at < w.Until {
			return true
		}
	}
	return false
}

func (p *policyRun) canonReminders(e notify.Entity, impact uint64) int {
	n := 0
	for _, d := range p.canon {
		if d.Decision.Entity == e && d.Decision.Kind == notify.KindReminder && d.Decision.ImpactRevision == impact && p.delivers(d) {
			n++
		}
	}
	return n
}

func policyCadence(k notify.Kind) PolicyReason {
	if k == notify.KindDigest {
		return policyReasonDigestCadence
	}
	return policyReasonQueueCadence
}

// classify gives one parity mismatch its reason (and the legacy trigger).
func (p *policyRun) classify(m notify.ParityMismatch) (PolicyReason, LedgerTrigger) {
	lk := ledgerKey{Entity: m.Entity, Kind: m.Kind, Impact: m.ImpactRevision, Ordinal: m.Ordinal}
	rk := lk
	if m.Recipient != nil {
		rk.Recipient, rk.HasRecipient = *m.Recipient, true
	}
	immediate := ledgerImmediate(m.Kind)
	switch m.Field {
	case "only_legacy":
		recs := p.llog[lk]
		for _, r := range recs {
			e := r.Entry
			if !ledgerAttempted(e) {
				continue
			}
			switch {
			case !immediate:
				return policyCadence(m.Kind), e.Trigger
			case p.retained(m.Kind):
				return policyReasonCustomerRetained, e.Trigger
			case e.Trigger == ledgerTriggerPerOccurrence:
				if p.covered(e.Entity, e.ImpactRevision) {
					return policyReasonRepeatOccurrence, e.Trigger
				}
			case e.Trigger == ledgerTriggerRateNoDenominator:
				return policyReasonFakeRate, e.Trigger
			case e.Kind == notify.KindReminder || e.Trigger == ledgerTriggerReminderTimer:
				switch {
				case p.ackCovers(e.Entity, e.ImpactRevision, e.EventTime):
					return policyReasonReminderAfterAck, e.Trigger
				case p.canonReminders(e.Entity, e.ImpactRevision) > 0:
					return policyReasonReminderCadence, e.Trigger
				}
				return policyReasonReminderLost, e.Trigger
			}
			return policyReasonUrgentLost, e.Trigger
		}
		if len(recs) == 0 {
			return policyReasonLegacySuppressedOnly, ""
		}
		return policyReasonLegacySuppressedOnly, recs[0].Entry.Trigger
	case "only_shadow":
		for _, d := range p.clog[lk] {
			if !p.delivers(d) {
				continue
			}
			switch {
			case !immediate:
				return policyCadence(m.Kind), ""
			case m.Kind == notify.KindWorseImpact && p.ackedBefore(m.Entity, m.ImpactRevision, d.At):
				return policyReasonWorseAfterAck, ""
			}
			return policyReasonExtraInterrupt, ""
		}
		return policyReasonCanonicalSuppressedOnly, ""
	case "recipients":
		var lost, added bool
		var trigger LedgerTrigger
		extraCanon := false
		for _, r := range p.llog[lk] {
			k := ledgerKeyOf(r.Entry)
			if _, ok := p.crec[k]; !ok && ledgerAttempted(r.Entry) {
				if !lost {
					trigger = r.Entry.Trigger
				}
				lost = true
			}
		}
		for _, d := range p.clog[lk] {
			k := policyDecisionKey(d.Decision)
			if _, ok := p.lrec[k]; !ok {
				extraCanon = true
				if p.delivers(d) {
					added = true
				}
			}
		}
		switch {
		case !immediate && (lost || added):
			return policyCadence(m.Kind), trigger
		case lost && p.retained(m.Kind):
			return policyReasonCustomerRetained, trigger
		case lost:
			return policyReasonRecipientDropped, trigger
		case added:
			return policyReasonRecipientAdded, ""
		case extraCanon:
			return policyReasonCanonicalSuppressedOnly, ""
		}
		return policyReasonLegacySuppressedOnly, ""
	case "suppression":
		l, c := p.lrec[rk], p.crec[rk]
		lAtt, cDel := ledgerAttempted(l.Entry), p.delivers(c)
		switch {
		case !immediate && (lAtt || cDel):
			return policyCadence(m.Kind), l.Entry.Trigger
		case lAtt && !cDel:
			if p.retained(m.Kind) {
				return policyReasonCustomerRetained, l.Entry.Trigger
			}
			switch c.Decision.Suppression {
			case notify.CodeMaintenance:
				if p.windowCovers(m.Entity, c.At, notify.ActionMaintenance) {
					return policyReasonIgnoredWindow, l.Entry.Trigger
				}
				return policyReasonSilencedNoWindow, l.Entry.Trigger
			case notify.CodeSnoozed:
				if p.windowCovers(m.Entity, c.At, notify.ActionSnooze) {
					return policyReasonIgnoredWindow, l.Entry.Trigger
				}
				return policyReasonSilencedNoWindow, l.Entry.Trigger
			}
			return policyReasonUrgentLost, l.Entry.Trigger
		case !lAtt && cDel:
			if m.Kind == notify.KindWorseImpact && p.ackedBefore(m.Entity, m.ImpactRevision, c.At) {
				return policyReasonWorseAfterAck, l.Entry.Trigger
			}
			return policyReasonExtraInterrupt, l.Entry.Trigger
		case l.Entry.Outcome == ledgerSuppressed && !cDel:
			return policyReasonSuppressionReason, l.Entry.Trigger
		}
		return policyReasonCanonicalSuppressedOnly, l.Entry.Trigger
	case "source_version":
		return policyReasonSourceSkew, p.lrec[rk].Entry.Trigger
	}
	return policyReasonDedup, ""
}

func policyDiffKey(d PolicyDifference) ledgerKey {
	k := ledgerKey{Entity: d.Entity, Kind: d.Kind, Impact: d.ImpactRevision, Ordinal: d.Ordinal}
	if d.Recipient != nil {
		k.Recipient, k.HasRecipient = *d.Recipient, true
	}
	return k
}

func policyDiffLess(a, b PolicyDifference) bool {
	ka, kb := policyDiffKey(a), policyDiffKey(b)
	switch {
	case ka != kb:
		return ledgerKeyLess(ka, kb)
	case a.Field != b.Field:
		return a.Field < b.Field
	}
	return a.Reason < b.Reason
}

func (p *policyRun) compare(ctx context.Context) error {
	shadow := make([]notify.ShadowDecision, len(p.canon))
	for i, d := range p.canon {
		shadow[i] = d.Decision
	}
	p.parity = notify.CompareParity(shadow, ledgerDecisions(p.red))
	for i, m := range p.parity.Mismatches {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		reason, trigger := p.classify(m)
		p.diffs = append(p.diffs, PolicyDifference{Entity: m.Entity, Kind: m.Kind, ImpactRevision: m.ImpactRevision, Ordinal: m.Ordinal, Recipient: m.Recipient,
			Field: m.Field, Class: policyReasonTable[reason].Class, Reason: reason, Trigger: trigger})
	}
	for _, r := range p.red.Late {
		e := r.Entry
		p.diffs = append(p.diffs, PolicyDifference{Entity: e.Entity, Kind: e.Kind, ImpactRevision: e.ImpactRevision, Ordinal: e.Ordinal, Recipient: e.Recipient,
			Field: "ledger_late", Class: policyNoise, Reason: policyReasonLateDelivery, Trigger: e.Trigger})
	}
	for _, r := range p.red.DuplicateDeliveries {
		e := r.Entry
		p.diffs = append(p.diffs, PolicyDifference{Entity: e.Entity, Kind: e.Kind, ImpactRevision: e.ImpactRevision, Ordinal: e.Ordinal, Recipient: e.Recipient,
			Field: "ledger_duplicate", Class: policyNoise, Reason: policyReasonDuplicateDelivery, Trigger: e.Trigger})
	}
	sort.SliceStable(p.diffs, func(i, j int) bool { return policyDiffLess(p.diffs[i], p.diffs[j]) })
	p.applyApprovals()
	p.evaluateControls()
	return nil
}

// applyApprovals validates every approval and lets the valid ones make noise
// intentional, within their expected impact. A blocker is never waived.
func (p *policyRun) applyApprovals() {
	approvals := append([]PolicyApproval(nil), p.approved.Approvals...)
	sort.SliceStable(approvals, func(i, j int) bool {
		if approvals[i].ID != approvals[j].ID {
			return approvals[i].ID < approvals[j].ID
		}
		return approvals[i].Difference < approvals[j].Difference
	})
	var valid []PolicyApproval
	ids := map[string]bool{}
	for _, a := range approvals {
		info, known := policyReasonTable[a.Difference]
		switch {
		case !ledgerSafeName(a.ID):
			p.finding("approval_incomplete", true, "")
		case ids[a.ID]:
			p.finding("approval_ambiguous", true, a.ID)
		case !policyTextOK(a.OwnerReason) || !ledgerSafeName(a.ApprovedBy) || a.PolicyRevision == 0 || a.Expected.Effect == "" || a.Expected.MaxDecisions == 0:
			ids[a.ID] = true
			p.finding("approval_incomplete", true, a.ID)
		case !known:
			ids[a.ID] = true
			p.finding("approval_unknown_difference", true, a.ID)
		case info.Class == policyMissingUrgency:
			ids[a.ID] = true
			p.finding("approval_blocker_class", true, a.ID)
		case info.Class == policyInert:
			ids[a.ID] = true
			p.finding("approval_not_needed", false, a.ID)
		case a.PolicyRevision != p.approved.Revision:
			ids[a.ID] = true
			p.finding("approval_revision_mismatch", true, a.ID)
		case a.Expected.Effect != info.Effect:
			ids[a.ID] = true
			p.finding("approval_effect_mismatch", true, a.ID)
		default:
			ids[a.ID] = true
			valid = append(valid, a)
		}
	}
	matched := map[string]int{}
	exceeded := map[string]bool{}
	for i := range p.diffs {
		d := &p.diffs[i]
		// Only noise reasons are approvable, so only noise can match a candidate.
		var cands []PolicyApproval
		for _, a := range valid {
			if a.Difference == d.Reason && (a.Entity == nil || *a.Entity == d.Entity) {
				cands = append(cands, a)
			}
		}
		sort.SliceStable(cands, func(x, y int) bool { return cands[x].Entity != nil && cands[y].Entity == nil })
		for _, a := range cands {
			if matched[a.ID] < int(a.Expected.MaxDecisions) {
				matched[a.ID]++
				d.Class, d.Approval = policyIntentional, a.ID
				break
			}
		}
		if d.Class == policyNoise && len(cands) > 0 {
			exceeded[cands[0].ID] = true
		}
	}
	for _, a := range valid {
		use := PolicyApprovalUse{ID: a.ID, Matched: matched[a.ID], Max: a.Expected.MaxDecisions}
		switch {
		case exceeded[a.ID]:
			// The observed impact is what the approval would have had to cover.
			use.Matched += p.excess(a)
			p.finding("approval_impact_exceeded", true, a.ID)
		case matched[a.ID] == 0:
			p.finding("approval_unused", false, a.ID)
		}
		p.uses = append(p.uses, use)
	}
}

// excess counts the differences an exhausted approval could not cover.
func (p *policyRun) excess(a PolicyApproval) int {
	n := 0
	for _, d := range p.diffs {
		if d.Class == policyNoise && a.Difference == d.Reason && (a.Entity == nil || *a.Entity == d.Entity) {
			n++
		}
	}
	return n
}

// policyControlEqual says whether the canonical configuration holds the
// control's value; comparable is false for a control the configuration cannot hold.
func policyControlEqual(c PolicyControl, cfg notify.Config) (comparable, equal bool) {
	switch c.Kind {
	case policyControlMinOperations:
		return true, c.Value == uint64(cfg.MinOperations)
	case policyControlMinFailures:
		return true, c.Value == uint64(cfg.MinFailures)
	case policyControlRateBP:
		return true, c.Value == uint64(cfg.RateBasisPoints)
	case policyControlRegressionMin:
		return true, c.Value == uint64(cfg.RegressionMin)
	case policyControlFirstReminder:
		return true, c.Value == uint64(cfg.FirstReminder)
	case policyControlReminderEvery:
		return true, c.Value == uint64(cfg.ReminderEvery)
	case policyControlMaxSuppress:
		return true, c.Value == uint64(cfg.MaxSuppression)
	case policyControlDigestZone:
		return true, c.Zone == cfg.DefaultZone
	case policyControlCriticalCodes:
		a, b := slices.Clone(c.Codes), slices.Clone(cfg.CriticalCodes)
		sort.Strings(a)
		sort.Strings(b)
		return true, slices.Equal(slices.Compact(a), slices.Compact(b))
	}
	return false, false
}

// evaluateControls decides what adoption does with each threshold control the
// customer tools hold: preserved, superseded with a recorded reason, or retained
// externally with one. Anything else is a silent discard and a blocker.
func (p *policyRun) evaluateControls() {
	disp := map[string]PolicyControlDisposition{}
	for _, d := range p.approved.Controls {
		if _, dup := disp[d.Control]; dup {
			p.finding("control_disposition_ambiguous", true, d.Control)
			continue
		}
		disp[d.Control] = d
	}
	known := map[string]bool{}
	controls := append([]PolicyControl(nil), p.legacy.Controls...)
	sort.SliceStable(controls, func(i, j int) bool { return controls[i].ID < controls[j].ID })
	p.controls.Recorded = len(controls)
	for _, c := range controls {
		known[c.ID] = true
		d, ok := disp[c.ID]
		if !ok {
			p.finding("control_silently_discarded", true, c.ID)
			p.controls.Unresolved++
			continue
		}
		switch d.Disposition {
		case policyDispPreserved:
			if cmp, eq := policyControlEqual(c, p.approved.Config); !cmp || !eq {
				p.finding("control_preserved_mismatch", true, c.ID)
				p.controls.Unresolved++
				continue
			}
			p.controls.Preserved++
		default:
			if !policyTextOK(d.Reason) || !ledgerSafeName(d.ApprovedBy) || d.PolicyRevision != p.approved.Revision {
				p.finding("control_supersession_incomplete", true, c.ID)
				p.controls.Unresolved++
				continue
			}
			if d.Disposition == policyDispSuperseded {
				p.controls.Superseded++
			} else {
				p.controls.RetainedExternal++
			}
		}
	}
	ids := make([]string, 0, len(disp))
	for id := range disp {
		if !known[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		p.finding("control_disposition_orphan", false, id)
	}
}

func (p *policyRun) hasFinding(codes ...string) bool {
	for _, f := range p.findings {
		for _, c := range codes {
			if f.Code == c {
				return true
			}
		}
	}
	return false
}

func policyStatusOf(exercised, fail bool) PolicyCheckStatus {
	switch {
	case fail:
		return policyFail
	case !exercised:
		return policyNotExercised
	}
	return policyPass
}

func policyInterruptTrigger(t LedgerTrigger) bool {
	switch t {
	case ledgerTriggerImpact, ledgerTriggerRate, ledgerTriggerRegression, ledgerTriggerCriticalCode:
		return true
	}
	return false
}

// checks evaluates the named semantic behaviours of the plan.
func (p *policyRun) checks() []PolicyCheck {
	var out []PolicyCheck
	add := func(name string, st PolicyCheckStatus) { out = append(out, PolicyCheck{Name: name, Status: st}) }
	lost := func(pred func(PolicyDifference) bool) bool {
		for _, d := range p.diffs {
			if policyReasonTable[d.Reason].Class == policyMissingUrgency && pred(d) {
				return true
			}
		}
		return false
	}

	// Grouping: repeated occurrences of one group are one canonical opening.
	groupEntities := map[notify.Entity]bool{}
	for _, r := range p.red.Records {
		if ledgerAttempted(r.Entry) && r.Entry.Trigger == ledgerTriggerPerOccurrence {
			groupEntities[r.Entry.Entity] = true
		}
	}
	opens := map[notify.Entity]map[uint64]map[uint64]bool{}
	for _, d := range p.canon {
		x := d.Decision
		if x.Kind == notify.KindOpen && p.delivers(d) && groupEntities[x.Entity] {
			if opens[x.Entity] == nil {
				opens[x.Entity] = map[uint64]map[uint64]bool{}
			}
			if opens[x.Entity][x.ImpactRevision] == nil {
				opens[x.Entity][x.ImpactRevision] = map[uint64]bool{}
			}
			opens[x.Entity][x.ImpactRevision][x.Ordinal] = true
		}
	}
	ungrouped := false
	for _, byImpact := range opens {
		for _, ords := range byImpact {
			if len(ords) > 1 {
				ungrouped = true
			}
		}
	}
	add(policyCheckGrouping, policyStatusOf(len(groupEntities) > 0, ungrouped || lost(func(d PolicyDifference) bool { return d.Trigger == ledgerTriggerPerOccurrence })))

	// Impact, rate and regression can interrupt.
	exercised := false
	for _, r := range p.red.Records {
		if ledgerAttempted(r.Entry) && ledgerImmediate(r.Entry.Kind) && policyInterruptTrigger(r.Entry.Trigger) {
			exercised = true
		}
	}
	add(policyCheckInterrupts, policyStatusOf(exercised, lost(func(d PolicyDifference) bool { return policyInterruptTrigger(d.Trigger) })))

	add(policyCheckDenominator, p.denominatorCheck())
	add(policyCheckAck, p.ackCheck())
	add(policyCheckRecovery, p.recoveryCheck())

	ordering := !p.hasFinding("ledger_attempt_conflict", "ledger_time_inversion")
	newestL, newestC := map[notify.Entity]uint64{}, map[notify.Entity]uint64{}
	for _, r := range p.red.Records {
		newestL[r.Entry.Entity] = max(newestL[r.Entry.Entity], r.Entry.SourceVersion)
	}
	for _, d := range p.canon {
		newestC[d.Decision.Entity] = max(newestC[d.Decision.Entity], d.Decision.SourceVersion)
	}
	for e, v := range newestL {
		if c, ok := newestC[e]; ok && c < v {
			ordering = false
		}
	}
	s := p.red.Stats
	add(policyCheckLate, policyStatusOf(s.Late > 0, !ordering && s.Late > 0))
	add(policyCheckDuplicate, policyStatusOf(s.Duplicates+s.DuplicateDeliveries > 0, !ordering && s.Duplicates+s.DuplicateDeliveries > 0))
	add(policyCheckRetry, policyStatusOf(s.Retries > 0, !ordering && s.Retries > 0))

	// Queue and digest cadence.
	cadence, unresolved := false, false
	for _, r := range p.red.Records {
		cadence = cadence || !ledgerImmediate(r.Entry.Kind)
	}
	for _, d := range p.canon {
		cadence = cadence || !ledgerImmediate(d.Decision.Kind)
	}
	for _, d := range p.diffs {
		if d.Reason == policyReasonQueueCadence || d.Reason == policyReasonDigestCadence {
			cadence = true
			unresolved = unresolved || d.Class == policyNoise
		}
	}
	switch {
	case !cadence:
		add(policyCheckCadence, policyNotExercised)
	case unresolved:
		add(policyCheckCadence, policyUnverified)
	default:
		add(policyCheckCadence, policyPass)
	}

	add(policyCheckWindows, policyStatusOf(len(p.legacy.Windows) > 0, p.hasFinding("window_missing_reason", "window_missing_expiry")))
	add(policyCheckOwnership, p.ownershipCheck())
	add(policyCheckControls, policyStatusOf(len(p.legacy.Controls) > 0, p.hasFinding("control_silently_discarded", "control_preserved_mismatch", "control_supersession_incomplete", "control_disposition_ambiguous")))
	return out
}

// denominatorCheck: a rate is only ever a rate when its denominator was known.
func (p *policyRun) denominatorCheck() PolicyCheckStatus {
	exercised, unverified := false, false
	for _, d := range p.canon {
		if d.Basis != notify.BasisErrorRate || !p.delivers(d) {
			continue
		}
		exercised = true
		switch d.Rate {
		case notify.RateKnown:
		case "":
			unverified = true
		default:
			return policyFail
		}
	}
	for _, r := range p.red.Records {
		e := r.Entry
		if !ledgerAttempted(e) || e.Trigger != ledgerTriggerRateNoDenominator {
			continue
		}
		exercised = true
		for _, d := range p.clog[policyLogical(ledgerKeyOf(e))] {
			if p.delivers(d) && d.Basis == "" {
				unverified = true
			}
		}
	}
	switch {
	case !exercised:
		return policyNotExercised
	case unverified:
		return policyUnverified
	}
	return policyPass
}

// ackCheck: an ACK pauses reminders for the impact it covers and never a worse one.
func (p *policyRun) ackCheck() PolicyCheckStatus {
	worsened, fail := false, false
	for _, a := range p.legacy.Acks {
		for _, d := range p.canon {
			x := d.Decision
			if x.Entity != a.Entity || !p.delivers(d) || d.At < a.At {
				continue
			}
			if x.Kind == notify.KindReminder && x.ImpactRevision <= a.ImpactRevision {
				fail = true
			}
			if x.Kind == notify.KindWorseImpact && x.ImpactRevision > a.ImpactRevision {
				worsened = true
			}
		}
		for _, r := range p.red.Records {
			e := r.Entry
			if e.Entity != a.Entity || e.Kind != notify.KindWorseImpact || !ledgerAttempted(e) || e.EventTime < a.At || e.ImpactRevision <= a.ImpactRevision {
				continue
			}
			worsened = true
			if !p.covered(e.Entity, e.ImpactRevision) {
				fail = true
			}
		}
	}
	return policyStatusOf(len(p.legacy.Acks) > 0 && worsened, fail)
}

// recoveryCheck: a source recovery and an incident resolution are separate
// events; the canonical owner announces each only for its own event.
func (p *policyRun) recoveryCheck() PolicyCheckStatus {
	type facts struct{ recovered, resolved int }
	byEntity := map[notify.Entity]*facts{}
	get := func(e notify.Entity) *facts {
		if byEntity[e] == nil {
			byEntity[e] = &facts{}
		}
		return byEntity[e]
	}
	var sawRecovered, sawResolved bool
	for _, f := range p.legacy.Lifecycle {
		if f.Type == policyLifecycleRecovered {
			get(f.Entity).recovered++
			sawRecovered = true
		} else {
			get(f.Entity).resolved++
			sawResolved = true
		}
	}
	canon := map[notify.Entity]*facts{}
	seen := map[ledgerKey]bool{}
	for _, d := range p.canon {
		x := d.Decision
		if x.Kind != notify.KindRecovery && x.Kind != notify.KindResolution {
			continue
		}
		if k := policyLogical(policyDecisionKey(x)); !seen[k] {
			seen[k] = true
			if canon[x.Entity] == nil {
				canon[x.Entity] = &facts{}
			}
			if x.Kind == notify.KindRecovery {
				canon[x.Entity].recovered++
			} else {
				canon[x.Entity].resolved++
			}
			get(x.Entity)
		}
	}
	for e, f := range byEntity {
		c := canon[e]
		if c == nil {
			c = &facts{}
		}
		if (f.recovered > 0) != (c.recovered > 0) || (f.resolved > 0) != (c.resolved > 0) {
			return policyFail
		}
	}
	if sawRecovered && sawResolved {
		return policyPass
	}
	return policyNotExercised
}

// ownershipCheck: exactly one normal sender per notification class.
func (p *policyRun) ownershipCheck() PolicyCheckStatus {
	legacySeen, canonSeen := map[string]bool{}, map[string]bool{}
	for _, r := range p.red.Records {
		if ledgerAttempted(r.Entry) {
			legacySeen[policyClassOf(r.Entry.Kind)] = true
		}
	}
	for _, d := range p.canon {
		if p.delivers(d) {
			canonSeen[policyClassOf(d.Decision.Kind)] = true
		}
	}
	for _, c := range []string{policyClassUrgent, policyClassReminder, policyClassRecovery, policyClassQueue, policyClassDigest} {
		if !legacySeen[c] && !canonSeen[c] {
			continue
		}
		owner, ok := p.owners[c]
		switch {
		case !ok:
			p.finding("ownership_unspecified", true, c)
		case owner == policyOwnerCustomer && canonSeen[c]:
			p.finding("dual_normal_sender", true, c)
		}
	}
	fail := p.hasFinding("ownership_unspecified", "dual_normal_sender", "ownership_ambiguous")
	return policyStatusOf(len(p.owners) > 0 || len(legacySeen)+len(canonSeen) > 0, fail)
}

func (p *policyRun) report() PolicyReport {
	r := PolicyReport{SchemaVersion: 1, PolicyRevision: p.approved.Revision, Compared: p.parity.Compared, Ledger: p.red.Stats,
		MissingUrgency: []PolicyDifference{}, Noise: []PolicyDifference{}, Intentional: []PolicyDifference{}, Inert: []PolicyDifference{}}
	bad := map[ledgerKey]bool{}
	for _, m := range p.parity.Mismatches {
		if m.Field == "source_version" || m.Field == "suppression" {
			k := ledgerKey{Entity: m.Entity, Kind: m.Kind, Impact: m.ImpactRevision, Ordinal: m.Ordinal}
			if m.Recipient != nil {
				k.Recipient, k.HasRecipient = *m.Recipient, true
			}
			bad[k] = true
		}
	}
	r.Identical = p.parity.Compared - len(bad)
	for _, d := range p.diffs {
		switch d.Class {
		case policyMissingUrgency:
			r.MissingUrgency = append(r.MissingUrgency, d)
		case policyNoise:
			r.Noise = append(r.Noise, d)
		case policyIntentional:
			r.Intentional = append(r.Intentional, d)
		default:
			r.Inert = append(r.Inert, d)
		}
	}
	r.Checks = p.checks()
	r.Controls = p.controls
	r.Approvals = p.uses
	if r.Approvals == nil {
		r.Approvals = []PolicyApprovalUse{}
	}
	ledgerSortFindings(p.findings)
	r.Findings = p.findings
	if r.Findings == nil {
		r.Findings = []PolicyFinding{}
	}
	blocked := len(r.MissingUrgency) > 0
	for _, f := range r.Findings {
		blocked = blocked || f.Blocker
	}
	var unverified, unexercised bool
	for _, c := range r.Checks {
		blocked = blocked || c.Status == policyFail
		unverified = unverified || c.Status == policyUnverified
		unexercised = unexercised || c.Status == policyNotExercised
	}
	switch {
	case blocked:
		r.Verdict = policyVerdictBlocked
	case len(p.red.Records) == 0 || len(p.canon) == 0:
		r.Verdict = policyVerdictInsufficient
	case len(r.Noise) > 0 || unverified:
		r.Verdict = policyVerdictUnresolved
	case unexercised:
		r.Verdict = policyVerdictIncomplete
	default:
		r.Verdict = policyVerdictReconciled
	}
	return r
}

// PolicyPublic projects a report onto the closed public summary: counts and
// enums only. It never carries an entity, a recipient key, a reason text or an
// identifier of anything the customer owns. It does not claim customer
// acceptance, whatever the verdict.
func PolicyPublic(r PolicyReport) PolicyPublicSummary {
	s := PolicyPublicSummary{SchemaVersion: 1, Compared: r.Compared, Identical: r.Identical, MissingUrgency: len(r.MissingUrgency), Noise: len(r.Noise), Intentional: len(r.Intentional),
		Inert: len(r.Inert), ByReason: map[string]int{}, Ledger: r.Ledger, Controls: r.Controls, Verdict: r.Verdict}
	for _, list := range [][]PolicyDifference{r.MissingUrgency, r.Noise, r.Intentional, r.Inert} {
		for _, d := range list {
			if _, ok := policyReasonTable[d.Reason]; ok {
				s.ByReason[string(d.Reason)]++
			}
		}
	}
	for _, f := range r.Findings {
		if f.Blocker {
			s.BlockerFindings++
		} else {
			s.OtherFindings++
		}
	}
	for _, c := range r.Checks {
		switch c.Status {
		case policyPass:
			s.ChecksPassed++
		case policyFail:
			s.ChecksFailed++
		case policyUnverified:
			s.ChecksUnverified++
		default:
			s.ChecksNotExercised++
		}
	}
	return s
}

// runPolicyCompare is the `policy-compare` subcommand (the parent passes the
// arguments after the subcommand name). It reads private JSON inputs, writes the
// private report and the closed public summary exclusively, and fails the
// command unless the verdict is reconciled; the evidence is written either way.
func runPolicyCompare(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy-compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	legacyPath := fs.String("legacy", "", "private LegacyEvidence JSON")
	canonicalPath := fs.String("canonical", "", "private CanonicalShadowEvidence JSON")
	approvedPath := fs.String("approved-policy", "", "private ApprovedPolicy JSON")
	output := fs.String("private-output", "", "external private directory for policy-report.json")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall operator deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: adoption policy-compare --legacy FILE --canonical FILE --approved-policy FILE --private-output DIRECTORY --public-summary FILE")
	}
	if fs.NArg() != 0 || !nonempty(*legacyPath, *canonicalPath, *approvedPath, *output, *summaryPath) {
		return errors.New("all policy-compare paths required")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var legacy LegacyEvidence
	var canonical CanonicalShadowEvidence
	var approved ApprovedPolicy
	if readInput(*legacyPath, &legacy) != nil || readInput(*canonicalPath, &canonical) != nil || readInput(*approvedPath, &approved) != nil {
		return errors.New("invalid private operator input")
	}
	dir, err := privateDirectory(ctx, *output, nil, *acl)
	if err != nil {
		return err
	}
	report, err := ComparePolicy(ctx, legacy, canonical, approved)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("policy comparison cancelled or deadline exceeded")
	}
	if err := writeExclusive(filepath.Join(dir, "policy-report.json"), report); err != nil {
		return errors.New("private report creation failed")
	}
	if err := writeExclusive(*summaryPath, PolicyPublic(report)); err != nil {
		return errors.New("summary creation failed; private report retained")
	}
	if report.Verdict != policyVerdictReconciled {
		return fmt.Errorf("policy comparison not reconciled: %s", report.Verdict)
	}
	return nil
}
