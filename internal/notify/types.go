// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package notify is C08's notification side. This file owns the closed shapes
// of the canonical policy reducer (policy.go): the events it consumes, the
// state it carries and the intents it emits. Nothing here sends, stores or
// reads a clock; the durable outbox and the sender worker are separate,
// later work and consume Intent through the Delivery shape below.
//
// The shapes deliberately mirror, and never import, the committed issue,
// condition, job and incident packages: an adapter maps their exported types
// (incidents.State/Effect, issues.Evidence/Issue regression provenance,
// condition events) onto these closed events. Only typed fields cross this
// boundary: identifiers, enums, counts and times. Telemetry text, error
// messages and human reasons never reach an Intent.
package notify

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// EntityKind is the closed set of notifiable entities. They stay distinct:
// an alert condition, an error issue and a human incident are different
// lifecycles that are only linked, never merged.
type EntityKind string

const (
	EntityIssue     EntityKind = "issue"
	EntityCondition EntityKind = "condition"
	EntityIncident  EntityKind = "incident"
)

// Entity is one notifiable entity inside the state's organization.
type Entity struct {
	Kind EntityKind `json:"kind"`
	ID   model.ID   `json:"id"`
}

func (e Entity) valid() bool {
	switch e.Kind {
	case EntityIssue, EntityCondition, EntityIncident:
		return e.ID != (model.ID{})
	}
	return false
}

// Tier is the urgency tier of the current evidence. Urgent notifies
// immediately; queue is visible at once in the shared queue and is also a
// daily digest candidate. none is no notifiable evidence.
type Tier string

const (
	TierNone   Tier = "none"
	TierQueue  Tier = "queue"
	TierUrgent Tier = "urgent"
)

func (t Tier) rank() int {
	switch t {
	case TierUrgent:
		return 2
	case TierQueue:
		return 1
	}
	return 0
}

// Severity orders impact; higher is worse. It has the same scale as the
// incident severity so the incident adapter maps it one to one.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityMinor    Severity = 1
	SeverityMajor    Severity = 2
	SeverityCritical Severity = 3
)

func (s Severity) valid() bool { return s <= SeverityCritical }

// SourceState is the linked source's own state, independent of any human
// workflow. Unknown is never recovered.
type SourceState string

const (
	SourceFiring    SourceState = "firing"
	SourceRecovered SourceState = "recovered"
	SourceUnknown   SourceState = "unknown"
)

// Freshness is how current a source observation is.
type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

func (f Freshness) valid() bool {
	return f == FreshnessFresh || f == FreshnessStale || f == FreshnessUnknown
}

// worse is the more doubtful of two freshness values.
func (f Freshness) worse(o Freshness) Freshness {
	rank := func(v Freshness) int {
		switch v {
		case FreshnessFresh:
			return 0
		case FreshnessStale:
			return 1
		}
		return 2
	}
	if rank(o) > rank(f) {
		return o
	}
	return f
}

// HumanStatus is the human workflow status only; it never says whether the
// source is still failing.
type HumanStatus string

const (
	HumanOpen     HumanStatus = "open"
	HumanResolved HumanStatus = "resolved"
)

// Basis is why a tier was chosen.
type Basis string

const (
	BasisNone         Basis = "none"
	BasisCriticalCode Basis = "critical_code"
	BasisErrorRate    Basis = "error_rate"
	BasisRegression   Basis = "regression"
	BasisCount        Basis = "count"
	BasisCondition    Basis = "condition"
	BasisIncident     Basis = "incident"
)

// RateState says whether an error rate could be computed. A percentage is
// never invented: any state other than RateKnown means the rate is unknown.
type RateState string

const (
	RateNotApplicable  RateState = "not_applicable"
	RateKnown          RateState = "known"
	RateNoDenominator  RateState = "unknown_no_denominator"
	RateIncomplete     RateState = "unknown_incomplete"
	RateStale          RateState = "unknown_stale"
	RateWindowMismatch RateState = "unknown_window_mismatch"
	RateConflict       RateState = "unknown_conflict"
	RateInconsistent   RateState = "unknown_inconsistent"
)

// Kind is the closed set of intent kinds. Urgent, reminder, worse impact,
// recovery, resolution and current-state go to recipients immediately; queue
// goes to the shared queue immediately; digest is the daily per-recipient
// summary.
type Kind string

const (
	KindOpen        Kind = "open"
	KindReminder    Kind = "reminder"
	KindWorseImpact Kind = "worse_impact"
	KindRecovery    Kind = "recovery"
	KindResolution  Kind = "resolution"
	KindCurrent     Kind = "current_state"
	KindQueue       Kind = "queue"
	KindDigest      Kind = "digest"
)

// Route is where an intent is delivered.
type Route string

const (
	RouteImmediate Route = "immediate"
	RouteQueue     Route = "queue"
	RouteDigest    Route = "digest"
)

func routeOf(k Kind) Route {
	switch k {
	case KindQueue:
		return RouteQueue
	case KindDigest:
		return RouteDigest
	}
	return RouteImmediate
}

// Disposition is whether an intent is to be delivered. A suppressed or failed
// intent is still recorded so the reason is visible; it is never a success.
type Disposition string

const (
	DispositionDeliver    Disposition = "deliver"
	DispositionSuppressed Disposition = "suppressed"
	DispositionFailed     Disposition = "failed"
)

// Code is the closed reason on a suppressed or failed intent.
type Code string

const (
	CodeNone          Code = ""
	CodeMaintenance   Code = "maintenance"
	CodeSnoozed       Code = "snoozed"
	CodeShadow        Code = "shadow"
	CodeNoDestination Code = "no_destination"
)

// DeliveryMode says whether this policy's intents may leave the product.
// Shadow computes every decision without sending: it is the no-send phase of
// an owner cutover. Exactly one canonical owner decides in either mode.
type DeliveryMode string

const (
	ModeActive DeliveryMode = "active"
	ModeShadow DeliveryMode = "shadow"
)

// Mode is how an evidence event reached the policy.
type Mode string

const (
	// ModeLive is current evidence.
	ModeLive Mode = "live"
	// ModeBackfill is historical evidence replayed into the product. It is
	// recorded as late history and never interrupts anyone.
	ModeBackfill Mode = "backfill"
	// ModeOperatorReplay is an explicit operator replay: it is processed as
	// live evidence.
	ModeOperatorReplay Mode = "operator_replay"
)

// Fixed policy windows and bounds.
const (
	// ErrorWindow is the event window evidence is grouped in.
	ErrorWindow = model.UnixNano(5 * time.Minute)
	// LateAfter is how long after a window closed evidence for it is late
	// history instead of live evidence.
	LateAfter = model.UnixNano(10 * time.Minute)

	MaxWindows           = 3
	MaxWindowOccurrences = 1024
	MaxEventOccurrences  = 512
	MaxRecipients        = 32
	MaxLinked            = 8
	MaxCursors           = 16
	MaxCriticalCodes     = 32
	MaxCriticalServices  = 8
	MaxSentMarks         = 64
	MaxReasonBytes       = 512
	MaxName              = 64
	// MaxSuppressionHard bounds the configurable snooze/maintenance maximum.
	MaxSuppressionHard = model.UnixNano(90 * 24 * time.Hour)
)

// Config is the scoped, editable policy. DefaultConfig holds the approved
// defaults: at least 20 observed operations AND at least 5 deduplicated
// failures AND at least a 5% rate, or an approved critical operation code, or
// a qualifying regression with at least 5 occurrences; one opening, first
// reminder after 15 minutes then every 60 while unacknowledged.
type Config struct {
	MinOperations   uint32         `json:"min_operations"`
	MinFailures     uint32         `json:"min_failures"`
	RateBasisPoints uint32         `json:"rate_basis_points"`
	RegressionMin   uint32         `json:"regression_min"`
	CriticalCodes   []string       `json:"critical_codes,omitempty"`
	FirstReminder   model.UnixNano `json:"first_reminder_ns"`
	ReminderEvery   model.UnixNano `json:"reminder_every_ns"`
	MaxSuppression  model.UnixNano `json:"max_suppression_ns"`
	// DefaultZone is the installation digest zone; empty is UTC.
	DefaultZone string `json:"default_zone,omitempty"`
}

// DefaultConfig returns the approved default policy.
func DefaultConfig() Config {
	return Config{
		MinOperations:   20,
		MinFailures:     5,
		RateBasisPoints: 500,
		RegressionMin:   5,
		FirstReminder:   model.UnixNano(15 * time.Minute),
		ReminderEvery:   model.UnixNano(60 * time.Minute),
		MaxSuppression:  model.UnixNano(7 * 24 * time.Hour),
	}
}

func (c Config) clone() Config {
	c.CriticalCodes = append([]string(nil), c.CriticalCodes...)
	return c
}

func (c Config) critical(code string) bool {
	for _, v := range c.CriticalCodes {
		if v == code {
			return true
		}
	}
	return false
}

// PolicyRef is the scoped current policy revision an event was produced
// under. Config must accompany a revision the state has not adopted yet.
type PolicyRef struct {
	Revision model.Revision `json:"revision"`
	Config   *Config        `json:"config,omitempty"`
}

// Recipient is one org-owned destination the policy notifies. Zone is the
// digest zone; empty falls back to the policy default, then UTC.
type Recipient struct {
	ID         model.ID       `json:"id"`
	Zone       string         `json:"zone,omitempty"`
	Enabled    bool           `json:"enabled"`
	DigestNext model.UnixNano `json:"digest_next_ns,omitempty"`
	// DigestSeen is the queue revision the last delivered digest covered.
	DigestSeen uint64 `json:"digest_seen,omitempty"`
}

// Denominator is the named operation-count provenance for a rate. Only a
// complete one for exactly the evidence window yields a rate.
type Denominator struct {
	Name        string         `json:"name"`
	WindowStart model.UnixNano `json:"window_start_ns"`
	Operations  model.Uint64   `json:"operations"`
	Complete    bool           `json:"complete"`
}

// Regression is the issue's regression provenance for the window.
type Regression struct {
	// Eligible says the occurrence(s) qualify as a regression at all.
	Eligible bool `json:"eligible"`
	// Occurrences is the number of qualifying deduplicated occurrences.
	Occurrences uint32 `json:"occurrences"`
	// Reopened says the issue workflow reopened the issue.
	Reopened      bool `json:"reopened,omitempty"`
	AncestryKnown bool `json:"ancestry_known"`
}

// ServiceRef names the affected service. A newly affected critical service
// is a material impact change.
type ServiceRef struct {
	ID       model.ID `json:"id"`
	Critical bool     `json:"critical,omitempty"`
}

// IssueEvidence is one batch of deduplicated occurrence IDs in one 5-minute
// window, with its provenance. Duplicate occurrence IDs never raise a count.
type IssueEvidence struct {
	// WindowStart is aligned to ErrorWindow.
	WindowStart model.UnixNano `json:"window_start_ns"`
	// Occurrences are occurrence IDs only, never text.
	Occurrences []model.ID `json:"occurrences,omitempty"`
	// Code is an operation error code; it is critical only if the policy
	// approves it. It needs at least one occurrence.
	Code        string       `json:"code,omitempty"`
	Freshness   Freshness    `json:"freshness"`
	Denominator *Denominator `json:"denominator,omitempty"`
	Regression  *Regression  `json:"regression,omitempty"`
	Service     *ServiceRef  `json:"service,omitempty"`
}

// ConditionEvidence is one alert condition observation. Seq is the source
// sequence: an observation that does not advance it is late history.
type ConditionEvidence struct {
	Seq       uint64      `json:"seq"`
	State     SourceState `json:"state"`
	Freshness Freshness   `json:"freshness"`
	Severity  Severity    `json:"severity"`
	Episode   model.ID    `json:"episode_id"`
	Service   *ServiceRef `json:"service,omitempty"`
}

// IncidentEvidence is the human incident's snapshot. Version orders it: a
// snapshot that does not advance it is late history.
type IncidentEvidence struct {
	Version        model.Revision `json:"version"`
	Status         HumanStatus    `json:"status"`
	Severity       Severity       `json:"severity"`
	ImpactRevision uint64         `json:"impact_revision"`
	Episode        model.ID       `json:"episode_id"`
	Source         SourceState    `json:"source"`
	Freshness      Freshness      `json:"freshness"`
	Service        *ServiceRef    `json:"service,omitempty"`
}

// ActionType is the closed set of human actions that change delivery. Other
// incident actions (assign, link) do not affect delivery and are not mapped.
type ActionType string

const (
	ActionAck            ActionType = "ack"
	ActionResolve        ActionType = "resolve"
	ActionSnooze         ActionType = "snooze"
	ActionUnsnooze       ActionType = "unsnooze"
	ActionMaintenance    ActionType = "maintenance"
	ActionMaintenanceEnd ActionType = "maintenance_end"
)

// ScopeKind is how far a snooze or maintenance window reaches.
type ScopeKind string

const (
	ScopeEntity  ScopeKind = "entity"
	ScopeProject ScopeKind = "project"
	ScopeService ScopeKind = "service"
)

// Scope is the reach of a window. A service scope applies only to states
// that affect that service; other states ignore it.
type Scope struct {
	Kind    ScopeKind `json:"kind"`
	Service *model.ID `json:"service,omitempty"`
}

// HumanAction is one human decision. ACK covers the impact revision the human
// saw and pauses reminders only. Snooze and maintenance need a reason, a
// scope and an expiry.
type HumanAction struct {
	Type    ActionType     `json:"type"`
	Actor   model.ID       `json:"actor"`
	Version model.Revision `json:"version"`
	// ImpactRevision is the revision an ACK covers.
	ImpactRevision uint64         `json:"impact_revision,omitempty"`
	Scope          Scope          `json:"scope,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Until          model.UnixNano `json:"until,omitempty"`
}

// Timer fires every deadline that is due at the decision time: reminders,
// snooze and maintenance expiry and digests. Replaying one is harmless.
type Timer struct{}

// DestinationChange adds, updates or removes one recipient.
type DestinationChange struct {
	Recipient model.ID `json:"recipient"`
	Enabled   bool     `json:"enabled"`
	Zone      string   `json:"zone,omitempty"`
	Remove    bool     `json:"remove,omitempty"`
}

// OwnerCutover transfers the one canonical owner, for instance from an issue
// to the incident it was promoted to, and/or switches shadow and active
// delivery. Command makes a replay a no-op.
type OwnerCutover struct {
	Command model.ID     `json:"command_id"`
	To      Entity       `json:"to"`
	Mode    DeliveryMode `json:"mode"`
}

// EventKind is the closed event union tag.
type EventKind string

const (
	EventIssue       EventKind = "issue_evidence"
	EventCondition   EventKind = "condition_evidence"
	EventIncident    EventKind = "incident_evidence"
	EventAction      EventKind = "human_action"
	EventTimer       EventKind = "timer"
	EventDestination EventKind = "destination_change"
	EventCutover     EventKind = "owner_cutover"
)

// PolicyEvent is a closed union: Kind selects exactly one payload.
type PolicyEvent struct {
	Kind    EventKind `json:"kind"`
	Command model.ID  `json:"command_id"`
	Org     model.ID  `json:"org_id"`
	Project model.ID  `json:"project_id"`
	Policy  model.ID  `json:"policy_id"`
	// PolicyRef is the scoped current policy revision.
	PolicyRef PolicyRef `json:"policy"`
	// OwnerRevision is the expected canonical-owner revision. A mismatch
	// fails closed.
	OwnerRevision model.Revision `json:"owner_revision"`
	// Entity names the entity the event is about; it must be linked to the
	// state. Timer and destination events leave it nil.
	Entity *Entity `json:"entity,omitempty"`
	Mode   Mode    `json:"mode,omitempty"`
	// Cursor is the source cursor the evidence was read at.
	Cursor *model.Cursor `json:"cursor,omitempty"`

	Issue       *IssueEvidence     `json:"issue,omitempty"`
	Condition   *ConditionEvidence `json:"condition,omitempty"`
	Incident    *IncidentEvidence  `json:"incident,omitempty"`
	Action      *HumanAction       `json:"action,omitempty"`
	Timer       *Timer             `json:"timer,omitempty"`
	Destination *DestinationChange `json:"destination,omitempty"`
	Cutover     *OwnerCutover      `json:"cutover,omitempty"`
}

// WindowState is the merged evidence of one 5-minute window. Merging is
// commutative: any order of the same batches yields the same window.
type WindowState struct {
	Start model.UnixNano `json:"start_ns"`
	// Occurrences are the distinct occurrence IDs, ascending. At
	// MaxWindowOccurrences the smallest are kept and Saturated is set, so
	// Failures is then a lower bound.
	Occurrences []model.ID   `json:"occurrences,omitempty"`
	Saturated   bool         `json:"saturated,omitempty"`
	Critical    bool         `json:"critical,omitempty"`
	Freshness   Freshness    `json:"freshness"`
	Denominator *Denominator `json:"denominator,omitempty"`
	// DenominatorMismatch / DenominatorConflict record a denominator that
	// could not be used.
	DenominatorMismatch bool        `json:"denominator_mismatch,omitempty"`
	DenominatorConflict bool        `json:"denominator_conflict,omitempty"`
	Regression          *Regression `json:"regression,omitempty"`
}

// Explanation is the current, typed count/rate/regression explanation.
type Explanation struct {
	Basis    Basis     `json:"basis"`
	Rate     RateState `json:"rate"`
	Failures uint32    `json:"failures"`
	// Saturated says Failures is a lower bound.
	Saturated  bool         `json:"saturated,omitempty"`
	Operations model.Uint64 `json:"operations,omitempty"`
	// RateBasisPoints is set only when Rate is RateKnown (floor of
	// failures*10000/operations).
	RateBasisPoints uint32      `json:"rate_basis_points,omitempty"`
	Regression      *Regression `json:"regression,omitempty"`
}

// KindMark records that an intent was decided: which kind, for which impact
// revision and ordinal, and with what disposition. The ledger is bounded.
type KindMark struct {
	Kind           Kind           `json:"kind"`
	ImpactRevision uint64         `json:"impact_revision"`
	Ordinal        uint64         `json:"ordinal"`
	Disposition    Disposition    `json:"disposition"`
	Code           Code           `json:"code,omitempty"`
	At             model.UnixNano `json:"at_ns"`
}

// Ack is the acknowledgment: who, when and which impact revision it covers.
type Ack struct {
	Actor          model.ID       `json:"actor"`
	At             model.UnixNano `json:"at_ns"`
	ImpactRevision uint64         `json:"impact_revision"`
}

// Window is a reasoned, expiring snooze or maintenance scope.
type Window struct {
	Scope   Scope          `json:"scope"`
	Actor   model.ID       `json:"actor"`
	Reason  string         `json:"reason"`
	From    model.UnixNano `json:"from_ns"`
	Until   model.UnixNano `json:"until_ns"`
	Version model.Revision `json:"version"`
}

// Active reports whether the window covers at.
func (w *Window) Active(at model.UnixNano) bool {
	return w != nil && at >= w.From && at < w.Until
}

// Reminders is the reminder schedule. Next is zero when no reminder is due.
type Reminders struct {
	Next model.UnixNano `json:"next_ns,omitempty"`
	Sent uint32         `json:"sent"`
}

// PolicyState is the policy state of one canonical notification subject: the
// first entity of a chain of linked entities, owned at any moment by exactly
// one canonical entity. It is plain data: bounded, JSON-serializable and
// safe to keep as opaque control state. Decide never mutates its argument.
type PolicyState struct {
	Org     model.ID `json:"org_id"`
	Project model.ID `json:"project_id"`
	Policy  model.ID `json:"policy_id"`
	// Subject is the immutable identity of this state.
	Subject Entity `json:"subject"`
	// Owner is the one canonical entity that decides urgency; OwnerRevision
	// advances on every cutover. Linked is every entity allowed to feed
	// evidence, including Owner.
	Owner         Entity         `json:"owner"`
	OwnerRevision model.Revision `json:"owner_revision"`
	Linked        []Entity       `json:"linked"`
	LastCutover   *model.ID      `json:"last_cutover,omitempty"`
	// Adopt is set by a cutover to an incident while an episode is open: the
	// incident's first snapshot adopts that episode instead of opening one.
	Adopt bool `json:"adopt,omitempty"`

	PolicyRevision model.Revision `json:"policy_revision"`
	Config         Config         `json:"config"`
	Mode           DeliveryMode   `json:"mode"`
	Recipients     []Recipient    `json:"recipients,omitempty"`

	// Cursors is the highest applied source cursor per data group.
	Cursors []model.Cursor `json:"cursors,omitempty"`
	// Late counts evidence recorded as late history; Backfilled counts
	// backfill evidence. Neither ever interrupts anyone.
	Late       uint32 `json:"late,omitempty"`
	Backfilled uint32 `json:"backfilled,omitempty"`

	Windows         []WindowState  `json:"windows,omitempty"`
	ConditionSeq    uint64         `json:"condition_seq,omitempty"`
	IncidentVersion model.Revision `json:"incident_version,omitempty"`
	SourceImpact    uint64         `json:"source_impact,omitempty"`
	Service         *ServiceRef    `json:"service,omitempty"`
	// CriticalServices are the critical services affected so far, ascending.
	CriticalServices []model.ID `json:"critical_services,omitempty"`

	Source      SourceState `json:"source"`
	SourceFresh Freshness   `json:"source_freshness"`
	Human       HumanStatus `json:"human"`
	Tier        Tier        `json:"tier"`
	Severity    Severity    `json:"severity"`
	Explanation Explanation `json:"explanation"`

	// Episode counts opening notifications. EpisodeOpen is true once the
	// current episode opened. EpisodeRef is the source episode ID when known.
	Episode     uint64    `json:"episode"`
	EpisodeOpen bool      `json:"episode_open,omitempty"`
	EpisodeRef  *model.ID `json:"episode_ref,omitempty"`
	// ImpactRevision is the policy's material-impact revision; PeakSeverity
	// is the worst severity seen in the episode.
	ImpactRevision uint64   `json:"impact_revision"`
	PeakSeverity   Severity `json:"peak_severity"`
	Worse          uint64   `json:"worse,omitempty"`
	Recoveries     uint64   `json:"recoveries,omitempty"`
	Updates        uint64   `json:"updates,omitempty"`

	// QueueRevision advances on every queue-visible change, immediately.
	QueueRevision uint64     `json:"queue_revision"`
	QueueKey      queueKey   `json:"queue_key"`
	Sent          []KindMark `json:"sent,omitempty"`

	Reminders   Reminders `json:"reminders"`
	Ack         *Ack      `json:"ack,omitempty"`
	Snooze      *Window   `json:"snooze,omitempty"`
	Maintenance *Window   `json:"maintenance,omitempty"`
	// SnoozeEnded and MaintenanceEnded are the highest ended window
	// versions: a late snooze/maintenance older than that never starts.
	SnoozeEnded      model.Revision `json:"snooze_ended,omitempty"`
	MaintenanceEnded model.Revision `json:"maintenance_ended,omitempty"`
	// Pending says an intent was suppressed or a reminder paused; when the
	// suppression ends the policy reevaluates once and emits at most one
	// current-state update.
	Pending bool `json:"pending,omitempty"`
}

// queueKey is the queue-visible summary; a change of any field is a queue
// change.
type queueKey struct {
	Tier     Tier        `json:"tier"`
	Severity Severity    `json:"severity"`
	Source   SourceState `json:"source"`
	Human    HumanStatus `json:"human"`
	Owner    Entity      `json:"owner"`
}

// IntentKey is the C08 stable identity of an intent:
// (org, policy, entity, impact_revision, kind, recipient). Ordinal tells
// repeats of one kind within one revision apart (reminder number, digest
// local date, queue revision) and is zero for kinds that occur once. A nil
// Recipient is the shared queue or the missing-destination failure.
type IntentKey struct {
	Org            model.ID  `json:"org_id"`
	Policy         model.ID  `json:"policy_id"`
	Entity         Entity    `json:"entity"`
	ImpactRevision uint64    `json:"impact_revision"`
	Kind           Kind      `json:"kind"`
	Recipient      *model.ID `json:"recipient,omitempty"`
	Ordinal        uint64    `json:"ordinal,omitempty"`
}

// Template is the approved template data: typed fields only. A renderer picks
// the wording from Kind; no telemetry, message, source or human text is here.
type Template struct {
	Entity       Entity      `json:"entity"`
	Tier         Tier        `json:"tier"`
	Severity     Severity    `json:"severity"`
	Source       SourceState `json:"source"`
	Freshness    Freshness   `json:"freshness"`
	Human        HumanStatus `json:"human"`
	Acknowledged bool        `json:"acknowledged,omitempty"`
	Explanation  Explanation `json:"explanation"`
	Service      *ServiceRef `json:"service,omitempty"`
	// Reminder is the reminder number for KindReminder.
	Reminder uint32 `json:"reminder,omitempty"`
	// Digest identifies the digest for KindDigest.
	Digest *DigestFact `json:"digest,omitempty"`
	// Queue is the queue revision for KindQueue and KindDigest.
	Queue uint64 `json:"queue,omitempty"`
}

// DigestFact is the digest identity: one per recipient, local date and policy
// revision. The outbox groups digest intents by ID.
type DigestFact struct {
	ID        model.ID       `json:"id"`
	LocalDate uint32         `json:"local_date"`
	Revision  model.Revision `json:"policy_revision"`
}

// Intent is one decision: safe, stable and idempotent. It is intent only;
// nothing here sends. Cause is the event that produced it (audit only, not
// part of the identity).
type Intent struct {
	ID          model.ID       `json:"id"`
	Key         IntentKey      `json:"key"`
	Route       Route          `json:"route"`
	Disposition Disposition    `json:"disposition"`
	Code        Code           `json:"code,omitempty"`
	At          model.UnixNano `json:"at_ns"`
	Cause       model.ID       `json:"cause"`
	Template    Template       `json:"template"`
}

// Eligible reports that the intent is to be delivered.
func (i Intent) Eligible() bool { return i.Disposition == DispositionDeliver }

// OutcomeKind is the closed delivery outcome set. Unknown means the provider
// may have accepted the message; a retry keeps the original delivery ID.
type OutcomeKind string

const (
	OutcomeAccepted OutcomeKind = "accepted"
	OutcomeRetry    OutcomeKind = "retry"
	OutcomeTerminal OutcomeKind = "terminal"
	OutcomeUnknown  OutcomeKind = "unknown"
)

// Outcome is the safe result of one delivery attempt.
type Outcome struct {
	Kind OutcomeKind `json:"kind"`
	// ProviderID is set for accepted only.
	ProviderID string `json:"provider_id,omitempty"`
	// Code is a safe failure code for retry and terminal.
	Code string `json:"code,omitempty"`
	// RetryAfter is the provider's retry hint for retry.
	RetryAfter model.UnixNano `json:"retry_after_ns,omitempty"`
}

// Delivery is one outbox entry derived from an eligible Intent. Its ID is the
// stable idempotency ID and equals Intent.ID; retries and unknown outcomes
// keep it.
type Delivery struct {
	ID          model.ID       `json:"id"`
	Key         IntentKey      `json:"key"`
	Route       Route          `json:"route"`
	Template    Template       `json:"template"`
	Attempt     uint32         `json:"attempt"`
	NextAttempt model.UnixNano `json:"next_attempt_ns"`
	FenceExpiry model.UnixNano `json:"fence_expiry_ns,omitempty"`
}

// Sender is the consumer-owned seam a provider implements and the worker
// calls. Implementations perform the real send; this package never does.
type Sender interface {
	Send(ctx context.Context, scope auth.Scope, d Delivery) (Outcome, error)
}

// Reason is the closed set of refusal reasons.
type Reason string

const (
	ReasonOwnerRevision  Reason = "owner_revision_mismatch"
	ReasonNotLinked      Reason = "entity_not_linked"
	ReasonPolicyStale    Reason = "policy_revision_stale"
	ReasonPolicyConfig   Reason = "policy_config_required"
	ReasonPolicyConflict Reason = "policy_config_conflict"
	ReasonScope          Reason = "scope_mismatch"
	ReasonInvalidEvent   Reason = "invalid_event"
	ReasonInvalidState   Reason = "invalid_state"
	ReasonInvalidZone    Reason = "invalid_zone"
	ReasonTimeRange      Reason = "time_out_of_range"
	ReasonQuota          Reason = "state_bound_exceeded"
)

// Error is a typed refusal. It unwraps to a model.Fault carrying the code so
// callers can use the shared error classes.
type Error struct {
	Code   model.Code
	Reason Reason
}

func (e *Error) Error() string { return string(e.Code) + ": " + string(e.Reason) }

// Unwrap returns the shared fault for the code.
func (e *Error) Unwrap() error {
	f := model.Fail(e.Code)
	f.SafeDetail = string(e.Reason)
	return f
}

// Is matches another *Error with the same reason.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason
}

// ReasonOf extracts the reason of a typed refusal.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}

func refuse(code model.Code, reason Reason) error { return &Error{Code: code, Reason: reason} }

// safeName reports a bounded identifier made of letters, digits and _ . : -.
func safeName(s string) bool {
	if s == "" || len(s) > MaxName {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

// safeReason reports a bounded, printable, non-empty human reason.
func safeReason(s string) bool {
	if s == "" || len(s) > MaxReasonBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
