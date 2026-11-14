// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package incidents is C08 human incident response: one incident is a human
// workflow entity that is deliberately separate from the alert condition and the
// error issue it is linked to. The reducer in this package is pure and
// deterministic; Service binds it to the C05 control group.
package incidents

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Type is the closed set of incident actions. snooze/unsnooze and
// maintenance/maintenance_end are distinct scopes with distinct history.
type Type string

const (
	TypeOpen           Type = "open"
	TypeAck            Type = "ack"
	TypeResolve        Type = "resolve"
	TypeAssign         Type = "assign"
	TypeImpact         Type = "impact"
	TypeSnooze         Type = "snooze"
	TypeUnsnooze       Type = "unsnooze"
	TypeMaintenance    Type = "maintenance"
	TypeMaintenanceEnd Type = "maintenance_end"
	TypeLink           Type = "link"
)

// Origin says whether an action is a human decision or a system condition
// event. A system event can never change human-owned state.
type Origin string

const (
	OriginHuman  Origin = "human"
	OriginSystem Origin = "system"
)

// Status is the human workflow status only. It never says whether the source
// is still failing.
type Status string

const (
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
)

// ConditionState and Freshness are the linked source's own state. Unknown is
// never treated as recovered.
type ConditionState string

const (
	ConditionFiring    ConditionState = "firing"
	ConditionRecovered ConditionState = "recovered"
	ConditionUnknown   ConditionState = "unknown"
)

type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

// Severity orders impact; a higher value is worse.
type Severity uint8

const (
	SeverityMinor    Severity = 1
	SeverityMajor    Severity = 2
	SeverityCritical Severity = 3
)

// LinkKind names structured evidence an incident is linked to.
type LinkKind string

const (
	LinkCondition LinkKind = "condition"
	LinkIssue     LinkKind = "issue"
	LinkRelease   LinkKind = "release"
	LinkService   LinkKind = "service"
	LinkIncident  LinkKind = "incident"
)

// Link is one structured, ID-only evidence link.
type Link struct {
	Kind LinkKind `json:"kind"`
	ID   model.ID `json:"id"`
}

// Limits. The defaults are the approved 7-day snooze/maintenance maximum and
// bounded per-incident history so control state stays bounded.
const (
	DefaultMaxWindow = model.UnixNano(7 * 24 * time.Hour)
	HardMaxWindow    = model.UnixNano(90 * 24 * time.Hour)
	MaxTimeline      = 128
	MaxLinks         = 32
	MaxReasonBytes   = 512
)

// Target names one incident inside one organization and project.
type Target struct {
	Org      model.ID `json:"org_id"`
	Project  model.ID `json:"project_id"`
	Incident model.ID `json:"incident_id"`
}

// Impact is one source observation: the linked condition, its episode, the
// impact severity, and the condition's state and freshness.
type Impact struct {
	Condition model.ID       `json:"condition_id"`
	Episode   model.ID       `json:"episode_id"`
	Severity  Severity       `json:"severity"`
	State     ConditionState `json:"state"`
	Freshness Freshness      `json:"freshness"`
}

// Action is one C05 IncidentAction command. Actor comes from the validated
// session (Service.Act overwrites it), never from a request body.
type Action struct {
	CommandID       model.ID       `json:"command_id"`
	ExpectedVersion model.Revision `json:"expected_version"`
	Type            Type           `json:"type"`
	Origin          Origin         `json:"origin"`
	Actor           model.ID       `json:"actor"`
	Target          Target         `json:"target"`
	Reason          string         `json:"reason,omitempty"`
	Owner           *model.ID      `json:"owner,omitempty"`
	Until           model.UnixNano `json:"until,omitempty"`
	Impact          *Impact        `json:"impact,omitempty"`
	Previous        *model.ID      `json:"previous,omitempty"`
	Link            *Link          `json:"link,omitempty"`
	// MaxWindow bounds Until for snooze and maintenance; zero is the 7-day default.
	MaxWindow model.UnixNano `json:"max_window,omitempty"`
}

// Entry is one immutable timeline record. The state is exactly the replay of its
// timeline, so a past result can always be reproduced.
type Entry struct {
	At     model.UnixNano `json:"at"`
	Action Action         `json:"action"`
}

// Ack is the acknowledgment: who, when, and the impact revision it covers.
type Ack struct {
	Actor          model.ID       `json:"actor"`
	At             model.UnixNano `json:"at"`
	ImpactRevision uint64         `json:"impact_revision"`
	Version        model.Revision `json:"version"`
}

// Window is a reasoned, expiring snooze or maintenance scope. Ended is nonzero
// once it was ended explicitly.
type Window struct {
	Actor   model.ID       `json:"actor"`
	Reason  string         `json:"reason"`
	From    model.UnixNano `json:"from"`
	Until   model.UnixNano `json:"until"`
	Ended   model.UnixNano `json:"ended,omitempty"`
	Version model.Revision `json:"version"`
}

// Active reports whether the window covers at.
func (w *Window) Active(at model.UnixNano) bool {
	return w != nil && w.Ended == 0 && at >= w.From && at < w.Until
}

// Condition is the linked source condition's own state and freshness.
type Condition struct {
	ID        model.ID       `json:"id"`
	State     ConditionState `json:"state"`
	Freshness Freshness      `json:"freshness"`
	At        model.UnixNano `json:"at"`
}

// State is one incident. Human status, owner, ACK, snooze and maintenance are
// separate from the linked condition and from impact. The header fields
// (incident_id, org_id, project_id, version) are the closed schema the control
// handler checks without importing this package.
type State struct {
	ID             model.ID       `json:"incident_id"`
	Org            model.ID       `json:"org_id"`
	Project        model.ID       `json:"project_id"`
	Version        model.Revision `json:"version"`
	Status         Status         `json:"status"`
	Owner          *model.ID      `json:"owner,omitempty"`
	Condition      Condition      `json:"condition"`
	Episode        model.ID       `json:"episode_id"`
	Severity       Severity       `json:"severity"`
	ImpactRevision uint64         `json:"impact_revision"`
	Ack            *Ack           `json:"ack,omitempty"`
	Snooze         *Window        `json:"snooze,omitempty"`
	Maintenance    *Window        `json:"maintenance,omitempty"`
	Links          []Link         `json:"links,omitempty"`
	Previous       *model.ID      `json:"previous,omitempty"`
	ResolvedAt     model.UnixNano `json:"resolved_at,omitempty"`
	Timeline       []Entry        `json:"timeline"`

	// Erased is set on the state Service.Get reads for an incident whose state a
	// deletion erased: only the closed header (ID, Org, Project, Version) is
	// filled and nothing derived from telemetry remains. It is never stored.
	Erased bool `json:"-"`
}

// DetailErased is the SafeDetail of the model.NotFound an action on an erased
// incident gets: a deletion removed the incident's state, so there is nothing to
// act on. It is not storage damage (model.Corrupt).
const DetailErased = "incident_erased"

// AckCurrent reports whether the ACK covers the current impact revision.
func (s State) AckCurrent() bool {
	return s.Ack != nil && s.Ack.ImpactRevision == s.ImpactRevision
}

// ReminderPaused reports whether reminder-kind delivery is paused at the given
// time. Only reminders pause; a worse impact still notifies.
func (s State) ReminderPaused(at model.UnixNano) bool {
	return s.Status == StatusOpen && (s.AckCurrent() || s.Snooze.Active(at))
}

// EffectKind is the closed set of safe audit/outbox intents. An Effect is
// intent only: nothing in this package sends anything.
type EffectKind string

const (
	EffectAudit           EffectKind = "audit"
	EffectNotifyOpen      EffectKind = "notify_open"
	EffectNotifyImpact    EffectKind = "notify_impact"
	EffectRemindersPause  EffectKind = "reminders_pause"
	EffectRemindersStop   EffectKind = "reminders_stop"
	EffectRemindersResume EffectKind = "reminders_resume"
	EffectMaintBegin      EffectKind = "maintenance_begin"
	EffectMaintEnd        EffectKind = "maintenance_end"
	EffectOpenLinked      EffectKind = "open_linked_incident"
)

// Effect carries safe identifiers and codes only, never evidence text.
type Effect struct {
	Kind           EffectKind     `json:"kind"`
	Incident       model.ID       `json:"incident_id"`
	Version        model.Revision `json:"version"`
	Command        model.ID       `json:"command_id"`
	Actor          model.ID       `json:"actor"`
	Origin         Origin         `json:"origin"`
	Action         Type           `json:"action"`
	ImpactRevision uint64         `json:"impact_revision,omitempty"`
	Eligible       bool           `json:"eligible,omitempty"`
	Code           string         `json:"code,omitempty"`
	Until          model.UnixNano `json:"until,omitempty"`
	Subject        *model.ID      `json:"subject,omitempty"`
}

// VersionConflict is a lost optimistic-concurrency race: the incident is at
// Current, not at the version the action expected. It is never retried as
// another human action.
type VersionConflict struct{ Current model.Revision }

func (c *VersionConflict) Error() string {
	return "conflict: incident_version_conflict current=" + strconv.FormatUint(uint64(c.Current), 10)
}

func (c *VersionConflict) Unwrap() error {
	f := model.Fail(model.Conflict)
	f.SafeDetail = "incident_version_conflict"
	return f
}

// IsVersionConflict extracts the current version from a VersionConflict.
func IsVersionConflict(err error) (model.Revision, bool) {
	var c *VersionConflict
	if errors.As(err, &c) {
		return c.Current, true
	}
	return 0, false
}

func fault(code model.Code, detail string) error {
	f := model.Fail(code)
	f.SafeDetail = detail
	return f
}

func equalActions(a, b Action) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}
