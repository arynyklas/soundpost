// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
)

// NotificationBinding is the notification policy a project's conditions are
// decided under: which policy and revision, its configuration, and the
// destinations (recipient IDs of org-owned destinations) it notifies.
type NotificationBinding struct {
	Policy     model.ID
	Revision   model.Revision
	Config     notify.Config
	Recipients []model.ID
}

// NotificationRouting says how a project's condition changes are notified. There
// is no policy catalogue in control state yet, so there is no production
// implementation: a node without one decides no condition notification (the
// conditions themselves are still consumed). found=false means the project is
// not routed.
type NotificationRouting interface {
	Routing(ctx context.Context, scope auth.Scope, project model.ID) (binding NotificationBinding, found bool, err error)
}

// conditionSeverity maps the free-text severity of a rule to the closed policy
// severity: "critical" and "major" keep their rank, every other text (including
// none) is minor, so unknown text can never page as critical.
func conditionSeverity(text string) notify.Severity {
	switch strings.ToLower(text) {
	case "critical":
		return notify.SeverityCritical
	case "major":
		return notify.SeverityMajor
	}
	return notify.SeverityMinor
}

// conditionEvidence maps a committed condition to the policy evidence it
// carries. ok is false while the condition may not notify (its newest event was
// only backfilled), has said nothing definite (pending, or no phase) or has no
// episode: there is nothing to notify. The source
// sequence is the condition's committed version, which advances with every
// accepted change, so a repeat decides nothing.
func conditionEvidence(st conditions.State) (notify.ConditionEvidence, bool) {
	if !st.Notify || st.Episode == nil {
		return notify.ConditionEvidence{}, false
	}
	var source notify.SourceState
	switch st.Phase {
	case conditions.PhaseFiring, conditions.PhaseRecovering:
		source = notify.SourceFiring
	case conditions.PhaseRecovered:
		source = notify.SourceRecovered
	default:
		return notify.ConditionEvidence{}, false
	}
	return notify.ConditionEvidence{Seq: uint64(st.Version), State: source, Freshness: notify.Freshness(st.Freshness), Severity: conditionSeverity(st.Severity), Episode: *st.Episode}, true
}

func policyCommand(parts ...[]byte) model.ID {
	h := sha256.New()
	for _, p := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// submitConditions decides the committed conditions of the project that may
// notify into the delivery outbox, at most NotifyLimit per pass. Submitting is
// idempotent (the policy state remembers the condition sequence it applied), so
// a condition already decided costs one read and commits nothing.
func (w *Workers) submitConditions(ctx context.Context, admin auth.Scope, project model.ID, lease replica.FenceToken, report *PassReport) (int, error) {
	binding, found, err := w.cfg.Routing.Routing(ctx, admin, project)
	if err != nil || !found {
		return 0, err
	}
	records, err := w.app.Control.Conditions(ctx, admin, project)
	if err != nil {
		return 0, err
	}
	submitted := 0
	budget := w.cfg.NotifyLimit
	for _, rec := range records {
		if budget <= 0 {
			break
		}
		if err = ctx.Err(); err != nil {
			return submitted, err
		}
		var st conditions.State
		if json.Unmarshal(rec.State, &st) != nil {
			continue
		}
		evidence, ok := conditionEvidence(st)
		if !ok {
			continue
		}
		subject := notify.Entity{Kind: notify.EntityCondition, ID: rec.ID}
		state, known, err := w.policyState(ctx, admin, project, binding.Policy, subject)
		if err != nil {
			return submitted, err
		}
		if known && state.ConditionSeq >= evidence.Seq && recipientsMatch(state, binding.Recipients) {
			continue
		}
		budget--
		n, err := w.decide(ctx, admin, project, binding, subject, state, known, evidenceEvent{seq: evidence.Seq, condition: &evidence}, lease)
		submitted += n
		if err != nil {
			if deposed(err) {
				return submitted, err
			}
			// One condition's refusal (a policy conflict, an owner moved) must not
			// starve the others; it is retried by the next pass.
			report.Errors = append(report.Errors, StageError{Project: project, Stage: StageNotify, Code: code(err)})
		}
	}
	return submitted, nil
}

// incidentEvidence maps a committed incident to the policy evidence it carries.
// The source is the linked condition's state and freshness; the version is the
// incident's committed version, which advances with every accepted action, so a
// repeat decides nothing. ok is false for an incident whose state a deletion
// erased or that carries nothing the policy accepts.
func incidentEvidence(st incidents.State) (notify.IncidentEvidence, bool) {
	if st.Erased || st.Version == 0 || st.ImpactRevision == 0 || st.Episode == (model.ID{}) {
		return notify.IncidentEvidence{}, false
	}
	var status notify.HumanStatus
	switch st.Status {
	case incidents.StatusOpen:
		status = notify.HumanOpen
	case incidents.StatusResolved:
		status = notify.HumanResolved
	default:
		return notify.IncidentEvidence{}, false
	}
	var source notify.SourceState
	switch st.Condition.State {
	case incidents.ConditionFiring:
		source = notify.SourceFiring
	case incidents.ConditionRecovered:
		source = notify.SourceRecovered
	default:
		source = notify.SourceUnknown
	}
	freshness := notify.FreshnessUnknown
	switch st.Condition.Freshness {
	case incidents.FreshnessFresh:
		freshness = notify.FreshnessFresh
	case incidents.FreshnessStale:
		freshness = notify.FreshnessStale
	}
	severity := notify.Severity(st.Severity)
	if st.Severity < incidents.SeverityMinor || st.Severity > incidents.SeverityCritical {
		return notify.IncidentEvidence{}, false
	}
	return notify.IncidentEvidence{Version: st.Version, Status: status, Severity: severity, ImpactRevision: st.ImpactRevision, Episode: st.Episode, Source: source, Freshness: freshness}, true
}

// submitIncidents decides the committed incidents of the project into the
// delivery outbox, at most NotifyLimit per pass, exactly as submitConditions does
// for conditions: the policy state remembers the incident version it applied, so
// an incident already decided costs one read and commits nothing.
func (w *Workers) submitIncidents(ctx context.Context, admin auth.Scope, project model.ID, lease replica.FenceToken, report *PassReport) (int, error) {
	binding, found, err := w.cfg.Routing.Routing(ctx, admin, project)
	if err != nil || !found {
		return 0, err
	}
	records, err := w.app.Control.Incidents(ctx, admin, project)
	if err != nil {
		return 0, err
	}
	submitted := 0
	budget := w.cfg.NotifyLimit
	for _, rec := range records {
		if budget <= 0 {
			break
		}
		if err = ctx.Err(); err != nil {
			return submitted, err
		}
		if rec.Erased() {
			continue
		}
		var st incidents.State
		if json.Unmarshal(rec.State, &st) != nil {
			continue
		}
		evidence, ok := incidentEvidence(st)
		if !ok {
			continue
		}
		subject := notify.Entity{Kind: notify.EntityIncident, ID: rec.ID}
		state, known, err := w.policyState(ctx, admin, project, binding.Policy, subject)
		if err != nil {
			return submitted, err
		}
		if known && state.IncidentVersion >= evidence.Version && recipientsMatch(state, binding.Recipients) {
			continue
		}
		budget--
		n, err := w.decide(ctx, admin, project, binding, subject, state, known, evidenceEvent{seq: uint64(evidence.Version), incident: &evidence}, lease)
		submitted += n
		if err != nil {
			if deposed(err) {
				return submitted, err
			}
			report.Errors = append(report.Errors, StageError{Project: project, Stage: StageNotify, Code: code(err)})
		}
	}
	return submitted, nil
}

func (w *Workers) policyState(ctx context.Context, admin auth.Scope, project, policy model.ID, subject notify.Entity) (notify.PolicyState, bool, error) {
	rec, found, err := w.app.Control.PolicyRecord(ctx, admin, project, policy, string(subject.Kind)+":"+subject.ID.String())
	if err != nil || !found {
		return notify.PolicyState{}, false, err
	}
	var state notify.PolicyState
	if json.Unmarshal(rec.State, &state) != nil {
		return notify.PolicyState{}, false, model.Fail(model.Corrupt)
	}
	return state, true, nil
}

func recipientsMatch(state notify.PolicyState, want []model.ID) bool {
	have := map[model.ID]bool{}
	for _, r := range state.Recipients {
		if r.Enabled {
			have[r.ID] = true
		}
	}
	for _, id := range want {
		if !have[id] {
			return false
		}
	}
	return true
}

// evidenceEvent is the one piece of source evidence a notification decision
// carries: a condition's or an incident's snapshot, ordered by seq (the
// condition's committed version, the incident's version).
type evidenceEvent struct {
	seq       uint64
	condition *notify.ConditionEvidence
	incident  *notify.IncidentEvidence
}

// decide submits the missing recipients and then the evidence of one condition
// or incident. Every event's command ID derives from what it says, so retries
// are no-ops.
func (w *Workers) decide(ctx context.Context, admin auth.Scope, project model.ID, binding NotificationBinding, subject notify.Entity, state notify.PolicyState, known bool, evidence evidenceEvent, lease replica.FenceToken) (int, error) {
	org := admin.OrgID()
	at := w.cfg.Clock.Now()
	ref, ownerRevision := policyFraming(known, state, binding)
	base := func(kind notify.EventKind, command model.ID) notify.PolicyEvent {
		return notify.PolicyEvent{Kind: kind, Command: command, Org: org, Project: project, Policy: binding.Policy, PolicyRef: ref, OwnerRevision: ownerRevision}
	}
	enabled := map[model.ID]bool{}
	for _, r := range state.Recipients {
		if r.Enabled {
			enabled[r.ID] = true
		}
	}
	submitted := 0
	for _, recipient := range binding.Recipients {
		if enabled[recipient] {
			continue
		}
		var rev [8]byte
		binary.BigEndian.PutUint64(rev[:], uint64(binding.Revision))
		ev := base(notify.EventDestination, policyCommand([]byte("destination"), org[:], project[:], binding.Policy[:], subject.ID[:], recipient[:], rev[:]))
		ev.Destination = &notify.DestinationChange{Recipient: recipient, Enabled: true}
		sub, err := w.outbox.Submit(ctx, admin, lease, subject, ev, at)
		if err != nil {
			return submitted, err
		}
		if !sub.Unchanged {
			submitted++
		}
		ref.Config = nil
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], evidence.seq)
	kind, tag := notify.EventCondition, "condition"
	if evidence.incident != nil {
		kind, tag = notify.EventIncident, "incident"
	}
	ev := base(kind, policyCommand([]byte(tag), org[:], project[:], binding.Policy[:], subject.ID[:], seq[:]))
	entity := subject
	ev.Entity = &entity
	ev.Mode = notify.ModeLive
	ev.Condition, ev.Incident = evidence.condition, evidence.incident
	sub, err := w.outbox.Submit(ctx, admin, lease, subject, ev, at)
	if err != nil {
		return submitted, err
	}
	if !sub.Unchanged {
		submitted++
	}
	return submitted, nil
}

// policyFraming is the policy reference and expected owner revision an event
// for the subject carries: a first event, and one under a revision the state has
// not adopted, bring the configuration; an existing state's owner revision is
// the one it holds.
func policyFraming(known bool, state notify.PolicyState, binding NotificationBinding) (notify.PolicyRef, model.Revision) {
	ref, ownerRevision := notify.PolicyRef{Revision: binding.Revision}, model.Revision(1)
	if known {
		ownerRevision = state.OwnerRevision
	}
	if !known || state.PolicyRevision != binding.Revision {
		config := binding.Config
		ref.Config = &config
	}
	return ref, ownerRevision
}
