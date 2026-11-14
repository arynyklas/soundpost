// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents

import (
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

func humanOnly(t Type) bool {
	switch t {
	case TypeAck, TypeResolve, TypeAssign, TypeSnooze, TypeUnsnooze, TypeMaintenance, TypeMaintenanceEnd:
		return true
	}
	return false
}

func validType(t Type) bool {
	return humanOnly(t) || t == TypeOpen || t == TypeImpact || t == TypeLink
}

func reasonRequired(t Type) bool {
	switch t {
	case TypeResolve, TypeSnooze, TypeUnsnooze, TypeMaintenance, TypeMaintenanceEnd:
		return true
	}
	return false
}

func validReason(s string) bool {
	if len(s) > MaxReasonBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validImpact(i Impact) bool {
	if i.Condition == (model.ID{}) || i.Episode == (model.ID{}) || i.Severity < SeverityMinor || i.Severity > SeverityCritical {
		return false
	}
	switch i.State {
	case ConditionFiring, ConditionRecovered, ConditionUnknown:
	default:
		return false
	}
	switch i.Freshness {
	case FreshnessFresh, FreshnessStale, FreshnessUnknown:
	default:
		return false
	}
	// Missing, stale or partial data is unknown, never recovered.
	return !(i.State == ConditionRecovered && i.Freshness != FreshnessFresh)
}

func validLink(l Link) bool {
	switch l.Kind {
	case LinkCondition, LinkIssue, LinkRelease, LinkService, LinkIncident:
		return l.ID != (model.ID{})
	}
	return false
}

// validate checks everything about an action that needs no state: shape,
// origin class and which fields the type may carry.
func validate(a Action, at model.UnixNano) error {
	t := a.Target
	if a.CommandID == (model.ID{}) || a.Actor == (model.ID{}) || t.Org == (model.ID{}) || t.Project == (model.ID{}) || t.Incident == (model.ID{}) || !validType(a.Type) || at <= 0 {
		return fault(model.Invalid, "incident_action_invalid")
	}
	if a.Origin != OriginHuman && a.Origin != OriginSystem {
		return fault(model.Invalid, "incident_origin_invalid")
	}
	if humanOnly(a.Type) && a.Origin != OriginHuman || a.Type == TypeImpact && a.Origin != OriginSystem {
		return fault(model.Forbidden, "incident_origin_forbidden")
	}
	if !validReason(a.Reason) || reasonRequired(a.Type) && a.Reason == "" {
		return fault(model.Invalid, "incident_reason_invalid")
	}
	windowed := a.Type == TypeSnooze || a.Type == TypeMaintenance
	if a.Owner != nil && a.Type != TypeAssign || a.Impact != nil != (a.Type == TypeOpen || a.Type == TypeImpact) ||
		a.Previous != nil && a.Type != TypeOpen || a.Link != nil != (a.Type == TypeLink) ||
		(a.Until != 0 || a.MaxWindow != 0) && !windowed {
		return fault(model.Invalid, "incident_action_fields")
	}
	if a.Owner != nil && *a.Owner == (model.ID{}) || a.Previous != nil && (*a.Previous == (model.ID{}) || *a.Previous == t.Incident) {
		return fault(model.Invalid, "incident_action_invalid")
	}
	if a.Impact != nil && !validImpact(*a.Impact) || a.Link != nil && (!validLink(*a.Link) || a.Link.Kind == LinkIncident && a.Link.ID == t.Incident) {
		return fault(model.Invalid, "incident_action_invalid")
	}
	if a.Type == TypeOpen && a.ExpectedVersion != 0 {
		return fault(model.Invalid, "incident_action_invalid")
	}
	if windowed {
		limit := a.MaxWindow
		if limit == 0 {
			limit = DefaultMaxWindow
		}
		if limit < 0 || limit > HardMaxWindow || a.Until <= at || a.Until-at > limit {
			return fault(model.Invalid, "incident_window_invalid")
		}
	}
	return nil
}

func (s State) clone() State {
	c := s
	c.Links = append([]Link(nil), s.Links...)
	c.Timeline = append([]Entry(nil), s.Timeline...)
	if s.Owner != nil {
		o := *s.Owner
		c.Owner = &o
	}
	if s.Ack != nil {
		a := *s.Ack
		c.Ack = &a
	}
	if s.Snooze != nil {
		w := *s.Snooze
		c.Snooze = &w
	}
	if s.Maintenance != nil {
		w := *s.Maintenance
		c.Maintenance = &w
	}
	return c
}

// Replay rebuilds a state from its timeline. State is exactly this function of
// its timeline.
func Replay(timeline []Entry) (State, error) {
	var s State
	for _, e := range timeline {
		next, _, err := Apply(s, e.Action, e.At)
		if err != nil {
			return State{}, err
		}
		s = next
	}
	return s, nil
}

// At returns the state as it stood right after the given version.
func (s State) At(version model.Revision) (State, error) {
	if version > model.Revision(len(s.Timeline)) {
		return State{}, model.Fail(model.NotFound)
	}
	return Replay(s.Timeline[:version])
}

// Applied returns the version at which a command committed.
func (s State) Applied(command model.ID) (model.Revision, bool) {
	for i, e := range s.Timeline {
		if e.Action.CommandID == command {
			return model.Revision(i + 1), true
		}
	}
	return 0, false
}

func audit(next State, a Action) Effect {
	return Effect{Kind: EffectAudit, Incident: next.ID, Version: next.Version, Command: a.CommandID, Actor: a.Actor, Origin: a.Origin, Action: a.Type}
}

// Apply is the deterministic reducer. It reads no clock, generates no ID and
// sends nothing: effects are safe audit/outbox intent only. A command already
// in the timeline returns the state as it stood at that command with no new
// effects (the original result); the same ID with different content is a
// conflict. Otherwise the action must expect the current version: a lost race
// is a *VersionConflict carrying the current version.
func Apply(state State, cmd Action, at model.UnixNano) (State, []Effect, error) {
	if err := validate(cmd, at); err != nil {
		return State{}, nil, err
	}
	t := cmd.Target
	if state.Version > 0 {
		if state.ID != t.Incident || state.Org != t.Org || state.Project != t.Project {
			return State{}, nil, model.Fail(model.NotFound)
		}
		if v, ok := state.Applied(cmd.CommandID); ok {
			if state.Timeline[v-1].Action.Actor != cmd.Actor {
				return State{}, nil, model.Fail(model.NotFound) // another principal's command ID
			}
			if !equalActions(state.Timeline[v-1].Action, cmd) {
				return State{}, nil, fault(model.Conflict, "incident_command_reused")
			}
			orig, err := state.At(v)
			return orig, nil, err
		}
	}
	if cmd.Type == TypeOpen {
		if state.Version != 0 {
			return State{}, nil, &VersionConflict{Current: state.Version}
		}
	} else if state.Version == 0 {
		return State{}, nil, model.Fail(model.NotFound)
	}
	if cmd.ExpectedVersion != state.Version {
		return State{}, nil, &VersionConflict{Current: state.Version}
	}
	if len(state.Timeline) >= MaxTimeline {
		return State{}, nil, fault(model.Quota, "incident_timeline_full")
	}
	next := state.clone()
	next.Version++
	next.Timeline = append(next.Timeline, Entry{At: at, Action: cmd})
	var effects []Effect
	var err error
	switch cmd.Type {
	case TypeOpen:
		effects = applyOpen(&next, cmd, at)
	case TypeImpact:
		effects, err = applyImpact(&next, state, cmd, at)
	case TypeLink:
		err = applyLink(&next, cmd)
	default:
		effects, err = applyHuman(&next, cmd, at)
	}
	if err != nil {
		return State{}, nil, err
	}
	if len(effects) == 0 && next.Version == state.Version+1 && cmd.Type == TypeImpact && unchangedImpact(state, next) {
		return state, nil, nil // an observation that changes nothing is not a state change
	}
	return next, append([]Effect{audit(next, cmd)}, effects...), nil
}

func unchangedImpact(before, after State) bool {
	a, b := before.Condition, after.Condition
	return a.ID == b.ID && a.State == b.State && a.Freshness == b.Freshness && before.Episode == after.Episode && before.Severity == after.Severity && before.ImpactRevision == after.ImpactRevision
}

func applyOpen(next *State, a Action, at model.UnixNano) []Effect {
	i := *a.Impact
	next.ID, next.Org, next.Project = a.Target.Incident, a.Target.Org, a.Target.Project
	next.Status = StatusOpen
	next.Condition = Condition{ID: i.Condition, State: i.State, Freshness: i.Freshness, At: at}
	next.Episode, next.Severity, next.ImpactRevision = i.Episode, i.Severity, 1
	next.Links = []Link{{Kind: LinkCondition, ID: i.Condition}}
	if a.Previous != nil {
		p := *a.Previous
		next.Previous = &p
		next.Links = append(next.Links, Link{Kind: LinkIncident, ID: p})
	}
	return []Effect{notify(EffectNotifyOpen, *next, a, at)}
}

// notify builds a notification intent. Maintenance suppresses new notification
// intents (recorded, with the reason) while ACK and snooze never do.
func notify(kind EffectKind, next State, a Action, at model.UnixNano) Effect {
	e := Effect{Kind: kind, Incident: next.ID, Version: next.Version, Command: a.CommandID, Actor: a.Actor, Origin: a.Origin, Action: a.Type, ImpactRevision: next.ImpactRevision, Eligible: true}
	if m := next.Maintenance; m != nil && m.Active(at) {
		e.Eligible, e.Code, e.Until = false, "maintenance", m.Until
	}
	return e
}

func applyImpact(next *State, before State, a Action, at model.UnixNano) ([]Effect, error) {
	i := *a.Impact
	if i.Condition != before.Condition.ID {
		return nil, fault(model.Invalid, "incident_condition_mismatch")
	}
	next.Condition = Condition{ID: i.Condition, State: i.State, Freshness: i.Freshness, At: at}
	if before.Status == StatusResolved {
		// A resolved timeline is never rewritten or reopened. The source's
		// state stays visible; a new episode or worse impact proposes a new
		// linked incident.
		if i.State == ConditionFiring && (i.Episode != before.Episode || i.Severity > before.Severity) {
			subject := before.ID
			return []Effect{{Kind: EffectOpenLinked, Incident: next.ID, Version: next.Version, Command: a.CommandID, Actor: a.Actor, Origin: a.Origin, Action: a.Type, Eligible: true, Subject: &subject}}, nil
		}
		return nil, nil
	}
	if i.State != ConditionFiring {
		return nil, nil
	}
	worse := i.Episode != before.Episode || i.Severity > before.Severity
	next.Episode, next.Severity = i.Episode, i.Severity
	if !worse {
		return nil, nil
	}
	next.ImpactRevision++
	return []Effect{notify(EffectNotifyImpact, *next, a, at)}, nil
}

func applyLink(next *State, a Action) error {
	if next.Status == StatusResolved {
		return fault(model.Conflict, "incident_resolved")
	}
	for _, l := range next.Links {
		if l == *a.Link {
			return fault(model.Conflict, "incident_link_exists")
		}
	}
	if len(next.Links) >= MaxLinks {
		return fault(model.Quota, "incident_links_full")
	}
	next.Links = append(next.Links, *a.Link)
	return nil
}

func applyHuman(next *State, a Action, at model.UnixNano) ([]Effect, error) {
	if next.Status != StatusOpen {
		return nil, fault(model.Conflict, "incident_resolved")
	}
	base := Effect{Incident: next.ID, Version: next.Version, Command: a.CommandID, Actor: a.Actor, Origin: a.Origin, Action: a.Type, ImpactRevision: next.ImpactRevision}
	with := func(k EffectKind) Effect { e := base; e.Kind = k; return e }
	switch a.Type {
	case TypeAck:
		if next.AckCurrent() {
			return nil, fault(model.Conflict, "incident_already_acknowledged")
		}
		next.Ack = &Ack{Actor: a.Actor, At: at, ImpactRevision: next.ImpactRevision, Version: next.Version}
		return []Effect{with(EffectRemindersPause)}, nil
	case TypeResolve:
		next.Status, next.ResolvedAt = StatusResolved, at
		return []Effect{with(EffectRemindersStop)}, nil
	case TypeAssign:
		if next.Owner == nil && a.Owner == nil || next.Owner != nil && a.Owner != nil && *next.Owner == *a.Owner {
			return nil, fault(model.Conflict, "incident_owner_unchanged")
		}
		next.Owner = nil
		if a.Owner != nil {
			o := *a.Owner
			next.Owner = &o
		}
		return nil, nil
	case TypeSnooze:
		// Active is judged at the action time, not the recorded one.
		if next.Snooze.Active(at) {
			return nil, fault(model.Conflict, "incident_snooze_active")
		}
		next.Snooze = &Window{Actor: a.Actor, Reason: a.Reason, From: at, Until: a.Until, Version: next.Version}
		e := with(EffectRemindersPause)
		e.Until = a.Until
		return []Effect{e}, nil
	case TypeUnsnooze:
		if !next.Snooze.Active(at) {
			return nil, fault(model.Conflict, "incident_no_active_snooze")
		}
		next.Snooze.Ended = at
		return []Effect{with(EffectRemindersResume)}, nil
	case TypeMaintenance:
		if next.Maintenance.Active(at) {
			return nil, fault(model.Conflict, "incident_maintenance_active")
		}
		next.Maintenance = &Window{Actor: a.Actor, Reason: a.Reason, From: at, Until: a.Until, Version: next.Version}
		e := with(EffectMaintBegin)
		e.Until = a.Until
		return []Effect{e}, nil
	default: // TypeMaintenanceEnd
		if !next.Maintenance.Active(at) {
			return nil, fault(model.Conflict, "incident_no_active_maintenance")
		}
		next.Maintenance.Ended = at
		return []Effect{with(EffectMaintEnd)}, nil
	}
}

// Proposal is a suggestion that two incidents share structured evidence. It is
// only a proposal: nothing here merges, links or changes an incident, and text
// similarity is never consulted.
type Proposal struct {
	A, B     model.ID
	Evidence Link
}

// Correlate proposes, for every pair of open incidents, each common service,
// release or issue link, in a deterministic order.
func Correlate(states []State) []Proposal {
	var out []Proposal
	for i := range states {
		for j := i + 1; j < len(states); j++ {
			a, b := states[i], states[j]
			if a.Status != StatusOpen || b.Status != StatusOpen || a.Org != b.Org || a.Project != b.Project || a.ID == b.ID {
				continue
			}
			for _, la := range a.Links {
				if la.Kind != LinkService && la.Kind != LinkRelease && la.Kind != LinkIssue {
					continue
				}
				for _, lb := range b.Links {
					if la == lb {
						x, y := a.ID, b.ID
						if y.String() < x.String() {
							x, y = y, x
						}
						out = append(out, Proposal{A: x, B: y, Evidence: la})
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		p, q := out[i], out[j]
		if p.A != q.A {
			return p.A.String() < q.A.String()
		}
		if p.B != q.B {
			return p.B.String() < q.B.String()
		}
		if p.Evidence.Kind != q.Evidence.Kind {
			return p.Evidence.Kind < q.Evidence.Kind
		}
		return p.Evidence.ID.String() < q.Evidence.ID.String()
	})
	return out
}
