// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions

import (
	"bytes"
	"crypto/sha256"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// The event statuses: the C04 telemetry vocabulary (firing, recovered, unknown)
// plus the C07 rule lifecycle (pending, recovering, resolved). resolved is the
// rules module's word for recovered.
func canonicalStatus(s string) (string, bool) {
	switch s {
	case "pending", "firing", "recovering", "recovered", "unknown":
		return s, true
	case "resolved":
		return "recovered", true
	}
	return "", false
}

// statusRank orders the statuses of two events with the same timestamp and no
// sequence: the deterministic tie key. It never prefers a recovery over a firing.
func statusRank(status string) int {
	switch status {
	case "recovered":
		return 0
	case "pending":
		return 1
	case "recovering":
		return 2
	case "firing":
		return 3
	}
	return 4 // unknown: the most cautious
}

func safeText(v string, max int) bool {
	if v == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// normalize validates an event and returns a private copy with no nil slices, so
// the same event always has the same canonical form and digest.
func normalize(e model.ConditionEvent) (model.ConditionEvent, string, error) {
	invalid := func() (model.ConditionEvent, string, error) {
		return model.ConditionEvent{}, "", fault(model.Invalid, DetailInvalidEvent)
	}
	status, ok := canonicalStatus(e.Status)
	if !ok || e.Condition == (model.ID{}) || e.Epoch == (model.ID{}) || e.At < 0 || !safeText(e.Severity, maxSeverity) {
		return invalid()
	}
	if len(e.Labels) > maxLabels || e.Labels.Validate() != nil || len(e.Links) > maxLinks {
		return invalid()
	}
	for _, l := range e.Labels {
		if len(l.Name) > maxLabelName || len(l.Value) > maxLabelVal || !utf8.ValidString(l.Name) || !utf8.ValidString(l.Value) {
			return invalid()
		}
	}
	for _, id := range e.Links {
		if id == (model.ID{}) {
			return invalid()
		}
	}
	out := e
	out.Labels = append(model.Labels{}, e.Labels...)
	out.Links = append([]model.ID{}, e.Links...)
	return out, status, nil
}

func digestOf(e model.ConditionEvent) (model.Hash, error) {
	raw, err := model.CanonicalJSON(e)
	if err != nil {
		return model.Hash{}, fault(model.Invalid, DetailInvalidEvent)
	}
	return model.Hash(sha256.Sum256(raw)), nil
}

func clone(s State) State {
	out := s
	out.Labels = append(model.Labels{}, s.Labels...)
	out.Links = append([]model.ID{}, s.Links...)
	out.Recent = append([]EventRef{}, s.Recent...)
	if s.Rule != nil {
		rule := *s.Rule
		out.Rule = &rule
	}
	if s.Episode != nil {
		episode := *s.Episode
		out.Episode = &episode
	}
	return out
}

type ordering int

const (
	orderNewer ordering = iota
	orderStale
	orderDuplicate
	orderConflict
)

// order places an event relative to the newest accepted one.
//
//   - A trusted event (Sequence > 0) is ordered by sequence within its epoch. A
//     different epoch (a restarted producer, a new rule version) supersedes only
//     by event time, with the epoch ID as the final deterministic tie key, so an
//     old epoch can never come back.
//   - A timestamp-only event is ordered by event time, then by a status rank that
//     never prefers a recovery, then by digest. It can never overwrite a trusted
//     sequence, and any trusted event supersedes timestamp-only state.
//   - An event whose (epoch, sequence) was already accepted is a duplicate when
//     it is byte-identical and a conflict otherwise.
func order(cur State, ref EventRef) ordering {
	if len(cur.Recent) == 0 {
		return orderNewer
	}
	if ref.Sequence > 0 {
		for _, seen := range cur.Recent {
			if seen.Epoch == ref.Epoch && seen.Sequence == ref.Sequence {
				if seen.Digest == ref.Digest {
					return orderDuplicate
				}
				return orderConflict
			}
		}
	}
	last := cur.Recent[len(cur.Recent)-1]
	switch {
	case ref.Sequence > 0 && last.Sequence == 0:
		return orderNewer
	case ref.Sequence == 0 && last.Sequence > 0:
		return orderStale
	case ref.Sequence > 0 && ref.Epoch == last.Epoch:
		if ref.Sequence > last.Sequence {
			return orderNewer
		}
		return orderStale
	case ref.Sequence > 0:
		if ref.At != last.At {
			if ref.At > last.At {
				return orderNewer
			}
			return orderStale
		}
		if bytes.Compare(ref.Epoch[:], last.Epoch[:]) > 0 {
			return orderNewer
		}
		return orderStale
	}
	if ref.At != last.At {
		if ref.At > last.At {
			return orderNewer
		}
		return orderStale
	}
	if a, b := statusRank(ref.Status), statusRank(last.Status); a != b {
		if a > b {
			return orderNewer
		}
		return orderStale
	}
	if bytes.Compare(ref.Digest[:], last.Digest[:]) > 0 {
		return orderNewer
	}
	return orderStale
}

// Reduce folds one event into a condition's state. It is pure: no clock, no I/O,
// no randomness, and it never modifies current. The same (state, event) always
// yields the same result, which is what makes retries, replays and restarts
// converge.
//
// An old or duplicate event returns the state unchanged (Version included), so
// the caller can tell that nothing happened and commit nothing. A replay of an
// accepted (epoch, sequence) with a different payload is a conflict and is
// rejected. An unknown status never moves the phase: it records unknown
// freshness and is never a recovery.
func Reduce(current State, event model.ConditionEvent) (State, error) {
	ev, status, err := normalize(event)
	if err != nil {
		return current, err
	}
	digest, err := digestOf(ev)
	if err != nil {
		return current, err
	}
	ref := EventRef{Epoch: ev.Epoch, Sequence: ev.Sequence, At: ev.At, Status: status, Digest: digest}
	base := current
	if current.Version == 0 {
		base = State{Condition: ev.Condition}
	} else {
		if current.Condition != ev.Condition {
			return current, fault(model.Invalid, DetailInvalidEvent)
		}
		if len(current.Recent) == 0 {
			return current, model.Fail(model.Corrupt)
		}
		switch order(current, ref) {
		case orderStale, orderDuplicate:
			return current, nil
		case orderConflict:
			return current, fault(model.Conflict, DetailEventConflict)
		}
	}
	next := clone(base)
	prev := base.Phase
	next.Version = base.Version + 1
	next.Epoch, next.Sequence, next.EventAt = ev.Epoch, ev.Sequence, ev.At
	next.Severity, next.Labels, next.Links = ev.Severity, ev.Labels, ev.Links
	next.Notify = true
	if status != "unknown" {
		next.Phase = Phase(status)
	}
	switch next.Phase {
	case PhasePending, PhaseFiring, PhaseRecovering:
		if prev == PhaseNone || prev == PhaseRecovered {
			episode := derive("episode", ev.Condition[:], ev.Epoch[:], u64(uint64(ev.Sequence)), u64(uint64(ev.At)))
			next.Episode = &episode
		}
	}
	if status == "unknown" {
		mergeFreshness(&next, ev.At, FreshnessUnknown, ReasonSourceUnknown)
	} else {
		mergeFreshness(&next, ev.At, FreshnessFresh, "")
	}
	next.Recent = append(next.Recent, ref)
	if len(next.Recent) > MaxRecent {
		next.Recent = append([]EventRef{}, next.Recent[len(next.Recent)-MaxRecent:]...)
	}
	return next, nil
}

func freshnessRank(f Freshness) int {
	switch f {
	case FreshnessFresh:
		return 0
	case FreshnessStale:
		return 1
	}
	return 2
}

// mergeFreshness records newer evidence about how far the state can be trusted
// and reports whether it changed anything.
//
// Evidence is ordered by the time it describes, and not-fresh evidence wins a
// tie (stale, then unknown, then the reason code), so the result does not depend
// on the order observations and events arrive in. Healthy evidence changes only
// state that is not already fresh: a steady healthy rule must not write the
// control group at every evaluation. The price is that an older not-fresh
// observation delivered late can mark a fresh condition unknown until the next
// healthy evaluation corrects it, which errs in the safe direction.
func mergeFreshness(s *State, at model.UnixNano, f Freshness, reason string) bool {
	switch {
	case s.Freshness == "":
	case f == FreshnessFresh:
		if s.Freshness == FreshnessFresh || at <= s.FreshAt {
			return false
		}
	default:
		newer := at > s.FreshAt
		if at == s.FreshAt {
			a, b := freshnessRank(f), freshnessRank(s.Freshness)
			newer = a > b || a == b && reason > s.Reason
		}
		if !newer {
			return false
		}
	}
	s.Freshness, s.Reason, s.FreshAt = f, reason, at
	return true
}

func classify(o Observation) (Freshness, string, error) {
	invalid := func() (Freshness, string, error) { return "", "", fault(model.Invalid, DetailInvalidEvent) }
	if o.At < 0 {
		return invalid()
	}
	switch o.Health {
	case HealthOK:
		if o.Reason != "" {
			return invalid()
		}
		return FreshnessFresh, "", nil
	case HealthUnknown, HealthError:
		reason := o.Reason
		if reason == "" {
			reason = ReasonUnspecified
		}
		f, ok := reasons[reason]
		if !ok {
			return invalid()
		}
		return f, reason, nil
	}
	return invalid()
}

// Observe folds the input health of one rule evaluation into a condition. It
// never changes the phase and never produces a recovery: unknown, error, stale
// producer, an incomplete shard and an evidence gap are explicit freshness, kept
// as history, and clear only by later healthy evidence.
func Observe(current State, obs Observation) (State, error) {
	f, reason, err := classify(obs)
	if err != nil {
		return current, err
	}
	if current.Version == 0 || current.Condition == (model.ID{}) {
		return current, fault(model.Invalid, DetailInvalidEvent)
	}
	next := clone(current)
	if !mergeFreshness(&next, obs.At, f, reason) {
		return current, nil
	}
	next.Version = current.Version + 1
	return next, nil
}

// Join folds one rule-produced event and the health of the evaluation that
// produced it as one transition. A recovery that claims to come from an
// evaluation that was not healthy is refused: the rules reducer never produces
// one, and this is the second line that keeps missing input from recovering a
// condition.
func Join(current State, event model.ConditionEvent, obs Observation) (State, error) {
	status, ok := canonicalStatus(event.Status)
	if ok && obs.Health != HealthOK && (status == "recovering" || status == "recovered") {
		return current, fault(model.Invalid, DetailRecoveryBlocked)
	}
	reduced, err := Reduce(current, event)
	if err != nil {
		return current, err
	}
	observed, err := Observe(reduced, obs)
	if err != nil {
		return current, err
	}
	if reduced.Version != current.Version && observed.Version != reduced.Version {
		observed.Version = reduced.Version // one transition, one version
	}
	return observed, nil
}
