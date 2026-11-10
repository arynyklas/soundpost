// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"bytes"
	"sort"

	"soundpost/internal/model"
)

// Reduce folds one evaluation into the committed state. It is pure: no clock, no
// I/O, no randomness; the same (state, evaluation, rule) always yields the same
// transition, which is what makes retries, replays and restarts converge.
//
// Alert rules are driven by per-series membership: a series present in the
// evaluated instant vector is true, an absent one false, whatever any numeric
// sample says. The phases are inactive, pending (true, for not yet elapsed),
// firing, and recovering (false while firing, hold not yet elapsed):
//
//   - true:  inactive -> pending, or straight to firing when elapsed >= for;
//     pending -> firing once now-since >= for; recovering -> firing.
//   - false: pending -> inactive; firing -> recovering, or straight to inactive
//     when the recovery hold is zero; recovering -> inactive once
//     now-recoverySince >= hold.
//
// An unknown or error evaluation changes no phase and no frontier and never
// recovers anything. A complete evaluation whose input evidence is incomplete
// (RecoveryBlocked) advances true series normally but treats absent series as
// unknown: not false. A gap of more than one interval since the last applied
// evaluation restarts the frontier of a pending or recovering series, because
// continuity across unobserved time is not proven.
func Reduce(current State, eval Evaluation, rule Rule) (Transition, error) {
	invalid := func() (Transition, error) { return Transition{}, model.Fail(model.Invalid) }
	if rule.Interval <= 0 || eval.Kind != rule.Kind || eval.Version != rule.Version || eval.Rule != rule.ID || eval.At < 0 {
		return invalid()
	}
	switch eval.Mode {
	case ModeLive, ModeBackfill, ModeReplay:
	default:
		return invalid()
	}
	switch eval.Outcome {
	case OutcomeComplete, OutcomeUnknown, OutcomeError:
	default:
		return invalid()
	}
	if current.Version != 0 && current.Version != eval.Version {
		return invalid()
	}
	if current.Applied != nil && eval.At <= current.Applied.At {
		return Transition{}, model.Fail(model.Stale)
	}

	next := State{
		Org: eval.Org, Project: eval.Project, Rule: eval.Rule, Version: eval.Version, Definition: eval.Definition,
		Revision: current.Revision + 1, Series: make(map[string]SeriesState, len(current.Series)),
		Cursors: append([]model.Cursor{}, current.Cursors...), Health: current.Health, Reason: current.Reason, Sequence: current.Sequence,
		Replays: current.Replays, Missed: current.Missed,
	}
	for key, st := range current.Series {
		st.Labels = append(model.Labels{}, st.Labels...)
		next.Series[key] = st
	}
	ref := eval.Ref()
	next.Applied = &ref

	if eval.Outcome != OutcomeComplete {
		next.Health = HealthUnknown
		if eval.Outcome == OutcomeError {
			next.Health = HealthError
		}
		next.Reason = eval.Reason
		return Transition{State: next}, nil
	}
	next.Health, next.Reason = HealthOK, ""
	if eval.RecoveryBlocked {
		next.Health, next.Reason = HealthUnknown, eval.Reason
	}
	next.Cursors = mergeCursors(next.Cursors, eval.Cursors)
	if rule.Kind != KindAlert {
		return Transition{State: next}, nil
	}

	gap := current.Applied != nil && eval.At-current.Applied.At > model.UnixNano(rule.Interval)
	present := make(map[string]model.Labels, len(eval.Members))
	for _, labels := range eval.Members {
		present[seriesKey(labels)] = labels
	}
	keys := make([]string, 0, len(present)+len(next.Series))
	for key := range present {
		keys = append(keys, key)
	}
	for key := range next.Series {
		if _, dup := present[key]; !dup {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	var out Transition
	forNS, holdNS := model.UnixNano(rule.For), model.UnixNano(rule.RecoveryHold)
	for _, key := range keys {
		st, had := next.Series[key]
		before := PhaseInactive
		if had {
			before = st.Phase
		}
		labels, isPresent := present[key]
		after := before
		switch {
		case isPresent:
			if !had {
				st = SeriesState{Labels: append(model.Labels{}, labels...), Phase: PhaseInactive}
			}
			switch st.Phase {
			case PhaseInactive:
				st.Since, st.RecoverySince = eval.At, 0
				after = PhasePending
			case PhasePending:
				if gap {
					st.Since = eval.At
				}
			case PhaseRecovering, PhaseFiring:
				st.RecoverySince = 0
				after = PhaseFiring
			}
			if after == PhasePending && eval.At-st.Since >= forNS {
				after = PhaseFiring
			}
			st.Phase = after
			next.Series[key] = st
		case eval.RecoveryBlocked:
			continue
		default:
			switch st.Phase {
			case PhasePending:
				after = PhaseInactive
			case PhaseFiring:
				st.RecoverySince = eval.At
				after = PhaseRecovering
				if holdNS == 0 {
					after = PhaseInactive
				}
			case PhaseRecovering:
				if gap {
					st.RecoverySince = eval.At
				}
				if eval.At-st.RecoverySince >= holdNS {
					after = PhaseInactive
				}
			}
			if after == PhaseInactive {
				delete(next.Series, key)
			} else {
				st.Phase = after
				next.Series[key] = st
			}
		}
		if after == before {
			continue
		}
		out.Changed = append(out.Changed, key)
		status := string(after)
		if after == PhaseInactive && before != PhasePending {
			status = "resolved"
		}
		next.Sequence++
		evLabels := st.Labels
		if len(evLabels) == 0 {
			evLabels = labels
		}
		event := model.ConditionEvent{
			Condition: derive("condition", eval.Org[:], eval.Project[:], eval.Rule[:], []byte(key)),
			Epoch:     derive("epoch", eval.Rule[:], u64(uint64(eval.Version))),
			Sequence:  next.Sequence, At: eval.At, Status: status, Severity: rule.Severity,
			Labels: append(model.Labels{}, evLabels...), Links: []model.ID{},
		}
		out.Conditions = append(out.Conditions, ConditionIntent{
			ID:     derive("condition-intent", eval.Org[:], eval.Project[:], eval.Rule[:], u64(uint64(eval.Version)), u64(uint64(eval.At)), []byte(key), []byte(status)),
			Event:  event,
			Notify: eval.Mode != ModeBackfill,
			Mode:   eval.Mode,
		})
	}
	out.State = next
	return out, nil
}

// mergeCursors keeps, per group, the highest index, ordered by group.
func mergeCursors(a, b []model.Cursor) []model.Cursor {
	best := make(map[model.ID]model.Uint64, len(a)+len(b))
	for _, list := range [][]model.Cursor{a, b} {
		for _, c := range list {
			if have, ok := best[c.Group]; !ok || c.Index > have {
				best[c.Group] = c.Index
			}
		}
	}
	out := make([]model.Cursor, 0, len(best))
	for group, index := range best {
		out = append(out, model.Cursor{Group: group, Index: index})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Group[:], out[j].Group[:]) < 0 })
	return out
}
