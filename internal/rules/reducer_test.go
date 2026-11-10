// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"reflect"
	"testing"
	"time"

	"soundpost/internal/model"
)

const sec = model.UnixNano(time.Second)

func labels(pairs ...string) model.Labels {
	out := model.Labels{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, model.Label{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func alertRule(forD, hold time.Duration) Rule {
	return Rule{ID: model.ID{1}, Project: model.ID{2}, Version: 1, Kind: KindAlert, Profile: "promql-prometheus-3.13.5", FeatureSet: "fs", Expression: "up", Interval: 60 * time.Second, For: forD, RecoveryHold: hold, Severity: "page"}
}

// step is one evaluation fed to the pure reducer.
type step struct {
	at      int64 // seconds
	members []model.Labels
	outcome Outcome
	blocked bool
	mode    Mode
}

func evalOf(rule Rule, s step) Evaluation {
	outcome := s.outcome
	if outcome == "" {
		outcome = OutcomeComplete
	}
	mode := s.mode
	if mode == "" {
		mode = ModeLive
	}
	members := s.members
	if members == nil {
		members = []model.Labels{}
	}
	return Evaluation{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, At: model.UnixNano(s.at) * sec, Mode: mode, Kind: rule.Kind,
		Outcome: outcome, Reason: map[Outcome]string{OutcomeUnknown: ReasonTimeout, OutcomeError: ReasonQueryError}[outcome], RecoveryBlocked: s.blocked,
		Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(s.at)}}, Members: members}
}

// run reduces the steps in order and returns the phase of the one series after
// each, the final state and every emitted condition status.
func run(t *testing.T, rule Rule, steps []step) (phases []Phase, state State, statuses []string) {
	t.Helper()
	state = State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Series: map[string]SeriesState{}}
	for _, s := range steps {
		tr, err := Reduce(state, evalOf(rule, s), rule)
		if err != nil {
			t.Fatalf("t=%d: %v", s.at, err)
		}
		state = tr.State
		phase := PhaseInactive
		for _, st := range state.Series {
			phase = st.Phase
		}
		phases = append(phases, phase)
		for _, c := range tr.Conditions {
			statuses = append(statuses, c.Event.Status)
		}
	}
	return
}

var one = []model.Labels{labels("job", "api")}

// for=120s: pending at 0 and 60, firing at 120. With a 60s recovery hold the
// first false at 180 enters recovering, the next at 240 recovers. A timeout at
// 180 is unknown: it neither recovers nor resets the hold; with the default zero
// hold only an actual complete false result recovers, and does so immediately.
func TestForRecoveryAndUnknown(t *testing.T) {
	rule := alertRule(120*time.Second, 60*time.Second)
	phases, state, statuses := run(t, rule, []step{
		{at: 0, members: one}, {at: 60, members: one}, {at: 120, members: one}, // pending, pending, firing
		{at: 180}, {at: 240}, // recovering, inactive
	})
	want := []Phase{PhasePending, PhasePending, PhaseFiring, PhaseRecovering, PhaseInactive}
	if !reflect.DeepEqual(phases, want) {
		t.Fatalf("for/recovery-hold boundaries changed: %v, want %v", phases, want)
	}
	if !reflect.DeepEqual(statuses, []string{"pending", "firing", "recovering", "resolved"}) || len(state.Series) != 0 {
		t.Fatalf("condition events: %v, series left: %v", statuses, state.Series)
	}
	if state.Sequence != 4 {
		t.Fatalf("condition sequence %d, want one per event", state.Sequence)
	}

	// A timeout at 180 is not a recovery, whatever follows.
	phases, state, statuses = run(t, rule, []step{
		{at: 0, members: one}, {at: 60, members: one}, {at: 120, members: one},
		{at: 180, outcome: OutcomeUnknown}, {at: 240, outcome: OutcomeUnknown}, {at: 300, outcome: OutcomeError},
	})
	for i, phase := range phases[3:] {
		if phase != PhaseFiring {
			t.Fatalf("unknown input %d moved a firing series to %s", i, phase)
		}
	}
	if state.Health != HealthError || state.Reason != ReasonQueryError || len(statuses) != 2 {
		t.Fatalf("health=%s reason=%q events=%v", state.Health, state.Reason, statuses)
	}

	// Unknown between the false that began recovery and the false that would end
	// it neither finishes nor restarts the hold: 180 recovering, 240 unknown, 300
	// is the first complete false after the hold elapsed.
	phases, _, _ = run(t, rule, []step{
		{at: 0, members: one}, {at: 60, members: one}, {at: 120, members: one},
		{at: 180}, {at: 240, outcome: OutcomeUnknown}, {at: 300},
	})
	if !reflect.DeepEqual(phases[3:], []Phase{PhaseRecovering, PhaseRecovering, PhaseInactive}) {
		t.Fatalf("unknown in the recovery hold: %v", phases[3:])
	}

	// Zero hold: recovers only on an actual complete false result, immediately.
	zero := alertRule(120*time.Second, 0)
	phases, _, statuses = run(t, zero, []step{
		{at: 0, members: one}, {at: 60, members: one}, {at: 120, members: one},
		{at: 180, outcome: OutcomeUnknown}, {at: 240, outcome: OutcomeError}, {at: 300},
	})
	if !reflect.DeepEqual(phases[3:], []Phase{PhaseFiring, PhaseFiring, PhaseInactive}) || statuses[len(statuses)-1] != "resolved" {
		t.Fatalf("zero hold: %v %v", phases[3:], statuses)
	}
}

// A true observation changes nothing numeric: only presence counts. And a
// pending series that goes absent is reset, not carried.
func TestMembershipDrivesPhaseAndPendingResets(t *testing.T) {
	rule := alertRule(120*time.Second, 0)
	phases, _, statuses := run(t, rule, []step{
		{at: 0, members: one}, {at: 60}, // pending, then reset
		{at: 120, members: one}, {at: 180, members: one}, {at: 240, members: one}, // pending again from 120, firing at 240
	})
	if !reflect.DeepEqual(phases, []Phase{PhasePending, PhaseInactive, PhasePending, PhasePending, PhaseFiring}) {
		t.Fatalf("phases %v", phases)
	}
	if !reflect.DeepEqual(statuses, []string{"pending", "inactive", "pending", "firing"}) {
		t.Fatalf("a reset pending was reported as a recovery: %v", statuses)
	}
	// for=0 fires on the first true observation.
	phases, _, _ = run(t, alertRule(0, 0), []step{{at: 0, members: one}})
	if phases[0] != PhaseFiring {
		t.Fatalf("for=0: %v", phases)
	}
}

// Each series is its own condition; one recovering does not move another.
func TestSeriesAreIndependent(t *testing.T) {
	rule := alertRule(0, 60*time.Second)
	a, b := labels("job", "a"), labels("job", "b")
	state := State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Series: map[string]SeriesState{}}
	statusesOf := map[model.ID][]string{}
	for _, s := range []step{{at: 0, members: []model.Labels{a, b}}, {at: 60, members: []model.Labels{b}}, {at: 120, members: []model.Labels{b}}} {
		tr, err := Reduce(state, evalOf(rule, s), rule)
		if err != nil {
			t.Fatal(err)
		}
		state = tr.State
		for _, c := range tr.Conditions {
			statusesOf[c.Event.Condition] = append(statusesOf[c.Event.Condition], c.Event.Status)
		}
	}
	if len(state.Series) != 1 || state.Series[seriesKey(b)].Phase != PhaseFiring {
		t.Fatalf("series after a's hold elapsed: %+v", state.Series)
	}
	if len(statusesOf) != 2 {
		t.Fatalf("two series, %d conditions: %v", len(statusesOf), statusesOf)
	}
	var sawResolved, sawQuiet bool
	for _, statuses := range statusesOf {
		switch len(statuses) {
		case 3: // a: firing, recovering, resolved
			sawResolved = statuses[1] == "recovering" && statuses[2] == "resolved"
		case 1: // b: firing once, never touched by a's recovery
			sawQuiet = statuses[0] == "firing"
		}
	}
	if !sawResolved || !sawQuiet {
		t.Fatalf("per-condition history: %v", statusesOf)
	}
}

// Evidence that the input itself was incomplete blocks recovery (an absent
// series is then unknown, not false) but never blocks a true observation.
func TestEvidenceBlocksRecoveryNotFiring(t *testing.T) {
	rule := alertRule(0, 0)
	phases, state, _ := run(t, rule, []step{
		{at: 0, members: one},
		{at: 60, blocked: true},                // complete but evidence incomplete: absent is unknown
		{at: 120, members: one, blocked: true}, // present is still present
		{at: 180},                              // evidence clean and absent: recovers
	})
	if !reflect.DeepEqual(phases, []Phase{PhaseFiring, PhaseFiring, PhaseFiring, PhaseInactive}) {
		t.Fatalf("phases %v", phases)
	}
	if state.Health != HealthOK || state.Reason != "" {
		t.Fatalf("health after a clean evaluation: %s %q", state.Health, state.Reason)
	}
	_, blocked, _ := run(t, rule, []step{{at: 0, members: one}, {at: 60, blocked: true}})
	if blocked.Health != HealthUnknown {
		t.Fatalf("blocked evaluation health: %s", blocked.Health)
	}
}

// A gap of more than one interval since the last applied evaluation restarts a
// pending frontier (continuity is unproven) but cannot start a recovery.
func TestGapRestartsPendingFrontier(t *testing.T) {
	rule := alertRule(120*time.Second, 0)
	phases, _, _ := run(t, rule, []step{
		{at: 0, members: one}, {at: 60, members: one},
		{at: 240, members: one}, // 3 intervals later: unobserved time does not count
		{at: 300, members: one}, {at: 360, members: one},
	})
	if !reflect.DeepEqual(phases, []Phase{PhasePending, PhasePending, PhasePending, PhasePending, PhaseFiring}) {
		t.Fatalf("pending across a gap: %v", phases)
	}
}

// Notifications follow the mode: live and an explicitly replayed evaluation
// notify, a backfilled one never does, whatever transition it makes.
func TestBackfillNeverNotifies(t *testing.T) {
	rule := alertRule(0, 0)
	for mode, want := range map[Mode]bool{ModeLive: true, ModeReplay: true, ModeBackfill: false} {
		state := State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Series: map[string]SeriesState{}}
		tr, err := Reduce(state, evalOf(rule, step{at: 60, members: one, mode: mode}), rule)
		if err != nil || len(tr.Conditions) != 1 {
			t.Fatalf("%s: %v %+v", mode, err, tr.Conditions)
		}
		if tr.Conditions[0].Notify != want || tr.Conditions[0].Mode != mode {
			t.Fatalf("%s: notify=%v mode=%s", mode, tr.Conditions[0].Notify, tr.Conditions[0].Mode)
		}
	}
}

// The reducer is deterministic and never aliases or mutates its input.
func TestReduceIsPureAndOrderIndependent(t *testing.T) {
	rule := alertRule(60*time.Second, 60*time.Second)
	a, b, c := labels("job", "a"), labels("job", "b"), labels("job", "c")
	base := State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Series: map[string]SeriesState{}}
	first, err := Reduce(base, evalOf(rule, step{at: 0, members: []model.Labels{a, b, c}}), rule)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := first.State
	snapshotSeries := map[string]SeriesState{}
	for k, v := range first.State.Series {
		snapshotSeries[k] = v
	}
	x, err := Reduce(first.State, evalOf(rule, step{at: 60, members: []model.Labels{c, a, b}}), rule)
	if err != nil {
		t.Fatal(err)
	}
	y, err := Reduce(first.State, evalOf(rule, step{at: 60, members: []model.Labels{b, c, a}}), rule)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("member order changed the transition:\n%+v\n%+v", x, y)
	}
	if !reflect.DeepEqual(first.State.Series, snapshotSeries) || first.State.Revision != snapshot.Revision || len(base.Series) != 0 {
		t.Fatal("Reduce mutated its input state")
	}
	for i := 1; i < len(x.Conditions); i++ {
		if x.Conditions[i-1].Event.Sequence >= x.Conditions[i].Event.Sequence {
			t.Fatalf("condition sequence not increasing: %+v", x.Conditions)
		}
	}
}

func TestReduceRejectsInvalidInput(t *testing.T) {
	rule := alertRule(0, 0)
	state := State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Series: map[string]SeriesState{}}
	ok, err := Reduce(state, evalOf(rule, step{at: 60, members: one}), rule)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"not after the last applied": func() error { _, err := Reduce(ok.State, evalOf(rule, step{at: 60}), rule); return err },
		"before the last applied":    func() error { _, err := Reduce(ok.State, evalOf(rule, step{at: 30}), rule); return err },
		"other version": func() error {
			e := evalOf(rule, step{at: 120})
			e.Version = 2
			_, err := Reduce(ok.State, e, rule)
			return err
		},
		"other kind": func() error {
			e := evalOf(rule, step{at: 120})
			e.Kind = KindRecording
			_, err := Reduce(ok.State, e, rule)
			return err
		},
		"unknown outcome": func() error {
			e := evalOf(rule, step{at: 120})
			e.Outcome = "recovered"
			_, err := Reduce(ok.State, e, rule)
			return err
		},
		"unknown mode": func() error {
			e := evalOf(rule, step{at: 120})
			e.Mode = "now"
			_, err := Reduce(ok.State, e, rule)
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Input cursors only ever move forward, per group.
	next, err := Reduce(ok.State, func() Evaluation {
		e := evalOf(rule, step{at: 120, members: one})
		e.Cursors = []model.Cursor{{Group: model.ID{9}, Index: 5}, {Group: model.ID{8}, Index: 7}}
		return e
	}(), rule)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Cursor{{Group: model.ID{8}, Index: 7}, {Group: model.ID{9}, Index: model.Uint64(60)}}
	if !reflect.DeepEqual(next.State.Cursors, want) {
		t.Fatalf("cursors %+v, want %+v", next.State.Cursors, want)
	}
	unknown, err := Reduce(next.State, evalOf(rule, step{at: 180, outcome: OutcomeUnknown}), rule)
	if err != nil || !reflect.DeepEqual(unknown.State.Cursors, want) {
		t.Fatalf("an unknown evaluation moved the input cursors: %+v %v", unknown.State.Cursors, err)
	}
}
