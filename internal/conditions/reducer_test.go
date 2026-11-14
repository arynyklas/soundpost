// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

var (
	cond   = model.ID{0xc1}
	epoch1 = model.ID{0xe1}
	epoch2 = model.ID{0xe2}
)

func labels(pairs ...string) model.Labels {
	out := model.Labels{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, model.Label{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func event(epoch model.ID, seq uint64, at int64, status string) model.ConditionEvent {
	return model.ConditionEvent{Condition: cond, Epoch: epoch, Sequence: model.Uint64(seq), At: model.UnixNano(at), Status: status, Severity: "critical", Labels: labels("job", "api"), Links: []model.ID{}}
}

func reduce(t *testing.T, s conditions.State, e model.ConditionEvent) conditions.State {
	t.Helper()
	next, err := conditions.Reduce(s, e)
	if err != nil {
		t.Fatalf("reduce %s epoch=%x seq=%d: %v", e.Status, e.Epoch[0], e.Sequence, err)
	}
	return next
}

func code(err error) model.Code {
	if f, ok := err.(*model.Fault); ok {
		return f.Code
	}
	return ""
}

func detail(err error) string {
	if f, ok := err.(*model.Fault); ok {
		return f.SafeDetail
	}
	return ""
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Events are ordered by the source's epoch and sequence, not by arrival: an old
// or duplicate event can never overwrite newer state, the same event retried is
// a no-op, and a conflicting replay of an accepted event is rejected.
func TestConditionSourceOrdering(t *testing.T) {
	t.Run("old and duplicate events change nothing", func(t *testing.T) {
		firing := reduce(t, conditions.State{}, event(epoch2, 10, 100, "firing"))
		if firing.Phase != conditions.PhaseFiring || firing.Sequence != 10 || firing.Epoch != epoch2 || firing.Version != 1 || firing.Freshness != conditions.FreshnessFresh || firing.Episode == nil {
			t.Fatalf("first event: %+v", firing)
		}
		before := mustJSON(t, firing)
		older := reduce(t, firing, event(epoch2, 9, 90, "recovered"))
		if !reflect.DeepEqual(older, firing) || older.Version != 1 {
			t.Fatalf("recovered seq-9 overwrote firing seq-10: %+v", older)
		}
		dup := reduce(t, firing, event(epoch2, 10, 100, "firing"))
		if !reflect.DeepEqual(dup, firing) || dup.Version != 1 || len(dup.Recent) != 1 {
			t.Fatalf("a duplicate seq-10 produced an effect: %+v", dup)
		}
		if mustJSON(t, firing) != before {
			t.Fatal("Reduce mutated its input state")
		}
	})

	t.Run("a conflicting replay of an accepted sequence rejects", func(t *testing.T) {
		firing := reduce(t, conditions.State{}, event(epoch2, 10, 100, "firing"))
		for name, e := range map[string]model.ConditionEvent{
			"status":   event(epoch2, 10, 100, "recovered"),
			"time":     event(epoch2, 10, 101, "firing"),
			"severity": func() model.ConditionEvent { e := event(epoch2, 10, 100, "firing"); e.Severity = "info"; return e }(),
			"labels": func() model.ConditionEvent {
				e := event(epoch2, 10, 100, "firing")
				e.Labels = labels("job", "web")
				return e
			}(),
			"links": func() model.ConditionEvent {
				e := event(epoch2, 10, 100, "firing")
				e.Links = []model.ID{{7}}
				return e
			}(),
		} {
			next, err := conditions.Reduce(firing, e)
			if code(err) != model.Conflict || detail(err) != conditions.DetailEventConflict || !reflect.DeepEqual(next, firing) {
				t.Errorf("%s: err=%v state changed=%v", name, err, !reflect.DeepEqual(next, firing))
			}
		}
		// The conflict is detected against an accepted event that is no longer the
		// current one, too.
		s := reduce(t, conditions.State{}, event(epoch2, 8, 80, "pending"))
		s = reduce(t, s, event(epoch2, 9, 90, "firing"))
		s = reduce(t, s, event(epoch2, 10, 100, "recovering"))
		if _, err := conditions.Reduce(s, event(epoch2, 9, 90, "recovered")); code(err) != model.Conflict {
			t.Fatalf("a conflicting replay of accepted seq-9: %v", err)
		}
		// A sequence that was never accepted (it was lost) is just late.
		late := reduce(t, s, event(epoch2, 7, 70, "recovered"))
		if !reflect.DeepEqual(late, s) {
			t.Fatalf("a late never-accepted event changed state: %+v", late)
		}
	})

	t.Run("sequence orders trusted events within an epoch, event time does not", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 10, 100, "firing"))
		// Seq 11 carries an earlier event time (clock skew): the sequence wins.
		s = reduce(t, s, event(epoch1, 11, 50, "recovered"))
		if s.Phase != conditions.PhaseRecovered || s.Sequence != 11 || s.EventAt != 50 {
			t.Fatalf("a higher sequence with an earlier time was refused: %+v", s)
		}
		// Seq 5 carries a later event time: still old.
		same := reduce(t, s, event(epoch1, 5, 9000, "firing"))
		if !reflect.DeepEqual(same, s) {
			t.Fatalf("a lower sequence with a later time overwrote state: %+v", same)
		}
	})

	t.Run("a new epoch supersedes only by event time; an old epoch cannot return", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 40, 100, "firing"))
		s = reduce(t, s, event(epoch2, 1, 200, "recovered"))
		if s.Epoch != epoch2 || s.Sequence != 1 || s.Phase != conditions.PhaseRecovered {
			t.Fatalf("a restarted producer's first event was refused: %+v", s)
		}
		// The old epoch's late events (even with a higher sequence) are old.
		stale := reduce(t, s, event(epoch1, 41, 150, "firing"))
		if !reflect.DeepEqual(stale, s) {
			t.Fatalf("an old epoch overwrote the new one: %+v", stale)
		}
		// A never-seen epoch whose event time is older than the current state is
		// not trusted to supersede it.
		old := reduce(t, s, event(model.ID{0xe0}, 99, 120, "firing"))
		if !reflect.DeepEqual(old, s) {
			t.Fatalf("an unseen older-time epoch overwrote state: %+v", old)
		}
	})

	t.Run("two epochs at the same event time are ordered by epoch, whatever arrives first", func(t *testing.T) {
		a := event(epoch1, 1, 100, "firing")
		b := event(epoch2, 1, 100, "recovered")
		for name, order := range map[string][]model.ConditionEvent{"low epoch first": {a, b}, "high epoch first": {b, a}} {
			s := conditions.State{}
			for _, e := range order {
				s = reduce(t, s, e)
			}
			if s.Epoch != epoch2 || s.Phase != conditions.PhaseRecovered {
				t.Errorf("%s: %+v", name, s)
			}
		}
	})

	t.Run("a timestamp-only adapter cannot overwrite a newer trusted sequence", func(t *testing.T) {
		trusted := reduce(t, conditions.State{}, event(epoch1, 3, 100, "firing"))
		// Much later wall-clock time, no sequence: still not trusted over seq 3.
		got := reduce(t, trusted, event(epoch1, 0, 9_000_000, "recovered"))
		if !reflect.DeepEqual(got, trusted) || got.Phase != conditions.PhaseFiring {
			t.Fatalf("a timestamp-only event overwrote a trusted sequence: %+v", got)
		}
		// And a trusted event supersedes timestamp-only state whatever the times,
		// in either arrival order.
		u := event(epoch1, 0, 500, "recovered")
		tr := event(epoch1, 1, 100, "firing")
		for name, order := range map[string][]model.ConditionEvent{"untrusted first": {u, tr}, "trusted first": {tr, u}} {
			s := conditions.State{}
			for _, e := range order {
				s = reduce(t, s, e)
			}
			if s.Phase != conditions.PhaseFiring || s.Sequence != 1 {
				t.Errorf("%s: %+v", name, s)
			}
		}
	})

	t.Run("timestamp-only events order by time and a deterministic tie key", func(t *testing.T) {
		a := event(epoch1, 0, 100, "firing")
		b := event(epoch1, 0, 100, "recovered")
		var finals []string
		for _, order := range [][]model.ConditionEvent{{a, b}, {b, a}, {a, b, a, b}} {
			s := conditions.State{}
			for _, e := range order {
				s = reduce(t, s, e)
			}
			finals = append(finals, string(s.Phase))
		}
		// Equal event time: the tie never prefers a recovery over a firing.
		if finals[0] != "firing" || finals[1] != "firing" || finals[2] != "firing" {
			t.Fatalf("tie key outcomes %v", finals)
		}
		s := reduce(t, conditions.State{}, a)
		later := reduce(t, s, event(epoch1, 0, 101, "recovered"))
		if later.Phase != conditions.PhaseRecovered {
			t.Fatalf("a later timestamp-only event was refused: %+v", later)
		}
		earlier := reduce(t, later, event(epoch1, 0, 99, "firing"))
		if !reflect.DeepEqual(earlier, later) {
			t.Fatalf("an earlier timestamp-only event overwrote a later one: %+v", earlier)
		}
		dup := reduce(t, later, event(epoch1, 0, 101, "recovered"))
		if !reflect.DeepEqual(dup, later) {
			t.Fatalf("a duplicate timestamp-only event produced an effect: %+v", dup)
		}
	})

	t.Run("unknown is not a recovery", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 1, 100, "firing"))
		s = reduce(t, s, event(epoch1, 2, 110, "unknown"))
		if s.Phase != conditions.PhaseFiring || s.Freshness != conditions.FreshnessUnknown || s.Reason != conditions.ReasonSourceUnknown || s.Recovered() || !s.Phase.Active() {
			t.Fatalf("unknown moved the phase: %+v", s)
		}
		s = reduce(t, s, event(epoch1, 3, 120, "firing"))
		if s.Freshness != conditions.FreshnessFresh || s.Reason != "" {
			t.Fatalf("a definite event did not restore freshness: %+v", s)
		}
		s = reduce(t, s, event(epoch1, 4, 130, "recovered"))
		if !s.Recovered() {
			t.Fatalf("a definite recovery is not recovered: %+v", s)
		}
		// Unknown first: no definite phase, and never "recovered".
		u := reduce(t, conditions.State{}, event(epoch1, 1, 100, "unknown"))
		if u.Phase != conditions.PhaseNone || u.Recovered() || u.Freshness != conditions.FreshnessUnknown {
			t.Fatalf("unknown-only condition: %+v", u)
		}
	})

	t.Run("episodes", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 1, 100, "pending"))
		first := episode(t, s)
		s = reduce(t, s, event(epoch1, 2, 110, "firing"))
		s = reduce(t, s, event(epoch1, 3, 120, "recovering"))
		s = reduce(t, s, event(epoch1, 4, 130, "firing"))
		if episode(t, s) != first {
			t.Fatal("pending, firing, recovering and firing again are one episode")
		}
		s = reduce(t, s, event(epoch1, 5, 140, "resolved"))
		if s.Phase != conditions.PhaseRecovered {
			t.Fatalf("resolved is the rules vocabulary for recovered: %+v", s)
		}
		s = reduce(t, s, event(epoch1, 6, 150, "firing"))
		if episode(t, s) == first {
			t.Fatal("firing again after a recovery is a new episode")
		}
	})

	t.Run("accepted history is bounded", func(t *testing.T) {
		s := conditions.State{}
		for i := 1; i <= conditions.MaxRecent+9; i++ {
			s = reduce(t, s, event(epoch1, uint64(i), int64(i), "firing"))
		}
		if len(s.Recent) != conditions.MaxRecent || s.Recent[len(s.Recent)-1].Sequence != conditions.MaxRecent+9 {
			t.Fatalf("recent: %d refs", len(s.Recent))
		}
		// Replaying an accepted sequence that has left the history is just old.
		old := reduce(t, s, event(epoch1, 1, 1, "recovered"))
		if !reflect.DeepEqual(old, s) {
			t.Fatal("an old replay overwrote state")
		}
	})

	t.Run("invalid events", func(t *testing.T) {
		bad := map[string]func(e *model.ConditionEvent){
			"zero condition": func(e *model.ConditionEvent) { e.Condition = model.ID{} },
			"zero epoch":     func(e *model.ConditionEvent) { e.Epoch = model.ID{} },
			"status":         func(e *model.ConditionEvent) { e.Status = "paging" },
			"severity text":  func(e *model.ConditionEvent) { e.Severity = "line\nbreak" },
			"no severity":    func(e *model.ConditionEvent) { e.Severity = "" },
			"long severity":  func(e *model.ConditionEvent) { e.Severity = strings.Repeat("s", 65) },
			"negative time":  func(e *model.ConditionEvent) { e.At = -1 },
			"unsorted labels": func(e *model.ConditionEvent) {
				e.Labels = model.Labels{{Name: "b", Value: "1"}, {Name: "a", Value: "2"}}
			},
			"too many labels": func(e *model.ConditionEvent) {
				for i := 0; i < 65; i++ {
					e.Labels = append(e.Labels, model.Label{Name: "l" + strings.Repeat("x", i), Value: "v"})
				}
			},
			"long label value": func(e *model.ConditionEvent) { e.Labels = labels("job", strings.Repeat("v", 1025)) },
			"zero link":        func(e *model.ConditionEvent) { e.Links = []model.ID{{}} },
			"too many links": func(e *model.ConditionEvent) {
				for i := 0; i < 65; i++ {
					e.Links = append(e.Links, model.ID{byte(i + 1)})
				}
			},
		}
		for name, mutate := range bad {
			e := event(epoch1, 1, 100, "firing")
			mutate(&e)
			if _, err := conditions.Reduce(conditions.State{}, e); code(err) != model.Invalid {
				t.Errorf("%s: %v", name, err)
			}
		}
		s := reduce(t, conditions.State{}, event(epoch1, 1, 100, "firing"))
		other := event(epoch1, 2, 110, "firing")
		other.Condition = model.ID{0xc2}
		if _, err := conditions.Reduce(s, other); code(err) != model.Invalid {
			t.Fatalf("an event of another condition folded into this one: %v", err)
		}
	})
}

// Arrival order does not decide the outcome: duplicate and stale retries woven
// between the events, and an event delivered before its predecessor, converge on
// the state the newest sequence defines.
func TestConditionOrderingConvergesUnderReorderedRetries(t *testing.T) {
	events := []model.ConditionEvent{
		event(epoch1, 1, 100, "pending"), event(epoch1, 2, 110, "firing"), event(epoch1, 3, 120, "unknown"),
		event(epoch1, 4, 130, "firing"), event(epoch1, 5, 140, "recovering"), event(epoch1, 6, 150, "recovered"),
	}
	fold := func(order ...int) conditions.State {
		s := conditions.State{}
		for _, i := range order {
			next, err := conditions.Reduce(s, events[i])
			if err != nil {
				t.Fatalf("event %d: %v", i, err)
			}
			s = next
		}
		return s
	}
	inOrder := fold(0, 1, 2, 3, 4, 5)
	// Duplicates and stale retries interleaved: identical state, all of it.
	retried := fold(0, 1, 0, 2, 1, 3, 2, 0, 4, 3, 5, 5, 4, 1)
	if mustJSON(t, inOrder) != mustJSON(t, retried) {
		t.Fatalf("retries changed the state:\n%s\n%s", mustJSON(t, inOrder), mustJSON(t, retried))
	}
	// A genuinely reordered delivery drops the events that arrive after a newer
	// one, and still ends at the newest sequence.
	reordered := fold(0, 2, 1, 5, 4, 3)
	if reordered.Sequence != inOrder.Sequence || reordered.Phase != inOrder.Phase || reordered.Freshness != inOrder.Freshness || reordered.EventAt != inOrder.EventAt || !reordered.Recovered() {
		t.Fatalf("reordered delivery ended in %+v, want %+v", reordered, inOrder)
	}
}

// ruleHarness feeds the real, committed C07 reducer's transitions into the
// condition lifecycle: this package consumes the rules module's decisions and
// never recomputes for / recovery-hold semantics itself.
type ruleHarness struct {
	t       *testing.T
	rule    rules.Rule
	rstate  rules.State
	cstates map[model.ID]conditions.State
	org     model.ID
}

func newRuleHarness(t *testing.T, forDur, hold time.Duration) *ruleHarness {
	r := rules.Rule{ID: model.ID{0xa1}, Project: model.ID{0xb1}, Version: 1, Kind: rules.KindAlert, Interval: time.Minute, For: forDur, RecoveryHold: hold, Severity: "page"}
	return &ruleHarness{t: t, rule: r, cstates: map[model.ID]conditions.State{}, org: model.ID{0xd1}}
}

type evalSpec struct {
	at      int64
	members []model.Labels
	outcome rules.Outcome
	reason  string
	blocked bool
}

// step evaluates one grid point with the real rules.Reduce and applies its
// result to the conditions exactly as the join does: the observation first, then
// each condition event of the evaluation. It returns the statuses emitted.
func (h *ruleHarness) step(s evalSpec) []string {
	h.t.Helper()
	ev := rules.Evaluation{Org: h.org, Project: h.rule.Project, Rule: h.rule.ID, Version: 1, At: model.UnixNano(s.at) * model.UnixNano(time.Second), Mode: rules.ModeLive, Kind: rules.KindAlert,
		Outcome: s.outcome, Reason: s.reason, RecoveryBlocked: s.blocked, Members: s.members, Cursors: []model.Cursor{}}
	tr, err := rules.Reduce(h.rstate, ev, h.rule)
	if err != nil {
		h.t.Fatal(err)
	}
	h.rstate = tr.State
	obs := conditions.Observation{At: ev.At, Health: conditions.Health(tr.State.Health), Reason: tr.State.Reason}
	for _, existing := range h.cstates {
		next, err := conditions.Observe(existing, obs)
		if err != nil {
			h.t.Fatal(err)
		}
		h.cstates[existing.Condition] = next
	}
	var statuses []string
	for _, intent := range tr.Conditions {
		cur := h.cstates[intent.Event.Condition]
		next, err := conditions.Join(cur, intent.Event, obs)
		if err != nil {
			h.t.Fatalf("join %s: %v", intent.Event.Status, err)
		}
		h.cstates[intent.Event.Condition] = next
		statuses = append(statuses, intent.Event.Status)
	}
	return statuses
}

func (h *ruleHarness) only() conditions.State {
	h.t.Helper()
	if len(h.cstates) != 1 {
		h.t.Fatalf("%d conditions", len(h.cstates))
	}
	for _, s := range h.cstates {
		return s
	}
	return conditions.State{}
}

var api = []model.Labels{labels("job", "api")}

func eq(a []string, b ...string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// The rules reducer owns pending/for/recovery-hold; the lifecycle follows its
// transitions, and anything that is not a complete answer never recovers.
func TestRuleMissingAndFence(t *testing.T) {
	t.Run("inactive pending firing recovering recovered", func(t *testing.T) {
		h := newRuleHarness(t, 2*time.Minute, time.Minute)
		if got := h.step(evalSpec{at: 0, members: api, outcome: rules.OutcomeComplete}); !eq(got, "pending") || h.only().Phase != conditions.PhasePending {
			t.Fatalf("t=0: %v %+v", got, h.only())
		}
		if got := h.step(evalSpec{at: 60, members: api, outcome: rules.OutcomeComplete}); len(got) != 0 {
			t.Fatalf("t=60 (for not elapsed): %v", got)
		}
		if got := h.step(evalSpec{at: 120, members: api, outcome: rules.OutcomeComplete}); !eq(got, "firing") || h.only().Phase != conditions.PhaseFiring {
			t.Fatalf("t=120: %v %+v", got, h.only())
		}
		firing := h.only()
		if got := h.step(evalSpec{at: 180, outcome: rules.OutcomeComplete}); !eq(got, "recovering") || h.only().Phase != conditions.PhaseRecovering || !h.only().Phase.Active() || h.only().Recovered() {
			t.Fatalf("t=180: %v %+v", got, h.only())
		}
		if got := h.step(evalSpec{at: 240, outcome: rules.OutcomeComplete}); !eq(got, "resolved") || !h.only().Recovered() {
			t.Fatalf("t=240: %v %+v", got, h.only())
		}
		if h.only().Version <= firing.Version {
			t.Fatalf("no progress: %+v", h.only())
		}
	})

	t.Run("default zero recovery hold recovers on the first healthy absence", func(t *testing.T) {
		h := newRuleHarness(t, 0, 0)
		if got := h.step(evalSpec{at: 0, members: api, outcome: rules.OutcomeComplete}); !eq(got, "firing") {
			t.Fatalf("for=0 fires at once: %v", got)
		}
		if got := h.step(evalSpec{at: 60, outcome: rules.OutcomeComplete}); !eq(got, "resolved") || !h.only().Recovered() {
			t.Fatalf("zero hold: %v %+v", got, h.only())
		}
	})

	// A firing condition, then every kind of missing or untrustworthy input: no
	// event, no phase change, an explicit freshness, and never a recovery.
	for _, tc := range []struct {
		name    string
		spec    evalSpec
		fresh   conditions.Freshness
		reason  string
		blocked bool
	}{
		{"unknown (timeout)", evalSpec{at: 60, outcome: rules.OutcomeUnknown, reason: rules.ReasonTimeout}, conditions.FreshnessUnknown, "timeout", false},
		{"unknown (incomplete shard)", evalSpec{at: 60, outcome: rules.OutcomeUnknown, reason: rules.ReasonUnavailable}, conditions.FreshnessUnknown, "unavailable", false},
		{"error", evalSpec{at: 60, outcome: rules.OutcomeError, reason: rules.ReasonQueryError}, conditions.FreshnessUnknown, "query_error", false},
		{"stale producer", evalSpec{at: 60, outcome: rules.OutcomeComplete, reason: rules.ReasonStaleProducer, blocked: true}, conditions.FreshnessStale, "stale_producer", true},
		{"evidence gap", evalSpec{at: 60, outcome: rules.OutcomeComplete, reason: rules.ReasonEvidenceGap, blocked: true}, conditions.FreshnessUnknown, "evidence_gap", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRuleHarness(t, 0, 0)
			h.step(evalSpec{at: 0, members: api, outcome: rules.OutcomeComplete})
			before := h.only()
			if got := h.step(tc.spec); len(got) != 0 {
				t.Fatalf("missing input emitted %v", got)
			}
			after := h.only()
			if after.Phase != conditions.PhaseFiring || after.Recovered() || after.Freshness != tc.fresh || after.Reason != tc.reason || after.FreshAt != 60*model.UnixNano(time.Second) {
				t.Fatalf("after missing input: %+v", after)
			}
			if after.Sequence != before.Sequence || after.Epoch != before.Epoch {
				t.Fatal("an observation moved the source order")
			}
			// The condition is absent from the next healthy-but-blocked evaluation
			// too: still not recovered.
			if tc.blocked {
				h.step(evalSpec{at: 120, outcome: rules.OutcomeComplete, reason: tc.spec.reason, blocked: true})
				if s := h.only(); s.Phase != conditions.PhaseFiring || s.Recovered() {
					t.Fatalf("blocked absence recovered: %+v", s)
				}
			}
			// A later complete, healthy evaluation that finds the series absent is
			// the first recovery, and restores freshness.
			if got := h.step(evalSpec{at: 180, outcome: rules.OutcomeComplete}); !eq(got, "resolved") || !h.only().Recovered() || h.only().Reason != "" {
				t.Fatalf("recovery after the data returned: %v %+v", got, h.only())
			}
		})
	}

	t.Run("a recovery from a not-ok evaluation is refused", func(t *testing.T) {
		firing := reduce(t, conditions.State{}, event(epoch1, 1, 100, "firing"))
		for _, status := range []string{"recovering", "recovered", "resolved"} {
			for _, obs := range []conditions.Observation{{At: 200, Health: conditions.HealthUnknown, Reason: "timeout"}, {At: 200, Health: conditions.HealthError, Reason: "query_error"}} {
				next, err := conditions.Join(firing, event(epoch1, 2, 200, status), obs)
				if code(err) != model.Invalid || detail(err) != conditions.DetailRecoveryBlocked || !reflect.DeepEqual(next, firing) {
					t.Errorf("%s with %s observation: %v", status, obs.Health, err)
				}
			}
		}
		// A firing event with a not-ok observation still fires, but explicitly
		// unknown; arrival order of event and observation is irrelevant.
		obs := conditions.Observation{At: 200, Health: conditions.HealthUnknown, Reason: "evidence_gap"}
		viaJoin, err := conditions.Join(conditions.State{}, event(epoch1, 1, 200, "firing"), obs)
		if err != nil {
			t.Fatal(err)
		}
		e := reduce(t, conditions.State{}, event(epoch1, 1, 200, "firing"))
		viaObserveLast, _ := conditions.Observe(e, obs)
		if viaJoin.Phase != conditions.PhaseFiring || viaJoin.Freshness != conditions.FreshnessUnknown || viaJoin.Reason != "evidence_gap" ||
			viaJoin.Freshness != viaObserveLast.Freshness || viaJoin.Reason != viaObserveLast.Reason || viaJoin.FreshAt != viaObserveLast.FreshAt {
			t.Fatalf("join %+v vs observe-after %+v", viaJoin, viaObserveLast)
		}
		// One transition is one version, whether the event, the observation or both
		// changed something.
		if viaJoin.Version != 1 {
			t.Fatalf("event and observation together made version %d", viaJoin.Version)
		}
		onlyObs, err := conditions.Join(firing, event(epoch1, 1, 100, "firing"), conditions.Observation{At: 300, Health: conditions.HealthUnknown, Reason: "timeout"})
		if err != nil || onlyObs.Version != firing.Version+1 || onlyObs.Sequence != firing.Sequence || onlyObs.Freshness != conditions.FreshnessUnknown {
			t.Fatalf("a duplicate event with a new observation: %+v %v", onlyObs, err)
		}
	})

	t.Run("freshness is ordered by evaluation time and unknown wins a tie", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 1, 100, "firing"))
		ok := conditions.Observation{At: 200, Health: conditions.HealthOK}
		unknown := conditions.Observation{At: 200, Health: conditions.HealthUnknown, Reason: "timeout"}
		for name, order := range map[string][]conditions.Observation{"ok first": {ok, unknown}, "unknown first": {unknown, ok}} {
			cur := s
			for _, o := range order {
				next, err := conditions.Observe(cur, o)
				if err != nil {
					t.Fatal(err)
				}
				cur = next
			}
			if cur.Freshness != conditions.FreshnessUnknown || cur.Reason != "timeout" {
				t.Errorf("%s: %+v", name, cur)
			}
		}
		// An older observation never overwrites a newer one; a repeat is a no-op.
		down, _ := conditions.Observe(s, unknown)
		newer, _ := conditions.Observe(down, conditions.Observation{At: 300, Health: conditions.HealthOK})
		older, _ := conditions.Observe(newer, conditions.Observation{At: 250, Health: conditions.HealthUnknown, Reason: "timeout"})
		if !reflect.DeepEqual(older, newer) || newer.Freshness != conditions.FreshnessFresh || newer.FreshAt != 300 {
			t.Fatalf("an older observation overwrote a newer one: %+v", older)
		}
		again, _ := conditions.Observe(newer, conditions.Observation{At: 300, Health: conditions.HealthOK})
		if !reflect.DeepEqual(again, newer) {
			t.Fatal("a repeated observation produced an effect")
		}
		// A healthy observation of a condition that is already fresh changes
		// nothing, so a steady healthy rule does not write the control group on
		// every evaluation.
		steady, _ := conditions.Observe(s, conditions.Observation{At: 900, Health: conditions.HealthOK})
		if !reflect.DeepEqual(steady, s) || steady.Version != s.Version {
			t.Fatalf("a healthy observation of a fresh condition committed: %+v", steady)
		}
	})

	t.Run("an observation reason is a closed code, never text", func(t *testing.T) {
		s := reduce(t, conditions.State{}, event(epoch1, 1, 100, "firing"))
		for _, reason := range []string{"SELECT secret FROM tokens", "timeout, user=alice", "TIMEOUT"} {
			if _, err := conditions.Observe(s, conditions.Observation{At: 200, Health: conditions.HealthError, Reason: reason}); code(err) != model.Invalid {
				t.Errorf("reason %q: %v", reason, err)
			}
		}
		if _, err := conditions.Observe(s, conditions.Observation{At: 200, Health: "healthy"}); code(err) != model.Invalid {
			t.Errorf("health: %v", err)
		}
		if _, err := conditions.Observe(conditions.State{}, conditions.Observation{At: 200, Health: conditions.HealthOK}); code(err) != model.Invalid {
			t.Errorf("an observation of a condition that does not exist: %v", err)
		}
		// A missing reason for a not-ok observation is explicit, not empty.
		got, err := conditions.Observe(s, conditions.Observation{At: 200, Health: conditions.HealthUnknown})
		if err != nil || got.Reason != conditions.ReasonUnspecified || got.Freshness != conditions.FreshnessUnknown {
			t.Fatalf("unspecified: %+v %v", got, err)
		}
	})
}

func episode(t *testing.T, s conditions.State) model.ID {
	t.Helper()
	if s.Episode == nil {
		t.Fatalf("no episode: %+v", s)
	}
	return *s.Episode
}
