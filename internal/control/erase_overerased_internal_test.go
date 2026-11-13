// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"reflect"
	"testing"

	"soundpost/internal/model"
)

// CD-9 (decision D3): begin, completion and import erase exactly what
// intersects the predicate's [Start,End): an opaque state whose recorded window
// (the span of the evidence times it names) does not intersect the range is
// kept, however late its evidence is. A state with no recorded window keeps the
// fail-closed erasure and is counted per book in the operation's OverErased.

type windowBooks struct {
	st                  *State
	org, project, other model.ID
	kinds               []string
}

// windowCase is one opaque state and what the exact rule does with it.
type windowCase struct {
	name  string
	state string
	erase bool // erased at all
	over  bool // erased without a recorded window
}

var windowCases = []windowCase{
	{"inside", `{"at":60}`, true, false},
	{"after the end", `{"at":1000}`, false, false},
	{"at the end is outside", `{"at":"100"}`, false, false},
	{"at the start is inside", `{"at":40}`, true, false},
	{"before the start", `{"at":10}`, false, false},
	{"window spans the range", `{"timeline":[{"at":10},{"at":1000}]}`, true, false},
	{"window spans, none inside", `{"a_at":10,"b_ns":"1000"}`, true, false},
	{"nested evidence inside", `{"runs":{"x":{"attempts":[{"observed_ns":99}]}},"as_of_ns":1000}`, true, false},
	{"later action times only", `{"condition":{"at":1000},"as_of_ns":2000}`, false, false},
	{"durations are not instants", `{"definition":{"grace_ns":"60"},"as_of_ns":1000}`, false, false},
	{"names no time", `{"labels":{"host":"a"}}`, true, true},
	{"only unset times", `{"effective_from_ns":0,"at":0}`, true, true},
	{"unreadable time", `{"at":"yesterday","as_of_ns":1000}`, true, true},
	{"unreadable state", `{"at":{"nested":true}}`, true, true},
}

func newWindowBooks(cases []windowCase) *windowBooks {
	w := &windowBooks{st: &State{}, org: model.ID{0x10}, project: model.ID{0x11}, other: model.ID{0x12}}
	w.st.IncidentBooks = map[string]json.RawMessage{}
	w.st.ConditionBooks = map[string]json.RawMessage{}
	w.st.JobBooks = map[string]json.RawMessage{}
	for i, c := range cases {
		id := model.ID{0xa0, byte(i)}
		for _, project := range []model.ID{w.project, w.other} {
			inc, _ := json.Marshal(IncidentRecord{Org: w.org, Project: project, ID: id, Version: 1, State: json.RawMessage(c.state)})
			w.st.IncidentBooks[incidentKey(w.org, project, id)] = inc
			cond, _ := json.Marshal(ConditionRecord{Org: w.org, Project: project, ID: id, Version: 1, State: json.RawMessage(c.state)})
			w.st.ConditionBooks[conditionKey(w.org, project, id)] = cond
			job, _ := json.Marshal(JobRecord{Org: w.org, Project: project, Job: id, Version: 1, State: json.RawMessage(c.state)})
			w.st.JobBooks[jobKey(w.org, project, id)] = job
		}
	}
	return w
}

func (w *windowBooks) erased(t *testing.T, book string, project, id model.ID) bool {
	t.Helper()
	var raw json.RawMessage
	switch book {
	case model.OverErasedIncident:
		rec, _, err := loadIncident(w.st, incidentKey(w.org, project, id))
		if err != nil {
			t.Fatal(err)
		}
		raw = rec.State
	case model.OverErasedCondition:
		rec, _, err := loadCondition(w.st, conditionKey(w.org, project, id))
		if err != nil {
			t.Fatal(err)
		}
		raw = rec.State
	default:
		rec, _, err := loadJobRecord(w.st, jobKey(w.org, project, id))
		if err != nil {
			t.Fatal(err)
		}
		raw = rec.State
	}
	return stateIsTombstone(raw)
}

func (w *windowBooks) rangeOp(at model.UnixNano) model.DeletionOperation {
	return model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: w.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{w.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}, RequestedAt: at}
}

func TestCD9BeginErasesExactlyTheStatesWhoseWindowIntersectsTheRange(t *testing.T) {
	w := newWindowBooks(windowCases)
	op := w.rangeOp(5)
	if err := eraseControlPayloads(w.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	wantOver := uint64(0)
	for i, c := range windowCases {
		id := model.ID{0xa0, byte(i)}
		if c.over {
			wantOver++
		}
		for _, book := range []string{model.OverErasedIncident, model.OverErasedCondition, model.OverErasedJob} {
			if got := w.erased(t, book, w.project, id); got != c.erase {
				t.Errorf("%s %s: erased=%v, want %v", book, c.name, got, c.erase)
			}
			if w.erased(t, book, w.other, id) {
				t.Errorf("%s %s: a project the deletion does not name was erased", book, c.name)
			}
		}
	}
	want := []model.OverErased{
		{Book: model.OverErasedIncident, Count: model.Uint64(wantOver)},
		{Book: model.OverErasedCondition, Count: model.Uint64(wantOver)},
		{Book: model.OverErasedJob, Count: model.Uint64(wantOver)},
	}
	if wantOver == 0 || !reflect.DeepEqual(op.OverErased, want) {
		t.Fatalf("over-erased = %+v, want %+v", op.OverErased, want)
	}
	// Completing re-runs the erasure: the tombstones are never covered or counted again.
	op.Phase = model.DeletePhaseComplete
	if err := eraseControlPayloads(w.st, &op, 9); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(op.OverErased, want) {
		t.Fatalf("a second pass changed the over-erased counts: %+v", op.OverErased)
	}
}

// A retirement erases every state of its projects exactly, so nothing is over-erased;
// an entity deletion covers none.
func TestCD9RetireAndEntityModesReportNoOverErasure(t *testing.T) {
	for _, p := range []model.DeletePredicate{
		{Operation: model.ID{0xdd}, Org: model.ID{0x10}, Mode: model.DeleteRetireProject, Projects: []model.ID{{0x11}}},
		{Operation: model.ID{0xdd}, Org: model.ID{0x10}, Mode: model.DeleteRetireOrg},
		{Operation: model.ID{0xdd}, Org: model.ID{0x10}, Mode: model.DeleteEntity, Projects: []model.ID{{0x11}}, Entities: []model.ID{{0xe7}}},
	} {
		w := newWindowBooks(windowCases)
		op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: p}
		if err := eraseControlPayloads(w.st, &op, 5); err != nil {
			t.Fatal(err)
		}
		if len(op.OverErased) != 0 {
			t.Errorf("%s: over-erased %+v, want none", p.Mode, op.OverErased)
		}
	}
}

// The late pass counts a state it erases without a window too, into the same
// operation record, and a state with a window outside the range adds nothing.
func TestCD9LateErasureCountsStatesWithoutAWindow(t *testing.T) {
	w := newWindowBooks(nil)
	op := w.rangeOp(5)
	op.Phase, op.CompletedAt = model.DeletePhaseComplete, 7
	w.st.Deletions = map[string]model.DeletionOperation{op.Predicate.Operation.String(): op}
	put := func(n byte, state string) {
		id := model.ID{0xb0, n}
		raw, _ := json.Marshal(IncidentRecord{Org: w.org, Project: w.project, ID: id, Version: 1, State: json.RawMessage(state)})
		w.st.IncidentBooks[incidentKey(w.org, w.project, id)] = raw
	}
	put(1, `{"labels":{}}`) // no window: erased, counted
	put(2, `{"at":1000}`)   // window after the end: kept
	put(3, `{"at":60}`)     // inside: erased exactly
	if err := eraseLateEffect(w.st, w.org, w.project); err != nil {
		t.Fatal(err)
	}
	got := w.st.Deletions[op.Predicate.Operation.String()].OverErased
	if want := []model.OverErased{{Book: model.OverErasedIncident, Count: 1}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("late over-erased = %+v, want %+v", got, want)
	}
	put(4, `{"labels":{}}`)
	if err := eraseLateEffect(w.st, w.org, w.project); err != nil {
		t.Fatal(err)
	}
	if got = w.st.Deletions[op.Predicate.Operation.String()].OverErased; len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("the counts must accumulate across passes: %+v", got)
	}
}
