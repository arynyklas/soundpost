// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 09.08x-W1 / 11.03-W4: an opaque state that carries a per-state provenance (the
// earliest and the latest record time its producer folded into it) is covered by a
// historical range when that interval meets the range's half-open [start,end), at
// begin, completion, import and in the late pass alike, besides what the rule over
// the times the state names covers: the provenance never narrows that rule (it is
// not read as times the state names). A state without a provenance keeps the old
// rule (the window of the times it names, fail-closed when it names none); a
// malformed provenance is unattributable and is dropped whole, counted as
// over-erased.
func TestStateRulesReadTheProvenance(t *testing.T) {
	org, project := model.ID{0x10}, model.ID{0x11}
	rng := model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}
	prov := func(from, to string) string { return `"provenance":{"from_ns":"` + from + `","to_ns":"` + to + `"}` }
	for _, c := range []struct {
		name        string
		state       string
		begin, late bool // covered by the begin/completion rule, by the late rule
		over        bool // covered without an attributable window
	}{
		// The residual W4 names: the evidence inside the range rolled out of the bounded
		// part, every time the state still names lies after the end.
		{"rolled-out evidence inside the range", `{"event_ns":"1000","recent":[{"event_ns":"1000"}],` + prov("60", "1000") + `}`, true, true, false},
		{"rolled-out evidence before the start, the latest after the end", `{"event_ns":"1000",` + prov("10", "1000") + `}`, true, true, false},
		{"the interval reaches into the range", `{"event_ns":"1000",` + prov("30", "50") + `}`, true, true, false},
		{"the interval ends at the start", `{"event_ns":"1000",` + prov("10", "40") + `}`, true, true, false},
		{"the interval starts at the start", `{"event_ns":"1000",` + prov("40", "40") + `}`, true, true, false},
		{"one point inside", `{"event_ns":"1000",` + prov("99", "99") + `}`, true, true, false},
		// Provenance wholly outside the range: kept, as is a state that names nothing inside.
		{"entirely before the start", `{"event_ns":"1000",` + prov("10", "39") + `}`, false, false, false},
		{"starts at the end", `{"event_ns":"2000",` + prov("100", "2000") + `}`, false, false, false},
		{"entirely after the end", `{"event_ns":"1000",` + prov("1000", "1000") + `}`, false, false, false},
		// What the state names is read as before: the provenance only adds.
		{"a time named inside covers the state, whatever the provenance", `{"at":"60","event_ns":"1000",` + prov("1000", "1000") + `}`, true, true, false},
		{"visible times span the range, the provenance is outside", `{"first_at":"10","at":"1000",` + prov("2000", "2000") + `}`, true, false, false},
		{"a state that names no time is attributed by its provenance: outside", `{"labels":{},` + prov("1000", "1000") + `}`, false, false, false},
		{"a state that names no time is attributed by its provenance: inside", `{"labels":{},` + prov("60", "60") + `}`, true, true, false},
		// A provenance that cannot be read is unattributable: dropped whole, counted.
		{"provenance is not an object", `{"event_ns":"1000","provenance":"x"}`, true, true, true},
		{"provenance is a list", `{"event_ns":"1000","provenance":[{"from_ns":"10","to_ns":"20"}]}`, true, true, true},
		{"provenance is empty", `{"event_ns":"1000","provenance":{}}`, true, true, true},
		{"interval runs backwards", `{"event_ns":"1000",` + prov("50", "10") + `}`, true, true, true},
		{"interval has an unset time", `{"event_ns":"1000",` + prov("0", "10") + `}`, true, true, true},
		{"a time is not a number", `{"event_ns":"1000",` + prov("a", "10") + `}`, true, true, true},
		{"an unknown member", `{"event_ns":"1000","provenance":{"from_ns":"10","to_ns":"20","x":1}}`, true, true, true},
		{"an unreadable time beside a good provenance", `{"at":"yesterday",` + prov("1000", "1000") + `}`, true, true, true},
		// A state without a provenance is the old rule.
		{"legacy: names a time inside", `{"event_ns":"60"}`, true, true, false},
		{"legacy: all after the end", `{"event_ns":"1000"}`, false, false, false},
		{"legacy: spans the range, none inside", `{"first_at":"10","at":"1000"}`, true, false, false},
		{"legacy: null member", `{"event_ns":"1000","provenance":null}`, false, false, false},
		{"legacy: names no time", `{"labels":{}}`, true, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := json.RawMessage(c.state)
			if got := stateErased(rng, org, project, raw); got != c.begin {
				t.Errorf("begin/complete rule: covered=%v, want %v", got, c.begin)
			}
			if got := stateErasedLate(rng, org, project, raw); got != c.late {
				t.Errorf("late rule: covered=%v, want %v", got, c.late)
			}
			if got := overErasure(rng, raw); got != c.over {
				t.Errorf("over-erasure: %v, want %v", got, c.over)
			}
		})
	}
}

// A retirement erases every state of its projects and an entity deletion none, whatever
// provenance the state carries; a tombstone is never covered again.
func TestStateRulesIgnoreTheProvenanceOutsideARange(t *testing.T) {
	org, project := model.ID{0x10}, model.ID{0x11}
	state := json.RawMessage(`{"event_ns":"1000","provenance":{"from_ns":"1000","to_ns":"1000"}}`)
	retire := model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}}
	entity := model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteEntity, Projects: []model.ID{project}, Entities: []model.ID{{0xe7}}}
	if !stateErased(retire, org, project, state) || !stateErasedLate(retire, org, project, state) || overErasure(retire, state) {
		t.Error("a retirement must erase the state exactly")
	}
	if stateErased(entity, org, project, state) || stateErasedLate(entity, org, project, state) {
		t.Error("an entity deletion covers no state")
	}
	rng := model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 5000}
	tomb := tombstoneState("condition_id", model.ID{1}, org, project, 3, model.ID{0xdd})
	if stateErased(rng, org, project, tomb) || stateErasedLate(rng, org, project, tomb) {
		t.Error("a tombstone is covered again")
	}
}
