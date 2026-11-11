// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"soundpost/internal/model"
)

// stateErasedLate decides, for the late re-erasure only, whether an opaque
// state is derived from the range's half-open [start,end); stateErased, which
// begin, completion and import use, keeps its documented coarse rule. (09.06
// review C-1.)
func TestStateErasedLateRule(t *testing.T) {
	org, project := model.ID{0x10}, model.ID{0x11}
	rangeOf := func(start, end model.UnixNano) model.DeletePredicate {
		return model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: start, End: end}
	}
	for _, c := range []struct {
		name         string
		p            model.DeletePredicate
		state        string
		late, coarse bool
	}{
		{"evidence inside", rangeOf(40, 100), `{"at":"60"}`, true, true},
		{"evidence at start", rangeOf(40, 100), `{"at":40}`, true, true},
		{"evidence at end is outside", rangeOf(40, 100), `{"at":"100"}`, false, true},
		{"evidence after the end", rangeOf(40, 100), `{"event_ns":"1000"}`, false, true},
		{"evidence before the start", rangeOf(40, 100), `{"event_ns":"10"}`, false, false},
		{"evidence inside among later action times", rangeOf(40, 100), `{"condition":{"at":60},"timeline":[{"at":1000},{"at":2000}]}`, true, true},
		{"evidence before and after, none inside", rangeOf(40, 100), `{"a_at":10,"b_ns":"1000"}`, false, true},
		{"nested evidence inside", rangeOf(40, 100), `{"runs":{"x":{"attempts":[{"observed_ns":99}]}},"as_of_ns":1000}`, true, true},
		{"names no time", rangeOf(40, 100), `{"labels":{"host":"a"}}`, true, true},
		{"only unset times", rangeOf(40, 100), `{"effective_from_ns":0,"at":0}`, true, false},
		{"unreadable time", rangeOf(40, 100), `{"at":"yesterday","as_of_ns":1000}`, true, true},
		{"unreadable state", rangeOf(40, 100), `{`, true, true},
		{"unset time beside a later one, range from zero", rangeOf(0, 100), `{"effective_from_ns":0,"as_of_ns":1000}`, false, true},
		{"durations are not instants, range from zero", rangeOf(0, 100), `{"definition":{"grace_ns":"60","max_runtime_ns":"70","observer_stale_after_ns":"80"},"as_of_ns":1000}`, false, true},
		{"a real instant is still read, range from zero", rangeOf(0, 100), `{"definition":{"grace_ns":"60"},"as_of_ns":50}`, true, true},
		{"retire project", model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}}, `{"at":1000}`, true, true},
		{"retire org", model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteRetireOrg}, `{"at":1000}`, true, true},
		{"entity covers none", model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteEntity, Projects: []model.ID{project}, Entities: []model.ID{{0xe7}}}, `{"at":60}`, false, false},
		{"another project", model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{{0x12}}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}, `{"at":60}`, false, false},
		{"a tombstone is never covered again", rangeOf(40, 100), string(tombstoneState("incident_id", model.ID{1}, org, project, 3, model.ID{0xdd})), false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := json.RawMessage(c.state)
			if got := stateErasedLate(c.p, org, project, raw); got != c.late {
				t.Errorf("late rule: covered=%v, want %v", got, c.late)
			}
			if got := stateErased(c.p, org, project, raw); got != c.coarse {
				t.Errorf("begin/complete rule: covered=%v, want %v (that rule is unchanged)", got, c.coarse)
			}
		})
	}
}
