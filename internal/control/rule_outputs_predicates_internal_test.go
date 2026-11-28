// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// countingControl counts how often a read of the control state asks for the deletion predicates:
// every ask is a deep copy of each predicate's lists (model.ReadOnlyControl hands out copies only).
type countingControl struct {
	model.ReadOnlyControl
	predicateReads int
}

func (c *countingControl) DeletionPredicates(phases ...string) []model.DeletePredicate {
	c.predicateReads++
	return c.ReadOnlyControl.DeletionPredicates(phases...)
}

// RuleOutputs marks each output obsolete when a deletion covers it. The deletion predicates are
// copied by the read-only view each time they are asked for, so asking once per output made the read
// cost outputs x deletions x list sizes; one read of the state asks once.
func TestRuleOutputsAsksForTheDeletionPredicatesOnce(t *testing.T) {
	org, project, other := model.NewID(), model.NewID(), model.NewID()
	st := model.ControlState{RuleOutputs: map[string]json.RawMessage{}, Deletions: map[string]model.DeletionOperation{}}
	// Three fencing deletions of the same project with long lists, plus one deletion of another project
	// and one that is not in force.
	var projects []model.ID
	for range 64 {
		projects = append(projects, model.NewID())
	}
	covering := func(start, end model.UnixNano, scope ...model.ID) model.DeletePredicate {
		op := model.NewID()
		return model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteHistoricalRange, Projects: append(append([]model.ID{}, projects...), scope...), Signals: []model.Kind{model.Metric}, Start: start, End: end}
	}
	for _, p := range []struct {
		phase string
		pred  model.DeletePredicate
	}{
		{model.DeletePhaseFencing, covering(100, 200, project)},
		{model.DeletePhaseComplete, covering(300, 400, project)},
		{model.DeletePhaseFencing, covering(500, 600, other)},
		{model.DeletePhaseHeld, covering(700, 800, project)},
	} {
		st.Deletions[p.pred.Operation.String()] = model.DeletionOperation{Phase: p.phase, Predicate: p.pred}
	}
	const outputs = 200
	want := map[model.ID]bool{}
	for i := range outputs {
		at := model.UnixNano(i * 5) // 0 .. 995: [100,200) and [300,400) are covered, the rest is not
		o := RuleOutput{ID: model.NewID(), Org: org, Project: project, Rule: model.NewID(), At: at, Signal: model.Metric, Phase: RulePhasePending}
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		st.RuleOutputs[o.ID.String()] = raw
		want[o.ID] = at >= 100 && at < 200 || at >= 300 && at < 400
	}
	view := &countingControl{ReadOnlyControl: model.ReadOnlyOf(&st)}
	got, err := ruleOutputsOf(view, org, project, model.ID{}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != outputs {
		t.Fatalf("%d outputs, want %d", len(got), outputs)
	}
	var obsolete int
	for _, o := range got {
		if o.Obsolete != want[o.ID] {
			t.Fatalf("output at %d: obsolete = %v, want %v", o.At, o.Obsolete, want[o.ID])
		}
		if o.Obsolete {
			obsolete++
		}
	}
	if obsolete != 40 {
		t.Fatalf("%d obsolete outputs, want 40 (fixture)", obsolete)
	}
	if view.predicateReads > 1 {
		t.Fatalf("the read asked for the deletion predicates %d times for %d outputs, want once", view.predicateReads, outputs)
	}
}
