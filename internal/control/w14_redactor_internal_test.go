// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The rules a journal redaction pass applies are those of the FINISHED deletions only (complete or
// failed): while a deletion is fencing or held, the live state still holds the effects that the live
// erasure drops when it completes, and redacting retained commands by it would rewrite history under
// a state that has not erased yet. RedactRetainedControlCommands checks that every erasing deletion
// is finished before it starts, but the redactor re-reads the state when a command was applied since
// (a deletion that began meanwhile is then in the state it reads), so the filter is its own guard.
func TestTheRedactorsRulesHoldOnlyFinishedDeletions(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // one complete deletion, f.operation
	template := f.finishedDeletion()[f.operation.String()]
	phases := map[model.ID]string{
		{0xde, 0x02}: model.DeletePhaseFencing,
		{0xde, 0x03}: model.DeletePhaseHeld,
		{0xde, 0x04}: model.DeletePhaseFailed,
	}
	if err := f.s.Update(f.ctx, func(st *State) error {
		for id, phase := range phases {
			op := template
			op.Predicate.Operation = id
			op.Phase = phase
			st.Deletions[id.String()] = op
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := &controlRedactor{s: f.s}
	if err := r.load(); err != nil {
		t.Fatal(err)
	}
	var live, rules []string
	for id := range r.live.Deletions {
		live = append(live, id)
	}
	for id := range r.rules.Deletions {
		rules = append(rules, id)
	}
	slices.Sort(live)
	slices.Sort(rules)
	if len(live) != 4 {
		t.Fatalf("fixture invalid: the live state holds %d deletions, want 4: %v", len(live), live)
	}
	want := []string{f.operation.String(), model.ID{0xde, 0x04}.String()}
	slices.Sort(want)
	if !slices.Equal(rules, want) {
		t.Fatalf("the redactor's rules are %v, want exactly the complete and the failed deletion %v (live: %v)", rules, want, live)
	}
}
