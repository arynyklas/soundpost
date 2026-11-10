// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"path/filepath"
	"testing"

	"soundpost/internal/model"
)

// A scrub covers exactly the erasures committed before it read the state: an
// erasure that committed while it ran freed pages it may already have passed, so
// settling must leave it owed, and an operation that was erased again after the
// scrub's read stays owed even though an earlier erasure of it was covered.
// (01.08 CD-3: the debt is derived from the audit log alone.)
func TestSettleScrubCoversOnlyErasuresBeforeItsRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	org, one, two := model.ID{0x10}, model.ID{0xa1}, model.ID{0xa2}
	erased := func(st *State, op model.ID, at int64) {
		st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.ID{0xbb}, Action: controlErasedAction, Time: at, Org: org.String(), Targets: []model.ID{op}, Outcome: model.AuditAllowed})
	}
	if err = s.Update(ctx, func(st *State) error {
		pred := func(op model.ID) model.DeletePredicate {
			return model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{{0x11}}, Generation: 1}
		}
		st.Deletions = map[string]model.DeletionOperation{
			one.String(): {Predicate: pred(one), Phase: model.DeletePhaseFailed, Principal: model.ID{0xbb}},
			two.String(): {Predicate: pred(two), Phase: model.DeletePhaseFailed, Principal: model.ID{0xbb}},
		}
		erased(st, one, 10) // position 0
		erased(st, two, 20) // position 1
		erased(st, one, 30) // position 2: after the scrub's read below
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	debts := func() map[model.ID]scrubDebt {
		t.Helper()
		st, err := s.localState()
		if err != nil {
			t.Fatal(err)
		}
		return owedScrubs(st.Audits)
	}
	if d := debts(); len(d) != 2 || d[one] != (scrubDebt{last: 2, at: 30}) || d[two] != (scrubDebt{last: 1, at: 20}) {
		t.Fatalf("debts before any scrub: %+v", d)
	}

	// A scrub that read the log when it had two entries covers operation two and
	// the first erasure of operation one, not operation one's third entry.
	if err = s.settleScrub(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if d := debts(); len(d) != 1 || d[one] != (scrubDebt{last: 2, at: 30}) {
		t.Fatalf("debts after a scrub that covered the first two entries: %+v", d)
	}
	revision := func() model.Revision {
		st, err := s.localState()
		if err != nil {
			t.Fatal(err)
		}
		return st.Revision
	}
	before := revision()
	if err = s.settleScrub(ctx, 2); err != nil { // nothing is left that it covers: commits nothing
		t.Fatal(err)
	}
	if revision() != before {
		t.Fatal("a scrub with nothing left to settle committed a control update")
	}

	// A later scrub covers it, and the audit it appends carries the erasure's own time.
	if err = s.settleScrub(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if d := debts(); len(d) != 0 {
		t.Fatalf("debts after the covering scrub: %+v", d)
	}
	st, err := s.localState()
	if err != nil {
		t.Fatal(err)
	}
	last := st.Audits[len(st.Audits)-1]
	if last.Action != controlScrubbedAction || last.Time != 30 || len(last.Targets) != 1 || last.Targets[0] != one {
		t.Fatalf("the settling audit: %+v", last)
	}
}
