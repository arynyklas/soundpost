// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func erasingAudit(op model.ID, at time.Time) model.ControlAudit {
	return model.ControlAudit{ID: model.NewID(), Principal: model.NewID(), RequestID: model.NewID(), Action: controlErasedAction, Time: at.UnixNano(), Targets: []model.ID{op}}
}

// The scrub reads the audit log, zeroes free pages for as long as that takes, and settles exactly the
// erasures it read. The log is expired in between by any voter's worker, so what the scrub carries from
// its read to its settle must not be a position in the log: the erasing audits are never expired and are
// counted instead. Here an expiry removes ten rows before the scrub settles and a second erasure commits
// after the scrub's read; only the first may be settled.
func TestScrubCoverageIsNotShiftedByAnAuditExpiryBetweenItsReadAndItsSettle(t *testing.T) {
	s, _ := openAuthorityStore(t)
	ctx := context.Background()
	now := time.Now()
	covered, uncovered := model.NewID(), model.NewID()
	if err := s.Update(ctx, func(st *State) error {
		for range 10 {
			st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.NewID(), RequestID: model.NewID(), Action: "x.old", Time: now.Add(-400 * 24 * time.Hour).UnixNano()})
		}
		st.Audits = append(st.Audits, erasingAudit(covered, now))
		org := model.NewID()
		st.Deletions = map[string]model.DeletionOperation{
			covered.String():   {Principal: model.NewID(), Predicate: model.DeletePredicate{Operation: covered, Org: org, Mode: model.DeleteRetireProject}},
			uncovered.String(): {Principal: model.NewID(), Predicate: model.DeletePredicate{Operation: uncovered, Org: org, Mode: model.DeleteRetireProject}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read, err := s.localState() // what ScrubErased reads before it starts zeroing
	if err != nil {
		t.Fatal(err)
	}
	through := scrubCoverage(read.Audits)
	if rep, err := s.ExpireControlLog(ctx, ControlLogPolicy{Now: now, AuditDays: 365}); err != nil || rep.Audits != 10 {
		t.Fatalf("setup: %+v %v", rep, err)
	}
	if err = s.Update(ctx, func(st *State) error { st.Audits = append(st.Audits, erasingAudit(uncovered, now)); return nil }); err != nil {
		t.Fatal(err)
	}
	if err = s.settleScrub(ctx, through); err != nil {
		t.Fatal(err)
	}
	after, err := s.localState()
	if err != nil {
		t.Fatal(err)
	}
	debts := owedScrubs(after.Audits)
	if _, owed := debts[covered]; owed {
		t.Fatal("the erasure the scrub covered is still owed after the settle")
	}
	if _, owed := debts[uncovered]; !owed {
		t.Fatal("an erasure that committed after the scrub read the log was settled by a scrub that never covered it")
	}
}

// expireControlLog is a pure function of the state and the policy: the planning read and the committing
// update, and every voter that runs a pass, compute the same answer from equal states whatever the map
// order, and a pass over its own result finds nothing.
func TestExpireControlLogIsAPureFunctionOfStateAndPolicy(t *testing.T) {
	now := time.Now()
	a := &State{Commands: map[string]model.ControlResult{}, CommandOwners: map[string]string{}}
	for i := range 40 {
		id := model.NewID().String()
		a.Commands[id] = model.ControlResult{Revision: model.Revision(i + 1)}
		a.CommandOwners[id] = "owner"
	}
	a.Commands["undated"], a.CommandOwners["undated"] = model.ControlResult{}, "owner" // revision 0: nothing dates it
	a.CommandOwners["orphan"] = "owner"                                                // an owner row whose command is gone
	a.RevisionClock = []model.RevisionStamp{
		{Revision: 12, At: now.Add(-30 * time.Hour).UnixNano()},
		{Revision: 20, At: now.Add(-26 * time.Hour).UnixNano()}, // the newest stamp older than 24 hours
		{Revision: 30, At: now.Add(-time.Hour).UnixNano()},
	}
	b := &State{Commands: maps.Clone(a.Commands), CommandOwners: maps.Clone(a.CommandOwners), RevisionClock: slices.Clone(a.RevisionClock)}
	p := ControlLogPolicy{Now: now, AuditDays: 365, CommandMax: 15}
	ra, rb := expireControlLog(a, p), expireControlLog(b, p)
	if ra != rb || !reflect.DeepEqual(a, b) {
		t.Fatalf("two passes over equal states disagree: %+v vs %+v", ra, rb)
	}
	// Revisions 1..20 are provably older than a day (20 commands) and the orphaned owner row goes with
	// them; of the 21 left (20 dated 21..40 and the undated one), 6 are over the cap of 15, oldest
	// first: the undated one (revision 0) and 21..25.
	if ra.Commands != 21 || ra.Capped != 6 || ra.Audits != 0 {
		t.Fatalf("report %+v, want 21 aged out (20 commands and the orphan), 6 capped", ra)
	}
	if len(a.Commands) != 15 || len(a.CommandOwners) != 15 {
		t.Fatalf("rows after the pass: %d commands, %d owners, want 15 of each", len(a.Commands), len(a.CommandOwners))
	}
	for _, c := range a.Commands {
		if c.Revision < 26 {
			t.Fatalf("a command of revision %d survived the pass", c.Revision)
		}
	}
	if again := expireControlLog(a, p); !again.none() {
		t.Fatalf("a pass over an already expired state is not a no-op: %+v", again)
	}
	// No stamp older than the window: nothing is provably old, so nothing is aged out by time.
	c := &State{Commands: map[string]model.ControlResult{"x": {Revision: 1}}, CommandOwners: map[string]string{"x": "owner"}, RevisionClock: []model.RevisionStamp{{Revision: 1, At: now.Add(-time.Hour).UnixNano()}}}
	if rep := expireControlLog(c, p); !rep.none() || len(c.Commands) != 1 {
		t.Fatalf("a command younger than the window was expired: %+v", rep)
	}
}
