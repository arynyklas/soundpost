// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func voters() replica.Members {
	return replica.Members{Revision: 1, Nodes: []replica.Member{
		{ID: 1, Address: "https://a.example", NodeIdentity: "n1", FailureDomain: "d1"},
		{ID: 2, Address: "https://b.example", NodeIdentity: "n2", FailureDomain: "d2"},
		{ID: 3, Address: "https://c.example", NodeIdentity: "n3", FailureDomain: "d3"},
	}}
}

var learner4 = replica.Member{ID: 4, Address: "https://d.example", NodeIdentity: "n4", FailureDomain: "d4", Learner: true}

func TestPlanMembershipReplacesALostVoterInTwoSteps(t *testing.T) {
	withLearner, already, err := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: learner4})
	if err != nil || already || withLearner.Revision != 2 || len(withLearner.Nodes) != 4 || !withLearner.Nodes[3].Learner {
		t.Fatalf("add learner = %+v, %v, %v", withLearner, already, err)
	}
	if again, already, err := PlanMembership(withLearner, MembershipChange{Op: MembershipAddLearner, Member: learner4}); err != nil || !already || again.Revision != 2 {
		t.Fatalf("a repeated add learner = %+v, %v, %v; want already", again, already, err)
	}
	replaced, already, err := PlanMembership(withLearner, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4})
	if err != nil || already || replaced.Revision != 3 || len(replaced.Nodes) != 3 {
		t.Fatalf("replace = %+v, %v, %v", replaced, already, err)
	}
	for _, m := range replaced.Nodes {
		if m.ID == 2 || m.Learner {
			t.Fatalf("replace left %+v", m)
		}
	}
	if _, already, err := PlanMembership(replaced, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4}); err != nil || !already {
		t.Fatalf("a repeated replace = %v, %v; want already", already, err)
	}
}

func TestPlanMembershipRefusesWhatDoesNotFit(t *testing.T) {
	withLearner, _, _ := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: learner4})
	sharedDomain, _, err := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: replica.Member{ID: 4, Address: "https://d.example", NodeIdentity: "n4", FailureDomain: "d1", Learner: true}})
	if err != nil {
		t.Fatalf("a learner may be added in any failure domain: %v", err)
	}
	for name, tc := range map[string]struct {
		from   replica.Members
		change MembershipChange
	}{
		"unknown operation":                           {voters(), MembershipChange{Op: "nope"}},
		"a voter given as the new learner":            {voters(), MembershipChange{Op: MembershipAddLearner, Member: replica.Member{ID: 4, Address: "https://d.example", NodeIdentity: "n4", FailureDomain: "d4"}}},
		"learner id taken by another identity":        {withLearner, MembershipChange{Op: MembershipAddLearner, Member: replica.Member{ID: 4, Address: "https://d.example", NodeIdentity: "other", FailureDomain: "d4", Learner: true}}},
		"learner add for an existing voter":           {voters(), MembershipChange{Op: MembershipAddLearner, Member: replica.Member{ID: 2, Address: "https://b.example", NodeIdentity: "n2", FailureDomain: "d2", Learner: true}}},
		"replace into a failure domain a voter holds": {sharedDomain, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4}},
		"replace without a learner":                   {voters(), MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4}},
		"replace promoting a voter":                   {withLearner, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 3}},
		"replace removing the learner":                {withLearner, MembershipChange{Op: MembershipReplace, Remove: 4, Promote: 4}},
		"replace removing an unknown node":            {withLearner, MembershipChange{Op: MembershipReplace, Remove: 9, Promote: 4}},
	} {
		if _, already, err := PlanMembership(tc.from, tc.change); err == nil || already {
			t.Errorf("%s: planned (already %v, err %v), want a refusal", name, already, err)
		}
	}
}

type fakeGroup struct {
	status replica.Status
	err    error
	calls  []replica.Members
}

func (f *fakeGroup) Status() replica.Status { return f.status }
func (f *fakeGroup) ChangeMembers(_ context.Context, expected model.Revision, next replica.Members) error {
	if expected != f.status.Revision {
		return replica.ErrConflict
	}
	f.calls = append(f.calls, next)
	return f.err
}

func TestStepMembershipActsOnlyOnTheGroupsThisNodeLeads(t *testing.T) {
	mk := func(leader uint64, members replica.Members) *fakeGroup {
		return &fakeGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: leader, Revision: members.Revision, Members: members}}
	}
	withLearner, _, _ := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: learner4})
	replaced, _, _ := PlanMembership(withLearner, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4})
	led, other, lagging, failedGroup, done := mk(1, withLearner), mk(2, withLearner), mk(1, withLearner), mk(1, withLearner), mk(1, replaced)
	lagging.err = replica.ErrStale
	failedGroup.status.Failed = true
	groups := []MembershipGroup{led, other, done, lagging, failedGroup}
	got := StepMembership(context.Background(), groups, MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4})
	want := []string{OutcomeApplied, OutcomeNotLeader, OutcomeAlready, OutcomeNotCaughtUp, OutcomeUnavailable}
	for i, o := range got {
		if o.Result != want[i] {
			t.Errorf("group %d: %q, want %q", i, o.Result, want[i])
		}
	}
	if len(other.calls) != 0 || len(failedGroup.calls) != 0 || len(done.calls) != 0 || len(led.calls) != 1 {
		t.Fatalf("proposals: led %d other %d failed %d done %d", len(led.calls), len(other.calls), len(failedGroup.calls), len(done.calls))
	}
	if got[1].Leader != 2 {
		t.Fatalf("a group led elsewhere does not name its leader: %+v", got[1])
	}
	if MembershipDone(got) {
		t.Fatal("a step with groups left to do reported done")
	}
	if !MembershipDone([]MembershipOutcome{{Result: OutcomeApplied}, {Result: OutcomeAlready}}) || MembershipDone(nil) {
		t.Fatal("MembershipDone does not reflect applied/already")
	}
}
