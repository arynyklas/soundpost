// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// fakeLayout is a MembershipLayout that refuses the members listed in refuse and records every question.
type fakeLayout struct {
	refuse  map[uint64]error
	asked   []replica.Member
	control model.ID
	reasons []string
}

func (f *fakeLayout) Admit(_ context.Context, m replica.Member) error {
	f.asked = append(f.asked, m)
	return f.refuse[m.ID]
}
func (f *fakeLayout) Incompatible(context.Context) (model.ID, []string) { return f.control, f.reasons }

func layoutRefusalOf(identity string) error {
	return &model.Fault{Code: model.Unsupported, SafeDetail: "layout_incompatible:" + identity}
}

// The live layout check runs once per step for the member being added or promoted, only for groups this node
// leads that the step would change: a refusal proposes nothing and names the member; a group led elsewhere or already
// holding the change is not asked about.
func TestStepMembershipAsksTheLayoutQuestionOnlyWhereItWouldChangeAGroup(t *testing.T) {
	mk := func(leader uint64, members replica.Members) *fakeGroup {
		return &fakeGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: leader, Revision: members.Revision, Members: members}}
	}
	withLearner, _, _ := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: learner4})
	ledA, ledB, other, has := mk(1, voters()), mk(1, voters()), mk(2, voters()), mk(1, withLearner)
	groups := []MembershipGroup{ledA, other, has, ledB}
	layout := &fakeLayout{refuse: map[uint64]error{4: layoutRefusalOf("n4")}}
	got := StepMembership(context.Background(), groups, layout, MembershipChange{Op: MembershipAddLearner, Member: learner4})
	want := []string{OutcomeLayoutIncompatible, OutcomeNotLeader, OutcomeAlready, OutcomeLayoutIncompatible}
	for i, o := range got {
		if o.Result != want[i] {
			t.Errorf("group %d: %q, want %q", i, o.Result, want[i])
		}
	}
	for _, i := range []int{0, 3} {
		if got[i].Detail != "layout_incompatible:n4" {
			t.Errorf("group %d: detail %q does not name the member", i, got[i].Detail)
		}
	}
	if len(ledA.calls)+len(ledB.calls)+len(other.calls)+len(has.calls) != 0 {
		t.Fatal("a refused member was proposed")
	}
	if len(layout.asked) != 1 || layout.asked[0] != learner4 {
		t.Fatalf("asked %+v, want the learner once, with its address and identity", layout.asked)
	}
	if MembershipDone(got) {
		t.Fatal("a refused step reported done")
	}
	// A member that answers is proposed as before.
	layout.refuse = nil
	got = StepMembership(context.Background(), groups, layout, MembershipChange{Op: MembershipAddLearner, Member: learner4})
	if got[0].Result != OutcomeApplied || got[3].Result != OutcomeApplied || len(ledA.calls) != 1 || len(ledB.calls) != 1 {
		t.Fatalf("a member that answers: %+v", got)
	}
}

// Promoting a learner to voter asks about the learner (found in the group's configuration): it may have been put
// back on the previous release since it was added. An error that is not a layout refusal is an unavailable
// group, retried; no layout at all is no check.
func TestStepMembershipChecksThePromotedLearnerAndFailsClosed(t *testing.T) {
	withLearner, _, _ := PlanMembership(voters(), MembershipChange{Op: MembershipAddLearner, Member: learner4})
	led := &fakeGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: withLearner.Revision, Members: withLearner}}
	change := MembershipChange{Op: MembershipReplace, Remove: 2, Promote: 4}
	layout := &fakeLayout{refuse: map[uint64]error{4: layoutRefusalOf("n4")}}
	got := StepMembership(context.Background(), []MembershipGroup{led}, layout, change)
	if got[0].Result != OutcomeLayoutIncompatible || got[0].Detail != "layout_incompatible:n4" || len(led.calls) != 0 {
		t.Fatalf("promotion of a member that cannot read the layout: %+v, %d proposals", got[0], len(led.calls))
	}
	if len(layout.asked) != 1 || layout.asked[0].ID != 4 || layout.asked[0].NodeIdentity != "n4" {
		t.Fatalf("asked %+v", layout.asked)
	}
	layout.refuse = map[uint64]error{4: errors.New("deadline")}
	if got = StepMembership(context.Background(), []MembershipGroup{led}, layout, change); got[0].Result != OutcomeUnavailable || len(led.calls) != 0 {
		t.Fatalf("a check that could not be made: %+v", got[0])
	}
	if got = StepMembership(context.Background(), []MembershipGroup{led}, nil, change); got[0].Result != OutcomeApplied {
		t.Fatalf("without a layout: %+v", got[0])
	}
}

// The control group's report carries the members that cannot read the layout as typed reasons; the data groups carry none.
func TestReportMembershipAttachesTheReasonsToTheControlGroupOnly(t *testing.T) {
	control := &fakeGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: voters()}}
	data := &fakeGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: voters()}}
	layout := &fakeLayout{control: control.status.Group, reasons: []string{"layout_incompatible:n2"}}
	got := ReportMembership(context.Background(), []MembershipGroup{data, control}, layout)
	if len(got[0].Reasons) != 0 || !slices.Equal(got[1].Reasons, []string{"layout_incompatible:n2"}) {
		t.Fatalf("reasons: data %v, control %v", got[0].Reasons, got[1].Reasons)
	}
	if got = ReportMembership(context.Background(), []MembershipGroup{control}, nil); len(got[0].Reasons) != 0 {
		t.Fatalf("without a layout: %v", got[0].Reasons)
	}
}
