// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The operator's two membership steps for replacing a voter that cannot rejoin (a lost or rolled
// back disk, replica.ErrJournalBehind): add a fresh identity as a learner to every group, and
// then, once it has caught up, promote it while removing the lost voter, in one joint change per
// group. Both are idempotent per group, so an operator repeats them until every group reports
// done.
const (
	// MembershipAddLearner installs Member as a learner in every group.
	MembershipAddLearner = "add_learner"
	// MembershipReplace promotes the learner Promote to voter and removes the voter Remove.
	MembershipReplace = "replace"
)

// MembershipChange is one operator step.
type MembershipChange struct {
	Op      string         `json:"op"`
	Member  replica.Member `json:"member,omitempty"`
	Remove  uint64         `json:"remove,string,omitempty"`
	Promote uint64         `json:"promote,string,omitempty"`
}

// Outcomes of one group.
const (
	// OutcomeApplied: this node led the group and the joint change was entered and left.
	OutcomeApplied = "applied"
	// OutcomeAlready: the group's configuration already is the requested one.
	OutcomeAlready = "already"
	// OutcomeNotLeader: another node leads the group; run the step there (Leader names it).
	OutcomeNotLeader = "not_leader"
	// OutcomeNotCaughtUp: the learner has not applied the group's current cut yet; retry later.
	OutcomeNotCaughtUp = "learner_not_caught_up"
	// OutcomeUnavailable: no quorum, no leader or the group failed closed; retry later.
	OutcomeUnavailable = "unavailable"
	// OutcomeRejected: the step does not fit the group's configuration (the group is unchanged).
	OutcomeRejected = "rejected"
	// OutcomeLayoutIncompatible: the member to add or promote does not answer, from its RUNNING binary, that
	// it reads the layout the installation's indexes are in (an organization is contracted, D70); the
	// group is unchanged and Detail names the member as layout_incompatible:<identity>.
	OutcomeLayoutIncompatible = "layout_incompatible"
)

// MembershipOutcome is the result for one group.
type MembershipOutcome struct {
	Group    model.ID       `json:"group"`
	Result   string         `json:"result"`
	Leader   uint64         `json:"leader,string,omitempty"`
	Revision model.Revision `json:"revision"`
	// Detail is the typed reason of a refusal (OutcomeLayoutIncompatible).
	Detail string `json:"detail,omitempty"`
}

// MembershipStatus is one group's configuration as this node sees it.
type MembershipStatus struct {
	Group   model.ID        `json:"group"`
	Leader  uint64          `json:"leader,string"`
	Term    uint64          `json:"term,string"`
	Applied uint64          `json:"applied,string"`
	Failed  bool            `json:"failed,omitempty"`
	Members replica.Members `json:"members"`
	// Reasons are the members of the control group that cannot be used as they are: each control member
	// other than this node whose running binary does not answer that it reads the contracted index layout
	// is layout_incompatible:<identity> (a voter put back on the previous release after the contraction).
	// Only the control group carries them.
	Reasons []string `json:"reasons,omitempty"`
}

// MembershipGroup is the part of a replication group the operator steps use.
type MembershipGroup interface {
	Status() replica.Status
	ChangeMembers(ctx context.Context, expected model.Revision, next replica.Members) error
}

// MembershipLayout is the live check of the layout the installation's indexes are in (D70), asked of the
// RUNNING binary of a member over the peer connection. Nil where it is a parameter: no check.
type MembershipLayout interface {
	// Admit refuses a member that would join the voters and cannot read the layout:
	// nil while no organization is contracted or when the member answers; otherwise a typed refusal naming it
	// (control.LayoutIncompatible), or the error that kept the answer from being known (fail closed).
	Admit(ctx context.Context, m replica.Member) error
	// AdmitLearner is Admit for a member added as a learner: it also admits one nothing is running for yet
	// (replica.ErrMemberNotRunning; the member is started after it is added), and refuses a running binary
	// that does not answer that it reads the layout.
	AdmitLearner(ctx context.Context, m replica.Member) error
	// Incompatible names the control group and the control members, other than this node, whose running
	// binary cannot read the contracted layout, as layout_incompatible:<identity>.
	Incompatible(ctx context.Context) (control model.ID, reasons []string)
}

// ErrNoMembership is returned on a node that is not part of a replicated installation.
var ErrNoMembership = errors.New("not a distributed installation")

// MembershipGroups returns this node's replication groups (the control group and the data groups).
func (a *App) MembershipGroups() ([]MembershipGroup, error) {
	if a.replication == nil {
		return nil, ErrNoMembership
	}
	out := make([]MembershipGroup, 0, len(a.replication.groups))
	for _, g := range a.replication.groups {
		out = append(out, g)
	}
	return out, nil
}

// PlanMembership computes the configuration that follows current when change is applied. already
// is true when current already is that configuration (a repeated step); an error means the step
// does not fit current and nothing may be proposed.
func PlanMembership(current replica.Members, change MembershipChange) (next replica.Members, already bool, err error) {
	find := func(id uint64) (replica.Member, bool) {
		for _, m := range current.Nodes {
			if m.ID == id {
				return m, true
			}
		}
		return replica.Member{}, false
	}
	next = replica.Members{Revision: current.Revision + 1, Nodes: slices.Clone(current.Nodes)}
	switch change.Op {
	case MembershipAddLearner:
		if !change.Member.Learner || change.Member.ID == 0 {
			return next, false, model.Fail(model.Invalid)
		}
		if have, ok := find(change.Member.ID); ok {
			if !have.Learner || have.NodeIdentity != change.Member.NodeIdentity || have.Address != change.Member.Address || have.FailureDomain != change.Member.FailureDomain {
				return next, false, model.Fail(model.Conflict)
			}
			return current, true, nil
		}
		next.Nodes = append(next.Nodes, change.Member)
	case MembershipReplace:
		if change.Remove == 0 || change.Promote == 0 || change.Remove == change.Promote {
			return next, false, model.Fail(model.Invalid)
		}
		promoted, havePromote := find(change.Promote)
		removed, haveRemove := find(change.Remove)
		switch {
		case havePromote && !promoted.Learner && !haveRemove:
			return current, true, nil
		case !havePromote || !promoted.Learner || !haveRemove || removed.Learner:
			return next, false, model.Fail(model.Conflict)
		}
		next.Nodes = slices.DeleteFunc(next.Nodes, func(m replica.Member) bool { return m.ID == change.Remove })
		for i := range next.Nodes {
			if next.Nodes[i].ID == change.Promote {
				next.Nodes[i].Learner = false
			}
		}
	default:
		return next, false, model.Fail(model.Invalid)
	}
	if err = replica.ValidateMembers(next); err != nil {
		return next, false, err
	}
	return next, false, nil
}

// StepMembership applies change to every group this node leads and reports every group. It never
// proposes for a group led elsewhere. A member that would join a group is first asked the layout
// question (layout.AdmitLearner for the learner added, layout.Admit for the learner promoted), once per
// step and only for a group the step would change and this node leads: a refusal proposes nothing and
// the group reports OutcomeLayoutIncompatible. A nil layout asks nothing.
func StepMembership(ctx context.Context, groups []MembershipGroup, layout MembershipLayout, change MembershipChange) []MembershipOutcome {
	asked := map[uint64]error{}
	admit := func(m replica.Member) error {
		if layout == nil {
			return nil
		}
		if err, ok := asked[m.ID]; ok {
			return err
		}
		var err error
		if change.Op == MembershipAddLearner {
			err = layout.AdmitLearner(ctx, m)
		} else {
			err = layout.Admit(ctx, m)
		}
		asked[m.ID] = err
		return err
	}
	out := make([]MembershipOutcome, 0, len(groups))
	for _, g := range groups {
		out = append(out, stepGroup(ctx, g, admit, change))
	}
	return out
}

func stepGroup(ctx context.Context, g MembershipGroup, admit func(replica.Member) error, change MembershipChange) MembershipOutcome {
	status := g.Status()
	outcome := MembershipOutcome{Group: status.Group, Leader: status.Leader, Revision: status.Revision}
	if status.Failed {
		outcome.Result = OutcomeUnavailable
		return outcome
	}
	next, already, err := PlanMembership(status.Members, change)
	switch {
	case err != nil:
		outcome.Result = OutcomeRejected
	case already:
		outcome.Result = OutcomeAlready
	case status.Leader != status.ID:
		outcome.Result = OutcomeNotLeader
	default:
		var joining replica.Member
		if change.Op == MembershipAddLearner {
			joining = change.Member
		} else {
			for _, m := range status.Members.Nodes {
				if m.ID == change.Promote {
					joining = m
				}
			}
		}
		if err = admit(joining); err != nil {
			var fault *model.Fault
			if errors.As(err, &fault) && fault.Code == model.Unsupported && strings.HasPrefix(fault.SafeDetail, control.LayoutIncompatiblePrefix) {
				outcome.Result, outcome.Detail = OutcomeLayoutIncompatible, fault.SafeDetail
			} else {
				outcome.Result = OutcomeUnavailable
			}
			return outcome
		}
		switch err = g.ChangeMembers(ctx, status.Members.Revision, next); {
		case err == nil:
			outcome.Result = OutcomeApplied
			outcome.Revision = next.Revision
		case errors.Is(err, replica.ErrStale) && change.Op == MembershipReplace:
			outcome.Result = OutcomeNotCaughtUp
		case errors.Is(err, replica.ErrConflict) || errors.Is(err, replica.ErrInvalid):
			outcome.Result = OutcomeRejected
		default:
			outcome.Result = OutcomeUnavailable
		}
	}
	return outcome
}

// MembershipDone reports whether every group ended in a configuration that holds the change.
func MembershipDone(outcomes []MembershipOutcome) bool {
	for _, o := range outcomes {
		if o.Result != OutcomeApplied && o.Result != OutcomeAlready {
			return false
		}
	}
	return len(outcomes) > 0
}

// ReportMembership returns this node's view of every group. The control group, as layout names it, also
// carries the control members that cannot read the layout (MembershipStatus.Reasons).
func ReportMembership(ctx context.Context, groups []MembershipGroup, layout MembershipLayout) []MembershipStatus {
	var controlGroup model.ID
	var reasons []string
	if layout != nil {
		controlGroup, reasons = layout.Incompatible(ctx)
	}
	out := make([]MembershipStatus, 0, len(groups))
	for _, g := range groups {
		s := g.Status()
		status := MembershipStatus{Group: s.Group, Leader: s.Leader, Term: s.Term, Applied: s.Applied, Failed: s.Failed, Members: s.Members}
		if s.Group == controlGroup {
			status.Reasons = reasons
		}
		out = append(out, status)
	}
	return out
}

// MembershipLayout is the live layout check of this node's control store (control.Store.CheckMemberLayout,
// control.Store.MembersIncompatible), the check `soundpost membership` runs before it proposes a member and
// when it reports. It is nil on a node that is not part of a replicated installation.
func (a *App) MembershipLayout() MembershipLayout {
	if a.replication == nil {
		return nil
	}
	return appLayout{a}
}

type appLayout struct{ app *App }

func (l appLayout) Admit(ctx context.Context, m replica.Member) error {
	return l.app.Control.CheckMemberLayout(ctx, m)
}

func (l appLayout) AdmitLearner(ctx context.Context, m replica.Member) error {
	return l.app.Control.CheckLearnerLayout(ctx, m)
}

func (l appLayout) Incompatible(ctx context.Context) (model.ID, []string) {
	group := l.app.Control.ReplicaGroup()
	if group == nil {
		return model.ID{}, nil
	}
	status := group.Status()
	others := make([]replica.Member, 0, len(status.Members.Nodes))
	for _, m := range status.Members.Nodes {
		if m.ID != status.ID {
			others = append(others, m)
		}
	}
	return status.Group, l.app.Control.MembersIncompatible(ctx, others)
}
