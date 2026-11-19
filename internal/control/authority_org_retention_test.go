// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// F-10.05-2, the residual wave 25 disclosed: the retention-class commands of one organization
// (deletion Begin, legal hold, retention policy, the fence steps, and the worker transitions of an
// operation) wrote installation-wide tables and so moved the installation-wide AuthorityRevision,
// which made every other organization's retention command with an older view conflict. They are
// now verified to have changed the rows of their own organization alone, and then move that
// organization's authority revision instead (Store.UpdateOrgAuthority's rule, applied to the rows
// of the retention tables as well as to the organization's record). The rule applies to a command
// proposed as a state patch (the fixtures below open the gate of a group whose members all declared
// protocol 5); a replacement keeps the installation-wide bump (TestWithoutThePatchGate...).

// retentionActor is one organization of the fixture the retention-class commands are issued for.
type retentionActor struct {
	f      *fenceFx
	org    model.ID
	p1, p2 model.ID
}

// ownActor is the fixture's own organization.
func (f *fenceFx) ownActor() *retentionActor {
	return &retentionActor{f: f, org: f.org, p1: f.project, p2: f.otherProject}
}

// tenantB creates a second organization with two projects and the fixture's administrator in it.
func (f *fenceFx) tenantB() *retentionActor {
	b := &retentionActor{f: f, org: model.NewID(), p1: model.NewID(), p2: model.NewID()}
	f.admin("create_org", b.org, auth.AdminPayload{Name: "tenant b", Reason: "second tenant"})
	f.admin("create_project", b.org, auth.AdminPayload{ID: b.p1, Name: "b1", Reason: "tenant b project"})
	f.admin("create_project", b.org, auth.AdminPayload{ID: b.p2, Name: "b2", Reason: "tenant b project"})
	f.admin("membership", b.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "tenant b membership"})
	return b
}

func (a *retentionActor) at() model.UnixNano { return model.UnixNano(a.f.now.UnixNano()) }

// send commits one retention-class command of the actor's organization on the revision that is
// current when it is built (the view of this command is never the point of the tests below).
func (a *retentionActor) send(kind control.CommandKind, id model.ID, payload any) (control.Result, error) {
	a.f.t.Helper()
	scope, err := a.f.svc.Authorize(a.f.ctx, a.f.cred, a.org, nil, auth.OrgAdmin)
	if err != nil {
		a.f.t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		a.f.t.Fatal(err)
	}
	return a.f.store.Transact(a.f.ctx, scope, control.Command{CommandID: id, ExpectedRevision: a.f.revision(), Kind: string(kind), Payload: raw})
}

func (a *retentionActor) must(kind control.CommandKind, id model.ID, payload any) {
	a.f.t.Helper()
	if _, err := a.send(kind, id, payload); err != nil {
		a.f.t.Fatalf("%s: %v", kind, err)
	}
}

func (a *retentionActor) deletion(req control.DeleteScope) model.ID {
	a.f.t.Helper()
	id := model.NewID()
	req.At, req.Reason = a.at(), "retention authority test"
	req.PhysicalDeadline, req.BackupDeadline = req.At+model.UnixNano(1e9), req.At+model.UnixNano(2e9)
	a.must(control.KindDeleteScope, id, req)
	return id
}

func (a *retentionActor) rangeOf(project model.ID) control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, End: 100}
}

func (a *retentionActor) placeHold(project model.ID) model.ID {
	a.f.t.Helper()
	id := model.NewID()
	a.must(control.KindPolicyChange, id, control.PolicyChange{Kind: "hold_place", Hold: &control.PlaceHold{Projects: []model.ID{project}, Reason: "litigation", At: a.at()}})
	return id
}

func (a *retentionActor) releaseHold(hold model.ID) {
	a.f.t.Helper()
	a.must(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "hold_release", Release: &control.ReleaseHold{Hold: hold, Reason: "settled", At: a.at()}})
}

func (a *retentionActor) policy(project *model.ID) {
	a.f.t.Helper()
	a.must(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "retention_policy", Retention: &control.SetRetention{Project: project, Days: map[model.Kind]uint32{model.Metric: 30}, Reason: "tune", At: a.at(), Effective: a.at()}})
}

// gap is an evidence gap an administrator of the organization declares for project.
func (a *retentionActor) gap(project model.ID) model.EvidenceGap {
	return model.EvidenceGap{ID: model.NewID(), Org: a.org, Project: project, Group: model.NewID(), After: 3, Through: 9, Count: 6, Start: 100, End: 200, Signals: []model.Kind{model.ErrorKind}, Reason: "pipeline_outage", RecordedAt: a.at()}
}

// fenced is a begun deletion with every barrier recorded, ready to complete.
func (a *retentionActor) fenced() model.ID {
	a.f.t.Helper()
	id := a.deletion(a.rangeOf(a.p1))
	if _, err := a.f.store.RecordBarriers(a.f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		a.f.t.Fatal(err)
	}
	return id
}

// retentionAction is one retention-class commit of an organization. prepare commits whatever the
// commit under test needs (outside the measured window) and returns the commit itself: exactly one
// control transition.
type retentionAction struct {
	name       string
	retiresOrg bool // the organization cannot take another command afterwards
	prepare    func(a *retentionActor) (commit func())
}

func retentionActions() []retentionAction {
	return []retentionAction{
		{name: "deletion Begin (range)", prepare: func(a *retentionActor) func() {
			return func() { a.deletion(a.rangeOf(a.p1)) }
		}},
		{name: "project retirement", prepare: func(a *retentionActor) func() {
			return func() { a.deletion(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{a.p2}}) }
		}},
		{name: "organization retirement", retiresOrg: true, prepare: func(a *retentionActor) func() {
			return func() { a.deletion(control.DeleteScope{Mode: model.DeleteRetireOrg}) }
		}},
		{name: "hold placed", prepare: func(a *retentionActor) func() {
			return func() { a.placeHold(a.p2) }
		}},
		{name: "hold released", prepare: func(a *retentionActor) func() {
			hold := a.placeHold(a.p2)
			return func() { a.releaseHold(hold) }
		}},
		{name: "retention policy (organization default)", prepare: func(a *retentionActor) func() {
			return func() { a.policy(nil) }
		}},
		{name: "retention policy (project)", prepare: func(a *retentionActor) func() {
			return func() { a.policy(&a.p1) }
		}},
		{name: "deletion held by a hold", prepare: func(a *retentionActor) func() {
			a.placeHold(a.p1)
			return func() { a.deletion(a.rangeOf(a.p1)) }
		}},
		{name: "BeginFence resumes a held deletion", prepare: func(a *retentionActor) func() {
			hold := a.placeHold(a.p1)
			held := a.deletion(a.rangeOf(a.p1))
			a.releaseHold(hold)
			return func() { a.must(control.KindBeginFence, model.NewID(), control.BeginFence{Operation: held, At: a.at()}) }
		}},
		{name: "CompleteFence barrier step", prepare: func(a *retentionActor) func() {
			id := a.deletion(a.rangeOf(a.p1))
			return func() {
				a.must(control.KindCompleteFence, model.NewID(), control.FenceStep{Step: "barrier", Operation: id, Barriers: cursors(3)})
			}
		}},
		{name: "CompleteFence complete step", prepare: func(a *retentionActor) func() {
			id := a.fenced()
			return func() {
				a.must(control.KindCompleteFence, model.NewID(), control.FenceStep{Step: "complete", Operation: id, At: a.at()})
			}
		}},
		{name: "CompleteFence fail step", prepare: func(a *retentionActor) func() {
			id := a.deletion(a.rangeOf(a.p1))
			return func() {
				a.must(control.KindCompleteFence, model.NewID(), control.FenceStep{Step: "fail", Operation: id, At: a.at(), SafeReason: "operator_failed"})
			}
		}},
		{name: "worker RecordBarriers", prepare: func(a *retentionActor) func() {
			id := a.deletion(a.rangeOf(a.p1))
			return func() {
				if _, err := a.f.store.RecordBarriers(a.f.ctx, id, cursors(model.DeleteSlots)); err != nil {
					a.f.t.Fatal(err)
				}
			}
		}},
		{name: "worker CompleteDeletion", prepare: func(a *retentionActor) func() {
			id := a.fenced()
			return func() {
				if _, err := a.f.store.CompleteDeletion(a.f.ctx, id, a.at(), nil); err != nil {
					a.f.t.Fatal(err)
				}
			}
		}},
		{name: "worker FailDeletion", prepare: func(a *retentionActor) func() {
			id := a.deletion(a.rangeOf(a.p1))
			return func() {
				if _, err := a.f.store.FailDeletion(a.f.ctx, id, a.at(), "operator_failed"); err != nil {
					a.f.t.Fatal(err)
				}
			}
		}},
		{name: "worker RecordPhysicalCleanup", prepare: func(a *retentionActor) func() {
			id := a.fenced()
			if _, err := a.f.store.CompleteDeletion(a.f.ctx, id, a.at(), nil); err != nil {
				a.f.t.Fatal(err)
			}
			if err := a.f.store.ScrubErased(a.f.ctx); err != nil {
				a.f.t.Fatal(err)
			}
			return func() {
				if _, err := a.f.store.RecordPhysicalCleanup(a.f.ctx, a.org, []model.ID{id}, a.at()); err != nil {
					a.f.t.Fatal(err)
				}
			}
		}},
		{name: "worker AdvanceDeleteGeneration", prepare: func(a *retentionActor) func() {
			return func() {
				if _, err := a.f.store.AdvanceDeleteGeneration(a.f.ctx, a.org); err != nil {
					a.f.t.Fatal(err)
				}
			}
		}},
		{name: "evidence gap declared again by an administrator", prepare: func(a *retentionActor) func() {
			gap := a.gap(a.p1)
			a.must(control.KindRecordEvidenceGap, model.NewID(), gap) // the first declaration is installation-wide: it is outside the window
			return func() { a.must(control.KindRecordEvidenceGap, model.NewID(), gap) }
		}},
	}
}

// orgReach is what a Begin of the organization is judged against: the later of the
// installation's authority revision and the organization's own.
func (f *fenceFx) orgReach(org model.ID) model.Revision {
	_, authority := f.revisions()
	return max(authority, f.orgAuthority(org))
}

// An evidence gap is keyed by a hash and bound by the backup attestation: declaring a new one stays an
// installation-wide authority write, and so conflicts the views of every organization, while the same
// declaration again (the action above) changes nothing but the books.
func TestANewEvidenceGapKeepsTheInstallationWideBump(t *testing.T) {
	f := newFenceFxPatch(t)
	b := f.tenantB()
	view, _ := f.revisions()
	b.must(control.KindRecordEvidenceGap, model.NewID(), b.gap(b.p1))
	rev, authority := f.revisions()
	if authority != rev || rev != view+1 {
		t.Fatalf("a new evidence gap: revision %d (was %d) installation authority %d, want it moved to the revision", rev, view, authority)
	}
	if err := f.beginAt(view); code(err) != model.Conflict {
		t.Fatalf("Begin of another organization on a view older than a new evidence gap: %v, want Conflict", err)
	}
}

// The same through a three-voter group: the organization's revision is part of the replicated state, so
// another organization's Begin submitted through a follower leaves a view taken on a third voter valid,
// and the voters end with the same state.
func TestAnotherOrganizationsBeginDoesNotConflictAViewOnAnyVoter(t *testing.T) {
	v := newControlVoters(t)
	for _, s := range v.stores {
		s.SetStatePatchGate(func() bool { return true })
	}
	for id := uint64(2); id <= 3; id++ {
		f := v.fx[id]
		sess, err := f.svc.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
		if err != nil {
			t.Fatal(err)
		}
		if f.cred, err = f.svc.Authenticate(f.ctx, sess.Token); err != nil {
			t.Fatal(err)
		}
	}
	v.leaderIs(1)
	b := v.fx[1].tenantB()
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	view, authority := v.fx[3].revisions()
	follower := &retentionActor{f: v.fx[2].fenceFx, org: b.org, p1: b.p1, p2: b.p2}
	follower.deletion(follower.rangeOf(follower.p1))
	follower.placeHold(follower.p2)
	if err := v.fx[3].beginAt(view); err != nil {
		t.Fatalf("Begin through voter 3 on a view taken before another organization's Begin and hold, which committed through voter 2: %v", err)
	}
	rev := v.mustRevision(1)
	v.await(2, rev)
	v.await(3, rev)
	for id := uint64(1); id <= 3; id++ {
		if _, now := v.fx[id].revisions(); now != authority {
			t.Fatalf("voter %d: installation authority %d, want it unchanged at %d", id, now, authority)
		}
		if got := v.fx[id].orgAuthority(b.org); got != rev-1 {
			t.Fatalf("voter %d: the other organization's authority revision is %d, want %d (its hold; the Begin of the fixture's organization came after)", id, got, rev-1)
		}
	}
	if v.fx[1].canonicalState() != v.fx[2].canonicalState() || v.fx[1].canonicalState() != v.fx[3].canonicalState() {
		t.Fatal("the voters diverged")
	}
}

// Another organization's retention-class commands do not invalidate a Begin's view (F-10.05-2
// residual): each of them is one transition that leaves the installation-wide authority revision
// alone and moves its own organization's, so a Begin of the fixture's organization on a view taken
// before it commits.
func TestAnotherOrganizationsRetentionCommandsDoNotConflictABegin(t *testing.T) {
	for _, c := range retentionActions() {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFxPatch(t)
			b := f.tenantB()
			commit := c.prepare(b)
			view, authority := f.revisions()
			commit()
			rev, now := f.revisions()
			if rev != view+1 {
				t.Fatalf("the commit spent %d revisions (%d -> %d), want exactly one", rev-view, view, rev)
			}
			if now != authority {
				t.Fatalf("installation floor %d -> %d: another organization's command must leave it alone", authority, now)
			}
			// The previous release reads the scalar, which moves with every commit: it refuses this view
			// (a false conflict on the upgrade window, never a stale same-organization view accepted).
			if g := f.globalAuthority(); g != rev || f.previousReleaseAccepts(view) {
				t.Fatalf("AuthorityRevision %d (revision %d): every retention-class commit must move it too; previous release accepts the old view: %v", g, rev, f.previousReleaseAccepts(view))
			}
			if got := f.orgAuthority(b.org); got != rev {
				t.Fatalf("organization authority %d, want the commit's revision %d", got, rev)
			}
			if err := f.beginAt(view); err != nil {
				t.Fatalf("Begin of the fixture's organization on a view taken before another organization's command: %v", err)
			}
		})
	}
}

// While the command is a replacement (the group is not all patch) every retention-class commit, and every
// admin command, is an ordinary bump: the organization's own revision is not stamped (the verification
// that stamps it is free only for a patch).
func TestWithoutThePatchGateEveryRetentionCommitMovesTheInstallationRevision(t *testing.T) {
	for _, c := range retentionActions() {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t) // no gate: every command is a replacement
			b := f.tenantB()
			commit := c.prepare(b)
			view, _ := f.revisions()
			commit()
			rev, authority := f.revisions()
			if rev != view+1 || authority != rev {
				t.Fatalf("revision %d -> %d, installation authority %d: the commit must move it to the revision", view, rev, authority)
			}
			if err := f.beginAt(view); code(err) != model.Conflict {
				t.Fatalf("Begin on a view older than the commit: %v, want Conflict", err)
			}
		})
	}
	t.Run("admin command", func(t *testing.T) {
		f := newFenceFx(t)
		view, _ := f.revisions()
		f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "an admin command with no patch gate"})
		rev, authority := f.revisions()
		if authority != rev || rev != view+1 {
			t.Fatalf("revision %d -> %d, installation authority %d: an admin command must move it while the group is not all patch", view, rev, authority)
		}
		if f.orgAuthority(f.org) != 0 {
			t.Fatalf("the organization's own revision was stamped (%d) in a replacement", f.orgAuthority(f.org))
		}
	})
}

// No stale view of the same organization is ever accepted: after each retention-class commit of
// the organization a Begin on a view taken before it conflicts, one taken after it commits (also
// with intake in between), and the commit is what the Begin is judged against.
func TestOwnRetentionCommandsStillConflictAStaleView(t *testing.T) {
	for _, c := range retentionActions() {
		if c.retiresOrg {
			continue // the organization takes no Begin afterwards
		}
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFxPatch(t)
			commit := c.prepare(f.ownActor())
			view, _ := f.revisions()
			commit()
			rev, _ := f.revisions()
			if rev != view+1 {
				t.Fatalf("the commit spent %d revisions, want exactly one", rev-view)
			}
			if reach := f.orgReach(f.org); reach != rev {
				t.Fatalf("a Begin of the organization is judged against %d, want the commit's revision %d", reach, rev)
			}
			if err := f.beginAt(view); code(err) != model.Conflict {
				t.Fatalf("Begin on a view older than the organization's own command: %v, want Conflict", err)
			}
			if err := f.beginAt(rev - 1); code(err) != model.Conflict {
				t.Fatalf("Begin on the revision just before the command: %v, want Conflict", err)
			}
			f.mustIntake()
			f.mustIntake()
			if err := f.beginAt(rev); err != nil {
				t.Fatalf("Begin on the view taken after the command, with intake since: %v", err)
			}
		})
	}
}

// A retention-class commit that writes anything the organization does not own keeps the
// installation-wide bump. The handler of KindPolicyChange is replaced by one that writes a chosen
// set of rows; the fixture's store is not given the real ones.
func TestRetentionCommandThatWritesAcrossOrganizationsKeepsTheGlobalBump(t *testing.T) {
	cases := []struct {
		name  string
		write func(f *fenceFx, other model.ID, st *control.State)
		// global says the commit must move the installation-wide revision (true) or only the
		// organization's own (false).
		global bool
	}{
		{name: "nothing beyond the organization's own rows", write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
		}},
		{name: "another organization's hold", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			id := model.NewID()
			st.Holds[id.String()] = holdRow(id, other)
		}},
		{name: "another organization's deletion operation", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			op := model.NewID()
			st.Deletions[op.String()] = deletionRow(op, other)
		}},
		{name: "another organization's delete generation", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.DeleteGenerations[other.String()]++
		}},
		{name: "another organization's retirement marker", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.RetiredProjects[other.String()+":"+model.NewID().String()] = model.NewID()
		}},
		{name: "another organization's retention policy", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.RetentionPolicies[other.String()] = append(st.RetentionPolicies[other.String()], policyRow(other, 1))
		}},
		{name: "another organization's record", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			o := st.Orgs[other.String()]
			o.Epoch++
			st.Orgs[other.String()] = o
		}},
		{name: "another organization's source", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.Sources["other-source"] = sourceRow(other)
		}},
		{name: "another organization's rule output", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.RuleOutputs[model.NewID().String()] = json.RawMessage(`{"org":"` + other.String() + `"}`)
		}},
		{name: "another organization's delivery", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.DeliveryBooks["delivery:"+model.NewID().String()] = json.RawMessage(`{"org":"` + other.String() + `"}`)
		}},
		{name: "another organization's book row", global: true, write: func(f *fenceFx, other model.ID, st *control.State) {
			f.ownRows(st)
			st.IncidentBooks[other.String()+":"+model.NewID().String()+":"+model.NewID().String()] = json.RawMessage(`{}`)
		}},
		{name: "an evidence gap (keyed by a hash, backup-attested)", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			id := model.NewID()
			if st.EvidenceGaps == nil {
				st.EvidenceGaps = map[string]model.EvidenceGap{}
			}
			st.EvidenceGaps[id.String()] = model.EvidenceGap{ID: id, Org: f.org, Project: model.NewID(), Group: model.NewID(), After: 1, Through: 2, Count: 1, Reason: "x", RecordedAt: 1}
		}},
		{name: "a row keyed without an organization (source fence)", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			if st.SourceFences == nil {
				st.SourceFences = map[string]model.SourceFence{}
			}
			st.SourceFences[model.NewID().String()] = model.SourceFence{Operation: model.NewID(), Source: model.NewID(), Org: f.org}
		}},
		{name: "a quota", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			if st.Quotas == nil {
				st.Quotas = map[string]model.QuotaState{}
			}
			st.Quotas[model.NewID().String()] = model.QuotaState{}
		}},
		{name: "a user", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			u := st.Users[f.user.String()]
			u.Disabled = true
			st.Users[f.user.String()] = u
		}},
		{name: "the installation key", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			st.PolicySigningKey += "x"
		}},
		{name: "an existing audit row edited", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			st.Audits[0].Reason += " edited"
		}},
		{name: "an existing command row removed", global: true, write: func(f *fenceFx, _ model.ID, st *control.State) {
			f.ownRows(st)
			for k := range st.Commands {
				delete(st.Commands, k)
				break
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFxUnbound(t)
			b := f.tenantB()
			if err := f.store.RegisterHandler(control.KindPolicyChange, func(_ auth.Scope, st *control.State, _ control.Command) (control.Effect, error) {
				c.write(f, b.org, st)
				return control.Effect{Phase: "test"}, nil
			}); err != nil {
				t.Fatal(err)
			}
			view, authority := f.revisions()
			own := f.ownActor()
			own.must(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "hold_place"})
			rev, now := f.revisions()
			if rev != view+1 {
				t.Fatalf("revision %d -> %d", view, rev)
			}
			if c.global && now != rev {
				t.Fatalf("a write outside the organization's rows left the installation authority at %d (revision %d)", now, rev)
			}
			if !c.global && (now != authority || f.orgAuthority(f.org) != rev) {
				t.Fatalf("a write of the organization's own rows moved the installation floor %d -> %d (organization authority %d, revision %d)", authority, now, f.orgAuthority(f.org), rev)
			}
			// The scalar the previous release judges against moves in every case.
			if g := f.globalAuthority(); g != rev || f.previousReleaseAccepts(view) {
				t.Fatalf("AuthorityRevision %d (revision %d), previous release accepts the old view: %v", g, rev, f.previousReleaseAccepts(view))
			}
			// Whatever it wrote, the commit invalidates the views of the organization itself.
			if f.orgReach(f.org) != rev {
				t.Fatalf("the organization's own commit is not what its views are judged against")
			}
		})
	}
}

// ownRows is the write every case above makes: rows the organization owns in each retention table
// (the shape of a real Begin that retires and erases).
func (f *fenceFx) ownRows(st *control.State) {
	op := model.NewID()
	own := f.org
	if st.Deletions == nil {
		st.Deletions = map[string]model.DeletionOperation{}
	}
	if st.Holds == nil {
		st.Holds = map[string]model.LegalHold{}
	}
	if st.DeleteGenerations == nil {
		st.DeleteGenerations = map[string]uint64{}
	}
	if st.RetiredProjects == nil {
		st.RetiredProjects = map[string]model.ID{}
	}
	if st.RetentionPolicies == nil {
		st.RetentionPolicies = map[string][]model.RetentionPolicyVersion{}
	}
	if st.Sources == nil {
		st.Sources = map[string]model.SourceAuthority{}
	}
	if st.RuleOutputs == nil {
		st.RuleOutputs = map[string]json.RawMessage{}
	}
	if st.DeliveryBooks == nil {
		st.DeliveryBooks = map[string]json.RawMessage{}
	}
	if st.IncidentBooks == nil {
		st.IncidentBooks = map[string]json.RawMessage{}
	}
	st.Deletions[op.String()] = deletionRow(op, own)
	st.Holds[op.String()] = holdRow(op, own)
	st.DeleteGenerations[own.String()]++
	st.RetiredProjects[own.String()+":"+model.NewID().String()] = op
	st.RetentionPolicies[own.String()] = append(st.RetentionPolicies[own.String()], policyRow(own, len(st.RetentionPolicies[own.String()])+1))
	st.Sources[op.String()] = sourceRow(own)
	st.RuleOutputs[op.String()] = json.RawMessage(`{"org":"` + own.String() + `"}`)
	st.DeliveryBooks["delivery:"+op.String()] = json.RawMessage(`{"org":"` + own.String() + `"}`)
	st.DeliveryBooks["policy:"+own.String()+":"+model.NewID().String()+":"+op.String()+":s"] = json.RawMessage(`{}`)
	st.IncidentBooks[own.String()+":"+model.NewID().String()+":"+op.String()] = json.RawMessage(`{}`)
	o := st.Orgs[own.String()]
	o.Epoch++
	st.Orgs[own.String()] = o
}

// The rows below are fully populated: the state is encoded for the group, and an identifier that
// is zero does not encode.
func holdRow(id, org model.ID) model.LegalHold {
	return model.LegalHold{ID: id, Org: org, Reason: "x", PlacedBy: model.NewID(), PlacedAt: 1}
}

func deletionRow(op, org model.ID) model.DeletionOperation {
	return model.DeletionOperation{Predicate: model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireProject}, Principal: model.NewID(), Phase: model.DeletePhaseHeld}
}

func policyRow(org model.ID, version int) model.RetentionPolicyVersion {
	return model.RetentionPolicyVersion{Org: org, Version: model.Uint64(version), Actor: model.NewID(), Reason: "x"}
}

func sourceRow(org model.ID) model.SourceAuthority {
	return model.SourceAuthority{ID: model.NewID(), Org: org, Project: model.NewID(), CredentialID: model.NewID(), Retired: true}
}
