// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// intake commits one real admission reservation: the transition every intake batch makes.
func intake(f *fenceFx) error {
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		return err
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		return err
	}
	authority, err := f.svc.SourceAuthority(f.ctx, src, true)
	if err != nil {
		return err
	}
	v := model.FloatBits(0x3ff0000000000000)
	policy := authority.Policy
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: model.Resource{Service: policy.Resources.Services[0], Environment: policy.Resources.Environments[0], Build: policy.Resources.Builds[0], Instance: policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "authority", Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(f.org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return err
	}
	canonical, _ := model.CanonicalJSON(policy)
	n := model.NormalizedBatch{Batch: b, Org: f.org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(canonical).String(), AdmissionAt: model.UnixNano(f.now.UnixNano())}
	_, err = f.store.ReserveAdmission(f.ctx, scope, n)
	return err
}

func (f *fenceFx) mustIntake() {
	f.t.Helper()
	if err := intake(f); err != nil {
		f.t.Fatal("intake:", err)
	}
}

func (f *fenceFx) revisions() (revision, authority model.Revision) {
	f.t.Helper()
	if err := f.store.View(f.ctx, func(st control.State) error {
		revision, authority = st.Revision, st.AuthorityRevision
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return
}

// beginAt commits a deletion Begin whose caller view is `view`.
func (f *fenceFx) beginAt(view model.Revision) error {
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, Reason: "owner erase request", At: model.UnixNano(f.now.UnixNano())}
	req.PhysicalDeadline = req.At + model.UnixNano(24*time.Hour)
	req.BackupDeadline = req.At + model.UnixNano(30*24*time.Hour)
	raw, err := json.Marshal(req)
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: view, Kind: string(control.KindDeleteScope), Payload: raw})
	return err
}

// (b) A non-authority write moves the global revision and leaves AuthorityRevision; an admin
// command moves both.
func TestNonAuthorityWriteDoesNotBumpAuthorityRevision(t *testing.T) {
	f := newFenceFx(t)
	rev0, auth0 := f.revisions()
	if auth0 != rev0 {
		t.Fatalf("after the fixture's authority writes: revision %d authority %d", rev0, auth0)
	}
	for range 3 {
		f.mustIntake()
	}
	rev1, auth1 := f.revisions()
	if rev1 != rev0+3 || auth1 != auth0 {
		t.Fatalf("three admissions: revision %d -> %d, authority %d -> %d; the revision must move by 3 and the authority revision not at all", rev0, rev1, auth0, auth1)
	}
	f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "an admin command is authority"})
	rev2, auth2 := f.revisions()
	if rev2 != rev1+1 || auth2 != rev2 {
		t.Fatalf("admin command: revision %d authority %d (was %d)", rev2, auth2, rev1)
	}
}

// (a) A deletion whose caller view predates an authority-class change still conflicts: one
// subtest per class. Each also shows the same Begin commits on a view taken after the change
// (so the conflict is the staleness, nothing else), and that unrelated intake between that view
// and the Begin does not matter.
func TestDeleteWithViewOlderThanAuthorityChangeStillConflicts(t *testing.T) {
	now := func(f *fenceFx) model.UnixNano { return model.UnixNano(f.now.UnixNano()) }
	classes := []struct {
		name   string
		change func(f *fenceFx)
		intake bool // whether intake can still run after the change
	}{
		{"retention policy change", func(f *fenceFx) {
			p := control.PolicyChange{Kind: "retention_policy", Retention: &control.SetRetention{Project: &f.project, Days: map[model.Kind]uint32{model.Metric: 30}, Reason: "tune", At: now(f), Effective: now(f)}}
			if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), p)); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"hold placed", func(f *fenceFx) {
			hold := control.PlaceHold{Projects: []model.ID{f.otherProject}, Reason: "litigation", At: now(f)}
			if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "hold_place", Hold: &hold})); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"project retirement", func(f *fenceFx) {
			if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.otherProject}}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"earlier deletion", func(f *fenceFx) {
			if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"org membership admin command", func(f *fenceFx) {
			f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "membership"})
		}, true},
		{"org project admin command", func(f *fenceFx) {
			f.admin("create_project", f.org, auth.AdminPayload{ID: model.NewID(), Name: "p3", Reason: "new project"})
		}, true},
		{"source policy admin command", func(f *fenceFx) {
			cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true})
			f.admin("source_policy", f.org, auth.AdminPayload{ID: f.source, Config: cfg, Reason: "narrow the source"})
		}, false},
		{"source grant revocation", func(f *fenceFx) {
			if err := f.svc.RevokeSource(f.ctx, f.cred, f.source, "revoked"); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			view, _ := f.revisions()
			c.change(f)
			rev, authority := f.revisions()
			if authority != rev || rev <= view {
				t.Fatalf("%s: revision %d authority %d (view %d): the change must stamp AuthorityRevision", c.name, rev, authority, view)
			}
			if err := f.beginAt(view); code(err) != model.Conflict {
				t.Fatalf("%s: Begin on a view older than the change: %v, want Conflict", c.name, err)
			}
			if c.intake {
				fresh, _ := f.revisions()
				f.mustIntake()
				f.mustIntake()
				if err := f.beginAt(fresh); err != nil {
					t.Fatalf("%s: Begin on a view taken after the change, with intake since: %v", c.name, err)
				}
				return
			}
			fresh, _ := f.revisions()
			if err := f.beginAt(fresh); err != nil {
				t.Fatalf("%s: Begin on a view taken after the change: %v", c.name, err)
			}
		})
	}
}

// (a) The window is exactly [AuthorityRevision, Revision] for every retention kind: stale by
// intake only is accepted, below the authority revision and above the revision conflict.
func TestRetentionKindsAcceptTheAuthorityWindowOnly(t *testing.T) {
	f := newFenceFx(t)
	holdID := model.NewID()
	hold := control.PlaceHold{Projects: []model.ID{f.otherProject}, Reason: "litigation", At: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, holdID, control.PolicyChange{Kind: "hold_place", Hold: &hold})); err != nil {
		t.Fatal(err)
	}
	held, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.otherProject}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), control.PolicyChange{Kind: "hold_release", Release: &control.ReleaseHold{Hold: holdID, Reason: "settled", At: model.UnixNano(f.now.UnixNano())}})); err != nil {
		t.Fatal(err)
	}
	view, authority := f.revisions()
	for range 4 {
		f.mustIntake()
	}
	rev, authority2 := f.revisions()
	if authority2 != authority || rev != view+4 {
		t.Fatalf("fixture: revision %d authority %d, view %d", rev, authority2, view)
	}
	at := model.UnixNano(f.now.UnixNano())
	gap := model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: model.NewID(), After: 3, Through: 9, Count: 6, Start: 100, End: 200, Signals: []model.Kind{model.ErrorKind}, Reason: "pipeline_outage", RecordedAt: at}
	commands := []struct {
		kind    control.CommandKind
		payload any
	}{
		{control.KindBeginFence, control.BeginFence{Operation: held, At: at}},
		{control.KindPolicyChange, control.PolicyChange{Kind: "retention_policy", Retention: &control.SetRetention{Project: &f.project, Days: map[model.Kind]uint32{model.Metric: 14}, Reason: "tune", At: at, Effective: at}}},
		{control.KindRecordEvidenceGap, gap},
		{control.KindDeleteScope, control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, End: 100, Reason: "r", At: at, PhysicalDeadline: at + 1, BackupDeadline: at + 1}},
	}
	for _, c := range commands {
		raw, _ := json.Marshal(c.payload)
		send := func(expected model.Revision) error {
			_, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: expected, Kind: string(c.kind), Payload: raw})
			return err
		}
		if err := send(rev + 1); code(err) != model.Conflict {
			t.Fatalf("%s: a revision above the current one: %v, want Conflict", c.kind, err)
		}
		if err := send(authority - 1); code(err) != model.Conflict {
			t.Fatalf("%s: a view older than the last authority change: %v, want Conflict", c.kind, err)
		}
		// The view taken after the authority change, before four admissions: accepted.
		if err := send(view); err != nil {
			t.Fatalf("%s: a view only intake has made stale: %v", c.kind, err)
		}
		// Each accepted command is itself an authority change: the old view is now stale.
		if err := send(view); code(err) != model.Conflict {
			t.Fatalf("%s: a view older than the command that just committed: %v, want Conflict", c.kind, err)
		}
		view, _ = f.revisions()
		authority = view
		f.mustIntake()
		rev, _ = f.revisions()
	}
}

// (c) Every other kind keeps the strict rule: a view even one admission old conflicts, and the
// exact current revision commits. Kind classification is checked beside it: the book kinds
// leave AuthorityRevision, everything else moves it.
func TestEveryOtherKindStaysStrictAndClassified(t *testing.T) {
	f := newFenceFx(t)
	noop := func(auth.Scope, *control.State, control.Command) (control.Effect, error) {
		return control.Effect{Phase: "noop"}, nil
	}
	kinds := []struct {
		kind  control.CommandKind
		bumps bool
	}{
		{control.KindCreateOrg, true}, {control.KindGrant, true}, {control.KindReserveAdmission, true}, {control.KindFinalizeAdmission, true},
		{control.KindApplyIssueEvidence, false}, {control.KindApplyCondition, false}, {control.KindApplyRuleEvaluation, false}, {control.KindIncidentAction, false},
		{control.KindClaimDelivery, false}, {control.KindCompleteDelivery, false}, {control.KindRegisterRelease, false}, {control.KindUpdateJob, false},
	}
	for _, k := range kinds {
		if err := f.store.RegisterHandler(k.kind, noop); err != nil {
			t.Fatal(k.kind, err)
		}
	}
	send := func(kind control.CommandKind, expected model.Revision) (control.Result, error) {
		return f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: expected, Kind: string(kind), Payload: json.RawMessage(`{}`)})
	}
	for _, k := range kinds {
		f.mustIntake()
		rev, authority := f.revisions()
		if authority >= rev {
			t.Fatalf("%s: fixture: revision %d authority %d", k.kind, rev, authority)
		}
		if _, err := send(k.kind, rev-1); code(err) != model.Conflict {
			t.Fatalf("%s: a view one admission old: %v, want Conflict (strict)", k.kind, err)
		}
		if _, err := send(k.kind, rev+1); code(err) != model.Conflict {
			t.Fatalf("%s: a revision above the current: %v, want Conflict", k.kind, err)
		}
		if _, err := send(k.kind, rev); err != nil {
			t.Fatalf("%s: the current revision: %v", k.kind, err)
		}
		rev2, authority2 := f.revisions()
		if rev2 != rev+1 {
			t.Fatalf("%s: revision %d -> %d", k.kind, rev, rev2)
		}
		if k.bumps && authority2 != rev2 || !k.bumps && authority2 != authority {
			t.Fatalf("%s: bumps=%v but authority %d -> %d at revision %d", k.kind, k.bumps, authority, authority2, rev2)
		}
	}
}

// (f) The field is part of the replicated state: it survives a restart, a seed export, and an
// install of the leader's snapshot, and every voter ends with the same state.
func TestAuthorityRevisionSurvivesRestartAndSeed(t *testing.T) {
	f := newFenceFx(t)
	f.mustIntake()
	f.mustIntake()
	rev, authority := f.revisions()
	if authority == 0 || authority >= rev {
		t.Fatalf("fixture: revision %d authority %d", rev, authority)
	}

	seed, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := control.OpenSeed(t.TempDir(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	if err = seeded.View(f.ctx, func(st control.State) error {
		if st.Revision != rev || st.AuthorityRevision != authority {
			t.Fatalf("seed: revision %d authority %d, want %d and %d", st.Revision, st.AuthorityRevision, rev, authority)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = auth.NewService(auth.AuthDependencies{Control: reopened, Now: func() time.Time { return f.now }}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if err = reopened.View(f.ctx, func(st control.State) error {
		if st.Revision != rev || st.AuthorityRevision != authority {
			t.Fatalf("restart: revision %d authority %d, want %d and %d", st.Revision, st.AuthorityRevision, rev, authority)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// (f) Three voters, one cut off while the leader commits an authority change and then
// non-authority writes: the snapshot install and the log replay both end in the same state, the
// same canonical bytes and the same AuthorityRevision.
func TestVotersAgreeOnAuthorityRevisionAfterSnapshotInstall(t *testing.T) {
	v := newControlVoters(t)
	leader := v.fx[1]
	leader.seedAll(leader.newSeed(leader.otherProject, "CANARYAUTHORITY0d2b86a7c41e"), 50)
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	v.mesh.cut(3, true)
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.otherProject}})
	for range 3 {
		leader.mustIntake()
	}
	v.await(2, v.mustRevision(1))
	leader.pass() // the leader's journal no longer holds what voter 3 needs: it is sent a snapshot
	v.mesh.cut(3, false)
	rev, authority := leader.revisions()
	if authority == 0 || authority >= rev {
		t.Fatalf("fixture: revision %d authority %d", rev, authority)
	}
	v.await(2, rev)
	v.await(3, rev)
	for id := uint64(2); id <= 3; id++ {
		r, a := v.fx[id].revisions()
		if r != rev || a != authority {
			t.Fatalf("voter %d: revision %d authority %d, leader has %d and %d", id, r, a, rev, authority)
		}
	}
	if v.fx[1].canonicalState() != v.fx[2].canonicalState() || v.fx[1].canonicalState() != v.fx[3].canonicalState() {
		t.Fatal("the voters diverged")
	}
}

// (g) A pre-change control.db (no field) is strict until it is stamped, and the first conflicting
// retention command stamps it, so the caller's retry commits even under intake.
func TestLegacyControlStateIsStrictThenHeals(t *testing.T) {
	f := newFenceFx(t)
	f.mustIntake()
	rev, err := f.store.MakeLegacyAuthorityForTest()
	if err != nil {
		t.Fatal(err)
	}
	if _, authority := f.revisions(); authority != 0 {
		t.Fatalf("fixture is not legacy: authority %d", authority)
	}
	// A view older than the current revision conflicts on a legacy state ...
	if err = f.beginAt(rev - 1); code(err) != model.Conflict {
		t.Fatalf("legacy state accepted a stale view: %v", err)
	}
	// ... and that conflict stamped the field, so the next view-then-Begin survives intake.
	now, authority := f.revisions()
	if authority != now || now != rev+1 {
		t.Fatalf("after the first conflict: revision %d authority %d, legacy revision %d", now, authority, rev)
	}
	view := now
	f.mustIntake()
	f.mustIntake()
	if err = f.beginAt(view); err != nil {
		t.Fatalf("Begin on a view stale by intake after the heal: %v", err)
	}
	// And the exact current revision always worked on a legacy state.
	g := newFenceFx(t)
	g.mustIntake()
	rev, err = g.store.MakeLegacyAuthorityForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err = g.beginAt(rev); err != nil {
		t.Fatalf("legacy state refused the current revision: %v", err)
	}
}

// (retry) Retrying a committed CommandID returns the stored outcome before any revision check,
// even when the retry's view predates an authority change.
func TestRetryOfCommittedDeleteReturnsStoredOutcomeBeforeRevisionCheck(t *testing.T) {
	f := newFenceFx(t)
	view, _ := f.revisions()
	id := model.NewID()
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, End: 100, Reason: "r", At: model.UnixNano(f.now.UnixNano()), PhysicalDeadline: model.UnixNano(f.now.UnixNano()) + 1, BackupDeadline: model.UnixNano(f.now.UnixNano()) + 1}
	raw, _ := json.Marshal(req)
	send := func(expected model.Revision) (control.Result, error) {
		return f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: id, ExpectedRevision: expected, Kind: string(control.KindDeleteScope), Payload: raw})
	}
	first, err := send(view)
	if err != nil {
		t.Fatal(err)
	}
	f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "authority change after the delete"})
	again, err := send(view)
	if err != nil || again.Revision != first.Revision || len(again.AffectedIDs) != 1 || again.AffectedIDs[0] != first.AffectedIDs[0] {
		t.Fatalf("retry of a committed command: %+v %v, want %+v", again, err, first)
	}
}
