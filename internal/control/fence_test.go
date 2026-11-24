// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fenceFx struct {
	t                *testing.T
	dir              string
	ctx              context.Context
	store            *control.Store
	svc              *auth.Service
	cred             auth.Credential
	user             model.ID
	org, project     model.ID
	otherProject     model.ID
	source           model.ID
	sourceCredential string
	now              time.Time
	// retry, when set, runs the leader-bound writes of a fixture (write). The fixtures of the
	// three-voter tests install one that waits out a move of the lead (see controlVoters.retryWrite);
	// a single store never needs it.
	retry func(attempt func() error) error
}

// write runs one leader-bound write of the fixture and answers its error. A single store runs it
// once. With retry installed, an attempt that found no leader for the moment (the host starved the
// voters long enough for the lead to move between two steps of the fixture) is run again once the
// lead is back. attempt must build everything it sends from what is current when it runs (lease,
// expected revision, scope) and keep the identity of the command it sends from one attempt to the
// next: a first attempt that did commit is then answered from the stored result of that command, as
// for any retried command, and never applied twice.
func (f *fenceFx) write(attempt func() error) error {
	f.t.Helper()
	if f.retry == nil {
		return attempt()
	}
	return f.retry(attempt)
}

// newFenceFx is the fixture of a group that has not declared the state patch protocol (every command is a
// replacement), unless SOUNDPOST_TEST_FENCE_PATCH is set: the suites of the writers of the job and issue
// books run both ways (the sparse commit of those writers needs the patch gate and the ledger layout).
func newFenceFx(t *testing.T) *fenceFx {
	return newFenceFxWith(t, true, os.Getenv("SOUNDPOST_TEST_FENCE_PATCH") != "")
}

// newFenceFxPatch is newFenceFx proposing every command as a state patch (the gate of a group whose
// members all declared protocol 5 is open): the mode in which the per-organization authority revision
// applies (authority_org.go).
func newFenceFxPatch(t *testing.T) *fenceFx { return newFenceFxWith(t, true, true) }

// newFenceFxUnbound is newFenceFxPatch without the retention handlers: a test that registers its own
// handler for a retention kind needs the kind free (RegisterHandler refuses a second one).
func newFenceFxUnbound(t *testing.T) *fenceFx { return newFenceFxWith(t, false, true) }

func newFenceFxWith(t *testing.T, bindRetention, patch bool) *fenceFx {
	t.Helper()
	f := &fenceFx{t: t, ctx: context.Background(), now: time.Unix(1_800_000_000, 0)}
	dir := t.TempDir()
	f.dir = dir
	var err error
	if f.store, err = control.Open(dir); err != nil {
		t.Fatal(err)
	}
	if patch {
		f.store.SetStatePatchGate(func() bool { return true })
	}
	t.Cleanup(func() { f.store.Close() })
	if f.svc, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return f.now }}); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnableSingle(f.ctx, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if bindRetention {
		if err = f.store.BindRetention(); err != nil {
			t.Fatal(err)
		}
	}
	boot, _ := f.store.BootstrapToken()
	s, err := f.svc.Bootstrap(f.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.user = s.User
	if f.cred, err = f.svc.Authenticate(f.ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	f.org, f.project, f.otherProject, f.source = model.NewID(), model.NewID(), model.NewID(), model.NewID()
	f.admin("create_org", f.org, auth.AdminPayload{Name: "fence", Reason: "fixture"})
	f.admin("create_project", f.org, auth.AdminPayload{ID: f.project, Name: "p1", Reason: "fixture"})
	f.admin("create_project", f.org, auth.AdminPayload{ID: f.otherProject, Name: "p2", Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "fixture"})
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 30, MaxSeries: 1000}
	issued, err := f.svc.OnboardSource(f.ctx, f.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(f.now.Add(time.Hour).UnixNano()), Policy: policy, Reason: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	f.sourceCredential = issued.Credential
	return f
}
func (f *fenceFx) revision() model.Revision {
	f.t.Helper()
	r, err := f.revisionNow()
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// revisionNow is revision for a step that handles the error itself (write).
func (f *fenceFx) revisionNow() (model.Revision, error) {
	var r model.Revision
	err := f.store.View(f.ctx, func(st control.State) error { r = st.Revision; return nil })
	return r, err
}
func (f *fenceFx) admin(kind string, org model.ID, p auth.AdminPayload) {
	f.t.Helper()
	raw, _ := json.Marshal(p)
	if _, err := f.svc.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}
func (f *fenceFx) adminScope() auth.Scope {
	f.t.Helper()
	s, err := f.scopeNow()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// scopeNow is adminScope for a step that handles the error itself (write).
func (f *fenceFx) scopeNow() (auth.Scope, error) {
	return f.svc.Authorize(f.ctx, f.cred, f.org, nil, auth.OrgAdmin)
}
func (f *fenceFx) readScope(project model.ID) (auth.Scope, error) {
	return f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{project}, auth.Read)
}
func (f *fenceFx) cmd(kind control.CommandKind, id model.ID, payload any) control.Command {
	f.t.Helper()
	c, err := f.cmdNow(kind, id, payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// cmdNow is cmd for a step that handles the error itself (write): the command expects the
// revision that is current when it is built.
func (f *fenceFx) cmdNow(kind control.CommandKind, id model.ID, payload any) (control.Command, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return control.Command{}, err
	}
	rev, err := f.revisionNow()
	if err != nil {
		return control.Command{}, err
	}
	return control.Command{CommandID: id, ExpectedRevision: rev, Kind: string(kind), Payload: raw}, nil
}

// transactNow is the whole of a command of the fixture's administrator (scope, command, Transact)
// for a step that handles the error itself (write).
func (f *fenceFx) transactNow(kind control.CommandKind, id model.ID, payload any) (control.Result, error) {
	scope, err := f.scopeNow()
	if err != nil {
		return control.Result{}, err
	}
	cmd, err := f.cmdNow(kind, id, payload)
	if err != nil {
		return control.Result{}, err
	}
	return f.store.Transact(f.ctx, scope, cmd)
}
func (f *fenceFx) del(req control.DeleteScope) (model.ID, control.Result, error) {
	id := model.NewID()
	res, err := f.delAs(id, req)
	return id, res, err
}

// delAs is del under a command identity the caller keeps (a retried write sends one command).
func (f *fenceFx) delAs(id model.ID, req control.DeleteScope) (control.Result, error) {
	if req.At == 0 {
		req.At = model.UnixNano(f.now.UnixNano())
	}
	if req.PhysicalDeadline == 0 {
		req.PhysicalDeadline = req.At + model.UnixNano(24*time.Hour)
		req.BackupDeadline = req.At + model.UnixNano(30*24*time.Hour)
	}
	if req.Reason == "" {
		req.Reason = "fixture deletion"
	}
	return f.transactNow(control.KindDeleteScope, id, req)
}
func code(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}
func cursors(n int) []model.Cursor {
	out := make([]model.Cursor, n)
	for i := range out {
		out[i] = model.Cursor{Group: model.NewID(), Index: model.Uint64(i + 1)}
	}
	return out
}
func (f *fenceFx) generation() uint64 {
	g, err := f.store.DeleteGeneration(f.ctx, f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func TestDeleteRetireProjectDeniesReadsAndAdvancesGenerationAtBegin(t *testing.T) {
	f := newFenceFx(t)
	scope, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.Revalidate(f.ctx, scope); err != nil {
		t.Fatal(err)
	}
	before := f.generation()
	id, res, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Phase != model.DeletePhaseFencing || len(res.AffectedIDs) != 1 || res.AffectedIDs[0] != id {
		t.Fatalf("begin result %+v", res)
	}
	if f.generation() <= before {
		t.Fatal("delete generation did not advance at Begin")
	}
	if err = f.svc.Revalidate(f.ctx, scope); code(err) != model.NotFound {
		t.Fatalf("a scope minted before Begin still reads: %v", err)
	}
	if _, err = f.readScope(f.project); code(err) != model.NotFound {
		t.Fatalf("retired project is still authorizable: %v", err)
	}
	if _, err = f.readScope(f.otherProject); code(err) != model.NotFound { // never granted: same answer as retired
		t.Fatalf("unexpected: %v", err)
	}
	var retired bool
	f.store.View(f.ctx, func(st control.State) error { retired = st.Sources[f.source.String()].Retired; return nil })
	if !retired {
		t.Fatal("source of the retired project is not retired")
	}
	active, err := f.store.ActiveDeletions(f.ctx, f.org, []model.ID{f.project})
	if err != nil || len(active) != 1 || active[0].Operation != id || active[0].Generation == 0 {
		t.Fatalf("active deletions %+v %v", active, err)
	}
	if other, _ := f.store.ActiveDeletions(f.ctx, f.org, []model.ID{f.otherProject}); len(other) != 0 {
		t.Fatal("retire_project leaked into an unrelated project")
	}
}

func TestDeleteScopeRetryAndExpectedRevision(t *testing.T) {
	f := newFenceFx(t)
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 10, End: 20, Reason: "r", At: model.UnixNano(f.now.UnixNano()), PhysicalDeadline: model.UnixNano(f.now.UnixNano()) + 5, BackupDeadline: model.UnixNano(f.now.UnixNano()) + 9}
	id := model.NewID()
	command := f.cmd(control.KindDeleteScope, id, req)
	first, err := f.store.Transact(f.ctx, f.adminScope(), command)
	if err != nil {
		t.Fatal(err)
	}
	gen := f.generation()
	retry, err := f.store.Transact(f.ctx, f.adminScope(), command)
	if err != nil || retry.Revision != first.Revision || f.generation() != gen {
		t.Fatalf("retry changed state: %v", err)
	}
	stale := f.cmd(control.KindDeleteScope, model.NewID(), req)
	stale.ExpectedRevision = 1
	if _, err = f.store.Transact(f.ctx, f.adminScope(), stale); code(err) != model.Conflict {
		t.Fatalf("stale expected revision accepted: %v", err)
	}
	// A historical range keeps every scope valid: other data stays readable.
	scope, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.Revalidate(f.ctx, scope); err != nil {
		t.Fatalf("range deletion killed unrelated reads: %v", err)
	}
}

func TestDeleteScopeRejectsMalformedAndForeignRequests(t *testing.T) {
	f := newFenceFx(t)
	foreign := model.NewID()
	cases := map[string]control.DeleteScope{
		"range without signals": {Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Start: 1, End: 2},
		"empty range":           {Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 5, End: 5},
		"entity two projects":   {Mode: model.DeleteEntity, Projects: []model.ID{f.project, f.otherProject}, Entities: []model.ID{model.NewID()}},
		"retire org projects":   {Mode: model.DeleteRetireOrg, Projects: []model.ID{f.project}},
		"unknown mode":          {Mode: "everything"},
		"no reason":             {Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}, Reason: "\t"},
	}
	for name, req := range cases {
		req.At = model.UnixNano(f.now.UnixNano())
		req.PhysicalDeadline, req.BackupDeadline = req.At+1, req.At+2
		if req.Reason == "" {
			req.Reason = "r"
		} else {
			req.Reason = ""
		}
		before := f.revision()
		if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindDeleteScope, model.NewID(), req)); code(err) != model.Invalid {
			t.Fatalf("%s: got %v", name, err)
		}
		if f.revision() != before {
			t.Fatalf("%s: rejected request changed state", name)
		}
	}
	_, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{foreign}})
	if code(err) != model.NotFound {
		t.Fatalf("foreign project must look absent: %v", err)
	}
}

func TestDeleteHoldBlocksBeginAndReleaseResumes(t *testing.T) {
	f := newFenceFx(t)
	holdID := model.NewID()
	hold := control.PlaceHold{Projects: []model.ID{f.project}, Reason: "litigation", At: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, holdID, control.PolicyChange{Kind: "hold_place", Hold: &hold})); err != nil {
		t.Fatal(err)
	}
	gen := f.generation()
	id, res, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if err != nil || res.Phase != model.DeletePhaseHeld {
		t.Fatalf("hold did not block Begin: %+v %v", res, err)
	}
	if f.generation() != gen {
		t.Fatal("a held request advanced the generation")
	}
	scope, err := f.readScope(f.project)
	if err != nil || f.svc.Revalidate(f.ctx, scope) != nil {
		t.Fatal("a held request denied reads")
	}
	op, ok, _ := f.store.DeletionOperation(f.ctx, id)
	if !ok || op.Phase != model.DeletePhaseHeld || len(op.Holds) != 1 || op.Holds[0] != holdID {
		t.Fatalf("held operation %+v", op)
	}
	// A completion on a held operation is not possible.
	if _, err = f.store.CompleteDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), nil); err == nil {
		t.Fatal("held operation completed")
	}
	release := control.PolicyChange{Kind: "hold_release", Release: &control.ReleaseHold{Hold: holdID, Reason: "settled", At: model.UnixNano(f.now.UnixNano())}}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), release)); err != nil {
		t.Fatal(err)
	}
	if op, _, _ = f.store.DeletionOperation(f.ctx, id); op.Phase != model.DeletePhaseHeld {
		t.Fatal("release must not silently start a deletion")
	}
	res, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindBeginFence, model.NewID(), control.BeginFence{Operation: id, At: model.UnixNano(f.now.UnixNano())}))
	if err != nil || res.Phase != model.DeletePhaseFencing || f.generation() <= gen {
		t.Fatalf("resume after release: %+v %v", res, err)
	}
}

func TestDeleteBarriersCompleteOnlyWithEverySlotAndAuthority(t *testing.T) {
	f := newFenceFx(t)
	id, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, AuthorityRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	all := cursors(64)
	at := model.UnixNano(f.now.UnixNano())
	if _, err = f.store.RecordBarriers(f.ctx, id, all[:63]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); code(err) != model.Unavailable {
		t.Fatalf("63 of 64 slots completed: %v", err)
	}
	// Recording is idempotent; a conflicting cursor for a fenced group is corruption, not an update.
	if _, err = f.store.RecordBarriers(f.ctx, id, all[:2]); err != nil {
		t.Fatal(err)
	}
	moved := all[0]
	moved.Index++
	if _, err = f.store.RecordBarriers(f.ctx, id, []model.Cursor{moved}); code(err) != model.Conflict {
		t.Fatalf("moved barrier accepted: %v", err)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, all[63:]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); code(err) != model.Unavailable {
		t.Fatalf("completed without the required authority checkpoint: %v", err)
	}
	op, _, _ := f.store.DeletionOperation(f.ctx, id)
	if op.Phase != model.DeletePhaseFencing {
		t.Fatalf("phase %s after failed completion", op.Phase)
	}
	gen := f.generation()
	stale := &model.DeletionAuthority{Generation: 0, At: at}
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, stale); code(err) != model.Unavailable {
		t.Fatalf("authority older than the operation generation accepted: %v", err)
	}
	ok := &model.DeletionAuthority{Generation: model.Uint64(op.Predicate.Generation), Head: model.HashCanonical([]byte("head")), At: at}
	op, err = f.store.CompleteDeletion(f.ctx, id, at, ok)
	if err != nil || op.Phase != model.DeletePhaseComplete || op.CompletedAt != at {
		t.Fatalf("complete: %+v %v", op, err)
	}
	if f.generation() <= gen {
		t.Fatal("generation did not advance at completion")
	}
	again, err := f.store.CompleteDeletion(f.ctx, id, at+5, ok)
	if err != nil || again.CompletedAt != at {
		t.Fatal("completion is not idempotent")
	}
}

func TestDeleteBarrierReplicationValidation(t *testing.T) {
	f := newFenceFx(t)
	id, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if err != nil {
		t.Fatal(err)
	}
	op, _, _ := f.store.DeletionOperation(f.ctx, id)
	good := model.DeleteBarrier{Predicate: op.Predicate, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
	if err = f.store.ValidateReplicatedDeleteBarrier(f.ctx, good); err != nil {
		t.Fatal(err)
	}
	forged := good
	forged.Predicate.Projects = []model.ID{f.otherProject}
	if err = f.store.ValidateReplicatedDeleteBarrier(f.ctx, forged); code(err) != model.Stale {
		t.Fatalf("forged predicate ordered: %v", err)
	}
	unknown := good
	unknown.Predicate.Operation = model.NewID()
	if err = f.store.ValidateReplicatedDeleteBarrier(f.ctx, unknown); code(err) != model.Stale {
		t.Fatalf("barrier for an operation control never committed: %v", err)
	}
}

func TestDeleteGenerationAdvancesForErasureAndIsMonotonic(t *testing.T) {
	f := newFenceFx(t)
	g0 := f.generation()
	g1, err := f.store.AdvanceDeleteGeneration(f.ctx, f.org)
	if err != nil || g1 <= g0 {
		t.Fatalf("advance %d -> %d %v", g0, g1, err)
	}
	if f.generation() != g1 {
		t.Fatal("advance not durable in state")
	}
	if _, err = f.store.DeleteGeneration(f.ctx, model.NewID()); code(err) != model.NotFound {
		t.Fatalf("unknown org: %v", err)
	}
}

func TestDeleteEvidenceGapIsIdempotentAndMarksIncomplete(t *testing.T) {
	f := newFenceFx(t)
	gap := model.EvidenceGap{Org: f.org, Project: f.project, Group: model.NewID(), After: 3, Through: 9, Count: 6, Start: 100, End: 200, Signals: []model.Kind{model.ErrorKind}, Reason: "pipeline_outage", RecordedAt: model.UnixNano(f.now.UnixNano())}
	first, err := f.store.RecordEvidenceGap(f.ctx, gap)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.store.RecordEvidenceGap(f.ctx, gap)
	if err != nil || second.ID != first.ID {
		t.Fatalf("gap not idempotent: %v", err)
	}
	gaps, _ := f.store.EvidenceGaps(f.ctx, f.org, f.project)
	if len(gaps) != 1 {
		t.Fatalf("%d gaps", len(gaps))
	}
	bad := gap
	bad.Through = bad.After
	if _, err = f.store.RecordEvidenceGap(f.ctx, bad); code(err) != model.Invalid {
		t.Fatalf("empty interval accepted: %v", err)
	}
	foreign := gap
	foreign.Project = model.NewID()
	if _, err = f.store.RecordEvidenceGap(f.ctx, foreign); code(err) != model.NotFound {
		t.Fatalf("foreign project gap: %v", err)
	}
}

func TestDeleteRetentionPolicyVersionsAreAuditedAndNeverRewritten(t *testing.T) {
	f := newFenceFx(t)
	put := func(days uint32) error {
		p := control.PolicyChange{Kind: "retention_policy", Retention: &control.SetRetention{Project: &f.project, Days: map[model.Kind]uint32{model.Metric: days}, Reason: "tune", At: model.UnixNano(f.now.UnixNano()), Effective: model.UnixNano(f.now.UnixNano())}}
		_, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, model.NewID(), p))
		return err
	}
	if err := put(30); err != nil {
		t.Fatal(err)
	}
	if err := put(7); err != nil {
		t.Fatal(err)
	}
	if err := put(0); code(err) != model.Invalid {
		t.Fatalf("zero days accepted: %v", err)
	}
	var versions []model.RetentionPolicyVersion
	var audits int
	f.store.View(f.ctx, func(st control.State) error {
		versions = st.RetentionPolicies[f.org.String()+":"+f.project.String()]
		for _, a := range st.Audits {
			if a.Action == "retention.policy" {
				audits++
			}
		}
		return nil
	})
	if len(versions) != 2 || versions[0].Version != 1 || versions[1].Version != 2 || versions[0].Days[model.Metric] != 30 || versions[1].Days[model.Metric] != 7 || audits != 2 {
		t.Fatalf("versions %+v audits %d", versions, audits)
	}
}

func TestDeleteEffectSuppressionFollowsActiveDeletions(t *testing.T) {
	f := newFenceFx(t)
	_, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.ErrorKind}, Start: 100, End: 200})
	if err != nil {
		t.Fatal(err)
	}
	entity := model.NewID()
	f.store.View(f.ctx, func(st control.State) error {
		if !control.EffectSuppressed(st, f.org, f.project, model.ErrorKind, 150, nil) {
			t.Fatal("effect of a deleted origin not suppressed")
		}
		if control.EffectSuppressed(st, f.org, f.project, model.ErrorKind, 200, nil) || control.EffectSuppressed(st, f.org, f.project, model.Metric, 150, nil) || control.EffectSuppressed(st, f.org, f.otherProject, model.ErrorKind, 150, nil) {
			t.Fatal("effect outside the predicate suppressed")
		}
		_ = entity
		return nil
	})
}

func TestDeleteImportRestoresTombstonesAndNeverLowersGeneration(t *testing.T) {
	f := newFenceFx(t)
	scope, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	g0 := f.generation()
	p := model.DeletePredicate{Operation: model.NewID(), Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}, Generation: model.Uint64(g0 + 40)}
	at := model.UnixNano(f.now.UnixNano())
	if err = f.store.ImportDeletions(f.ctx, []model.DeletePredicate{p}, at); err != nil {
		t.Fatal(err)
	}
	if g := f.generation(); g <= g0+40 {
		t.Fatalf("generation %d must pass the authority's %d", g, g0+40)
	}
	op, ok, _ := f.store.DeletionOperation(f.ctx, p.Operation)
	if !ok || op.Phase != model.DeletePhaseComplete {
		t.Fatalf("imported %+v", op)
	}
	if _, err = f.readScope(f.project); code(err) != model.NotFound {
		t.Fatalf("restored control still authorizes the retired project: %v", err)
	}
	if f.svc.Revalidate(f.ctx, scope) == nil {
		t.Fatal("pre-restore scope survived the import")
	}
	before := f.generation()
	if err = f.store.ImportDeletions(f.ctx, []model.DeletePredicate{p}, at); err != nil || f.generation() != before {
		t.Fatalf("import not idempotent: %v", err)
	}
	bad := p
	bad.Operation = model.NewID()
	bad.Mode = "nope"
	if err = f.store.ImportDeletions(f.ctx, []model.DeletePredicate{bad}, at); err == nil {
		t.Fatal("invalid tombstone imported")
	}
}

// The deletion authority is installation-wide and monotonic, so the ledger a
// restore applies can name an organization the restored control state never
// contained (it was created, and retired, after the backup's cut). Importing such
// a tombstone must neither fail (the restore could then never activate) nor invent
// the organization: it is recorded as a deny predicate keyed by IDs that are
// meaningless until the organization appears, and retirements stay permanent.
func TestDeleteImportOfAnUnknownOrganizationIsADenyPredicateNotAnOrganization(t *testing.T) {
	at := model.UnixNano(time.Unix(1_800_000_000, 0).UnixNano())
	type scenario struct {
		name      string
		predicate func(org, project model.ID) model.DeletePredicate
	}
	for _, sc := range []scenario{
		{"range", func(org, project model.ID) model.DeletePredicate {
			return model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 100, End: 200, Generation: 7}
		}},
		{"retire project", func(org, project model.ID) model.DeletePredicate {
			return model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}, Generation: 3}
		}},
		{"retire org", func(org, project model.ID) model.DeletePredicate {
			return model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteRetireOrg, Generation: 4}
		}},
	} {
		t.Run(sc.name, func(t *testing.T) {
			f := newFenceFx(t)
			org, project := model.NewID(), model.NewID()
			p := sc.predicate(org, project)
			if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{p}, at); err != nil {
				t.Fatalf("a tombstone for an organization the restored state does not know was refused: %v", err)
			}
			if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{p}, at); err != nil {
				t.Fatalf("import is not idempotent for an unknown organization: %v", err)
			}
			f.store.View(f.ctx, func(st control.State) error {
				if _, invented := st.Orgs[org.String()]; invented {
					t.Fatal("importing a tombstone invented the organization")
				}
				if _, invented := st.DeleteGenerations[org.String()]; invented {
					t.Fatal("importing a tombstone invented per-organization generation state")
				}
				if op, ok := st.Deletions[p.Operation.String()]; !ok || op.Phase != model.DeletePhaseComplete {
					t.Fatalf("the tombstone was not recorded as a completed deletion: %+v", op)
				}
				if p.Mode == model.DeleteRetireOrg {
					if st.RetiredOrgs[org.String()] != p.Operation {
						t.Fatal("a retired organization is not remembered as retired")
					}
				}
				if p.Mode == model.DeleteRetireProject {
					if st.RetiredProjects[org.String()+":"+project.String()] != p.Operation {
						t.Fatal("a retired project is not remembered as retired")
					}
				}
				return nil
			})
			if _, err := f.store.DeleteGeneration(f.ctx, org); code(err) != model.NotFound {
				t.Fatalf("an organization that does not exist has a delete generation: %v", err)
			}
			// The tombstone denies the organization's data whatever the organization is called later.
			denied, err := f.store.ActiveDeletions(f.ctx, org, []model.ID{project})
			if err != nil || len(denied) != 1 || denied[0].Operation != p.Operation {
				t.Fatalf("the tombstone is not an active deletion: %v %v", denied, err)
			}
			// If the organization ever appears, its data inside the predicate is still denied.
			create := func() error {
				raw, _ := json.Marshal(auth.AdminPayload{Name: "appears later", Reason: "fixture"})
				_, err := f.svc.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: org, Kind: "create_org", Payload: raw})
				return err
			}
			if p.Mode == model.DeleteRetireOrg {
				if err := create(); code(err) != model.NotFound {
					t.Fatalf("a retired organization was created: %v", err)
				}
				return
			}
			if err := create(); err != nil {
				t.Fatalf("an organization named only by a range tombstone cannot be created: %v", err)
			}
			f.store.View(f.ctx, func(st control.State) error {
				if p.Mode == model.DeleteHistoricalRange && !control.EffectSuppressed(st, org, project, model.Metric, 150, nil) {
					t.Fatal("the deny predicate does not cover the organization once it appears")
				}
				if p.Mode == model.DeleteRetireProject && !control.EffectSuppressed(st, org, project, model.Metric, 150, nil) {
					t.Fatal("a retired project of an organization that appears later is not denied")
				}
				if control.EffectSuppressed(st, org, model.NewID(), model.Metric, 150, nil) && p.Mode != model.DeleteRetireOrg {
					t.Fatal("the predicate denies a project it does not name")
				}
				return nil
			})
			if p.Mode == model.DeleteRetireProject {
				raw, _ := json.Marshal(auth.AdminPayload{ID: project, Name: "again", Reason: "fixture"})
				if _, err := f.svc.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: org, Kind: "create_project", Payload: raw}); code(err) != model.Conflict {
					t.Fatalf("a retired project ID was reused under an organization that appeared later: %v", err)
				}
			}
		})
	}
}
