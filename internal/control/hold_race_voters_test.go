// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// holdRace is the 01.08-W4 fixture: three control voters in one control Raft group, and a real
// storage engine plus a real retention.Service on voter 3, the voter that runs the physical pass.
// A legal hold is placed through voter 1 (acknowledged by the quorum voters 1 and 2) while voter 3
// either lags in apply or is cut off, which is the window a local read of the applied state cannot
// see.
type holdRace struct {
	t       *testing.T
	v       *controlVoters
	engine  *storage.Engine
	svc     *retention.Service
	plane   *holdRacePlane
	cred    auth.Credential
	records int
}

// holdRacePlane is voter 3's data plane: the real engine, with the erasing call observable and
// replaceable.
type holdRacePlane struct {
	*storage.Engine
	erased func(context.Context, []model.DeletePredicate, storage.EraseGuard) (storage.EraseReport, error)
}

func (p *holdRacePlane) EraseDeleted(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
	if p.erased != nil {
		return p.erased(ctx, preds, g)
	}
	return p.Engine.EraseDeleted(ctx, preds, g)
}

func newHoldRace(t *testing.T) *holdRace {
	t.Helper()
	v := newControlVotersWith(t, 3)
	h := &holdRace{t: t, v: v}
	laggard := v.fx[3]
	dir := t.TempDir()
	var err error
	if h.engine, err = storage.Open(filepath.Join(dir, "data"), laggard.svc); err != nil {
		t.Fatal(err)
	}
	transport := replica.NewLoopback()
	groups, err := h.engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "data", "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, laggard.store)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if err = transport.Register(g); err == nil {
			err = g.Campaign()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { h.engine.Close(); transport.Close() })
	if err = laggard.store.BindAdmissionOwner(h.engine); err != nil {
		t.Fatal(err)
	}
	if err = h.engine.BindDeletions(laggard.store); err != nil {
		t.Fatal(err)
	}
	h.plane = &holdRacePlane{Engine: h.engine}
	now := laggard.now
	if h.svc, err = retention.New(retention.Config{Control: laggard.store, Data: h.plane, Base: laggard.svc.SourceLifecycleGenerations(), Clock: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	session, err := laggard.svc.Login(laggard.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	if h.cred, err = laggard.svc.Authenticate(laggard.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	return h
}

// append admits one metric record through voter 3's engine.
func (h *holdRace) append(at int64) {
	h.t.Helper()
	f := h.v.fx[3]
	cred, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		h.t.Fatal(err)
	}
	scope, err := f.svc.SourceScope(f.ctx, cred, false)
	if err != nil {
		h.t.Fatal(err)
	}
	src, err := f.svc.SourceAuthority(f.ctx, cred, true)
	if err != nil {
		h.t.Fatal(err)
	}
	value := model.FloatBits(0x3ff0000000000000)
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{}, SampleKind: "float", Value: &value, Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(f.org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		h.t.Fatal(err)
	}
	policy, _ := model.CanonicalJSON(src.Policy)
	admitted := model.UnixNano(f.now.UnixNano())
	n := model.NormalizedBatch{Batch: b, Org: f.org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policy).String(), AdmissionAt: admitted, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: admitted + model.UnixNano(14*24*time.Hour)}}}
	if n.Reservation, err = f.store.ReserveAdmission(f.ctx, scope, n); err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.engine.Append(f.ctx, scope, n); err != nil {
		h.t.Fatal(err)
	}
	h.records++
}

// retire begins the deletion of the fixture project through voter 3 and returns its operation.
func (h *holdRace) retire() model.ID {
	h.t.Helper()
	f := h.v.fx[3]
	scope, err := f.svc.Authorize(f.ctx, h.cred, f.org, nil, auth.OrgAdmin)
	if err != nil {
		h.t.Fatal(err)
	}
	receipt, err := h.svc.Delete(f.ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: h.v.mustRevision(3), Mode: model.DeleteRetireProject, OrgID: f.org, ProjectIDs: []model.ID{f.project}, Reason: "hold race"})
	if err != nil {
		h.t.Fatal(err)
	}
	return receipt.OperationID
}

// placeHoldOnVoter1 places a legal hold over the fixture project through voter 1 and returns once
// voter 2 has applied it too, so the hold is committed by a quorum that does not include voter 3.
func (h *holdRace) placeHoldOnVoter1() model.ID {
	h.t.Helper()
	f := h.v.fx[1]
	id := model.NewID()
	hold := control.PlaceHold{Projects: []model.ID{f.project}, Reason: "litigation", At: model.UnixNano(f.now.UnixNano())}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindPolicyChange, id, control.PolicyChange{Kind: "hold_place", Hold: &hold})); err != nil {
		h.t.Fatal(err)
	}
	h.v.await(2, h.v.mustRevision(1))
	return id
}

func (h *holdRace) receipt(op model.ID) retention.DeleteReceipt {
	h.t.Helper()
	f := h.v.fx[3]
	scope, err := f.svc.Authorize(f.ctx, h.cred, f.org, nil, auth.OrgAdmin)
	if err != nil {
		h.t.Fatal(err)
	}
	r, err := h.svc.PollDelete(f.ctx, scope, op)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

// A hold acknowledged by the control quorum stops the erasure on a voter that is connected but has
// not applied it yet. Voter 3 is gated (its log appends are held back, its read-index traffic still
// flows), so when its erasing transaction is about to start the hold exists in the group and is NOT in
// the applied state of voter 3: a guard that asks only the applied state lets the bytes go. The erasing
// path asks the control group first (a linearizable read, which waits for voter 3 to apply the hold), so
// the hold wins and nothing is erased.
func TestHoldAcknowledgedByTheQuorumStopsTheErasureOnAVoterThatHasNotAppliedIt(t *testing.T) {
	h := newHoldRace(t)
	for i := range 3 {
		h.append(int64(5 + i))
	}
	op := h.retire()
	var hold model.ID
	var first *storage.EraseReport
	var firstErr error
	appliedByVoter3 := -1
	h.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		if first != nil {
			return h.engine.EraseDeleted(ctx, preds, g)
		}
		h.v.mesh.gateAppends(3, true)
		hold = h.placeHoldOnVoter1()
		// The race window itself: the quorum holds the hold, voter 3's applied state does not.
		snap, err := h.v.stores[3].AppliedHolds(control.HoldSnapshot{})
		if err != nil {
			t.Fatal(err)
		}
		appliedByVoter3 = len(snap.Holds)
		time.AfterFunc(400*time.Millisecond, func() { h.v.mesh.gateAppends(3, false) })
		report, err := h.engine.EraseDeleted(ctx, preds, g)
		first, firstErr = &report, err
		return report, err
	}
	err := h.svc.RunOnce(context.Background())
	h.v.mesh.gateAppends(3, false)
	if first == nil {
		t.Fatalf("the physical pass never ran: %v", err)
	}
	if hold == (model.ID{}) || appliedByVoter3 != 0 {
		t.Fatalf("fixture invalid: the hold must be committed by the quorum and unapplied on voter 3 when the erasing transaction starts (applied holds on voter 3: %d)", appliedByVoter3)
	}
	if firstErr != nil {
		t.Fatalf("the erasing call failed: %v", firstErr)
	}
	if first.Records != 0 || first.Blobs != 0 || first.Held == 0 {
		t.Fatalf("a hold acknowledged by the control quorum before the erasing transaction lost its bytes on a voter that had not applied it: %+v", *first)
	}
	if st := h.svc.Status(); st.ErasedRecords != 0 || st.ErasedBeforeHold != 0 {
		t.Fatalf("worker status after a vetoed erasure: %+v", st)
	}
	if got := h.receipt(op); got.Physical != retention.PhysicalHeld {
		t.Fatalf("physical-erasure success reported while a hold overlaps: %+v", got)
	}
}

// A voter that cannot confirm it is current erases nothing. Voter 3 is cut off from the group after its
// physical pass started: it cannot reach a quorum, a hold may have been committed that it will never see
// until it is reconnected, and a local read of its applied state would say "no hold". The erasing
// transaction's linearizable read fails, and the pass fails closed instead of erasing.
func TestErasureFailsClosedOnAVoterThatCannotReachTheControlQuorum(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 5 s read-index deadline")
	}
	h := newHoldRace(t)
	for i := range 3 {
		h.append(int64(5 + i))
	}
	h.retire()
	var report *storage.EraseReport
	var eraseErr error
	h.plane.erased = func(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
		if report != nil {
			return h.engine.EraseDeleted(ctx, preds, g)
		}
		h.v.mesh.cut(3, true)
		h.placeHoldOnVoter1()
		r, err := h.engine.EraseDeleted(ctx, preds, g)
		report, eraseErr = &r, err
		return r, err
	}
	_ = h.svc.RunOnce(context.Background())
	h.v.mesh.cut(3, false)
	if report == nil {
		t.Fatal("the physical pass never ran")
	}
	if eraseErr == nil {
		t.Fatalf("a voter cut off from the control quorum completed an erasure pass: %+v", *report)
	}
	if report.Records != 0 || report.Blobs != 0 {
		t.Fatalf("a voter cut off from the control quorum erased bytes: %+v (%v)", *report, eraseErr)
	}
	if st := h.svc.Status(); st.ErasedRecords != 0 {
		t.Fatalf("worker status after a failed-closed erasure: %+v", st)
	}
}
