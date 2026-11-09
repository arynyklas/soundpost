// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"sync/atomic"
	"testing"
	"time"
)

// fx is a real control store, auth service, replicated storage engine (one voter,
// 64 slots) and retention service with a deterministic clock.
type fx struct {
	t            *testing.T
	ctx          context.Context
	clock        atomic.Int64
	store        *control.Store
	auth         *auth.Service
	engine       *storage.Engine
	svc          *retention.Service
	cred         auth.Credential
	user         model.ID
	org, project model.ID
	other        model.ID
	source       auth.SourceCredential
	desc         model.SourceDescriptor
	plane        *plane
	authority    retention.Authority
	gens         auth.DeleteGenerations
}

// plane wraps the real engine so a test can make a slot unavailable or observe
// the physical pass.
type plane struct {
	*storage.Engine
	down     map[uint16]bool
	checks   func(storage.EraseCandidate) // observed by the expiry planner
	expired  func(context.Context, model.UnixNano, storage.EraseGuard) (storage.EraseReport, error)
	erased   func(context.Context, []model.DeletePredicate, storage.EraseGuard) (storage.EraseReport, error)
	trace    func(step string) error // called first by every post-erasure maintenance step; an error fails the step
	residual func() []string         // overrides what the engine declares as still holding deleted bytes
}

func (p *plane) step(name string) error {
	if p.trace != nil {
		return p.trace(name)
	}
	return nil
}
func (p *plane) ResidualStores() []string {
	if p.residual != nil {
		return p.residual()
	}
	return p.Engine.ResidualStores()
}
func (p *plane) CheckpointErasure(ctx context.Context, pr model.DeletePredicate) error {
	if err := p.step("checkpoint"); err != nil {
		return err
	}
	return p.Engine.CheckpointErasure(ctx, pr)
}
func (p *plane) CreateSnapshots(ctx context.Context) (storage.EngineSnapshot, error) {
	if err := p.step("snapshot"); err != nil {
		return storage.EngineSnapshot{}, err
	}
	return p.Engine.CreateSnapshots(ctx)
}
func (p *plane) DropSupersededSnapshots(ctx context.Context) (uint64, error) {
	if err := p.step("drop"); err != nil {
		return 0, err
	}
	return p.Engine.DropSupersededSnapshots(ctx)
}
func (p *plane) CompactJournals(ctx context.Context) error {
	if err := p.step("compact"); err != nil {
		return err
	}
	return p.Engine.CompactJournals(ctx)
}

func (p *plane) RecordDeleteBarrier(ctx context.Context, slot uint16, pr model.DeletePredicate) (model.Cursor, error) {
	if p.down[slot] {
		return model.Cursor{}, model.Fail(model.Unavailable)
	}
	return p.Engine.RecordDeleteBarrier(ctx, slot, pr)
}
func (p *plane) EraseDeleted(ctx context.Context, preds []model.DeletePredicate, g storage.EraseGuard) (storage.EraseReport, error) {
	if p.erased != nil {
		return p.erased(ctx, preds, g)
	}
	return p.Engine.EraseDeleted(ctx, preds, g)
}
func (p *plane) EraseExpired(ctx context.Context, now model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
	if p.expired != nil {
		return p.expired(ctx, now, g)
	}
	return p.Engine.EraseExpired(ctx, now, g)
}

type options struct {
	authority retention.Authority
	processed retention.Processed
	refs      retention.References
	pressure  bool
}

func newFx(t *testing.T, o options) *fx {
	t.Helper()
	f := &fx{t: t, ctx: context.Background()}
	f.clock.Store(time.Unix(1_800_000_000, 0).UnixNano())
	dir := t.TempDir()
	var err error
	if f.store, err = control.Open(filepath.Join(dir, "control")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	now := func() time.Time { return time.Unix(0, f.clock.Load()) }
	if f.auth, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err = f.store.EnableSingle(f.ctx, filepath.Join(dir, "control", "raft")); err != nil {
		t.Fatal(err)
	}
	boot, _ := f.store.BootstrapToken()
	s, err := f.auth.Bootstrap(f.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.user = s.User
	if f.cred, err = f.auth.Authenticate(f.ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	f.org, f.project, f.other = model.NewID(), model.NewID(), model.NewID()
	source := model.NewID()
	f.admin("create_org", auth.AdminPayload{Name: "ret", Reason: "fixture"})
	f.admin("create_project", auth.AdminPayload{ID: f.project, Name: "p1", Reason: "fixture"})
	f.admin("create_project", auth.AdminPayload{ID: f.other, Name: "p2", Reason: "fixture"})
	f.admin("membership", auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "fixture"})
	f.admin("grant", auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 30, MaxSeries: 100000}
	issued, err := f.auth.OnboardSource(f.ctx, f.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: source, Expires: model.UnixNano(now().Add(48 * time.Hour).UnixNano()), Policy: policy, Reason: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	f.desc = issued.Descriptor
	if f.source, err = f.auth.AuthenticateSource(f.ctx, issued.Credential, "", false); err != nil {
		t.Fatal(err)
	}
	f.engine, err = storage.Open(filepath.Join(dir, "data"), f.auth)
	if err != nil {
		t.Fatal(err)
	}
	transport := replica.NewLoopback()
	groups, err := f.engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "data", "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, f.store)
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
	t.Cleanup(func() { f.engine.Close(); transport.Close() })
	if err = f.store.BindAdmissionOwner(f.engine); err != nil {
		t.Fatal(err)
	}
	if err = f.engine.BindDeletions(f.store); err != nil {
		t.Fatal(err)
	}
	f.plane = &plane{Engine: f.engine, down: map[uint16]bool{}}
	f.authority = o.authority
	var pressure retention.Pressure
	if o.pressure {
		pressure = f.engine
	}
	f.svc, err = retention.New(retention.Config{Control: f.store, Data: f.plane, Base: f.auth.SourceLifecycleGenerations(), Authority: o.authority, Pressure: pressure, Processed: o.processed, References: o.refs, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	f.gens = f.svc
	return f
}
func (f *fx) at() time.Time           { return time.Unix(0, f.clock.Load()) }
func (f *fx) advance(d time.Duration) { f.clock.Add(int64(d)) }
func (f *fx) revision() model.Revision {
	var r model.Revision
	if err := f.store.View(f.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *fx) admin(kind string, p auth.AdminPayload) {
	f.t.Helper()
	raw, _ := json.Marshal(p)
	if _, err := f.auth.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: f.org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}
func (f *fx) adminScope() auth.Scope {
	f.t.Helper()
	s, err := f.auth.Authorize(f.ctx, f.cred, f.org, nil, auth.OrgAdmin)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *fx) readScope() (auth.Scope, error) {
	return f.auth.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.Read)
}

// append admits one metric record observed at `at` and returns the ACKed receipt.
func (f *fx) append(at int64, name string) (model.NormalizedBatch, model.Receipt, error) {
	f.t.Helper()
	b, err := f.batch(at, name)
	if err != nil {
		return b, model.Receipt{}, err
	}
	scope, err := f.auth.SourceScope(f.ctx, f.source, false)
	if err != nil {
		return b, model.Receipt{}, err
	}
	r, err := f.engine.Append(f.ctx, scope, b)
	return b, r, err
}

// batch builds a normalized, reserved batch without appending it.
func (f *fx) batch(at int64, name string) (model.NormalizedBatch, error) {
	scope, err := f.auth.SourceScope(f.ctx, f.source, false)
	if err != nil {
		return model.NormalizedBatch{}, err
	}
	src, err := f.auth.SourceAuthority(f.ctx, f.source, true)
	if err != nil {
		return model.NormalizedBatch{}, err
	}
	v := model.FloatBits(0x3ff0000000000000)
	b := model.Batch{Version: 1, Project: f.desc.Project, Source: f.desc.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(f.desc.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return model.NormalizedBatch{}, err
	}
	policy, _ := model.CanonicalJSON(src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: f.desc.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policy).String(), AdmissionAt: model.UnixNano(f.clock.Load()), Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: model.UnixNano(f.clock.Load()) + model.UnixNano(14*24*time.Hour)}}}
	n.Reservation, err = f.store.ReserveAdmission(f.ctx, scope, n)
	return n, err
}

// rows scans the project's metric rows through a fresh read scope.
func (f *fx) rows() (int, error) {
	scope, err := f.readScope()
	if err != nil {
		return 0, err
	}
	return f.rowsWith(scope)
}
func (f *fx) rowsWith(scope auth.Scope) (int, error) {
	it, err := f.engine.Scan(f.ctx, scope, storage.ScanRequest{Projects: []model.ID{f.project}, Signal: model.Metric, End: 1 << 60})
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for {
		p, err := it.Next(f.ctx)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n += p.Len()
	}
}
func code(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}
func (f *fx) del(mode string, mut func(*retention.DeleteRequest)) (retention.DeleteReceipt, error) {
	req := retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), Mode: mode, OrgID: f.org, Reason: "fixture deletion"}
	if mut != nil {
		mut(&req)
	}
	return f.svc.Delete(f.ctx, f.adminScope(), req)
}
func (f *fx) poll(id model.ID) retention.DeleteReceipt {
	f.t.Helper()
	r, err := f.svc.PollDelete(f.ctx, f.adminScope(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *fx) run() {
	f.t.Helper()
	if err := f.svc.RunOnce(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}
