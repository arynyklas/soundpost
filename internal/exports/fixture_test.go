// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fx is a real control store and auth service with an injectable clock, the
// same authority the production export service sits on.
type fx struct {
	t       *testing.T
	ctx     context.Context
	store   *control.Store
	svc     *auth.Service
	now     atomic.Int64
	actor   auth.Credential
	session auth.Session
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, ctx: context.Background()}
	f.now.Store(time.Now().UnixNano())
	dir := t.TempDir()
	var err error
	if f.store, err = control.Open(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if f.svc, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return time.Unix(0, f.now.Load()) }}); err != nil {
		t.Fatal(err)
	}
	enable, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	if err = f.store.EnableSingle(enable, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	boot, _ := f.store.BootstrapToken()
	if f.session, err = f.svc.Bootstrap(f.ctx, boot, "exports-owner@example.test", "exports owner password 2026"); err != nil {
		t.Fatal(err)
	}
	if f.actor, err = f.svc.Authenticate(f.ctx, f.session.Token); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fx) at() time.Time        { return time.Unix(0, f.now.Load()) }
func (f *fx) setClock(t time.Time) { f.now.Store(t.UnixNano()) }
func (f *fx) advance(d time.Duration) {
	f.now.Add(int64(d))
}
func (f *fx) cmd(org model.ID, kind string, p auth.AdminPayload) {
	f.t.Helper()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	p.Reason = "exports regression"
	raw, _ := json.Marshal(p)
	if _, err := f.svc.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}
func (f *fx) newOrg(name string) (org, project model.ID) {
	f.t.Helper()
	org, project = model.NewID(), model.NewID()
	f.cmd(org, "create_org", auth.AdminPayload{Name: name})
	f.cmd(org, "create_project", auth.AdminPayload{ID: project, Name: "p"})
	return org, project
}

// reader creates a member of org holding permission on project and logs in.
func (f *fx) reader(org, project model.ID, email string, permission auth.Permission) (auth.Credential, model.ID) {
	f.t.Helper()
	id := model.NewID()
	f.cmd(org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: "exports reader password"})
	f.cmd(org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
	f.cmd(org, "grant", auth.AdminPayload{UserID: id, ProjectID: project, Enabled: true, Permissions: []string{string(permission)}})
	login, err := f.svc.Login(f.ctx, email, "exports reader password", "")
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.svc.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return c, id
}
func (f *fx) scope(c auth.Credential, org, project model.ID) auth.Scope {
	f.t.Helper()
	s, err := f.svc.Authorize(f.ctx, c, org, []model.ID{project}, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// rawSource onboards a restricted-raw source readable only by reader, whose
// policy expires policyTTL from the fixture clock.
func (f *fx) rawSource(org, project, reader model.ID, policyTTL, sourceTTL time.Duration) model.ID {
	f.t.Helper()
	source := model.NewID()
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{reader}, Enabled: true})
	f.cmd(org, "source_policy", auth.AdminPayload{ID: source, Config: cfg})
	owner := f.session.User
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{{ID: "raw", Revision: 1, Line: "{msg}", Severity: "error", Fields: []model.TemplateField{{Name: "msg", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"}}}}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Expires: model.UnixNano(f.at().Add(policyTTL).UnixNano()), RawOwner: &owner, RawRationale: "exports regression", RawMaxBytes: 128}
	if _, err := f.svc.OnboardSource(f.ctx, f.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(f.at().Add(sourceTTL).UnixNano()), Policy: policy, Reason: "exports regression"}); err != nil {
		f.t.Fatal(err)
	}
	return source
}

// service builds an export service over a fresh cache with the given limits.
func (f *fx) service(sc Scanner, limits Limits) *Service {
	f.t.Helper()
	deletes := f.svc.SourceLifecycleGenerations()
	cache, err := auth.NewCache(f.svc, deletes, 64, time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	exp, err := NewWithLimits(f.svc, cache, deletes, sc, limits)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(exp.Close)
	return exp
}
func testLimits() Limits {
	l := DefaultLimits()
	l.SweepInterval = time.Hour // tests drive sweeping explicitly unless they say otherwise
	return l
}

// script is a scanner whose behavior each test dictates.
type script struct {
	pages     int           // pages of one row each before EOF
	partialAt int           // 1-based page flagged Partial (0 = none)
	startGate chan struct{} // Scan blocks until closed (nil = no block)
	parkAt    int64         // Next call that blocks on parkGate (0 = never)
	parked    chan struct{}
	parkGate  chan struct{}
	nexts     atomic.Int64
}

func (s *script) Scan(ctx context.Context, _ auth.Scope, _ storage.ScanRequest) (storage.RowIterator, error) {
	if s.startGate != nil {
		select {
		case <-s.startGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &scriptRows{s: s}, nil
}

type scriptRows struct {
	s    *script
	sent int
}

func (r *scriptRows) Next(ctx context.Context) (storage.Page, error) {
	n := r.s.nexts.Add(1)
	if r.s.parkAt != 0 && n == r.s.parkAt {
		r.s.parked <- struct{}{}
		select {
		case <-r.s.parkGate:
		case <-ctx.Done():
			return storage.Page{}, ctx.Err()
		}
	}
	if r.sent == r.s.pages {
		return storage.Page{}, io.EOF
	}
	r.sent++
	return rowPage(r.s.partialAt == r.sent), nil
}
func (r *scriptRows) Watermarks() []model.Cursor { return nil }
func (r *scriptRows) Close() error               { return nil }

func rowPage(partial bool) storage.Page {
	v := model.FloatBits(0x3ff0000000000000)
	return storage.Page{IDs: []model.ID{model.NewID()}, Times: []model.UnixNano{1}, ObservedTimes: []model.UnixNano{1}, Resources: []model.Resource{{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "i", Labels: model.Labels{}}}, Values: []model.Payload{{Metric: &model.MetricPoint{Name: "scripted_total", Labels: model.Labels{}, SampleKind: "float", Value: &v, Unit: "1", Type: "counter"}}}, Origins: []model.Cursor{{}}, Projects: []model.ID{model.NewID()}, Sources: []model.ID{model.NewID()}, Loss: []uint64{0}, Partial: partial}
}

// entryFor finds the live entry of an operation.
func (s *Service) entryFor(t *testing.T, id model.ID) *entry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.op.ID == id {
			return e
		}
	}
	t.Fatal("operation missing from service")
	return nil
}
func (e *entry) state() (Operation, [][]byte, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.op, e.chunks, e.expires
}

// settle waits for an operation to leave "running".
func (s *Service) settle(t *testing.T, e *entry) Operation {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if op, _, _ := e.state(); op.Phase != "running" {
			return op
		}
	}
	t.Fatal("export stayed pending")
	return Operation{}
}
func (s *Service) liveEntries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
