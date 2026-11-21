// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// slotPlane wraps the REAL storage engine and refuses the delete barrier of the
// slots in down: that data group is unreachable, everything else is the real
// engine. It is the same seam the retention package's own tests use.
type slotPlane struct {
	*storage.Engine
	down map[uint16]bool
}

func (p *slotPlane) RecordDeleteBarrier(ctx context.Context, slot uint16, pr model.DeletePredicate) (model.Cursor, error) {
	if p.down[slot] {
		return model.Cursor{}, model.Fail(model.Unavailable)
	}
	return p.Engine.RecordDeleteBarrier(ctx, slot, pr)
}

// fenceEnv is a real control store, auth service, 64-slot replicated storage
// engine and retention service behind the real deletion, action and operation
// routes over TLS. No appcore, no poller double: the contract poll
// GET /api/v1/operations/{id} reads the real retention service.
type fenceEnv struct {
	t        *testing.T
	ctx      context.Context
	store    *control.Store
	auth     *auth.Service
	svc      *retention.Service
	plane    *slotPlane
	srv      *httptest.Server
	owner    auth.Session
	ownerCr  auth.Credential
	member   auth.Session
	memberCr auth.Credential
	org      model.ID
	project  model.ID
	bystand  model.ID
}

func newFenceEnv(t *testing.T) *fenceEnv {
	t.Helper()
	e := &fenceEnv{t: t, ctx: context.Background()}
	dir := t.TempDir()
	var err error
	if e.store, err = control.Open(filepath.Join(dir, "control")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.store.Close() })
	if e.auth, err = auth.NewService(auth.AuthDependencies{Control: e.store}); err != nil {
		t.Fatal(err)
	}
	if err = e.store.EnableSingle(e.ctx, filepath.Join(dir, "control", "raft")); err != nil {
		t.Fatal(err)
	}
	if err = e.store.BindIncidentAction(); err != nil {
		t.Fatal(err)
	}
	engine, err := storage.Open(filepath.Join(dir, "data"), e.auth)
	if err != nil {
		t.Fatal(err)
	}
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "data", "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, e.store)
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
	t.Cleanup(func() { engine.Close(); transport.Close() })
	if err = e.store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	if err = engine.BindDeletions(e.store); err != nil {
		t.Fatal(err)
	}
	e.plane = &slotPlane{Engine: engine, down: map[uint16]bool{}}
	if e.svc, err = retention.New(retention.Config{Control: e.store, Data: e.plane, Base: e.auth.SourceLifecycleGenerations()}); err != nil {
		t.Fatal(err)
	}
	boot, err := e.store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if e.owner, err = e.auth.Bootstrap(e.ctx, boot, "fence-owner@example.test", "fence owner password 2026"); err != nil {
		t.Fatal(err)
	}
	if e.ownerCr, err = e.auth.Authenticate(e.ctx, e.owner.Token); err != nil {
		t.Fatal(err)
	}
	e.org, e.project, e.bystand = model.NewID(), model.NewID(), model.NewID()
	e.cmd(e.org, "create_org", auth.AdminPayload{Name: "fence org"})
	e.cmd(e.org, "create_project", auth.AdminPayload{ID: e.project, Name: "doomed"})
	e.cmd(e.org, "create_project", auth.AdminPayload{ID: e.bystand, Name: "bystander"})
	memberID := model.NewID()
	e.cmd(e.org, "create_user", auth.AdminPayload{ID: memberID, Email: "fence-member@example.test", Password: "fence member password 2026"})
	e.cmd(e.org, "membership", auth.AdminPayload{UserID: memberID, Enabled: true})
	for _, p := range []model.ID{e.project, e.bystand} {
		e.cmd(e.org, "grant", auth.AdminPayload{UserID: memberID, ProjectID: p, Enabled: true, Permissions: []string{string(auth.Read)}})
	}
	if e.member, err = e.auth.Login(e.ctx, "fence-member@example.test", "fence member password 2026", ""); err != nil {
		t.Fatal(err)
	}
	if e.memberCr, err = e.auth.Authenticate(e.ctx, e.member.Token); err != nil {
		t.Fatal(err)
	}
	incidentService, err := incidents.New(e.store, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	actions, err := httpapi.NewActions(incidentService, e.store, e.store, e.svc, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterDeletionRoutes(mux, e.auth, e.svc)
		httpapi.RegisterActionRoutes(mux, e.auth, actions)
		httpapi.RegisterOperationRoutes(mux, e.auth, actions)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *fenceEnv) revision() model.Revision {
	e.t.Helper()
	var r model.Revision
	if err := e.store.View(e.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *fenceEnv) cmd(org model.ID, kind string, p auth.AdminPayload) {
	e.t.Helper()
	p.Reason = "fence fixture"
	raw, _ := json.Marshal(p)
	if _, err := e.auth.AdminCommand(e.ctx, e.ownerCr, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: e.revision(), OrgID: org, Kind: kind, Payload: raw}); err != nil {
		e.t.Fatal(kind, err)
	}
}

func (e *fenceEnv) do(method, path string, body any) (int, []byte) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, reader)
	req.Header.Set("Cookie", "__Host-soundpost="+e.owner.Token)
	req.Header.Set("X-CSRF-Token", e.owner.CSRF)
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// canRead is whether the member's real authorization still reads the project.
func (e *fenceEnv) canRead(project model.ID) bool {
	_, err := e.auth.Authorize(e.ctx, e.memberCr, e.org, []model.ID{project}, auth.Read)
	return err == nil
}

// poll reads the contract path with no organization selector.
func (e *fenceEnv) poll(op model.ID) httpapi.LifecycleOperation {
	e.t.Helper()
	status, raw := e.do("GET", "/api/v1/operations/"+op.String(), nil)
	if status != 200 {
		e.t.Fatalf("contract poll: %d %s", status, raw)
	}
	var out httpapi.LifecycleOperation
	if err := model.StrictJSON(raw, &out); err != nil || out.ID != op {
		e.t.Fatalf("contract poll is not the LifecycleOperation: %v %s", err, raw)
	}
	return out
}

// completion is the completion instant of an operation and how many control
// audit entries name it.
func (e *fenceEnv) completion(op model.ID) (at model.UnixNano, audits int) {
	e.t.Helper()
	if err := e.store.View(e.ctx, func(st control.State) error {
		at = st.Deletions[op.String()].CompletedAt
		raw, _ := json.Marshal(st.Audits)
		audits = strings.Count(string(raw), op.String())
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return at, audits
}

// [05.03-W4] A REAL deletion over the real HTTP routes with exactly ONE unavailable
// data group: real control store, real 64-slot storage engine, real retention
// service and worker pass, real auth, and the real contract poll
// GET /api/v1/operations/{id} (no ?org=, no poller double). Only the one slot's
// barrier is refused.
//
//	begin     -> 202 fencing; reads of the retired project are already denied
//	pass 1    -> 63 of 64 barriers: still fencing, one pending group, not success
//	pass 2    -> the same fault: still fencing, never complete
//	recovered -> 64/64, complete exactly once (further passes change nothing)
func TestRealDeletionWithOneUnavailableGroupStaysFencingThenCompletesOnce(t *testing.T) {
	e := newFenceEnv(t)
	if !e.canRead(e.project) || !e.canRead(e.bystand) {
		t.Fatal("control: the member must read both projects before the deletion")
	}
	e.plane.down[41] = true

	command := model.NewID()
	status, raw := e.do("POST", "/api/v1/admin/deletions", map[string]any{"command_id": command.String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteRetireProject,
		"org_id": e.org.String(), "project_ids": []string{e.project.String()}, "reason": "one group is down"})
	if status != 202 {
		t.Fatalf("begin: %d %s", status, raw)
	}
	var begun httpapi.DeletionReceipt
	if err := model.StrictJSON(raw, &begun); err != nil || begun.Phase != model.DeletePhaseFencing || begun.OperationID != command {
		t.Fatalf("begin receipt: %v %s", err, raw)
	}
	op := begun.OperationID
	// Reads are denied the moment the saga begins, before any group confirmed.
	if e.canRead(e.project) {
		t.Fatal("a fencing deletion must already deny reads")
	}

	if err := e.svc.RunOnce(e.ctx); faultCode(err) != model.Unavailable {
		t.Fatalf("one unavailable group must surface as unavailable: %v", err)
	}
	first := e.poll(op)
	if first.State != httpapi.StateReady || first.Phase != model.DeletePhaseFencing || first.Progress != "63/64" || first.AppliedBarriers != 63 || first.PendingGroups != 1 || first.Physical == retention.PhysicalDone {
		t.Fatalf("one unavailable group must leave 63/64 fencing: %+v", first)
	}
	if e.canRead(e.project) {
		t.Fatal("a fencing deletion must keep reads denied")
	}
	if !e.canRead(e.bystand) {
		t.Fatal("the fault must not touch the project that is not being deleted")
	}

	if err := e.svc.RunOnce(e.ctx); faultCode(err) != model.Unavailable {
		t.Fatalf("second faulted pass: %v", err)
	}
	if second := e.poll(op); second.Phase != model.DeletePhaseFencing || second.Progress != "63/64" || second.PendingGroups != 1 {
		t.Fatalf("a repeated fault must not complete: %+v", second)
	}
	if at, _ := e.completion(op); at != 0 {
		t.Fatal("the operation completed while one group was unavailable")
	}

	// The group recovers: the operation completes once.
	delete(e.plane.down, 41)
	if err := e.svc.RunOnce(e.ctx); err != nil {
		t.Fatalf("recovered pass: %v", err)
	}
	done := e.poll(op)
	if done.Phase != model.DeletePhaseComplete || done.Progress != "64/64" || done.PendingGroups != 0 || done.AppliedBarriers != 64 {
		t.Fatalf("a recovered group must complete 64/64: %+v", done)
	}
	at, audits := e.completion(op)
	if at == 0 {
		t.Fatal("completion left no completion instant")
	}
	for range 2 {
		if err := e.svc.RunOnce(e.ctx); err != nil {
			t.Fatalf("idle pass: %v", err)
		}
	}
	if again, auditsAgain := e.completion(op); again != at || auditsAgain != audits {
		t.Fatalf("the operation must complete once: completed_at %d -> %d, audits %d -> %d", at, again, audits, auditsAgain)
	}
	if e.canRead(e.project) || !e.canRead(e.bystand) {
		t.Fatal("completion changed who may read what")
	}
	// A legal hold placed before a second deletion shows held, with the backup
	// deadline, not erased: the same contract path.
	scope, err := e.auth.Authorize(e.ctx, e.ownerCr, e.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := e.svc.PlaceHold(e.ctx, scope, retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: e.revision(), ProjectIDs: []model.ID{e.bystand}, Reason: "litigation hold"})
	if err != nil {
		t.Fatal(err)
	}
	second := model.NewID()
	status, raw = e.do("POST", "/api/v1/admin/deletions", map[string]any{"command_id": second.String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteRetireProject,
		"org_id": e.org.String(), "project_ids": []string{e.bystand.String()}, "reason": "held deletion"})
	if status != 409 || !strings.Contains(string(raw), httpapi.DetailDeletionHeld) {
		t.Fatalf("a held deletion answers 409 deletion_held: %d %s", status, raw)
	}
	held := e.poll(second)
	if held.Phase != model.DeletePhaseHeld || held.Holds != 1 || int64(held.BackupDeadline) <= time.Now().UnixNano() {
		t.Fatalf("held must show the hold and the backup deadline: %+v (hold %s)", held, hold)
	}
	if !e.canRead(e.bystand) {
		t.Fatal("a held deletion must not have denied reads: nothing was erased")
	}
}
