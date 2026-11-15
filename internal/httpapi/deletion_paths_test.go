// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// [10.07-W1] The historical_range, entity and retire_org modes, and the hold place/release and
// resume routes [10.07-W2], over the real HTTP routes, the real control store, the real storage
// engine and the real retention service: begin, drive the worker until the saga completes, and
// assert the response JSON and that the data is gone.

// drive runs the real worker pass until the operation is complete.
func (e *delEnv) drive(op model.ID) {
	e.t.Helper()
	for range 8 {
		if e.phase(op) == model.DeletePhaseComplete {
			return
		}
		_ = e.app.Retention.RunOnce(e.ctx)
	}
	e.t.Fatalf("operation %s did not complete: phase %q", op, e.phase(op))
}

func (e *delEnv) phase(op model.ID) string {
	e.t.Helper()
	var phase string
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { phase = st.Deletions[op.String()].Phase; return nil }); err != nil {
		e.t.Fatal(err)
	}
	return phase
}

// post sends body to any admin path as who (a nil who sends no credential).
func (e *delEnv) post(who *person, path string, body any, mutate func(*http.Request)) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(raw))
	if who != nil {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *delEnv) rev() string { return strconv.FormatUint(uint64(e.revision()), 10) }

// stored counts the rows of one signal of one project, read through the admin's real scope.
func (e *delEnv) stored(who person, org, project model.ID, kind model.Kind, names map[string]bool) int {
	e.t.Helper()
	scope, err := e.scope(who, org, project, auth.Read)
	if err != nil {
		e.t.Fatal(err)
	}
	rows, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for {
		page, err := rows.Next(e.ctx)
		if err == io.EOF {
			return n
		}
		if err != nil {
			e.t.Fatal(err)
		}
		for i := range page.Len() {
			if names == nil || page.Values[i].Metric != nil && names[page.Values[i].Metric.Name] {
				n++
			}
		}
	}
}

func (e *delEnv) metricAt(s sourceFixture, name string, at int64) {
	e.t.Helper()
	value := model.FloatBits(math.Float64bits(1))
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: e.resource(s), Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}})
}

func TestDeletionRouteHistoricalRangeErasesOnlyTheRange(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("range")
	for name, at := range map[string]int64{"in_a": 2000, "in_b": 3000, "before": 1000, "after": 4000} {
		e.metricAt(f.source, name, at)
	}
	all := map[string]bool{"in_a": true, "in_b": true, "before": true, "after": true}
	if got := e.stored(f.member, f.org, f.project, model.Metric, all); got != 4 {
		t.Fatalf("control: %d rows before the deletion, want 4", got)
	}
	command := model.NewID()
	body := map[string]any{"command_id": command.String(), "expected_revision": e.rev(), "mode": model.DeleteHistoricalRange, "org_id": f.org.String(), "project_ids": []string{f.project.String()},
		"signals": []string{string(model.Metric)}, "start_ns": "1500", "end_ns": "3500", "reason": "range erasure"}
	status, raw := e.begin(&f.admin, body, nil)
	r := e.receipt(status, 202, raw)
	if r.Mode != model.DeleteHistoricalRange || r.Phase != model.DeletePhaseFencing || r.OperationID != command || r.Generation == 0 || r.PhysicalDeadline == 0 || r.BackupDeadline <= r.PhysicalDeadline || r.Progress == "" || r.Physical == "" {
		t.Fatalf("not a complete fencing range receipt: %s", raw)
	}
	if len(r.OverErased) != 0 {
		t.Fatalf("a clean range reports no over-erasure: %s", raw)
	}
	e.drive(command)
	if got := e.stored(f.member, f.org, f.project, model.Metric, all); got != 2 {
		t.Fatalf("%d rows remain after the range deletion, want the 2 outside the range", got)
	}
	if got := e.stored(f.member, f.org, f.project, model.Metric, map[string]bool{"in_a": true, "in_b": true}); got != 0 {
		t.Fatalf("%d rows inside the range survive", got)
	}
	// The project itself is not retired: the member still reads it.
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("a range deletion denied the project: %d", got)
	}
	// The same command again is the completed receipt, with the physical erasure done.
	status, raw = e.begin(&f.admin, body, nil)
	done := e.receipt(status, 200, raw)
	if done.Phase != model.DeletePhaseComplete || done.Mode != model.DeleteHistoricalRange || done.OperationID != command || done.Generation != r.Generation || done.Physical != retention.PhysicalDone {
		t.Fatalf("the retry is not the completed range receipt: %s", raw)
	}
	pollStatus, pollRaw := e.poll(f.admin, f.org, command)
	if pollStatus != 200 || !strings.Contains(string(pollRaw), `"phase":"complete"`) {
		t.Fatalf("the poll does not show complete: %d %s", pollStatus, pollRaw)
	}
	if e.deletions() != 1 {
		t.Fatalf("%d deletions committed, want 1", e.deletions())
	}
}

func TestDeletionRouteEntityErasesOnlyTheNamedReplay(t *testing.T) {
	e := newDelEnv(t)
	project := model.NewID()
	org := e.org("entity", project)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay}, Replay: true, RetentionDays: map[model.Kind]uint32{model.Replay: 14}, MaxBytes: 1 << 30, MaxSeries: 100}
	src := e.onboard(org, project, model.NewID(), ids, pol, auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
	reader := e.user(org, "entity-reader@example.test")
	e.grant(org, reader, project, true, auth.Read)
	doomed, kept := newChainRecorder(), newChainRecorder()
	for i := range 3 {
		for _, r := range []*chainRecorder{doomed, kept} {
			c := r.next(t, i == 0)
			e.ingest(src, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: e.resource(src), Payload: model.Payload{Replay: &c}})
		}
	}
	if got := e.stored(reader, org, project, model.Replay, nil); got != 6 {
		t.Fatalf("control: %d replay chunks before the deletion, want 6", got)
	}
	command := model.NewID()
	body := map[string]any{"command_id": command.String(), "expected_revision": e.rev(), "mode": model.DeleteEntity, "org_id": org.String(), "project_ids": []string{project.String()},
		"signals": []string{string(model.Replay)}, "entity_ids": []string{doomed.replay.String()}, "reason": "erase one replay"}
	status, raw := e.begin(&e.actor, body, nil)
	r := e.receipt(status, 202, raw)
	if r.Mode != model.DeleteEntity || r.Phase != model.DeletePhaseFencing || r.OperationID != command || r.Generation == 0 || r.PhysicalDeadline == 0 || r.BackupDeadline <= r.PhysicalDeadline {
		t.Fatalf("not a fencing entity receipt: %s", raw)
	}
	e.drive(command)
	if got := e.stored(reader, org, project, model.Replay, nil); got != 3 {
		t.Fatalf("%d replay chunks remain, want the 3 of the other replay", got)
	}
	status, raw = e.begin(&e.actor, body, nil)
	done := e.receipt(status, 200, raw)
	if done.Phase != model.DeletePhaseComplete || done.Mode != model.DeleteEntity || done.Physical != retention.PhysicalDone {
		t.Fatalf("the retry is not the completed entity receipt: %s", raw)
	}
}

func TestDeletionRouteRetireOrgRetiresOnlyThatOrg(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("retire-org")
	other := e.fixture("retire-org-bystander")
	command := model.NewID()
	body := map[string]any{"command_id": command.String(), "expected_revision": e.rev(), "mode": model.DeleteRetireOrg, "org_id": f.org.String(), "reason": "retire the organization"}
	status, raw := e.begin(&f.admin, body, nil)
	r := e.receipt(status, 202, raw)
	if r.Mode != model.DeleteRetireOrg || r.Phase != model.DeletePhaseFencing || r.OperationID != command || r.Generation == 0 || r.PhysicalDeadline == 0 || r.BackupDeadline <= r.PhysicalDeadline {
		t.Fatalf("not a fencing retire_org receipt: %s", raw)
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 404 {
		t.Fatalf("a member's read of the retired org answers %d, want 404", got)
	}
	if got := e.ingestStatus(f.source, "after_retire_org"); got == 200 {
		t.Fatal("a retired org still accepts writes")
	}
	e.drive(command)
	status, raw = e.begin(&f.admin, body, nil)
	done := e.receipt(status, 200, raw)
	if done.Phase != model.DeletePhaseComplete || done.Mode != model.DeleteRetireOrg || done.Physical != retention.PhysicalDone || done.OperationID != command {
		t.Fatalf("the retry is not the completed retire_org receipt: %s", raw)
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 404 {
		t.Fatalf("after completion the retired org answers %d, want 404", got)
	}
	// The other organization is untouched: reads, writes and its data.
	if got := e.readStatus(other.member, other.org, other.project); got != 200 {
		t.Fatalf("a bystander org lost reads: %d", got)
	}
	if got := e.ingestStatus(other.source, "bystander_write"); got != 200 {
		t.Fatalf("a bystander org lost writes: %d", got)
	}
	if got := e.stored(other.member, other.org, other.project, model.Metric, nil); got == 0 {
		t.Fatal("a bystander org lost its data")
	}
}

// holdFlow places a hold through the route and returns its ID.
func (e *delEnv) placeHold(who *person, org, project model.ID, reason string) (int, []byte) {
	return e.post(who, "/api/v1/admin/holds", map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": org.String(), "project_ids": []string{project.String()}, "reason": reason}, nil)
}

func TestHoldRoutesPlaceReleaseAndResumeAHeldDeletion(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("holds")
	status, raw := e.placeHold(&f.admin, f.org, f.project, "litigation hold")
	var placed httpapi.HoldReceipt
	if status != 201 || model.StrictJSON(raw, &placed) != nil || placed.HoldID == (model.ID{}) || placed.OrgID != f.org || placed.State != "active" {
		t.Fatalf("place: %d %s", status, raw)
	}
	body := e.retire(f.org, f.project)
	status, raw = e.begin(&f.admin, body, nil)
	var refused httpapi.DeletionRefused
	if status != 409 || model.StrictJSON(raw, &refused) != nil || refused.Detail != httpapi.DetailDeletionHeld || len(refused.Receipt.Holds) != 1 || refused.Receipt.Holds[0] != placed.HoldID {
		t.Fatalf("the hold placed over HTTP does not hold the deletion: %d %s", status, raw)
	}
	operation := refused.Receipt.OperationID
	resume := "/api/v1/admin/deletions/" + operation.String() + "/resume"
	// Still held: resuming changes nothing, reads stay open.
	status, raw = e.post(&f.admin, resume, map[string]any{"org_id": f.org.String()}, nil)
	if status != 409 || !strings.Contains(string(raw), httpapi.DetailDeletionHeld) {
		t.Fatalf("resuming a deletion that is still held: %d %s", status, raw)
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("a held deletion denied reads: %d", got)
	}
	// Release over HTTP, then resume over HTTP: the saga begins and completes.
	status, raw = e.post(&f.admin, "/api/v1/admin/holds/"+placed.HoldID.String()+"/release", map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": f.org.String(), "reason": "matter closed"}, nil)
	var released httpapi.HoldReceipt
	if status != 200 || model.StrictJSON(raw, &released) != nil || released.HoldID != placed.HoldID || released.State != "released" {
		t.Fatalf("release: %d %s", status, raw)
	}
	status, raw = e.post(&f.admin, resume, map[string]any{"org_id": f.org.String()}, nil)
	r := e.receipt(status, 202, raw)
	if r.Phase != model.DeletePhaseFencing || r.OperationID != operation || len(r.Holds) != 0 {
		t.Fatalf("resume receipt: %s", raw)
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 404 {
		t.Fatalf("a resumed deletion did not deny reads: %d", got)
	}
	e.drive(operation)
	status, raw = e.post(&f.admin, resume, map[string]any{"org_id": f.org.String()}, nil)
	if status == 202 || status == 409 && strings.Contains(string(raw), httpapi.DetailDeletionHeld) {
		t.Fatalf("a completed deletion answers a resume as still running or held: %d %s", status, raw)
	}
}

func TestHoldRoutesRefuseEveryNonFreshOrgAdminTheSameWay(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("holds-matrix")
	stranger := e.org("holds-matrix-other", model.NewID())
	foreign := e.user(stranger, "holds-matrix-foreign@example.test")
	e.orgAdmin(stranger, foreign)
	stale := e.user(f.org, "holds-matrix-stale@example.test")
	e.orgAdmin(f.org, stale)
	if err := e.app.Control.Update(e.ctx, func(st *model.ControlState) error {
		for key, s := range st.Sessions {
			if s.User == stale.ID {
				s.Reauthenticated = 1
				st.Sessions[key] = s
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A real hold and a real held deletion exist, so a denial cannot be an absence.
	status, raw := e.placeHold(&f.admin, f.org, f.project, "litigation hold")
	var placed httpapi.HoldReceipt
	if status != 201 || model.StrictJSON(raw, &placed) != nil {
		t.Fatalf("control place: %d %s", status, raw)
	}
	status, raw = e.begin(&f.admin, e.retire(f.org, f.project), nil)
	var refused httpapi.DeletionRefused
	if status != 409 || model.StrictJSON(raw, &refused) != nil {
		t.Fatalf("control held: %d %s", status, raw)
	}
	operation := refused.Receipt.OperationID
	ghost := model.NewID()
	routes := []struct {
		name string
		path string
		body func(org model.ID) map[string]any
	}{
		{"place", "/api/v1/admin/holds", func(org model.ID) map[string]any {
			return map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": org.String(), "project_ids": []string{f.project.String()}, "reason": deletionCanary}
		}},
		{"release", "/api/v1/admin/holds/" + placed.HoldID.String() + "/release", func(org model.ID) map[string]any {
			return map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": org.String(), "reason": deletionCanary}
		}},
		{"resume", "/api/v1/admin/deletions/" + operation.String() + "/resume", func(org model.ID) map[string]any { return map[string]any{"org_id": org.String()} }},
	}
	before, beforeState := e.revision(), e.state()
	for _, route := range routes {
		cases := []struct {
			name   string
			who    *person
			org    model.ID
			mutate func(*http.Request)
			status int
		}{
			{"ordinary member with a read grant", &f.member, f.org, nil, 404},
			{"another organization's admin", &foreign, f.org, nil, 404},
			{"admin of a guessed organization", &f.admin, ghost, nil, 404},
			{"missing CSRF token", &f.admin, f.org, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
			{"foreign Origin", &f.admin, f.org, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
			{"no session", nil, f.org, nil, 401},
			{"org admin whose session is no longer fresh", &stale, f.org, nil, 403},
		}
		shapes := map[string]string{}
		for _, c := range cases {
			status, raw := e.post(c.who, route.path, route.body(c.org), c.mutate)
			if status != c.status {
				t.Errorf("%s/%s: status %d, want %d: %s", route.name, c.name, status, c.status, raw)
			}
			if strings.Contains(string(raw), deletionCanary) || strings.Contains(string(raw), f.project.String()) || strings.Contains(string(raw), placed.HoldID.String()) {
				t.Errorf("%s/%s: the refusal echoes the request: %s", route.name, c.name, raw)
			}
			shapes[c.name] = denial(t, status, raw)
		}
		if shapes["another organization's admin"] != shapes["admin of a guessed organization"] || shapes["ordinary member with a read grant"] != shapes["admin of a guessed organization"] {
			t.Errorf("%s: org denial distinguishes a real org from a missing one: %v", route.name, shapes)
		}
	}
	if e.revision() != before || e.state() != beforeState {
		t.Fatalf("a refused hold/resume request changed control state (revision %d -> %d)", before, e.revision())
	}
	// Malformed bodies change nothing either: unknown field, no reason, a bad path ID.
	for name, c := range map[string]struct {
		path string
		body map[string]any
	}{
		"unknown field":        {routes[0].path, map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": f.org.String(), "reason": "x", "wipe": true}},
		"place without reason": {routes[0].path, map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": f.org.String(), "reason": "  "}},
		"release bad hold id":  {"/api/v1/admin/holds/not-an-id/release", map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": f.org.String(), "reason": "x"}},
		"resume unknown field": {routes[2].path, map[string]any{"org_id": f.org.String(), "wipe": true}},
		"resume bad operation": {"/api/v1/admin/deletions/not-an-id/resume", map[string]any{"org_id": f.org.String()}},
	} {
		if status, raw := e.post(&f.admin, c.path, c.body, nil); status != 400 && status != 422 {
			t.Errorf("%s: status %d, want 400/422: %s", name, status, raw)
		}
	}
	if e.revision() != before || e.state() != beforeState {
		t.Fatal("a malformed hold/resume request changed control state")
	}
}

func TestHoldRoutesWithoutAHoldManagerAreNotAvailable(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("holds-nomanager")
	var typedNil *retention.Service
	for name, deleter := range map[string]httpapi.Deleter{"deleter without holds": onlyDeleter{e.app.Retention}, "typed nil service": typedNil, "nil interface": nil} {
		srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
			httpapi.RegisterDeletionRoutes(mux, e.app.Auth, deleter)
		}).Handler)
		before := e.revision()
		for _, path := range []string{"/api/v1/admin/holds", "/api/v1/admin/holds/" + model.NewID().String() + "/release", "/api/v1/admin/deletions/" + model.NewID().String() + "/resume"} {
			raw, _ := json.Marshal(map[string]any{"command_id": model.NewID().String(), "expected_revision": e.rev(), "org_id": f.org.String(), "reason": "x"})
			req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(raw))
			req.Header.Set("Cookie", "__Host-soundpost="+f.admin.Session.Token)
			req.Header.Set("X-CSRF-Token", f.admin.Session.CSRF)
			req.Header.Set("Origin", srv.URL)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var na httpapi.DeletionNotAvailable
			if resp.StatusCode != http.StatusNotImplemented || model.StrictJSON(body, &na) != nil || na.State != "not_available" || na.Reason != httpapi.ReasonDeletionNotWired {
				t.Errorf("%s %s: %d %s", name, path, resp.StatusCode, body)
			}
		}
		if e.revision() != before {
			t.Errorf("%s: control state changed", name)
		}
		srv.Close()
	}
}

// onlyDeleter hides every method of the service but Delete.
type onlyDeleter struct{ inner httpapi.Deleter }

func (o onlyDeleter) Delete(ctx context.Context, scope auth.Scope, req retention.DeleteRequest) (retention.DeleteReceipt, error) {
	return o.inner.Delete(ctx, scope, req)
}

// The counting wrapper of the real service passes the hold and resume calls
// through, so the same wrapper serves the begin, hold and resume routes.
func (c *countingDeleter) PlaceHold(ctx context.Context, scope auth.Scope, r retention.HoldRequest) (model.ID, error) {
	return c.inner.(httpapi.HoldManager).PlaceHold(ctx, scope, r)
}

func (c *countingDeleter) ReleaseHold(ctx context.Context, scope auth.Scope, command model.ID, expected model.Revision, hold model.ID, reason string) error {
	return c.inner.(httpapi.HoldManager).ReleaseHold(ctx, scope, command, expected, hold, reason)
}

func (c *countingDeleter) Resume(ctx context.Context, scope auth.Scope, operation model.ID) (retention.DeleteReceipt, error) {
	return c.inner.(httpapi.HoldManager).Resume(ctx, scope, operation)
}
