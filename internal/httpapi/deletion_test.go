// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

const deletionCanary = "CANARY-del-7f3a91c2e4b8"

// countingDeleter wraps the REAL retention service: it only counts how often an
// authority decision let a request reach Delete, so a denial is proven to have
// stopped in the handler and not merely to have been refused later by the
// service.
type countingDeleter struct {
	inner httpapi.Deleter
	calls atomic.Int64
}

func (c *countingDeleter) Delete(ctx context.Context, scope auth.Scope, req retention.DeleteRequest) (retention.DeleteReceipt, error) {
	c.calls.Add(1)
	return c.inner.Delete(ctx, scope, req)
}

// delEnv serves POST /api/v1/admin/deletions and the existing lifecycle poll
// over the real app (real auth, real control store, real retention service) on
// a second TLS server; the isoEnv server keeps serving ingest and capabilities
// so a test can prove data is actually denied.
type delEnv struct {
	*isoEnv
	srv     *httptest.Server
	deleter *countingDeleter
}

func newDelEnv(t *testing.T) *delEnv {
	t.Helper()
	e := &delEnv{isoEnv: newIsoEnv(t)}
	e.deleter = &countingDeleter{inner: e.app.Retention}
	actions, err := httpapi.NewActions(e.app.Incidents, e.app.Control, e.app.Control, e.app.Retention, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterDeletionRoutes(mux, e.app.Auth, e.deleter)
		httpapi.RegisterActionRoutes(mux, e.app.Auth, actions)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *delEnv) revision() model.Revision {
	e.t.Helper()
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		e.t.Fatal(err)
	}
	return revision
}

func (e *delEnv) state() string {
	e.t.Helper()
	var raw []byte
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) (err error) { raw, err = json.Marshal(st); return }); err != nil {
		e.t.Fatal(err)
	}
	return string(raw)
}

func (e *delEnv) deletions() int {
	e.t.Helper()
	var n int
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { n = len(st.Deletions); return nil }); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// raw posts body bytes to the deletion route. A nil person sends no credential.
func (e *delEnv) raw(who *person, srv *httptest.Server, body []byte, mutate func(*http.Request)) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/admin/deletions", bytes.NewReader(body))
	if who != nil {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", srv.URL)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *delEnv) begin(who *person, body map[string]any, mutate func(*http.Request)) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.raw(who, e.srv, raw, mutate)
}

// retire is a well-formed retire_project body at the CURRENT revision.
func (e *delEnv) retire(org model.ID, projects ...model.ID) map[string]any {
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	return map[string]any{"command_id": model.NewID().String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteRetireProject,
		"org_id": org.String(), "project_ids": ids, "reason": "operator erasure request"}
}

func (e *delEnv) orgAdmin(org model.ID, who person) {
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: who.ID, Enabled: true})
}

func (e *delEnv) poll(who person, org, operation model.ID) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/lifecycle/operations/"+operation.String()+"?org="+org.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *delEnv) receipt(status, want int, raw []byte) httpapi.DeletionReceipt {
	e.t.Helper()
	if status != want {
		e.t.Fatalf("status %d, want %d: %s", status, want, raw)
	}
	var r httpapi.DeletionReceipt
	if err := model.StrictJSON(raw, &r); err != nil {
		e.t.Fatalf("receipt is not the closed DTO: %v %s", err, raw)
	}
	return r
}

// readStatus is a real HTTPS read of the project's capabilities as who.
func (e *delEnv) readStatus(who person, org, project model.ID) int {
	e.t.Helper()
	status, _, _ := e.call(who, "GET", "/api/v1/capabilities?org="+org.String()+"&project="+project.String(), nil)
	return status
}

// ingestStatus posts one metric with the source's own credential.
func (e *delEnv) ingestStatus(s sourceFixture, name string) int {
	e.t.Helper()
	value := model.FloatBits(0x3ff0000000000000)
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(e.tick.Add(1)), Resource: e.resource(s), Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}
	batch := model.Batch{Version: 1, Project: s.Project, Source: s.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(s.Org, s.Project, s.ID, batch.Producer, record); err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", e.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+s.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// fixture builds one org with one project that holds ingested data, an org
// admin session (the bootstrap owner, who created the org), a member who can
// read the project, and a source credential.
type delFixture struct {
	org, project model.ID
	admin        person
	member       person
	source       sourceFixture
}

func (e *delEnv) fixture(name string) delFixture {
	e.t.Helper()
	project := model.NewID()
	org := e.org(name, project)
	member := e.user(org, name+"-member@example.test")
	e.grant(org, member, project, true, auth.Read)
	source := e.source(org, project, sharedIDs{model.NewID(), model.NewID(), model.NewID()}, []model.Kind{model.Metric})
	e.metric(source, "before_deletion")
	return delFixture{org: org, project: project, admin: e.actor, member: member, source: source}
}

func TestDeletionRouteBeginsARealSaga(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("saga")
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("control: the member cannot read before the deletion: %d", got)
	}
	if got := e.ingestStatus(f.source, "control_before"); got != 200 {
		t.Fatalf("control: the source cannot ingest before the deletion: %d", got)
	}
	body := e.retire(f.org, f.project)
	status, raw := e.begin(&f.admin, body, nil)
	r := e.receipt(status, 202, raw)
	if r.Phase != model.DeletePhaseFencing || r.OperationID.String() != body["command_id"] || r.Generation == 0 || r.PhysicalDeadline == 0 || r.BackupDeadline <= r.PhysicalDeadline {
		t.Fatalf("not a fencing receipt for this command: %s", raw)
	}
	if r.Mode != model.DeleteRetireProject {
		t.Fatalf("mode: %s", raw)
	}
	// The data is denied now, not merely receipted: a read and a write of the
	// erased project answer the same way as a project that never existed.
	if got := e.readStatus(f.member, f.org, f.project); got != 404 {
		t.Fatalf("a member's read of the retired project answers %d, want 404", got)
	}
	if got := e.ingestStatus(f.source, "after_deletion"); got == 200 {
		t.Fatalf("a retired project still accepts writes")
	}
	pollStatus, pollRaw := e.poll(f.admin, f.org, r.OperationID)
	if pollStatus != 200 || !strings.Contains(string(pollRaw), `"phase":"fencing"`) && !strings.Contains(string(pollRaw), `"phase":"complete"`) || !strings.Contains(string(pollRaw), r.OperationID.String()) {
		t.Fatalf("the lifecycle poll does not show the operation: %d %s", pollStatus, pollRaw)
	}
	if e.deletions() != 1 || e.deleter.calls.Load() != 1 {
		t.Fatalf("expected exactly one committed saga, got %d (calls %d)", e.deletions(), e.deleter.calls.Load())
	}
	// A second organization's project is untouched.
	other := e.fixture("saga-bystander")
	if got := e.readStatus(other.member, other.org, other.project); got != 200 {
		t.Fatalf("a bystander org lost reads: %d", got)
	}
}

func TestDeletionRouteRefusesMembersReadOnlyAndForeignOrgs(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("matrix")
	stranger := e.org("matrix-other", model.NewID())
	foreign := e.user(stranger, "matrix-foreign-admin@example.test")
	e.orgAdmin(stranger, foreign)
	// A server token whose principal IS an org admin but whose permission is
	// read-only.
	tokenAdmin := e.user(f.org, "matrix-token-admin@example.test")
	e.orgAdmin(f.org, tokenAdmin)
	e.grant(f.org, tokenAdmin, f.project, true, auth.Read)
	issued, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, f.org, tokenAdmin.ID, []model.ID{f.project}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "matrix read-only token")
	if err != nil {
		t.Fatal(err)
	}
	stale := e.user(f.org, "matrix-stale-admin@example.test")
	e.orgAdmin(f.org, stale)
	if err = e.app.Control.Update(e.ctx, func(st *model.ControlState) error {
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
	before, beforeState := e.revision(), e.state()
	ghost := model.NewID()
	body := func(org model.ID) map[string]any {
		b := e.retire(org, f.project)
		b["reason"] = deletionCanary
		return b
	}
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
		{"wrong CSRF token", &f.admin, f.org, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "not-the-token") }, 403},
		{"foreign Origin", &f.admin, f.org, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{"no Origin", &f.admin, f.org, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"no session", nil, f.org, nil, 401},
		{"read-only server token of an org admin", nil, f.org, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+issued.Token) }, 403},
		{"org admin whose session is no longer fresh", &stale, f.org, nil, 403},
	}
	var shapes = map[string]string{}
	for _, c := range cases {
		status, raw := e.begin(c.who, body(c.org), c.mutate)
		if status != c.status {
			t.Errorf("%s: status %d, want %d: %s", c.name, status, c.status, raw)
		}
		if strings.Contains(string(raw), deletionCanary) || strings.Contains(string(raw), f.project.String()) {
			t.Errorf("%s: the refusal echoes the request: %s", c.name, raw)
		}
		var fault model.Fault
		if json.Unmarshal(raw, &fault) != nil || fault.Code == "" {
			t.Errorf("%s: not a typed fault: %s", c.name, raw)
		}
		shapes[c.name] = denial(t, status, raw)
		if got := e.revision(); got != before {
			t.Fatalf("%s: a control command was committed (revision %d -> %d)", c.name, before, got)
		}
	}
	// Foreign org, member and a guessed org are one and the same answer.
	if shapes["another organization's admin"] != shapes["admin of a guessed organization"] || shapes["ordinary member with a read grant"] != shapes["admin of a guessed organization"] {
		t.Errorf("org denial distinguishes a real org from a missing one: %v", shapes)
	}
	if e.deleter.calls.Load() != 0 {
		t.Fatalf("a refused request reached the deletion service %d times", e.deleter.calls.Load())
	}
	if e.deletions() != 0 || e.state() != beforeState {
		t.Fatalf("a refused request changed control state")
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("a refused request denied reads: %d", got)
	}
	// Control: the same well-formed request from the real admin works.
	status, raw := e.begin(&f.admin, e.retire(f.org, f.project), nil)
	e.receipt(status, 202, raw)
}

func TestDeletionRouteIsIdempotentOnCommandID(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("idem")
	body := e.retire(f.org, f.project)
	status, raw := e.begin(&f.admin, body, nil)
	first := e.receipt(status, 202, raw)
	// The revision moved on (the first call committed), so the retry carries a
	// stale expected_revision and is still answered from the original command.
	// (control's replicated Update proposes a no-op entry for any replay and
	// bumps the revision; the saga and its audit must not be duplicated.)
	status, raw = e.begin(&f.admin, body, nil)
	second := e.receipt(status, 202, raw)
	if second.OperationID != first.OperationID || second.Generation != first.Generation || second.PhysicalDeadline != first.PhysicalDeadline || second.BackupDeadline != first.BackupDeadline || second.Mode != first.Mode {
		t.Fatalf("the retry is not the original receipt:\n%+v\n%+v", first, second)
	}
	if e.deletions() != 1 || e.auditCount("delete.begin") != 1 || e.deleter.calls.Load() != 2 {
		t.Fatalf("the retry began another saga: deletions %d, begin audits %d", e.deletions(), e.auditCount("delete.begin"))
	}
	// Another organization's admin cannot replay (or learn about) this command.
	stranger := e.org("idem-other", model.NewID())
	foreign := e.user(stranger, "idem-foreign@example.test")
	e.orgAdmin(stranger, foreign)
	replay := e.retire(stranger, model.NewID())
	replay["command_id"] = body["command_id"]
	status, raw = e.begin(&foreign, replay, nil)
	if status == 200 || status == 202 || strings.Contains(string(raw), first.OperationID.String()) {
		t.Fatalf("a foreign org replayed the command: %d %s", status, raw)
	}
	if e.deletions() != 1 {
		t.Fatalf("deletions: %d", e.deletions())
	}
}

func TestDeletionRouteIsClosed(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("closed")
	before, beforeState := e.revision(), e.state()
	good := func() map[string]any { return e.retire(f.org, f.project) }
	with := func(k string, v any) map[string]any { b := good(); b[k] = v; return b }
	without := func(k string) map[string]any { b := good(); delete(b, k); return b }
	canaryBody := with("mode", "nuke_"+deletionCanary)
	canaryBody["reason"] = deletionCanary
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown field", mustJSON(with("extra", deletionCanary))},
		{"unknown field with canary name", mustJSON(with(deletionCanary, "x"))},
		{"mode not in the closed set", mustJSON(with("mode", "wipe_everything"))},
		{"canary in a bad mode", mustJSON(canaryBody)},
		{"empty mode", mustJSON(with("mode", ""))},
		{"missing reason", mustJSON(without("reason"))},
		{"empty reason", mustJSON(with("reason", ""))},
		{"blank reason", mustJSON(with("reason", "   \t "))},
		{"reason over 512 bytes", mustJSON(with("reason", strings.Repeat("r", 513)))},
		{"oversized body", mustJSON(with("reason", strings.Repeat("r", 70000)))},
		{"valid body padded past the 64 KiB limit", append(mustJSON(good()), bytes.Repeat([]byte(" "), 70000)...)},
		{"missing command id", mustJSON(without("command_id"))},
		{"zero command id", mustJSON(with("command_id", "00000000000000000000000000"))},
		{"missing org", mustJSON(without("org_id"))},
		{"expected revision as a JSON number", []byte(strings.Replace(string(mustJSON(good())), `"expected_revision":"`+strconv.FormatUint(uint64(before), 10)+`"`, `"expected_revision":`+strconv.FormatUint(uint64(before), 10), 1))},
		{"expected revision with a leading zero", mustJSON(with("expected_revision", "0"+strconv.FormatUint(uint64(before), 10)))},
		{"expected revision negative", mustJSON(with("expected_revision", "-1"))},
		{"expected revision fractional", mustJSON(with("expected_revision", "1.0"))},
		{"expected revision overflow", mustJSON(with("expected_revision", "18446744073709551616"))},
		{"start as a JSON number", []byte(`{"command_id":"` + model.NewID().String() + `","expected_revision":"1","mode":"historical_range","org_id":"` + f.org.String() + `","project_ids":["` + f.project.String() + `"],"signals":["metric"],"start_ns":5,"end_ns":"9","reason":"r"}`)},
		{"retire_project without projects", mustJSON(without("project_ids"))},
		{"retire_project with entities", mustJSON(with("entity_ids", []string{model.NewID().String()}))},
		{"retire_org with projects", mustJSON(with("mode", model.DeleteRetireOrg))},
		{"historical_range without signals", mustJSON(with("mode", model.DeleteHistoricalRange))},
		{"duplicate project", mustJSON(with("project_ids", []string{f.project.String(), f.project.String()}))},
		{"project id not an id", mustJSON(with("project_ids", []string{"not-an-id"}))},
		{"unknown signal", mustJSON(with("signals", []string{"telepathy"}))},
		{"too many projects", mustJSON(with("project_ids", manyIDs(129)))},
		{"trailing second value", append(mustJSON(good()), []byte(`{}`)...)},
		{"trailing garbage", append(mustJSON(good()), []byte(`x`)...)},
		{"not an object", []byte(`[]`)},
		{"null", []byte(`null`)},
		{"empty body", nil},
		{"not json", []byte(`mode=retire_project`)},
	}
	for _, c := range cases {
		status, raw := e.raw(&f.admin, e.srv, c.body, nil)
		if status != 400 && status != 422 {
			t.Errorf("%s: status %d, want 400/422: %.200s", c.name, status, raw)
		}
		if strings.Contains(string(raw), deletionCanary) || strings.Contains(string(raw), "wipe_everything") || strings.Contains(string(raw), f.project.String()) {
			t.Errorf("%s: the refusal echoes the request: %s", c.name, raw)
		}
		if got := e.revision(); got != before {
			t.Fatalf("%s: a control command was committed (%d -> %d)", c.name, before, got)
		}
	}
	if e.deleter.calls.Load() != 0 || e.deletions() != 0 || e.state() != beforeState {
		t.Fatalf("a malformed request reached the service or changed state (calls %d)", e.deleter.calls.Load())
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("a malformed request denied reads: %d", got)
	}
	// The same payload, well formed, is accepted (the cases fail for their flaw only).
	status, raw := e.begin(&f.admin, good(), nil)
	e.receipt(status, 202, raw)
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = model.NewID().String()
	}
	return out
}

func TestDeletionRouteWithoutADeleterIsNotAvailable(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("nodeleter")
	var typedNil *retention.Service
	for name, deleter := range map[string]httpapi.Deleter{"nil interface": nil, "typed nil service": typedNil} {
		srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
			httpapi.RegisterDeletionRoutes(mux, e.app.Auth, deleter)
		}).Handler)
		before := e.revision()
		body := mustJSON(e.retire(f.org, f.project))
		status, raw := e.raw(&f.admin, srv, body, nil)
		var out httpapi.DeletionNotAvailable
		if status != http.StatusNotImplemented || model.StrictJSON(raw, &out) != nil || out.State != "not_available" || out.Reason != httpapi.ReasonDeletionNotWired {
			t.Errorf("%s: %d %s", name, status, raw)
		}
		// Not available discloses nothing to an unauthenticated caller either.
		if status, _ = e.raw(nil, srv, body, nil); status != 401 {
			t.Errorf("%s: an anonymous caller learns the wiring: %d", name, status)
		}
		if e.revision() != before || e.deletions() != 0 {
			t.Errorf("%s: state changed", name)
		}
		srv.Close()
	}
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("reads denied: %d", got)
	}
}

func TestDeletionRouteReportsAHeldDeletionAsConflict(t *testing.T) {
	e := newDelEnv(t)
	f := e.fixture("held")
	scope, err := e.app.Auth.Authorize(e.ctx, f.admin.Cred, f.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := e.app.Retention.PlaceHold(e.ctx, scope, retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: e.revision(), ProjectIDs: []model.ID{f.project}, Reason: "litigation hold"})
	if err != nil {
		t.Fatal(err)
	}
	body := e.retire(f.org, f.project)
	status, raw := e.begin(&f.admin, body, nil)
	if status != 409 {
		t.Fatalf("a held deletion answers %d, want 409: %s", status, raw)
	}
	var refused httpapi.DeletionRefused
	if err = model.StrictJSON(raw, &refused); err != nil {
		t.Fatalf("held body is not the closed DTO: %v %s", err, raw)
	}
	if refused.Code != string(model.Conflict) || refused.Detail != httpapi.DetailDeletionHeld || refused.Receipt.Phase != model.DeletePhaseHeld || len(refused.Receipt.Holds) != 1 || refused.Receipt.Holds[0] != hold || refused.Receipt.OperationID.String() != body["command_id"] {
		t.Fatalf("the held reason is not typed: %s", raw)
	}
	// Held is not fencing: the data is still readable and the poll says held.
	if got := e.readStatus(f.member, f.org, f.project); got != 200 {
		t.Fatalf("a held deletion already denied reads: %d", got)
	}
	pollStatus, pollRaw := e.poll(f.admin, f.org, refused.Receipt.OperationID)
	if pollStatus != 200 || !strings.Contains(string(pollRaw), `"phase":"held"`) {
		t.Fatalf("the poll does not show held: %d %s", pollStatus, pollRaw)
	}
	// The retry of the same command is still the held receipt, not a new saga.
	status, raw = e.begin(&f.admin, body, nil)
	if status != 409 || !strings.Contains(string(raw), httpapi.DetailDeletionHeld) || e.deletions() != 1 {
		t.Fatalf("retry of a held command: %d %s deletions %d", status, raw, e.deletions())
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The reason IS stored in the deletion operation and its audit entry (the
// contract), and nowhere else: never in an error body, never in the process
// log, never in a refused request's trace in control state.
func TestDeletionRouteNeverEchoesTheCanary(t *testing.T) {
	logs := &safeBuffer{}
	oldWriter, oldFlags, oldSlog := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags); slog.SetDefault(oldSlog) })
	e := newDelEnv(t)
	f := e.fixture("canary")
	stranger := e.org("canary-other", model.NewID())
	foreign := e.user(stranger, "canary-foreign@example.test")
	e.orgAdmin(stranger, foreign)
	refused := []struct {
		who  *person
		body map[string]any
		mut  func(*http.Request)
	}{
		{&f.admin, func() map[string]any { b := e.retire(f.org, f.project); b[deletionCanary] = deletionCanary; return b }(), nil},
		{&f.admin, func() map[string]any {
			b := e.retire(f.org, f.project)
			b["mode"] = deletionCanary
			b["reason"] = deletionCanary
			return b
		}(), nil},
		{&foreign, func() map[string]any { b := e.retire(f.org, f.project); b["reason"] = deletionCanary; return b }(), nil},
		{&f.member, func() map[string]any { b := e.retire(f.org, f.project); b["reason"] = deletionCanary; return b }(), nil},
		{&f.admin, func() map[string]any { b := e.retire(f.org, f.project); b["reason"] = deletionCanary; return b }(), func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
		{nil, func() map[string]any { b := e.retire(f.org, f.project); b["reason"] = deletionCanary; return b }(), nil},
		{&f.admin, func() map[string]any {
			b := e.retire(f.org, f.project)
			b["reason"] = deletionCanary + strings.Repeat("x", 600)
			return b
		}(), nil},
	}
	for i, c := range refused {
		status, raw := e.begin(c.who, c.body, c.mut)
		if status < 400 || strings.Contains(string(raw), deletionCanary) {
			t.Fatalf("refused case %d: %d %s", i, status, raw)
		}
	}
	if strings.Contains(e.state(), deletionCanary) {
		t.Fatalf("a refused request left the canary in control state")
	}
	// The accepted one stores the reason in the operation and its audit only.
	ok := e.retire(f.org, f.project)
	ok["reason"] = deletionCanary
	status, raw := e.begin(&f.admin, ok, nil)
	e.receipt(status, 202, raw)
	if strings.Contains(string(raw), deletionCanary) {
		t.Fatalf("the receipt echoes the reason: %s", raw)
	}
	if pollStatus, pollRaw := e.poll(f.admin, f.org, e.mustID(ok["command_id"])); pollStatus != 200 || strings.Contains(string(pollRaw), deletionCanary) {
		t.Fatalf("the poll echoes the reason: %d %s", pollStatus, pollRaw)
	}
	var stored, audits int
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, op := range st.Deletions {
			if strings.Contains(op.Reason, deletionCanary) {
				stored++
			}
		}
		for _, a := range st.Audits {
			if strings.Contains(a.Reason, deletionCanary) {
				audits++
				if a.Action != "delete.begin" || a.Org != f.org.String() {
					t.Errorf("the reason is in an unexpected audit entry: %+v", a)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if stored != 1 || audits != 1 {
		t.Fatalf("the reason is stored in %d operations and %d audits, want exactly 1 each", stored, audits)
	}
	if strings.Contains(logs.String(), deletionCanary) {
		t.Fatalf("the process log carries the canary: %s", logs.String())
	}
}

func (e *delEnv) mustID(v any) model.ID {
	e.t.Helper()
	id, err := model.ParseID(v.(string))
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *delEnv) auditCount(action string) int {
	e.t.Helper()
	var n int
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == action {
				n++
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}
