// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
)

// These tests close the survivors of the independent mutation review of evidence.go (05.04#15, wave 20): the revalidation of every
// route, the scope helpers, the release register body checks. Each one names the product rule it holds; the mutant that each one
// kills is named in the wave 21 report.

// routesSensReleases is a labelled double of the release seams: the real release service, with a hook that runs after the last read
// of a view or after a registration, so a test can end the caller's session in the middle of a request.
type routesSensReleases struct {
	*releases.Service
	afterRead     func()
	afterRegister func()
}

func (h *routesSensReleases) Graph(ctx context.Context, scope auth.Scope, project model.ID) (releases.Graph, error) {
	g, err := h.Service.Graph(ctx, scope, project)
	if h.afterRead != nil {
		h.afterRead()
	}
	return g, err
}

func (h *routesSensReleases) Register(ctx context.Context, scope auth.Scope, release model.Release, expected model.Revision, command model.ID) (model.Release, error) {
	out, err := h.Service.Register(ctx, scope, release, expected, command)
	if h.afterRegister != nil {
		h.afterRegister()
	}
	return out, err
}

// routesSensIssues is the fake issue reader with a hook that runs after the read.
type routesSensIssues struct {
	*fakeIssues
	afterRead func()
}

func (h *routesSensIssues) GroupingIssue(ctx context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error) {
	issue, err := h.fakeIssues.GroupingIssue(ctx, scope, project, id)
	if h.afterRead != nil {
		h.afterRead()
	}
	return issue, err
}

// routesSensServe replaces the environment's evidence server with one over the given evidence seams.
func (e *evEnv) routesSensServe(t *testing.T, ev *httpapi.Evidence) {
	t.Helper()
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, ev)
		e.app.RegisterArtifactRoutes(mux)
	}).Handler)
	t.Cleanup(e.srv.Close)
}

func (e *evEnv) routesSensRevision() model.Revision {
	e.t.Helper()
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		e.t.Fatal(err)
	}
	return revision
}

// Every evidence route revalidates the caller's scope AFTER its read and before it answers: a session that ends while the view is
// being built is never answered with the view (release, issue, occurrence and the release register route).
func TestEvidenceSensRoutesRevalidateTheScopeAfterTheirRead(t *testing.T) {
	type world struct {
		e      *evEnv
		org, p model.ID
		admin  person
		issues *routesSensIssues
		rels   *routesSensReleases
		listed model.GroupingEvidence
	}
	setup := func(t *testing.T) world {
		e := newEvEnv(t, nil, nil, true)
		p := model.NewID()
		org := e.org("evidence sens revalidate", p)
		admin := e.user(org, "sens-revalidate-admin@example.test")
		e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
		e.grant(org, admin, p, true, auth.Read)
		fp := model.HashCanonical([]byte("sens fingerprint"))
		listed := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 1234, ArrivalTime: 2000, Ancestry: "unknown", Freshness: "fresh"}
		issues := &routesSensIssues{fakeIssues: &fakeIssues{}}
		issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 2, Occurrences: []model.GroupingEvidence{listed}}
		rels := &routesSensReleases{Service: e.app.Releases}
		errs := &fakeErrors{found: true, occ: model.ErrorOccurrence{Occurrence: listed.OccurrenceID, Class: "SensFailure", Mechanism: "manual", Frames: []model.Frame{}}}
		e.routesSensServe(t, httpapi.NewEvidence(nil, rels, issues, httpapi.WithErrorOccurrences(errs)))
		return world{e, org, p, admin, issues, rels, listed}
	}
	endSession := func(w world) func() {
		return func() {
			if err := w.e.app.Auth.Logout(w.e.ctx, w.admin.Session.Token); err != nil {
				t.Error(err)
			}
		}
	}
	refused := func(t *testing.T, w world, path string, body any, arm func()) {
		t.Helper()
		if status, raw := w.e.post(w.admin, path, body, nil); status != 200 {
			t.Fatalf("%s before the session ends: %d %s", path, status, raw)
		}
		arm()
		if status, raw := w.e.post(w.admin, path, body, nil); status == 200 {
			t.Fatalf("%s answered a caller whose session ended while the view was built: %s", path, raw)
		}
	}

	t.Run("release", func(t *testing.T) {
		w := setup(t)
		scope, err := w.e.scope(w.admin, w.org, w.p, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		rel := model.NewID()
		w.e.register(scope, model.Release{ID: rel, Org: w.org, Project: w.p, BuildID: model.NewID(), BuildTime: 5, DisplayLabel: "v1"})
		refused(t, w, "/api/v1/evidence/release", map[string]any{"org": w.org.String(), "project": w.p.String(), "release": rel.String()}, func() { w.rels.afterRead = endSession(w) })
	})
	t.Run("issue", func(t *testing.T) {
		w := setup(t)
		refused(t, w, "/api/v1/evidence/issue", map[string]any{"org": w.org.String(), "project": w.p.String(), "issue": w.issues.issue.ID.String()}, func() { w.issues.afterRead = endSession(w) })
	})
	t.Run("occurrence", func(t *testing.T) {
		w := setup(t)
		refused(t, w, "/api/v1/evidence/occurrence", map[string]any{"org": w.org.String(), "project": w.p.String(), "issue": w.issues.issue.ID.String(), "occurrence": w.listed.OccurrenceID.String()}, func() { w.issues.afterRead = endSession(w) })
	})
	t.Run("register", func(t *testing.T) {
		w := setup(t)
		register := func() map[string]any {
			return map[string]any{"org": w.org.String(), "project": w.p.String(), "command_id": model.NewID().String(), "expected_revision": model.Uint64(w.e.routesSensRevision()),
				"release": map[string]any{"id": model.NewID().String(), "org": w.org.String(), "project": w.p.String(), "build_id": model.NewID().String(), "parents": []string{}, "build_time_ns": "5", "debug_artifacts": []map[string]any{}, "display_label": "v1", "revision": "0"}}
		}
		if status, raw := w.e.post(w.admin, "/api/v1/releases/register", register(), nil); status != 200 {
			t.Fatalf("register before the session ends: %d %s", status, raw)
		}
		w.rels.afterRegister = endSession(w)
		if status, raw := w.e.post(w.admin, "/api/v1/releases/register", register(), nil); status == 200 {
			t.Fatalf("register answered a caller whose session ended during the commit: %s", raw)
		}
	})
}

// revalidateAll revalidates the administrator's scope AND the telemetry-read scope: either one gone is a refusal.
func TestEvidenceSensRevalidateAllChecksTheAdminScopeAndTheReadScope(t *testing.T) {
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("evidence sens revalidate all", p)
	admin := e.user(org, "sens-revalidate-all-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "sens-revalidate-all-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	adminScope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	readScope, err := e.scope(reader, org, p, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpapi.RevalidateAllForTest(e.ctx, e.app.Auth, adminScope, &readScope); err != nil {
		t.Fatalf("both scopes are standing: %v", err)
	}
	// The read scope's session ends; the administrator's scope still stands.
	if err := e.app.Auth.Logout(e.ctx, reader.Session.Token); err != nil {
		t.Fatal(err)
	}
	if err := httpapi.RevalidateAllForTest(e.ctx, e.app.Auth, adminScope, nil); err != nil {
		t.Fatalf("the administrator's scope alone must still stand: %v", err)
	}
	if err := httpapi.RevalidateAllForTest(e.ctx, e.app.Auth, adminScope, &readScope); err == nil {
		t.Fatal("a read scope whose session ended was accepted next to a standing administrator scope")
	}
	// The administrator's session ends too.
	if err := e.app.Auth.Logout(e.ctx, admin.Session.Token); err != nil {
		t.Fatal(err)
	}
	if err := httpapi.RevalidateAllForTest(e.ctx, e.app.Auth, adminScope, nil); err == nil {
		t.Fatal("an administrator scope whose session ended was accepted")
	}
}

// The evidence scope needs an organization and at least one project (Invalid, never an empty scope), and the telemetry-read scope
// that unlocks stored error records is only the caller's own: an administrator's grant, a project reader's scope; never one for a
// caller without telemetry.read.
func TestEvidenceSensScopeHelpersRefuseEmptyRequestsAndNeverWidenTheReadScope(t *testing.T) {
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("evidence sens scope helpers", p)
	admin := e.user(org, "sens-scope-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	bare := e.user(org, "sens-scope-bare@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: bare.ID, Enabled: true})
	reader := e.user(org, "sens-scope-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	writer := e.user(org, "sens-scope-writer@example.test")
	e.grant(org, writer, p, true, auth.IssuesWrite)

	if _, err := httpapi.EvidenceScopeForTest(e.ctx, e.app.Auth, admin.Cred, org, nil); faultCode(err) != model.Invalid {
		t.Fatalf("an evidence scope for no project: %v", err)
	}
	if _, err := httpapi.EvidenceScopeForTest(e.ctx, e.app.Auth, admin.Cred, model.ID{}, []model.ID{p}); faultCode(err) != model.Invalid {
		t.Fatalf("an evidence scope for no organization: %v", err)
	}

	adminScope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	read, err := httpapi.DetailScopeForTest(e.ctx, e.app.Auth, admin.Cred, adminScope, org, p)
	if err != nil || read == nil || read.Permission() != auth.Read {
		t.Fatalf("an administrator with telemetry.read: scope %v err %v", read, err)
	}
	bareScope, err := e.scope(bare, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if read, err = httpapi.DetailScopeForTest(e.ctx, e.app.Auth, bare.Cred, bareScope, org, p); err != nil || read != nil {
		t.Fatalf("an administrator without telemetry.read got a read scope: %v %v", read, err)
	}
	readerScope, err := e.scope(reader, org, p, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	// A project reader's own telemetry.read scope IS the detail read scope (D92: she reads her project's error issues and their
	// stored records); it is her scope as it is, never a wider one.
	if read, err = httpapi.DetailScopeForTest(e.ctx, e.app.Auth, reader.Cred, readerScope, org, p); err != nil || read == nil || read.Permission() != auth.Read || !read.AllowsProject(p) || len(read.ProjectIDs()) != 1 {
		t.Fatalf("a project reader's detail scope: %v %v", read, err)
	}
	// A person who holds only issues.write reads the issue but no stored record: no detail scope.
	writerScope, err := e.scope(writer, org, p, auth.IssuesWrite)
	if err != nil {
		t.Fatal(err)
	}
	if read, err = httpapi.DetailScopeForTest(e.ctx, e.app.Auth, writer.Cred, writerScope, org, p); err != nil || read != nil {
		t.Fatalf("an issues.write holder got the detail read scope: %v %v", read, err)
	}
}

// A body the decoder refuses (an unknown field) is refused with the one typed invalid fault by the issue route: the view is never
// served from the fields that did decode.
func TestEvidenceSensIssueRouteRefusesAMalformedBody(t *testing.T) {
	issues := &fakeIssues{}
	e := newEvEnv(t, nil, issues, true)
	p := model.NewID()
	org := e.org("evidence sens malformed", p)
	admin := e.user(org, "sens-malformed-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: model.HashCanonical([]byte("sens malformed")), Workflow: "open", Revision: 2}
	body := map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String()}
	if status, raw := e.post(admin, "/api/v1/evidence/issue", body, nil); status != 200 {
		t.Fatalf("the well-formed request: %d %s", status, raw)
	}
	body["unexpected_field"] = "x"
	status, raw := e.post(admin, "/api/v1/evidence/issue", body, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("a body with an unknown field: %d %s", status, raw)
	}
	var fault struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &fault); err != nil || fault.Code != string(model.Invalid) {
		t.Fatalf("the refusal is not the typed invalid fault: %s", raw)
	}
}

// The register route needs every identifying ID and refuses a release that names another organization or project than the request
// does: one typed invalid fault (release_ids_required), nothing committed, and never the not-found of an unrelated scope check.
func TestEvidenceSensRegisterRefusesMissingOrMismatchedIDs(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p, other := model.NewID(), model.NewID()
	org := e.org("evidence sens register ids", p, other)
	admin := e.user(org, "sens-register-ids-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	build := model.NewID()
	// An empty string leaves the field out of the body (a zero ID is refused by the decoder before the route's own check).
	body := func(orgID, project, command, releaseOrg, releaseProject string) map[string]any {
		set := func(m map[string]any, key, value string) {
			if value != "" {
				m[key] = value
			}
		}
		release := map[string]any{"id": model.NewID().String(), "build_id": build.String(), "parents": []string{}, "build_time_ns": "5", "debug_artifacts": []map[string]any{}, "display_label": "v1", "revision": "0"}
		set(release, "org", releaseOrg)
		set(release, "project", releaseProject)
		out := map[string]any{"expected_revision": model.Uint64(e.routesSensRevision()), "release": release}
		set(out, "org", orgID)
		set(out, "project", project)
		set(out, "command_id", command)
		return out
	}
	o, pr, c := org.String(), p.String(), model.NewID().String()
	if status, raw := e.post(admin, "/api/v1/releases/register", body(o, pr, c, o, pr), nil); status != 200 {
		t.Fatalf("the consistent request: %d %s", status, raw)
	}
	for name, b := range map[string]map[string]any{
		"no organization":                   body("", pr, model.NewID().String(), "", pr),
		"no project":                        body(o, "", model.NewID().String(), o, ""),
		"no command":                        body(o, pr, "", o, pr),
		"a release of another organization": body(o, pr, model.NewID().String(), model.NewID().String(), pr),
		"a release of another project":      body(o, pr, model.NewID().String(), o, other.String()),
	} {
		before := e.routesSensRevision()
		status, raw := e.post(admin, "/api/v1/releases/register", b, nil)
		var fault struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(raw, &fault); err != nil || status != http.StatusBadRequest || fault.Code != string(model.Invalid) || fault.Detail != "release_ids_required" {
			t.Fatalf("%s: %d %s, want the typed invalid fault release_ids_required", name, status, raw)
		}
		if after := e.routesSensRevision(); after != before {
			t.Fatalf("%s: a refused registration changed the control revision %d -> %d", name, before, after)
		}
	}
}

// A command that is retried (same command ID) answers the release it first committed: the view names the committed release, never
// the ID the retry's body carries.
func TestEvidenceSensRegisterViewNamesTheCommittedRelease(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("evidence sens register view", p)
	admin := e.user(org, "sens-register-view-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	command, expected := model.NewID(), model.Uint64(e.routesSensRevision())
	first, retried := model.NewID(), model.NewID()
	register := func(id model.ID) (int, []byte) {
		return e.post(admin, "/api/v1/releases/register", map[string]any{"org": org.String(), "project": p.String(), "command_id": command.String(), "expected_revision": expected,
			"release": map[string]any{"id": id.String(), "org": org.String(), "project": p.String(), "build_id": model.NewID().String(), "parents": []string{}, "build_time_ns": "5", "debug_artifacts": []map[string]any{}, "display_label": "v1", "revision": "0"}}, nil)
	}
	status, raw := register(first)
	var view httpapi.RegisterReleaseView
	if err := json.Unmarshal(raw, &view); err != nil || status != 200 || view.ID != first {
		t.Fatalf("first registration: %d %s", status, raw)
	}
	status, raw = register(retried)
	if err := json.Unmarshal(raw, &view); err != nil || status != 200 || view.ID != first {
		t.Fatalf("the retried command must answer the release it committed (%s): %d %s", first, status, raw)
	}
}

// flakyControl is a labelled double of the control store whose next reads fail as unavailable: the failure of one authorization
// that a later, identical one would not repeat.
type flakyControl struct {
	auth.ControlStore
	fails atomic.Int32
}

func (f *flakyControl) View(ctx context.Context, fn func(model.ControlState) error) error {
	for {
		n := f.fails.Load()
		if n <= 0 {
			return f.ControlStore.View(ctx, fn)
		}
		if f.fails.CompareAndSwap(n, n-1) {
			return model.Fail(model.Unavailable)
		}
	}
}

// An authorization that FAILED is the answer: the administrator scope is not replaced by the read scope derived by a second
// authorization that happens to succeed, and a failed telemetry-read authorization is not read as "she holds no telemetry.read".
func TestEvidenceSensScopeHelpersReturnAFailedAuthorizationNotAnotherScope(t *testing.T) {
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("evidence sens failed authorization", p)
	admin := e.user(org, "sens-failed-authz-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	flaky := &flakyControl{ControlStore: e.app.Control}
	service, err := auth.NewService(auth.AuthDependencies{Control: flaky})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := service.Authenticate(e.ctx, admin.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	adminScope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}

	if scope, err := httpapi.EvidenceScopeForTest(e.ctx, service, cred, org, []model.ID{p}); err != nil || scope.Permission() != auth.OrgAdmin {
		t.Fatalf("the administrator scope with a healthy store: %v %v", scope.Permission(), err)
	}
	flaky.fails.Store(1)
	if scope, err := httpapi.EvidenceScopeForTest(e.ctx, service, cred, org, []model.ID{p}); faultCode(err) != model.Unavailable {
		t.Fatalf("a failed administrator authorization was answered with scope %v err %v, want the failure", scope.Permission(), err)
	}
	flaky.fails.Store(0)

	if read, err := httpapi.DetailScopeForTest(e.ctx, service, cred, adminScope, org, p); err != nil || read == nil {
		t.Fatalf("the telemetry-read scope with a healthy store: %v %v", read, err)
	}
	flaky.fails.Store(1)
	if read, err := httpapi.DetailScopeForTest(e.ctx, service, cred, adminScope, org, p); faultCode(err) != model.Unavailable || read != nil {
		t.Fatalf("a failed telemetry-read authorization was read as an answer: %v %v, want the failure", read, err)
	}
}

// A failed artifact-read authorization (the store unavailable) is the answer of the frames view: it is not read as "not an artifact reader" and
// replaced by the telemetry-reader fallback that a second, successful authorization would give.
func TestEvidenceSensFramesReturnsAFailedAuthorizationInsteadOfTheTelemetryFallback(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("evidence sens frames failed authorization", p)
	reader := e.user(org, "sens-frames-failed-authz@example.test")
	e.grant(org, reader, p, true, auth.Read)
	flaky := &flakyControl{ControlStore: e.app.Control}
	service, err := auth.NewService(auth.AuthDependencies{Control: flaky})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := service.Authenticate(e.ctx, reader.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	column := uint32(7)
	body := httpapi.FramesBody{Org: org, Project: p, Build: model.NewID(), Frames: []model.Frame{{Module: "app", Function: "boom", Artifact: model.NewID().String(), Line: 3, Column: &column, InApp: true}}}
	ev := httpapi.NewEvidence(&fakeResolver{answer: mapFrames}, e.app.Releases, nil)
	if v, _, err := ev.Frames(e.ctx, service, cred, body); err != nil || v.State != httpapi.StateIncomplete {
		t.Fatalf("the telemetry reader with a healthy store: %+v %v", v, err)
	}
	flaky.fails.Store(1)
	if v, _, err := ev.Frames(e.ctx, service, cred, body); faultCode(err) != model.Unavailable {
		t.Fatalf("a failed artifact-read authorization was answered with %+v err %v, want the failure", v.State, err)
	}
}
