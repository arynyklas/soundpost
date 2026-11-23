// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

type consoleRig struct {
	t     *testing.T
	ctx   context.Context
	app   *App
	owner auth.Credential
	org   model.ID
	p, q  model.ID
}

func newConsoleRig(t *testing.T) *consoleRig {
	t.Helper()
	r := &consoleRig{t: t, ctx: context.Background(), org: model.NewID(), p: model.NewID(), q: model.NewID()}
	app, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	r.app = app
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(r.ctx, boot, "console-owner@example.test", "console owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	if r.owner, err = app.Auth.Authenticate(r.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	r.cmd("create_org", auth.AdminPayload{Name: "console"})
	r.cmd("create_project", auth.AdminPayload{ID: r.p, Name: "p"})
	r.cmd("create_project", auth.AdminPayload{ID: r.q, Name: "q"})
	return r
}

func (r *consoleRig) cmd(kind string, p auth.AdminPayload) {
	r.t.Helper()
	var revision model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	p.Reason = "console rig"
	raw, _ := json.Marshal(p)
	if _, err := r.app.Auth.AdminCommand(r.ctx, r.owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: r.org, Kind: kind, Payload: raw}); err != nil {
		r.t.Fatal(kind, err)
	}
}

// reader is a member with telemetry.read on project.
func (r *consoleRig) reader(email string, project model.ID) auth.Credential {
	r.t.Helper()
	id := model.NewID()
	r.cmd("create_user", auth.AdminPayload{ID: id, Email: email, Password: "console reader password"})
	r.cmd("membership", auth.AdminPayload{UserID: id, Enabled: true})
	r.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := r.app.Auth.Login(r.ctx, email, "console reader password", "")
	if err != nil {
		r.t.Fatal(err)
	}
	c, err := r.app.Auth.Authenticate(r.ctx, login.Token)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *consoleRig) scope(c auth.Credential, project model.ID, permission auth.Permission) auth.Scope {
	r.t.Helper()
	s, err := r.app.Auth.Authorize(r.ctx, c, r.org, []model.ID{project}, permission)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// register commits a release with a debug artifact and a label history through the real registry.
func (r *consoleRig) register(project model.ID, label string, at int64, parents ...model.ID) model.ID {
	r.t.Helper()
	id := model.NewID()
	var revision model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	rel := model.Release{ID: id, Org: r.org, Project: project, BuildID: model.NewID(), Parents: parents, BuildTime: model.UnixNano(at), DisplayLabel: label,
		DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: model.NewID(), DebugID: "debug-" + label, SHA256: model.HashCanonical([]byte(label))}}}
	if _, err := r.app.Releases.Register(r.ctx, r.scope(r.owner, project, auth.OrgAdmin), rel, revision, model.NewID()); err != nil {
		r.t.Fatal(err)
	}
	return id
}

func TestReleaseListSourceReadsRecordsWithoutDebugArtifactsUnderTheCallersScope(t *testing.T) {
	r := newConsoleRig(t)
	reader := r.reader("source-reader@example.test", r.p)
	root := r.register(r.p, "v1", 10)
	child := r.register(r.p, "v2", 20, root)
	r.register(r.q, "other project", 30)
	source := &releaseListSource{app: r.app}
	if svc, err := r.app.NewIssueActions(releaseActionClock{}); err != nil {
		t.Fatal(err)
	} else {
		source.explain = svc
	}

	data, err := source.ReleaseList(r.ctx, r.scope(reader, r.p, auth.Read), r.p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Releases) != 2 || data.Capped || !data.IssuesKnown || len(data.Issues) != 0 {
		t.Fatalf("data: %+v", data)
	}
	for _, rel := range data.Releases {
		if rel.Project != r.p || len(rel.DebugArtifacts) != 0 || len(rel.History) != 0 {
			t.Fatalf("a registry record leaked into the list: %+v", rel)
		}
		if rel.ID == child && (len(rel.Parents) != 1 || rel.Parents[0] != root || rel.DisplayLabel != "v2" || rel.BuildTime != 20) {
			t.Fatalf("child: %+v", rel)
		}
	}
	// Without the issue lifecycle the counts are unknown, not an empty list of issues.
	bare := &releaseListSource{app: r.app}
	if data, err = bare.ReleaseList(r.ctx, r.scope(reader, r.p, auth.Read), r.p); err != nil || data.IssuesKnown || len(data.Releases) != 2 {
		t.Fatalf("no lifecycle: %+v %v", data, err)
	}
	// The other project is outside the reader's scope, whatever the caller asks: the same not-found.
	if _, err = source.ReleaseList(r.ctx, r.scope(reader, r.p, auth.Read), r.q); err == nil || err.(*model.Fault).Code != model.NotFound {
		t.Fatalf("a project outside the scope: %v", err)
	}
	// A scope whose grant was revoked after it was derived reads nothing.
	scope := r.scope(reader, r.p, auth.Read)
	id := scope.PrincipalID()
	r.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: r.p, Enabled: false})
	if _, err = source.ReleaseList(r.ctx, scope, r.p); err == nil {
		t.Fatal("a revoked scope listed releases")
	}
	// An organization administrator reads the other project's own releases only.
	if data, err = source.ReleaseList(r.ctx, r.scope(r.owner, r.q, auth.OrgAdmin), r.q); err != nil || len(data.Releases) != 1 || data.Releases[0].DisplayLabel != "other project" {
		t.Fatalf("project q: %+v %v", data, err)
	}
	// A retired project is not found.
	if err = r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		o := st.Orgs[r.org.String()]
		delete(o.Projects, r.q.String())
		st.Orgs[r.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = source.ReleaseList(r.ctx, r.scope(r.owner, r.p, auth.OrgAdmin), r.q); err == nil || err.(*model.Fault).Code != model.NotFound {
		t.Fatalf("a retired project: %v", err)
	}
}

func TestConsoleRegistersTheDirectoryAndDeployRoutes(t *testing.T) {
	r := newConsoleRig(t)
	mux := http.NewServeMux()
	r.app.registerDirectoryConsole(mux, ConsoleConfig{})
	r.app.registerDeployConsole(mux, ConsoleConfig{})
	for _, path := range []string{"/api/v1/directory", "/api/v1/directory/names", "/api/v1/releases/deploys", "/api/v1/releases/list"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("%s is not mounted", path)
		}
	}
	// And they answer: no credential is a refusal, never a 404 for a missing route.
	var _ httpapi.ReleaseListSource = &releaseListSource{}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/releases/list", nil))
	if rec.Code < 400 || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("anonymous release list: %d", rec.Code)
	}
}
