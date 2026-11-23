// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// releaseTokenWorld is a releaseWorld whose server also mounts the token routes, with an
// administrator as the principal of the tokens (the release registry commits as an organization administrator).
type releaseTokenWorld struct {
	*releaseWorld
	other model.ID // a second project of the organization
}

func newReleaseTokenWorld(t *testing.T) *releaseTokenWorld {
	t.Helper()
	w := newReleaseWorld(t)
	w.e.srv.Close()
	w.e.srv = httptest.NewTLSServer(httpapi.NewServer("", w.e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterDirectoryRoutes(mux, w.e.app.Auth)
		httpapi.RegisterDeployRoutes(mux, w.e.app.Auth)
		httpapi.RegisterReleaseListRoute(mux, w.e.app.Auth, w.source, w.e.cache)
		httpapi.RegisterEvidenceRoutes(mux, w.e.app.Auth, httpapi.NewEvidence(nil, w.e.app.Releases, nil))
	}).Handler)
	t.Cleanup(w.e.srv.Close)
	return &releaseTokenWorld{releaseWorld: w, other: w.q}
}

func (w *releaseTokenWorld) issue(org model.ID, principal model.ID, projects []model.ID, perms ...auth.Permission) (auth.IssuedServerToken, func(*http.Request)) {
	w.e.t.Helper()
	issued, err := w.e.app.Auth.IssueServerToken(w.e.ctx, w.e.actor.Cred, org, principal, projects, perms, time.Now().Add(time.Hour).Unix(), "ci pipeline")
	if err != nil {
		w.e.t.Fatal(err)
	}
	return issued, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+issued.Token) }
}

func (w *releaseTokenWorld) revision() model.Uint64 {
	var r model.Revision
	if err := w.e.app.Control.View(w.e.ctx, func(st model.ControlState) error { r = st.Revision; return nil }); err != nil {
		w.e.t.Fatal(err)
	}
	return model.Uint64(r)
}

func (w *releaseTokenWorld) register(bearer func(*http.Request), org, project model.ID) (int, []byte) {
	rel := map[string]any{"id": model.NewID().String(), "org": org.String(), "project": project.String(), "build_id": model.NewID().String(), "parents": []string{}, "build_time_ns": "9",
		"debug_artifacts": []map[string]any{}, "display_label": "ci build", "revision": "0"}
	return w.e.post(person{}, "/api/v1/releases/register", map[string]any{"org": org.String(), "project": project.String(), "command_id": model.NewID().String(), "expected_revision": w.revision(), "release": rel}, bearer)
}

func (w *releaseTokenWorld) record(bearer func(*http.Request), org, project, release model.ID) (int, []byte) {
	return w.e.post(person{}, "/api/v1/releases/deploys", map[string]any{"op": "record", "org": org.String(), "project": project.String(), "release": release.String(), "environment": w.env.String(), "command_id": model.NewID().String()}, bearer)
}

func TestReleaseWriteTokenRegistersAndRecordsOnlyForItsProject(t *testing.T) {
	w := newReleaseTokenWorld(t)
	issued, bearer := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	_ = issued

	if status, raw := w.register(bearer, w.org, w.p); status != 200 {
		t.Fatalf("a release.write token registers a release of its project: %d %s", status, raw)
	}
	if status, raw := w.record(bearer, w.org, w.p, w.r2); status != 200 {
		t.Fatalf("a release.write token records a deploy of its project: %d %s", status, raw)
	}
	// Another project of the same organization, another organization, an unknown project: the same refusal.
	other := model.NewID()
	for name, c := range map[string]struct{ org, project model.ID }{
		"another project":      {w.org, w.q},
		"another organization": {w.orgB, w.p},
		"unknown project":      {w.org, other},
	} {
		if status, raw := w.register(bearer, c.org, c.project); status != 404 {
			t.Errorf("register, %s: %d %s", name, status, raw)
		}
		if status, raw := w.record(bearer, c.org, c.project, w.r2); status != 404 {
			t.Errorf("record, %s: %d %s", name, status, raw)
		}
	}
	// The audit of the use names the token's principal; the use is the existing register/deploy audit.
	seen := map[string]bool{}
	for _, a := range auditsOf(t, w.e, w.org) {
		if a.Principal == w.admin.ID {
			seen[a.Action] = true
		}
	}
	if !seen["releases.register"] || !seen["releases.deploy"] {
		t.Fatalf("the use of the grant is audited: %v", seen)
	}
}

func TestReleaseWriteTokenRefusals(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	_, good := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	wrong := map[string]func(*http.Request){}
	_, wrong["telemetry.ingest"] = w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.Permission("telemetry.ingest"))
	_, wrong["artifacts.write"] = w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ArtifactWrite)
	_, wrong["telemetry.read"] = w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.Read)
	for name, bearer := range wrong {
		if status, raw := w.register(bearer, w.org, w.p); status != 404 {
			t.Errorf("register with a %s token: %d %s", name, status, raw)
		}
		if status, raw := w.record(bearer, w.org, w.p, w.r2); status != 404 {
			t.Errorf("record with a %s token: %d %s", name, status, raw)
		}
	}
	// A principal that is not an organization administrator: the registry would refuse it, so does the grant.
	_, member := w.issue(w.org, w.reader.ID, []model.ID{w.p}, auth.ReleaseWrite)
	if status, raw := w.register(member, w.org, w.p); status != 404 {
		t.Errorf("a token of a plain member registered a release: %d %s", status, raw)
	}
	// A human session cannot use the token path and a token cannot be used as a session.
	cred, err := e.app.Auth.Authenticate(e.ctx, w.reader.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.app.Auth.AuthorizeRelease(e.ctx, cred, w.org, w.p, auth.OrgAdmin); err == nil {
		t.Fatal("a session derived a release-write scope")
	}

	// Expired and revoked tokens are refused.
	issued, expiring := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	if status, raw := w.register(expiring, w.org, w.p); status != 200 {
		t.Fatalf("before the expiry: %d %s", status, raw)
	}
	if err = e.app.Control.Update(e.ctx, func(st *model.ControlState) error {
		for k, tok := range st.ServerTokens {
			if tok.ID == issued.ID {
				tok.Expires = 1
				st.ServerTokens[k] = tok
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status, raw := w.register(expiring, w.org, w.p); status < 400 {
		t.Fatalf("an expired token registered a release: %d %s", status, raw)
	}
	revoked, revokedBearer := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	if err = e.app.Auth.RevokeServerToken(e.ctx, e.actor.Cred, w.org, revoked.ID, "pipeline retired"); err != nil {
		t.Fatal(err)
	}
	if status, raw := w.register(revokedBearer, w.org, w.p); status < 400 {
		t.Fatalf("a revoked token registered a release: %d %s", status, raw)
	}
	if status, raw := w.record(revokedBearer, w.org, w.p, w.r2); status < 400 {
		t.Fatalf("a revoked token recorded a deploy: %d %s", status, raw)
	}
	_ = good
}

func TestReleaseWriteTokenCanDoNothingElse(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	issued, _ := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	cred, err := e.app.Auth.Authenticate(e.ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	// No other permission is derivable: reads, incident and issue actions, policies, destinations (organization
	// administration), artifacts, raw reads.
	for _, p := range []auth.Permission{auth.Read, auth.IncidentsWrite, auth.IssuesWrite, auth.PolicyWrite, auth.RulesWrite, auth.OrgAdmin, auth.ArtifactWrite, auth.ArtifactRead, auth.RawRead, auth.InstanceAdmin} {
		if _, err := e.app.Auth.Authorize(e.ctx, cred, w.org, []model.ID{w.p}, p); err == nil {
			t.Errorf("a release.write token derived %s", p)
		}
	}
	// Admin commands need a fresh human session; a token is none.
	raw, _ := json.Marshal(auth.AdminPayload{ID: model.NewID(), Name: "x", Reason: "token"})
	if _, err := e.app.Auth.AdminCommand(e.ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: model.Revision(w.revision()), OrgID: w.org, Kind: "create_project", Payload: raw}); err == nil {
		t.Fatal("a release.write token ran an admin command")
	}
	if _, err := e.app.Auth.AdminRead(e.ctx, cred, auth.AdminReadRequest{OrgID: w.org, Kind: "organization"}); err == nil {
		t.Fatal("a release.write token read the administration")
	}
	if _, err := e.app.Auth.ListServerTokens(e.ctx, cred, w.org); err == nil {
		t.Fatal("a release.write token listed tokens")
	}
	// The grant cannot be self-issued: not by the token, not by a plain member (a stale administrator session is
	// TestEndedAndStaleSessionsAreRefusedOnTheReleaseRoutes).
	if _, err := e.app.Auth.IssueServerToken(e.ctx, cred, w.org, w.admin.ID, []model.ID{w.p}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "self"); err == nil {
		t.Fatal("a token issued a token")
	}
	member, err := e.app.Auth.Authenticate(e.ctx, w.reader.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.Auth.IssueServerToken(e.ctx, member, w.org, w.reader.ID, []model.ID{w.p}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "member"); err == nil {
		t.Fatal("a plain member issued a release.write token")
	}
	// A project outside the organization cannot be named by the administrator either.
	if _, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, w.org, w.admin.ID, []model.ID{model.NewID()}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "nowhere"); err == nil {
		t.Fatal("a token for an unknown project")
	}
	// Over the routes: release list, deploy list, directory, evidence reads.
	for path, body := range map[string]map[string]any{
		"/api/v1/releases/list":     {"org": w.org.String(), "projects": []string{w.p.String()}},
		"/api/v1/releases/deploys":  {"op": "list", "org": w.org.String(), "projects": []string{w.p.String()}},
		"/api/v1/directory":         {"org": w.org.String()},
		"/api/v1/evidence/release":  {"org": w.org.String(), "project": w.p.String(), "release": w.r1.String()},
		"/api/v1/admin/tokens/list": {"org_id": w.org.String()},
	} {
		if status, raw := e.post(person{}, path, body, bearerOf(issued.Token)); status < 400 {
			t.Errorf("%s answered a release.write token: %d %s", path, status, raw)
		}
	}
	// Its scope may commit a release registration and nothing else.
	scope, err := e.app.Auth.AuthorizeRelease(e.ctx, cred, w.org, w.p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.ControlAuthorize(e.ctx, "RegisterRelease"); err != nil {
		t.Fatalf("registration: %v", err)
	}
	for _, kind := range []string{"Audit", "CreateOrg", "Grant", "PolicyChange", "IncidentAction", "SavedView", "DeleteScope", "BeginFence"} {
		if err := scope.ControlAuthorize(e.ctx, kind); err == nil {
			t.Errorf("the release scope may commit %s", kind)
		}
	}
}

func bearerOf(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func TestTokenListShowsReleaseWriteAndIssuanceIsAudited(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	issued, _ := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	revoked, _ := w.issue(w.org, w.admin.ID, []model.ID{w.p, w.q}, auth.ReleaseWrite, auth.ArtifactWrite)
	if err := e.app.Auth.RevokeServerToken(e.ctx, e.actor.Cred, w.org, revoked.ID, "retired"); err != nil {
		t.Fatal(err)
	}
	_, foreign := w.issueIn(w.orgB)

	// The list is an administrator's, per organization.
	status, raw := e.post(e.actor, "/api/v1/admin/tokens/list", map[string]any{"org_id": w.org.String()}, nil)
	if status != 200 {
		t.Fatalf("list: %d %s", status, raw)
	}
	var v struct {
		Tokens []struct {
			ID          string   `json:"id"`
			Principal   string   `json:"principal"`
			Projects    []string `json:"projects"`
			Permissions []string `json:"permissions"`
			State       string   `json:"state"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, tok := range v.Tokens {
		switch tok.ID {
		case issued.ID.String():
			got["issued"]++
			if len(tok.Permissions) != 1 || tok.Permissions[0] != "release.write" || len(tok.Projects) != 1 || tok.Projects[0] != w.p.String() || tok.State != "active" || tok.Principal != w.admin.ID.String() {
				t.Errorf("issued: %+v", tok)
			}
		case revoked.ID.String():
			got["revoked"]++
			if tok.State != "revoked" || len(tok.Permissions) != 2 {
				t.Errorf("revoked: %+v", tok)
			}
		case foreign:
			t.Errorf("a token of another organization is listed")
		}
	}
	if got["issued"] != 1 || got["revoked"] != 1 {
		t.Fatalf("list: %s", raw)
	}
	if strings.Contains(string(raw), issued.Token) {
		t.Fatal("the token secret is listed")
	}
	// A plain member and another organization's administrator are told nothing.
	if status, raw = e.post(w.reader, "/api/v1/admin/tokens/list", map[string]any{"org_id": w.org.String()}, nil); status < 400 {
		t.Fatalf("a member listed tokens: %d %s", status, raw)
	}
	// The issuance audit names the permission and the token.
	named := false
	for _, a := range auditsOf(t, e, w.org) {
		if a.Action == "issue_server_token" && strings.Contains(a.Reason, "release.write") && len(a.Targets) == 2 && a.Targets[0] == issued.ID {
			named = true
		}
	}
	if !named {
		t.Fatal("the issuance audit does not name release.write")
	}
}

// issueIn issues a release.write token in another organization and returns its ID.
func (w *releaseTokenWorld) issueIn(org model.ID) (auth.IssuedServerToken, string) {
	w.e.t.Helper()
	p := model.NewID()
	w.e.cmd(org, "create_project", auth.AdminPayload{ID: p, Name: "b"})
	issued, err := w.e.app.Auth.IssueServerToken(w.e.ctx, w.e.actor.Cred, org, w.stranger.ID, []model.ID{p}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "other org")
	if err != nil {
		w.e.t.Fatal(err)
	}
	return issued, issued.ID.String()
}

// Source-map upload by a release.write token: the existing artifact policy applies unchanged.
func TestReleaseWriteTokenUploadsSourceMapsUnderTheArtifactPolicy(t *testing.T) {
	e := newUploadEnv(t)
	issue := func(perms ...auth.Permission) string {
		issued, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, e.org, e.owner.ID, []model.ID{e.project}, perms, time.Now().Add(time.Hour).Unix(), "ci uploads")
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token
	}
	raw := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}`)
	manifest := func(mutate func(*model.ArtifactManifest)) []byte {
		m := model.ArtifactManifest{Version: 1, Org: e.org, Project: e.project, Source: e.source, Build: e.build, DebugID: "debug-" + model.NewID().String()[:8], GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(4102444800_000000000)}
		if mutate != nil {
			mutate(&m)
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	upload := func(token string, man []byte, file []byte) int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		p, _ := mw.CreateFormField("manifest")
		p.Write(man)
		p, _ = mw.CreateFormFile("file", "app.js.map")
		p.Write(file)
		mw.Close()
		req, _ := http.NewRequest("POST", e.server.URL+"/api/v1/artifacts", &body)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	releaseToken := issue(auth.ReleaseWrite)
	if status := upload(releaseToken, manifest(nil), raw); status != 200 {
		t.Fatalf("a release.write token uploads a public source map: %d", status)
	}
	// The artifact policy applies unchanged: the size ceiling, the type, project confinement, source content.
	if status := upload(releaseToken, manifest(func(m *model.ArtifactManifest) { m.Size = model.Uint64(len(raw)) + 1 }), raw); status < 400 {
		t.Fatalf("a body that is not the declared size: %d", status)
	}
	if status := upload(releaseToken, manifest(nil), []byte("not a source map but the same size ......................................")); status < 400 {
		t.Fatalf("a file that is not the declared map: %d", status)
	}
	if status := upload(releaseToken, manifest(func(m *model.ArtifactManifest) { m.SourceContent = true }), raw); status < 400 {
		t.Fatalf("source content through release.write: %d", status)
	}
	if status := upload(releaseToken, manifest(func(m *model.ArtifactManifest) { m.Project = model.NewID() }), raw); status != 404 {
		t.Fatalf("another project: %d", status)
	}
	if status := upload(releaseToken, manifest(func(m *model.ArtifactManifest) { m.Org = model.NewID() }), raw); status != 404 {
		t.Fatalf("another organization: %d", status)
	}
	if status := upload(releaseToken, manifest(func(m *model.ArtifactManifest) { m.Source = model.NewID() }), raw); status < 400 {
		t.Fatalf("a source the project does not own: %d", status)
	}
	// Tokens without the grant: ingest, read-only artifacts, telemetry.read.
	for name, perms := range map[string][]auth.Permission{"artifacts.read": {auth.ArtifactRead}, "telemetry.read": {auth.Read}, "telemetry.ingest": {"telemetry.ingest"}} {
		if status := upload(issue(perms...), manifest(nil), raw); status != 404 {
			t.Errorf("%s token uploaded: %d", name, status)
		}
	}
	// The existing gate is kept: an artifacts.write token still uploads, release.write does not widen it.
	if status := upload(issue(auth.ArtifactWrite), manifest(nil), raw); status != 200 {
		t.Fatalf("the artifacts.write path: %d", status)
	}
	// A principal that holds no artifacts.write grant and does not administer the organization is refused.
	bare := e.user(e.org, "upload-bare@example.test")
	issued, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, e.org, bare.ID, []model.ID{e.project}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "ci bare")
	if err != nil {
		t.Fatal(err)
	}
	if status := upload(issued.Token, manifest(nil), raw); status != 404 {
		t.Fatalf("a principal without artifacts.write: %d", status)
	}
}
