// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// A session that ended (logout) before the request is refused on register, deploy record and upload exactly as on every
// other route; a session whose re-authentication is stale cannot issue a token.
func TestEndedAndStaleSessionsAreRefusedOnTheReleaseRoutes(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	registerBody := func() map[string]any {
		rel := map[string]any{"id": model.NewID().String(), "org": w.org.String(), "project": w.p.String(), "build_id": model.NewID().String(), "parents": []string{}, "build_time_ns": "9",
			"debug_artifacts": []map[string]any{}, "display_label": "late", "revision": "0"}
		return map[string]any{"org": w.org.String(), "project": w.p.String(), "command_id": model.NewID().String(), "expected_revision": w.revision(), "release": rel}
	}
	deployBody := func() map[string]any {
		return map[string]any{"op": "record", "org": w.org.String(), "project": w.p.String(), "release": w.r2.String(), "environment": w.env.String(), "command_id": model.NewID().String()}
	}
	// Control: the live administrator session works.
	if status, raw := e.post(w.admin, "/api/v1/releases/register", registerBody(), nil); status != 200 {
		t.Fatalf("live session register: %d %s", status, raw)
	}
	if status, raw := e.post(w.admin, "/api/v1/releases/deploys", deployBody(), nil); status != 200 {
		t.Fatalf("live session record: %d %s", status, raw)
	}
	if err := e.app.Auth.Logout(e.ctx, w.admin.Session.Token); err != nil {
		t.Fatal(err)
	}
	if status, raw := e.post(w.admin, "/api/v1/releases/register", registerBody(), nil); status < 400 {
		t.Fatalf("a logged-out session registered a release: %d %s", status, raw)
	}
	if status, raw := e.post(w.admin, "/api/v1/releases/deploys", deployBody(), nil); status < 400 {
		t.Fatalf("a logged-out session recorded a deploy: %d %s", status, raw)
	}

	// Stale re-authentication: the session lives but its fresh window is over; issuing a token needs a fresh one.
	admin2 := e.user(w.org, "rw-admin2@example.test")
	e.cmd(w.org, "org_admin", auth.AdminPayload{UserID: admin2.ID, Enabled: true})
	if err := e.app.Control.Update(e.ctx, func(st *model.ControlState) error {
		for k, s := range st.Sessions {
			if s.User == admin2.ID {
				s.Reauthenticated = 1
				st.Sessions[k] = s
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stale, err := e.app.Auth.Authenticate(e.ctx, admin2.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.app.Auth.IssueServerToken(e.ctx, stale, w.org, w.admin.ID, []model.ID{w.p}, []auth.Permission{auth.ReleaseWrite}, time.Now().Add(time.Hour).Unix(), "stale"); err == nil {
		t.Fatal("a stale session issued a release.write token")
	}
}

func TestEndedSessionCannotUploadSourceMaps(t *testing.T) {
	e := newUploadEnv(t)
	raw := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}`)
	m := model.ArtifactManifest{Version: 1, Org: e.org, Project: e.project, Source: e.source, Build: e.build, DebugID: "debug-session", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(4102444800_000000000)}
	man, _ := json.Marshal(m)
	upload := func() int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		p, _ := mw.CreateFormField("manifest")
		p.Write(man)
		p, _ = mw.CreateFormFile("file", "app.js.map")
		p.Write(raw)
		mw.Close()
		req, _ := http.NewRequest("POST", e.server.URL+"/api/v1/artifacts", &body)
		req.Header.Set("Cookie", "__Host-soundpost="+e.owner.Session.Token)
		req.Header.Set("Origin", e.server.URL)
		req.Header.Set("X-CSRF-Token", e.owner.Session.CSRF)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := upload(); status != 200 {
		t.Fatalf("live session upload: %d", status)
	}
	if err := e.app.Auth.Logout(e.ctx, e.owner.Session.Token); err != nil {
		t.Fatal(err)
	}
	if status := upload(); status < 400 {
		t.Fatalf("a logged-out session uploaded: %d", status)
	}
}

func TestTokenListRefusesAnotherOrganizationsAdministrator(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	adminB := e.user(w.orgB, "rw-admin-b@example.test")
	e.cmd(w.orgB, "org_admin", auth.AdminPayload{UserID: adminB.ID, Enabled: true})
	for name, who := range map[string]person{"another organization's administrator": adminB, "a plain member": w.reader} {
		status, raw := e.post(who, "/api/v1/admin/tokens/list", map[string]any{"org_id": w.org.String()}, nil)
		if status != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	// The same administrator lists their own organization's tokens, and only those.
	status, raw := e.post(adminB, "/api/v1/admin/tokens/list", map[string]any{"org_id": w.orgB.String()}, nil)
	if status != 200 || bytes.Contains(raw, []byte(w.p.String())) {
		t.Fatalf("own organization: %d %s", status, raw)
	}
}
