// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// consoleEnv serves the directory, deploy and release-list routes over the evidence environment (which
// has a real release registry). The release list reads releases through source.
func consoleEnv(t *testing.T, source httpapi.ReleaseListSource) *evEnv {
	t.Helper()
	e := newEvEnv(t, nil, nil, true)
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterDirectoryRoutes(mux, e.app.Auth)
		httpapi.RegisterDeployRoutes(mux, e.app.Auth)
		httpapi.RegisterReleaseListRoute(mux, e.app.Auth, source, e.cache)
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, httpapi.NewEvidence(nil, e.app.Releases, nil))
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

type directoryAnswer struct {
	Org      string `json:"org"`
	Projects []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"projects"`
	Members []struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Admin       *bool  `json:"admin"`
		Enabled     *bool  `json:"enabled"`
	} `json:"members"`
	CanSetNames bool `json:"can_set_names"`
}

func (e *evEnv) directory(who person, org model.ID, projects ...model.ID) (int, directoryAnswer, []byte) {
	e.t.Helper()
	body := map[string]any{"org": org.String()}
	if len(projects) > 0 {
		ids := make([]string, len(projects))
		for i, p := range projects {
			ids[i] = p.String()
		}
		body["projects"] = ids
	}
	status, raw := e.post(who, "/api/v1/directory", body, nil)
	var v directoryAnswer
	if status == 200 {
		if err := json.Unmarshal(raw, &v); err != nil {
			e.t.Fatalf("directory answer: %v\n%s", err, raw)
		}
	}
	return status, v, raw
}

func (e *evEnv) setName(who person, org, user model.ID, name string, command model.ID) (int, []byte) {
	return e.post(who, "/api/v1/directory/names", map[string]any{"org": org.String(), "command_id": command.String(), "user": user.String(), "display_name": name}, nil)
}

func TestDirectoryRoutesScopeAndNames(t *testing.T) {
	e := consoleEnv(t, nil)
	p, q := model.NewID(), model.NewID()
	org := e.org("directory", p, q)
	orgB := e.org("directory B", model.NewID())
	admin := e.user(org, "dir-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "dir-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	other := e.user(org, "dir-other@example.test")
	e.grant(org, other, q, true, auth.Read)
	stranger := e.user(orgB, "dir-stranger@example.test")

	status, v, raw := e.directory(admin, org)
	if status != 200 || len(v.Projects) != 2 || !v.CanSetNames {
		t.Fatalf("administrator: %d %s", status, raw)
	}
	emails := map[string]bool{}
	for _, m := range v.Members {
		emails[m.Email] = true
		if m.Admin == nil || m.Enabled == nil {
			t.Fatalf("an administrator sees admin and enabled: %s", raw)
		}
	}
	if !emails["dir-reader@example.test"] || !emails["dir-other@example.test"] {
		t.Fatalf("an administrator sees who a member is: %s", raw)
	}

	status, v, raw = e.directory(reader, org)
	if status != 200 || len(v.Projects) != 1 || v.Projects[0].ID != p.String() {
		t.Fatalf("a member sees its own project only: %d %s", status, raw)
	}
	if strings.Contains(string(raw), "@") || strings.Contains(string(raw), `"admin"`) || strings.Contains(string(raw), `"enabled"`) {
		t.Fatalf("a member never sees e-mail, admin or enabled: %s", raw)
	}
	for _, m := range v.Members {
		if m.ID == other.ID.String() {
			t.Fatalf("a member of another project is listed for a member: %s", raw)
		}
	}

	// A user of another organization is told what a missing organization is told.
	missing, _ := e.post(stranger, "/api/v1/directory", map[string]any{"org": model.NewID().String()}, nil)
	if status, _, raw = e.directory(stranger, org); status != 404 || missing != 404 {
		t.Fatalf("stranger: %d %s (missing org: %d)", status, raw, missing)
	}
	// Unknown fields and a missing org are refused.
	if status, _ := e.post(admin, "/api/v1/directory", map[string]any{"org": org.String(), "email": "x"}, nil); status != 400 {
		t.Fatalf("an unknown field: %d", status)
	}
	if status, _ := e.post(admin, "/api/v1/directory", map[string]any{}, nil); status != 400 {
		t.Fatalf("no org: %d", status)
	}
	// No credential at all.
	if status, _ := e.post(person{}, "/api/v1/directory", map[string]any{"org": org.String()}, nil); status < 400 {
		t.Fatalf("anonymous: %d", status)
	}

	// Names: own by a member; never another's; any by an administrator; clear; the text is shown back.
	const alice = "Alice Ünïcode"
	if status, raw = e.setName(reader, org, reader.ID, alice, model.NewID()); status != 200 || strings.Contains(string(raw), "Alice") {
		t.Fatalf("a member names itself (and the answer never echoes the text): %d %s", status, raw)
	}
	if status, raw = e.setName(reader, org, other.ID, "Forged", model.NewID()); status != http.StatusForbidden {
		t.Fatalf("a member named another member: %d %s", status, raw)
	}
	if status, raw = e.setName(admin, org, other.ID, "Bob", model.NewID()); status != 200 {
		t.Fatalf("an administrator names anyone: %d %s", status, raw)
	}
	if status, raw = e.setName(stranger, org, stranger.ID, "Cross", model.NewID()); status != 404 {
		t.Fatalf("a user of another organization named itself here: %d %s", status, raw)
	}
	_, v, _ = e.directory(admin, org)
	got := map[string]string{}
	for _, m := range v.Members {
		got[m.ID] = m.DisplayName
	}
	if got[reader.ID.String()] != alice || got[other.ID.String()] != "Bob" {
		t.Fatalf("names: %+v", got)
	}
	if status, raw = e.setName(reader, org, reader.ID, "", model.NewID()); status != 200 || !strings.Contains(string(raw), `"cleared"`) {
		t.Fatalf("clear: %d %s", status, raw)
	}
	for name, text := range map[string]string{"control": "a\u0000b", "long": strings.Repeat("x", 81), "spaces": " x "} {
		if status, raw = e.setName(reader, org, reader.ID, text, model.NewID()); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	if status, _ = e.post(reader, "/api/v1/directory/names", map[string]any{"org": org.String(), "user": reader.ID.String(), "display_name": "x"}, nil); status != 400 {
		t.Fatalf("no command id: %d", status)
	}
	// Idempotent by command id, over the route.
	command := model.NewID()
	if status, _ = e.setName(reader, org, reader.ID, "Twice", command); status != 200 {
		t.Fatal(status)
	}
	if status, _ = e.setName(reader, org, reader.ID, "Twice", command); status != 200 {
		t.Fatalf("a retry: %d", status)
	}
	if status, _ = e.setName(reader, org, reader.ID, "Other", command); status != http.StatusConflict {
		t.Fatalf("the same command with other content: %d", status)
	}
	// The name text never reaches the audit log.
	audit, _ := json.Marshal(auditsOf(t, e, org))
	for _, text := range []string{"Twice", "Bob", "Alice"} {
		if strings.Contains(string(audit), text) {
			t.Fatalf("%q reached the audit log", text)
		}
	}
}

// auditsOf is the control audit rows of org.
func auditsOf(t *testing.T, e *evEnv, org model.ID) []model.ControlAudit {
	t.Helper()
	var out []model.ControlAudit
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Org == org.String() {
				out = append(out, a)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDirectoryRefusesAServerToken(t *testing.T) {
	e := consoleEnv(t, nil)
	p := model.NewID()
	org := e.org("directory token", p)
	reader := e.user(org, "dir-token@example.test")
	e.grant(org, reader, p, true, auth.Read)
	issued, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, org, reader.ID, []model.ID{p}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "directory token")
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+issued.Token) }
	if status, raw := e.post(person{}, "/api/v1/directory", map[string]any{"org": org.String()}, bearer); status != http.StatusForbidden {
		t.Fatalf("a server token read the directory: %d %s", status, raw)
	}
	if status, raw := e.post(person{}, "/api/v1/directory/names", map[string]any{"org": org.String(), "command_id": model.NewID().String(), "user": reader.ID.String(), "display_name": "x"}, bearer); status != http.StatusForbidden {
		t.Fatalf("a server token named a member: %d %s", status, raw)
	}
}
