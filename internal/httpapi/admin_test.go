// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"testing"
)

func TestAdminCannotGrantOutsideOrgOrReadSecrets(t *testing.T) {
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	activateHTTPControl(t, store, t.TempDir())
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	post := func(path string, v any, csrf string) (int, []byte) {
		t.Helper()
		b, _ := json.Marshal(v)
		req, _ := http.NewRequest("POST", server.URL+path, bytes.NewReader(b))
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var raw json.RawMessage
		if e = json.NewDecoder(resp.Body).Decode(&raw); e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, raw
	}
	token, _ := store.BootstrapToken()
	status, raw := post("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "owner@example.test", "Password": "correct horse battery staple 2026"}, "")
	if status != 200 {
		t.Fatalf("bootstrap status %d", status)
	}
	var session auth.Session
	if e = json.Unmarshal(raw, &session); e != nil {
		t.Fatal(e)
	}
	org := model.NewID()
	revision := func() model.Revision {
		var r model.Revision
		_ = store.View(ctx, func(st control.State) error { r = st.Revision; return nil })
		return r
	}
	command := func(kind string, org model.ID, p auth.AdminPayload) int {
		b, _ := json.Marshal(p)
		status, _ := post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision(), OrgID: org, Kind: kind, Payload: b}, session.CSRF)
		return status
	}
	if status = command("create_org", org, auth.AdminPayload{Name: "first", Reason: "test setup"}); status != 200 {
		t.Fatalf("create org status %d", status)
	}
	status = command("grant", model.NewID(), auth.AdminPayload{UserID: session.User, ProjectID: model.NewID(), Enabled: true, Permissions: []string{"telemetry.read"}, Reason: "foreign grant"})
	if status != 404 {
		t.Fatalf("foreign grant status %d", status)
	}
	status = command("destination", org, auth.AdminPayload{ID: model.NewID(), Name: "notify", Secret: "secret-not-for-read", Reason: "configure destination"})
	if status != 200 {
		t.Fatalf("destination status %d", status)
	}
	status, raw = post("/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: "organization"}, session.CSRF)
	if status != 200 || bytes.Contains(raw, []byte("secret-not-for-read")) || bytes.Contains(raw, []byte("local-v1")) {
		t.Fatalf("secret leaked or read failed status %d", status)
	}
	status, _ = post("/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: "organization"}, "wrong")
	if status != 403 {
		t.Fatalf("missing csrf status %d", status)
	}
	orgAdmin, ordinary := model.NewID(), model.NewID()
	for _, u := range []struct {
		id    model.ID
		email string
	}{{orgAdmin, "orgadmin@example.test"}, {ordinary, "member@example.test"}} {
		if code := command("create_user", org, auth.AdminPayload{ID: u.id, Email: u.email, Password: "member password long enough", Reason: "test account"}); code != 200 {
			t.Fatalf("create account %d", code)
		}
		if code := command("membership", org, auth.AdminPayload{UserID: u.id, Enabled: true, Reason: "test membership"}); code != 200 {
			t.Fatalf("membership %d", code)
		}
	}
	if code := command("org_admin", org, auth.AdminPayload{UserID: orgAdmin, Enabled: true, Reason: "test org admin"}); code != 200 {
		t.Fatalf("org admin %d", code)
	}
	status, raw = post("/api/v1/login", map[string]string{"Email": "orgadmin@example.test", "Password": "member password long enough"}, "")
	if status != 200 {
		t.Fatalf("org admin login %d", status)
	}
	if e = json.Unmarshal(raw, &session); e != nil {
		t.Fatal(e)
	}
	if code := command("create_org", model.NewID(), auth.AdminPayload{Name: "forbidden", Reason: "attempt instance action"}); code != 403 {
		t.Fatalf("org admin created organization: %d", code)
	}
	status, raw = post("/api/v1/login", map[string]string{"Email": "member@example.test", "Password": "member password long enough"}, "")
	if status != 200 {
		t.Fatalf("member login %d", status)
	}
	if e = json.Unmarshal(raw, &session); e != nil {
		t.Fatal(e)
	}
	status, _ = post("/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: "organization"}, session.CSRF)
	if status != 404 {
		t.Fatalf("ordinary member admin read %d", status)
	}
	if code := command("create_project", org, auth.AdminPayload{ID: model.NewID(), Name: "forbidden", Reason: "ordinary member attempt"}); code != 404 {
		t.Fatalf("ordinary member admin command %d", code)
	}
}
