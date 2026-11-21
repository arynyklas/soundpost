// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestSessionUI(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, t.TempDir())
	bundle := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<div id="root"></div><script type="module" src="/assets/main.js"></script>`)}, "assets/main.js": &fstest.MapFile{Data: []byte(`document.title='Soundpost'`)}}
	registrar, err := httpapi.UIRoutes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil, registrar).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	post := func(route string, body any, csrf string) (int, auth.Session) {
		t.Helper()
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", server.URL+route, bytes.NewReader(data))
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var session auth.Session
		_ = json.NewDecoder(resp.Body).Decode(&session)
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "__Host-soundpost" && (!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "") {
				t.Fatal("unsafe session cookie")
			}
		}
		return resp.StatusCode, session
	}
	token, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	status, session := post("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "browser@example.test", "Password": "browser fixture password 2026"}, "")
	if status != 200 || session.CSRF == "" {
		t.Fatalf("bootstrap %d", status)
	}
	old := session.CSRF
	status, session = post("/api/v1/reauthenticate", map[string]string{"Password": "browser fixture password 2026"}, old)
	if status != 200 || session.CSRF == old {
		t.Fatal("rotation failed")
	}
	status, _ = post("/api/v1/logout", struct{}{}, old)
	if status != 403 {
		t.Fatalf("old CSRF accepted %d", status)
	}
	status, _ = post("/api/v1/logout", struct{}{}, session.CSRF)
	if status != 200 {
		t.Fatalf("logout %d", status)
	}
	response, err := client.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("logged-out session survived")
	}
	response, err = client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("real UI headers missing")
	}
	for _, assets := range []fs.FS{nil, fstest.MapFS{}, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<div id="root"></div>`)}}} {
		if _, err := httpapi.UIRoutes(assets); err == nil {
			t.Fatal("invalid bundle accepted")
		}
	}
}

// An organization administrator who is not the instance administrator is refused
// elevation over HTTP, and the refusal is the same answer for a real organization and
// for one that does not exist: elevation is never an existence oracle.
func TestElevationOverHTTPRefusesNonInstanceAdminsUniformly(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, t.TempDir())
	registrar, err := httpapi.UIRoutes(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<div id="root"></div><script type="module" src="/assets/main.js"></script>`)}, "assets/main.js": &fstest.MapFile{Data: []byte(`document.title='Soundpost'`)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil, registrar).Handler)
	defer server.Close()
	boot, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := service.Bootstrap(context.Background(), boot, "elevation-owner@example.test", "elevation owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := service.Authenticate(context.Background(), ownerSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, member := model.NewID(), model.NewID()
	command := func(kind string, payload auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		_ = store.View(context.Background(), func(st control.State) error { revision = st.Revision; return nil })
		payload.Reason = "elevation refusal test"
		raw, _ := json.Marshal(payload)
		if _, e := service.AdminCommand(context.Background(), owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(kind, e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "elevation org"})
	command("create_user", auth.AdminPayload{ID: member, Email: "org-admin-http@example.test", Password: "org admin http password"})
	command("membership", auth.AdminPayload{UserID: member, Enabled: true})
	command("org_admin", auth.AdminPayload{UserID: member, Enabled: true})

	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	post := func(route string, body any, csrf string) (int, []byte) {
		t.Helper()
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", server.URL+route, bytes.NewReader(data))
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	status, raw := post("/api/v1/login", map[string]string{"Email": "org-admin-http@example.test", "Password": "org admin http password"}, "")
	var session auth.Session
	if err = json.Unmarshal(raw, &session); status != 200 || err != nil || session.CSRF == "" {
		t.Fatalf("login %d %s", status, raw)
	}
	answer := func(target model.ID) string {
		t.Helper()
		status, raw := post("/api/v1/elevation", map[string]any{"Reason": "org admin must not elevate", "Orgs": []model.ID{target}}, session.CSRF)
		var fault model.Fault
		if err := json.Unmarshal(raw, &fault); err != nil || status != http.StatusForbidden || fault.Code != model.Forbidden {
			t.Fatalf("non-instance administrator elevated or got %d %s", status, raw)
		}
		return http.StatusText(status) + "/" + string(fault.Code) + "/" + fault.SafeDetail
	}
	if real, missing := answer(org), answer(model.NewID()); real != missing {
		t.Fatalf("elevation distinguishes a real organization (%s) from a missing one (%s)", real, missing)
	}
}
