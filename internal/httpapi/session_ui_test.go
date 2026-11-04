// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
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
