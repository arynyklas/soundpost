// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// 09.06x-W2 over HTTP: the eleventh POST /api/v1/elevation of one session inside
// the window is HTTP 429 rate_limited with a Retry-After header; the first ten
// are answered by the elevation logic, never by the throttle.
func TestElevationRouteIsThrottledPerCredential(t *testing.T) {
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
	if _, err = service.Bootstrap(context.Background(), boot, "throttle-owner@example.test", "throttle owner password 2026"); err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	post := func(route string, body any, csrf string) (*http.Response, []byte) {
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
		return resp, raw
	}
	resp, raw := post("/api/v1/login", map[string]string{"Email": "throttle-owner@example.test", "Password": "throttle owner password 2026"}, "")
	var session auth.Session
	if err = json.Unmarshal(raw, &session); resp.StatusCode != 200 || err != nil || session.CSRF == "" {
		t.Fatalf("login %d %s", resp.StatusCode, raw)
	}
	elevate := func() (*http.Response, []byte) {
		return post("/api/v1/elevation", map[string]any{"Reason": "throttle over http", "Orgs": []model.ID{model.NewID()}}, session.CSRF)
	}
	for i := range 10 {
		if resp, raw = elevate(); resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("start %d was throttled early: %s", i, raw)
		}
	}
	resp, raw = elevate()
	var fault model.Fault
	if err = json.Unmarshal(raw, &fault); err != nil || resp.StatusCode != http.StatusTooManyRequests || fault.Code != "rate_limited" {
		t.Fatalf("the eleventh start was %d %s", resp.StatusCode, raw)
	}
	if after, e := strconv.Atoi(resp.Header.Get("Retry-After")); e != nil || after <= 0 || after > 300 {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
}
