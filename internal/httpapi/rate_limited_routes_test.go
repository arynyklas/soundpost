// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// L1-R03 F2: a credential over the elevation read-miss cap is answered by
// every route that resolves an elevation exactly as the session routes answer
// it: HTTP 429, the closed rate_limited body, a Retry-After in whole seconds
// (never 0), and the server correlation id. Before the fix these routes
// answered 503 unavailable with no Retry-After.
func TestElevationRateLimitIsHTTP429OnEveryRouteThatResolvesAnElevation(t *testing.T) {
	e := newInvEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	_ = ids
	project := model.NewID()
	org := e.org("rate limited org", project)
	alice := e.user(org, "alice-rate@example.test")
	e.grant(org, alice, project, true, auth.Read)

	// Guess 30 elevation IDs (each a NotFound miss), then the 31st is limited.
	for i := range 30 {
		if _, err := e.app.Auth.ResolveElevation(e.ctx, alice.Cred, model.NewID()); err == nil {
			t.Fatalf("setup: guess %d resolved", i)
		}
	}
	if _, err := e.app.Auth.ResolveElevation(e.ctx, alice.Cred, model.NewID()); err == nil {
		t.Fatal("setup: the credential is not over the read-miss cap")
	}

	body := queryBody{"org": org.String(), "projects": []string{project.String()}, "elevation": model.NewID().String()}
	for _, route := range []struct {
		name   string
		server *httptest.Server
		path   string
	}{
		{"query", e.queryEnv.server, "/api/v1/query"},
		{"format", e.queryEnv.server, "/api/v1/query/format"},
		{"discover", e.queryEnv.server, "/api/v1/discover"},
		{"exemplars", e.queryEnv.server, "/api/v1/exemplars"},
		{"investigate", e.server, "/api/v1/investigate"},
	} {
		saved := e.queryEnv.server
		e.queryEnv.server = route.server
		status, raw, header := e.queryEnv.post(alice, route.path, body)
		e.queryEnv.server = saved
		if status != http.StatusTooManyRequests {
			t.Errorf("%s: status %d, want 429: %s", route.name, status, raw)
			continue
		}
		var fault model.Fault
		if err := json.Unmarshal(raw, &fault); err != nil || fault.Code != "rate_limited" || !fault.Retryable || fault.SafeDetail != "rate_limited" {
			t.Errorf("%s: body %s", route.name, raw)
		}
		if after, err := strconv.Atoi(header.Get("Retry-After")); err != nil || after < 1 || after > 300 {
			t.Errorf("%s: Retry-After %q", route.name, header.Get("Retry-After"))
		}
		if header.Get("X-Request-ID") == "" || fault.RequestID.String() != header.Get("X-Request-ID") {
			t.Errorf("%s: body request_id %s does not carry the server correlation id %q", route.name, fault.RequestID, header.Get("X-Request-ID"))
		}
	}
}

// L1-R03 F7: the login-throttle 429 body carries the server correlation id its
// own X-Request-ID header advertises, not a fresh random one.
func TestLoginThrottleBodyCarriesTheServerCorrelationID(t *testing.T) {
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
	post := func(email string) (*http.Response, []byte) {
		b, _ := json.Marshal(map[string]string{"Email": email, "Password": "wrong password entirely"})
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/login", bytes.NewReader(b))
		req.Header.Set("Origin", server.URL)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		return resp, body.Bytes()
	}
	for range 10 {
		post("ghost-correlation@example.test")
	}
	resp, raw := post("ghost-correlation@example.test")
	var fault model.Fault
	if err := json.Unmarshal(raw, &fault); resp.StatusCode != http.StatusTooManyRequests || err != nil || fault.Code != "rate_limited" {
		t.Fatalf("not throttled: %d %s", resp.StatusCode, raw)
	}
	header := resp.Header.Get("X-Request-ID")
	if _, err := model.ParseID(header); err != nil || fault.RequestID.String() != header {
		t.Fatalf("429 body request_id %s, response X-Request-ID %q", fault.RequestID, header)
	}
}
