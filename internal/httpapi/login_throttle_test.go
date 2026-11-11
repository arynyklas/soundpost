// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"strconv"
	"testing"
)

func TestLoginRouteThrottlesIdenticallyForKnownAndUnknownAddresses(t *testing.T) {
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
	post := func(email string) (int, string, string) {
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
		return resp.StatusCode, resp.Header.Get("Retry-After"), body.String()
	}
	token, _ := store.BootstrapToken()
	b, _ := json.Marshal(map[string]string{"Token": token, "Email": "owner@example.test", "Password": "correct horse battery staple 2026"})
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/bootstrap", bytes.NewReader(b))
	req.Header.Set("Origin", server.URL)
	if resp, err := client.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("bootstrap: %v", err)
	}
	for i := 0; i < 10; i++ {
		post("owner@example.test")
		post("ghost@example.test")
	}
	var shapes []string
	for _, email := range []string{"owner@example.test", "ghost@example.test"} {
		status, retry, body := post(email)
		if secs, err := strconv.Atoi(retry); status != 429 || err != nil || secs < 1 {
			t.Fatalf("%s: status %d Retry-After %q", email, status, retry)
		}
		var f struct{ Code string }
		if err := json.Unmarshal([]byte(body), &f); err != nil || f.Code != "rate_limited" {
			t.Fatalf("%s: body %s", email, body)
		}
		shapes = append(shapes, retry)
	}
	// Real clock here: the two keys' first failures are a moment apart. Exact
	// equality is asserted in the auth unit test with an injected clock.
	a, _ := strconv.Atoi(shapes[0])
	b2, _ := strconv.Atoi(shapes[1])
	if d := a - b2; d < -3 || d > 3 {
		t.Fatalf("Retry-After differs: %v", shapes)
	}
}
