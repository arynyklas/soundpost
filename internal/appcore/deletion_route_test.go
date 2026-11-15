// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
)

// The default Open mounts the deletion route over its retention service. Without a
// credential the route must answer a refusal, never a 404 (the route is missing, so an
// operator cannot erase data through the product) and never a success.
func TestOpenWiresTheDeletionRoute(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Retention == nil {
		t.Fatal("the retention service is not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	const path = "/api/v1/admin/deletions"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotImplemented {
		t.Fatalf("POST %s is not registered or has no deleter: %d", path, rec.Code)
	}
	if rec.Code < 400 {
		t.Fatalf("POST %s answered %d without any credential", path, rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("GET %s answered %d", path, rec.Code)
	}
}

// The default Open mounts the one C11 polling route. Without a credential it
// must answer a refusal, never a 404 or 405 (the route is missing, so a
// deletion cannot be polled through the contract path).
func TestOpenWiresTheOperationsRoute(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	mux := http.NewServeMux()
	app.Register(mux)
	path := "/api/v1/operations/" + strings.Repeat("0", 31) + "1"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET %s without a credential answered %d, want 401", path, rec.Code)
	}
}

// The default Open mounts the C11 policy route (POST only). Without a credential
// it must answer a refusal (401, or 403 from the cross-site check that runs first
// on a POST), never a 404/405 (the route is missing) or a view.
func TestOpenWiresThePolicyRoute(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	mux := http.NewServeMux()
	app.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader("{}")))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("POST /api/v1/policies without a credential answered %d, want 401 or 403", rec.Code)
	}
}

// The default Open mounts the three input-adapter bridge routes (POST only).
// Without a credential each must answer a refusal, never a 404/405.
func TestOpenWiresTheInputAdapterRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	mux := http.NewServeMux()
	app.Register(mux)
	for _, path := range []string{"/adapters/v1/prometheus/write", "/adapters/v1/loki/push", "/adapters/v1/conditions"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s without a credential answered %d, want 401 or 403", path, rec.Code)
		}
	}
}

// The default Open binds the human issue lifecycle; without it every issue
// action answers not_available on a served node.
func TestOpenBindsTheIssueActions(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if !app.Actions.IssuesBound() {
		t.Fatal("Open left the issue lifecycle unbound: every issue action answers not_available")
	}
}

// The default Open binds the link resolver to the trace view; without it every
// trace answers its links section as not_available.
func TestOpenWiresTheTraceLinks(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if !app.Traces.LinksWired() {
		t.Fatal("Open left the trace view without a link resolver: every trace answers links not_available")
	}
}
