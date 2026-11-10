// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"soundpost/internal/appcore"
)

// The default Open wires the owned C06 engine and its four routes. The engine
// is built from the profiles embedded in the binary, so a process started from
// any directory, with no profiles directory beside it, can run the pinned
// PromQL and LogQL profiles. Registering the app's routes twice on one mux
// would panic, so this also proves App.Register does not mount any path twice.
func TestOpenWiresTheOwnedQueryEngineAndRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Query == nil {
		t.Fatal("the owned query engine is not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	for _, path := range []string{"/api/v1/query", "/api/v1/query/format", "/api/v1/discover", "/api/v1/exemplars"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Fatalf("POST %s is not registered: %d", path, rec.Code)
		}
		if rec.Code < 400 {
			t.Fatalf("POST %s answered %d without any credential", path, rec.Code)
		}
	}
	// The routes are POST-only: telemetry expressions never appear in a URL.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/query?expr=up", nil))
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/query answered %d", rec.Code)
	}
}

// The default Open builds the investigator over the owned query engine and the
// scope-checked link resolver and mounts its POST-only route. A credential-less
// request must be refused, never answered with a view.
func TestOpenWiresTheInvestigateRoute(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Investigator == nil {
		t.Fatal("the investigator is not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/investigate", strings.NewReader("{}")))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/v1/investigate is not registered: %d", rec.Code)
	}
	if rec.Code < 400 {
		t.Fatalf("POST /api/v1/investigate answered %d without any credential", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/investigate?kind=service", nil))
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/investigate answered %d", rec.Code)
	}
}

// The default Open builds the live service over the storage change feed and
// mounts its two routes. Without a credential neither may answer with a ticket
// or a stream, and a ticket is never accepted from a request body on the
// stream route.
func TestOpenWiresTheLiveRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Live == nil {
		t.Fatal("the live service is not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/live-tickets", strings.NewReader("{}")))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/v1/live-tickets is not registered: %d", rec.Code)
	}
	if rec.Code < 400 {
		t.Fatalf("POST /api/v1/live-tickets answered %d without any credential", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/live?ticket=none", nil))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/live is not registered: %d", rec.Code)
	}
	if rec.Code < 400 {
		t.Fatalf("GET /api/v1/live answered %d without any credential", rec.Code)
	}
}
