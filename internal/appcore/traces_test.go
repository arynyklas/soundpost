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

// The default Open builds the trace view handler over the storage span scan and
// mounts its POST-only route. Without a credential it must not answer with a view,
// and it must not be reachable by GET.
func TestOpenWiresTheTraceRoute(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Traces == nil {
		t.Fatal("the trace handlers are not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	const path = "/api/v1/traces/view"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST %s is not registered: %d", path, rec.Code)
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
