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
