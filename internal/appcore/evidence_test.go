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

// The default Open builds the evidence handlers over the release service and mounts
// their POST-only routes. Without a credential none of them may answer with a view,
// and none may be reachable by GET. No symbolication worker is configured by default,
// so the frame resolver is a nil interface and the handler reports not_available
// rather than an empty success; that state is asserted in the httpapi tests.
func TestOpenWiresTheEvidenceRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Evidence == nil {
		t.Fatal("the evidence handlers are not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	for _, path := range []string{"/api/v1/evidence/frames", "/api/v1/evidence/release", "/api/v1/evidence/issue"} {
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
}
