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

// The default Open mounts the job list and job view routes over the durable job
// store. Without a credential neither may answer with content, and neither may be
// reachable by GET.
func TestOpenWiresTheJobRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	mux := http.NewServeMux()
	app.Register(mux)
	for _, path := range []string{"/api/v1/jobs/list", "/api/v1/jobs/view"} {
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
