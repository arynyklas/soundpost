// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/model"
)

// The default Open installs the closed incident-action dispatcher on the control
// store and builds the incident service over it, so IncidentAction commands are
// applied deterministically on every replica and survive a snapshot restore.
// Binding is single-shot: a second bind is a Conflict, which proves the first
// one happened.
func TestOpenBindsTheIncidentActionDispatcherAndService(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Incidents == nil {
		t.Fatal("the incident service is not wired")
	}
	err = app.Control.BindIncidentAction()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Conflict {
		t.Fatalf("the incident-action dispatcher was not bound by Open: %v", err)
	}
}

// The default Open builds the human-action handlers over the incident service and
// mounts their POST-only routes. Without a credential none of them may answer
// with a view or an acknowledgement, and none may be reachable by GET.
func TestOpenWiresTheIncidentActionRoutes(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Actions == nil {
		t.Fatal("the incident action handlers are not wired")
	}
	mux := http.NewServeMux()
	app.Register(mux)
	for _, path := range []string{"/api/v1/actions", "/api/v1/incidents/get", "/api/v1/queue"} {
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
