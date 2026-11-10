// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
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
