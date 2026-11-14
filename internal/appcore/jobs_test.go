// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
)

// The default Open installs the closed job-update dispatcher on the control store
// and builds the jobs service over its durable store, so UpdateJob commands (job
// definitions, runs, attempts and the current health the reducer computes) are
// applied deterministically on every replica and survive a snapshot restore.
// Binding is single-shot: a second bind is a Conflict, which proves the first one
// happened.
func TestOpenBindsTheJobUpdateDispatcherAndService(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Jobs == nil {
		t.Fatal("the jobs service is not wired")
	}
	err = app.Control.BindJobUpdate()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Conflict {
		t.Fatalf("the job-update dispatcher was not bound by Open: %v", err)
	}
}
