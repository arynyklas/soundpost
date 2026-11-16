// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
)

// Open wires control's audit delta gate (D49) to the storage engine's replicated declarations: the
// gate is installed (control does not default to the delta command in the application), and a
// one-voter group declares itself once it has a leader, which opens it.
func TestOpenEngagesTheAuditDeltaOnceTheGroupDeclared(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	// Declarations only accumulate, so what control reports can never be ahead of what storage
	// reports a moment later: a gate that was not installed (control defaults to open) shows here
	// while the one-voter group has not declared itself yet.
	if control := app.Control.AuditDelta(); control && !app.Storage.ControlAuditDeltaReady() {
		t.Fatal("control proposes audit deltas while the group has not declared the protocol")
	}
	deadline := time.Now().Add(60 * time.Second)
	for !app.Control.AuditDelta() {
		if time.Now().After(deadline) {
			t.Fatal("the audit delta never engaged on a one-voter group")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !app.Storage.ControlAuditDeltaReady() {
		t.Fatal("control's gate is open while storage says the group has not declared")
	}
}
