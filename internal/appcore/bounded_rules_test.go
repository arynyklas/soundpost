// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
)

// Open wires control's bounded-state rules to the storage engine's replicated declarations: the gate
// is installed (it does not default to the new rules in the application), and a one-voter group
// declares itself once it has a leader, which engages the rules.
func TestOpenEngagesTheBoundedRulesOnceTheGroupDeclared(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	// Declarations only accumulate, so what control reports can never be ahead of what storage
	// reports a moment later: a gate that was not installed (control defaults to open) shows here
	// while the one-voter group has not declared itself yet.
	if control := app.Control.BoundedRules(); control && !app.Storage.ControlBoundsReady() {
		t.Fatal("control applies the bounded rules while the group has not declared the protocol")
	}
	deadline := time.Now().Add(60 * time.Second)
	for !app.Control.BoundedRules() {
		if time.Now().After(deadline) {
			t.Fatal("the bounded rules never engaged on a one-voter group")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !app.Storage.ControlBoundsReady() {
		t.Fatal("control's gate is open while storage says the group has not declared")
	}
}
