// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
)

// The default Open installs the closed condition-apply dispatcher on the control
// store, so ApplyCondition commands are applied deterministically on every
// replica and survive a snapshot restore. Binding is single-shot: a second bind
// is a Conflict, which proves the first one happened.
func TestOpenBindsTheConditionApplyDispatcher(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	err = app.Control.BindConditionApply()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Conflict {
		t.Fatalf("the condition-apply dispatcher was not bound by Open: %v", err)
	}
}
