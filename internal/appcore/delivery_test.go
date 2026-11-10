// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/model"
)

// The default Open installs the closed delivery-outbox dispatcher on the control
// store, so ClaimDelivery and CompleteDelivery commands (the durable notification
// outbox, its leases and attempt records) are applied deterministically on every
// replica and survive a snapshot restore. Binding is single-shot: a second bind
// is a Conflict, which proves the first one happened.
func TestOpenBindsTheDeliveryOutboxDispatcher(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	err = app.Control.BindDeliveryOutbox()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Conflict {
		t.Fatalf("the delivery-outbox dispatcher was not bound by Open: %v", err)
	}
}
