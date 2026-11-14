// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/replica"
)

// A member whose journal is behind what it acknowledged refuses to start with one typed reason.
func TestAJournalBehindWhatWasAcknowledgedIsRefusedWithATypedReason(t *testing.T) {
	err := fmt.Errorf("group /secret/dir: %w", replica.ErrJournalBehind)
	want := "soundpost: startup or service failed (reason=journal_behind_acknowledged)"
	if got := failureLine([]string{"soundpost", "serve"}, err); got != want {
		t.Fatalf("printed %q, want %q", got, want)
	}
}
