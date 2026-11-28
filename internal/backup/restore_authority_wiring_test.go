// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The restore authority protects a completed deletion only when the retention service
// that ran the deletion checkpointed it. `soundpost serve` used to install no authority
// (it now takes --authority-keys/--authority-dir), and this test is the privacy
// consequence of that gap, observed on the real restore path: the deletion completes,
// the authority journal never learns of it, and restoring the older backup serves the
// deleted row again. TestRestoreRequiresCurrentDeletionLedger is the same scenario with
// the authority installed, where the row stays denied.
func TestWithoutTheAuthorityOnRetentionARestoreRevivesACompletedDeletion(t *testing.T) {
	l := newLiveWith(t, false)
	l.append(100, "kept_early")
	l.append(200, "deleted_later")
	l.append(300, "kept_late")
	l.reconcile()
	before := l.mustBackup()
	if receipt := l.deleteRange(150, 250); receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	if rows := l.liveRows(); rows[200] || !rows[100] || !rows[300] {
		t.Fatalf("live rows after deletion: %v", rows)
	}
	root := l.newRoot()
	report, err := l.restoreTo(root, before, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tombstones != 0 {
		t.Fatalf("the authority holds %d tombstones although retention never checkpointed", report.Tombstones)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	rows, err := l.rows(r.app, r.reader())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restored rows after a completed deletion of [150,250): %v", rows)
	if !rows[200] {
		t.Fatal("the deleted row is denied after restore although no authority recorded the deletion: something other than the authority keeps it denied")
	}
}
