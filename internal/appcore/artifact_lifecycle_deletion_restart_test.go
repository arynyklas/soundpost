// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// A completed DELETION erases the bytes of the roots it covers and leaves their intents
// "published" (only an expiry or a fence retires an intent). The process must still restart: the
// read gate already refuses the root, so readiness does not demand the bytes of a root a deletion
// that is not held covers. (Independent review of 10.09, finding F1: Open failed corrupt.)
func TestWiredLifecycleProcessRestartsAfterACompletedEntityDeletion(t *testing.T) {
	r := newWLRig(t)
	r.lifecycleOf(true)
	a := r.upload("delrestart", false, time.Hour)
	other := r.upload("untouched", false, time.Hour)
	r.deleteAndComplete(a)
	if r.present(a) {
		t.Fatal("setup: the deleted artifact's bytes are still present")
	}
	if got := r.intentState(a); got != "published" {
		t.Fatalf("setup: the deleted root's intent is %q, want published (the deletion does not retire it)", got)
	}
	r.mustOpenAfterClose()
	if r.present(a) || r.routeRead(a.ID) != 404 {
		t.Fatal("a deleted artifact is readable after the restart")
	}
	if !r.present(other) {
		t.Fatal("the restart lost an artifact no deletion covers")
	}
	if err := r.app.Control.ValidateArtifactReferences(r.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWiredLifecycleProcessRestartsAfterACompletedRetireProject(t *testing.T) {
	r := newWLRig(t)
	r.lifecycleOf(true)
	a := r.upload("projretire", false, time.Hour)
	var rev model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	receipt, err := r.app.Retention.Delete(r.ctx, r.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteRetireProject, OrgID: r.org, ProjectIDs: []model.ID{r.project}, Reason: "restart after retire_project"})
	if err != nil {
		t.Fatal(err)
	}
	done := false
	for range 10 {
		if err = r.runOnce(); err != nil {
			t.Fatal(err)
		}
		d, perr := r.app.Retention.PollDelete(r.ctx, r.adminScope(), receipt.OperationID)
		if perr != nil {
			t.Fatal(perr)
		}
		if d.Phase == model.DeletePhaseComplete {
			done = true
			break
		}
	}
	if !done {
		t.Fatal("the retire_project deletion did not complete")
	}
	if r.present(a) {
		t.Fatal("setup: the retired project's artifact bytes are still present")
	}
	r.mustOpenAfterClose()
	if r.present(a) {
		t.Fatal("a retired project's artifact came back after the restart")
	}
}
