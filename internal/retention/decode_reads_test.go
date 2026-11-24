// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// A query asks the retention service for the delete generation of its organization when it begins and again
// when it finishes, and a client polls its deletions: every one of those reads used to decode the whole control
// blob (and, as it read under no WithoutBooks context, assemble the ledger's books too) for its own State. They
// read the decode every reader of the revision shares, and a commit that changed a member costs the next
// of them that member's decode, never the whole blob.
func TestQueryPathReadsOfTheRetentionServiceDoNotDecodeTheBlob(t *testing.T) {
	f := newFx(t, options{})
	projects := []model.ID{f.project}
	receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = projects, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := f.adminScope()
	read := func() {
		t.Helper()
		if _, err := f.svc.DeleteGeneration(f.ctx, f.org, projects); err != nil {
			t.Fatalf("DeleteGeneration: %v", err)
		}
		if _, err := f.svc.PollDelete(f.ctx, scope, receipt.OperationID); err != nil {
			t.Fatalf("PollDelete: %v", err)
		}
	}
	read() // what the first reads decode is shared by the rest
	before := f.store.DecodeStats()
	for range 20 {
		read()
	}
	got := f.store.DecodeStats()
	if n := got.Blobs - before.Blobs; n != 0 {
		t.Errorf("20 delete generation reads and polls decoded the whole blob %d times, want never", n)
	}
	if n := got.Members - before.Members; n != 0 {
		t.Errorf("20 reads of one revision decoded %d members, want none", n)
	}
	// A commit costs the readers after it the members it changed, once.
	f.admin("create_project", auth.AdminPayload{ID: model.NewID(), Name: "decode-reads", Reason: "test"})
	scope = f.adminScope()
	before = f.store.DecodeStats()
	for range 20 {
		read()
	}
	got = f.store.DecodeStats()
	if n := got.Blobs - before.Blobs; n != 0 {
		t.Errorf("after a commit, 20 reads decoded the whole blob %d times, want never", n)
	}
	if n := got.Whole - before.Whole; n != 0 {
		t.Errorf("after a commit, 20 reads decoded the whole state %d times, want the members it changed only", n)
	}
}
