// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

// After a restore the recovery administrator sees what is still inactive, item by
// item, as the reconciliation names it; reconciling one item shrinks the list and
// the pending count by exactly that item; only an instance administrator may look.
func TestRestoreViewListsExactlyWhatReconciliationCanReinstate(t *testing.T) {
	f := newRestoreFixture(t)
	if n, err := f.service.RestorePending(f.ctx); err != nil || n != 0 {
		t.Fatalf("a never-restored installation has nothing pending: %d %v", n, err)
	}
	token, _, service := f.restore()
	session, err := service.Bootstrap(f.ctx, token, "recovery-view@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := service.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.RestorePending(f.ctx)
	if err != nil || pending == 0 {
		t.Fatalf("restored installation reports nothing pending: %d %v", pending, err)
	}
	view, err := service.RestoreItems(f.ctx, recovery)
	if err != nil {
		t.Fatal(err)
	}
	if view.Pending != pending || len(view.Items) != pending {
		t.Fatalf("view and pending count disagree: pending %d, view %d with %d items", pending, view.Pending, len(view.Items))
	}
	kinds := map[auth.ReconcileKind]int{}
	var readerAccount auth.RestoreItem
	for _, item := range view.Items {
		kinds[item.Kind]++
		if item.Kind == auth.ReconcileAccount && item.User == f.reader.String() {
			readerAccount = item
		}
		if item.Label == "" {
			t.Fatalf("item without a label: %+v", item)
		}
	}
	for _, kind := range []auth.ReconcileKind{auth.ReconcileAccount, auth.ReconcileOrgAdmin, auth.ReconcileMembership, auth.ReconcileGrant, auth.ReconcileIntegration, auth.ReconcileSource} {
		if kinds[kind] == 0 {
			t.Fatalf("no %s item listed: %+v", kind, kinds)
		}
	}
	if readerAccount.Label != "reader@example.test" {
		t.Fatalf("the restored account is not labelled with its login: %+v", readerAccount)
	}
	// Reconcile exactly the listed account, from the listed fields, and watch it leave the list.
	if _, err = service.Reconcile(f.ctx, recovery, auth.Reconciliation{Kind: readerAccount.Kind, User: f.reader, Reason: "reauthorize the reader"}); err != nil {
		t.Fatal(err)
	}
	after, err := service.RestoreItems(f.ctx, recovery)
	if err != nil {
		t.Fatal(err)
	}
	if after.Pending != pending-1 || len(after.Items) != pending-1 {
		t.Fatalf("one reconciliation must remove exactly one item: %d -> %d (%d items)", pending, after.Pending, len(after.Items))
	}
	for _, item := range after.Items {
		if item.Kind == auth.ReconcileAccount && item.User == f.reader.String() {
			t.Fatal("a reconciled account is still listed")
		}
	}
	// The reinstated reader is an ordinary account: it cannot list what is pending.
	readerSession, err := service.Login(f.ctx, "reader@example.test", readerPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := service.Authenticate(f.ctx, readerSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.RestoreItems(f.ctx, reader); authCode(err) != model.Forbidden {
		t.Fatalf("a non-administrator listed the restore stash: %v", err)
	}
}
