// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func isForbidden(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.Forbidden
}

// The checks an ingest request makes before it changes anything (who the source is, whether it still is, the scope,
// whether the source is still the batch's) share one linearizable read of the control group: at a follower, where each was a
// ReadIndex round of 410-447 ms on the cluster, they were 4 rounds and are 1. The check before the receipt is answered, and the
// first check after the request's own reservation, make a round of their own.
func TestTheChecksOfOneRequestMakeOneControlRead(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	f := v.fx[2].fenceFx // a follower
	reads := v.stores[2].ReadCallsForTest

	ctx := model.WithReadShare(f.ctx)
	before := reads()
	src, err := f.svc.AuthenticateSource(ctx, f.sourceCredential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.SourceAuthority(ctx, src, true); err != nil {
		t.Fatal(err)
	}
	scope, err := f.svc.SourceScope(ctx, src, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = scope.RevalidateSource(ctx, f.project, f.source, true); err != nil {
		t.Fatal(err)
	}
	if got := reads() - before; got != 1 {
		t.Fatalf("4 checks of one request made %d control reads, want 1", got)
	}

	// The check before the answer is fresh.
	before = reads()
	if err = scope.RevalidateSource(model.WithoutReadShare(ctx), f.project, f.source, true); err != nil {
		t.Fatal(err)
	}
	if got := reads() - before; got != 1 {
		t.Fatalf("the final revalidation made %d control reads, want 1 of its own", got)
	}

	// What follows a change the request made is fresh too, and then shared again.
	model.InvalidateReadShare(ctx)
	before = reads()
	for range 3 {
		if err = scope.RevalidateSource(ctx, f.project, f.source, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := reads() - before; got != 1 {
		t.Fatalf("3 checks after an invalidation made %d control reads, want 1", got)
	}

	// Without a share every check reads, as before.
	before = reads()
	for range 3 {
		if err = scope.RevalidateSource(f.ctx, f.project, f.source, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := reads() - before; got != 3 {
		t.Fatalf("3 checks without a share made %d control reads, want 3", got)
	}
}

// A revoked source stops at the next request that reads, and a request that was already in progress when the revocation
// committed is not answered: its final revalidation reads the state after the revocation, whatever its earlier checks shared.
func TestARevocationIsSeenByTheNextRequestAndByTheFinalCheckOfOneInProgress(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	f := v.fx[2].fenceFx
	inProgress := model.WithReadShare(f.ctx)
	src, err := f.svc.AuthenticateSource(inProgress, f.sourceCredential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.svc.SourceScope(inProgress, src, false)
	if err != nil {
		t.Fatal(err)
	}
	owner := v.fx[1].fenceFx
	if err = owner.svc.RevokeSource(owner.ctx, owner.cred, owner.source, "revoked while a request was in progress"); err != nil {
		t.Fatal(err)
	}
	if err = scope.RevalidateSource(model.WithoutReadShare(inProgress), f.project, f.source, true); !isForbidden(err) {
		t.Fatalf("the final check of a request in progress after the revocation: %v, want forbidden", err)
	}
	next := model.WithReadShare(f.ctx)
	if _, err = f.svc.AuthenticateSource(next, f.sourceCredential, "", false); !isForbidden(err) {
		t.Fatalf("a request that began after the revocation: %v, want forbidden", err)
	}
}
