// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScopeRevalidateRefreshesSharedBoundedLease(t *testing.T) {
	ctx := context.Background()
	var clock atomic.Int64
	start := time.Unix(1800000000, 0)
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org := model.NewID()
	var revision model.Revision
	_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "lease organization", Reason: "lease regression"})
	if _, err := service.AdminCommand(ctx, credential, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: "create_org", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	scope, err := service.Authorize(ctx, credential, org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	copyOfScope := scope
	initial := scope.LeaseDeadline()
	if !initial.Equal(start.Add(5 * time.Second)) {
		t.Fatal("initial lease is not bounded to five seconds")
	}
	clock.Store(start.Add(6 * time.Second).UnixNano())
	if !scope.LeaseDeadline().Before(now()) {
		t.Fatal("expired lease incorrectly appears fresh")
	}
	if err := service.Revalidate(ctx, scope); err != nil {
		t.Fatalf("fresh authority read must refresh same Scope: %v", err)
	}
	want := now().Add(5 * time.Second)
	if !scope.LeaseDeadline().Equal(want) || !copyOfScope.LeaseDeadline().Equal(want) {
		t.Fatal("error-only Revalidate did not refresh shared auth-owned lease")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 8 {
				_ = scope.LeaseDeadline()
				if err := service.Revalidate(ctx, copyOfScope); err != nil {
					t.Errorf("concurrent revalidation: %v", err)
				}
			}
		}()
	}
	group.Wait()
	clock.Store(time.Unix(session.Expires-2, 0).UnixNano())
	if err := service.Revalidate(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if !scope.LeaseDeadline().Equal(time.Unix(session.Expires, 0)) {
		t.Fatal("lease outlives credential expiry")
	}
	clock.Store(time.Unix(session.Expires, 0).UnixNano())
	assertCode(t, service.Revalidate(ctx, scope), model.Unauthenticated)
	if !scope.LeaseDeadline().IsZero() {
		t.Fatal("failed revalidation left a usable lease")
	}
}
