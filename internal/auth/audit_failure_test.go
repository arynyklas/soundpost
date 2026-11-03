// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

// A real durable backing store remains readable while its commit path fails.
// This models a failed fsync without introducing an in-memory authority.
type failedCommitStore struct {
	*control.Store
	fail bool
}

func (s *failedCommitStore) Update(ctx context.Context, fn func(*control.State) error) error {
	if s.fail {
		return errors.New("injected durable commit failure")
	}
	return s.Store.Update(ctx, fn)
}
func TestElevationCommitFailureReleasesNoScope(t *testing.T) {
	ctx := context.Background()
	disk, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	store := &failedCommitStore{Store: disk}
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	token, _ := disk.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	org := model.NewID()
	if e = disk.Update(ctx, func(st *control.State) error {
		st.Orgs[org.String()] = control.Org{ID: org, Name: "org", Epoch: 1}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	elev, e := service.Elevate(ctx, session, "audit failure test", []model.ID{org})
	if e != nil {
		t.Fatal(e)
	}
	store.fail = true
	if _, e = service.ElevatedScope(ctx, elev, org, nil, auth.Read); e == nil {
		t.Fatal("read scope released without durable audit")
	}
	if _, e = service.Elevate(ctx, session, "second elevation", []model.ID{org}); e == nil {
		t.Fatal("elevation released without durable audit")
	}
}
