// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// bookReadingStore counts the reads that ask for the admission books.
type bookReadingStore struct {
	*control.Store
	withBooks atomic.Int64
}

func (s *bookReadingStore) View(ctx context.Context, fn func(model.ControlState) error) error {
	if model.WantsBooks(ctx) {
		s.withBooks.Add(1)
	}
	return s.Store.View(ctx, fn)
}

// The admission books (every reservation ever admitted and not yet settled) grow with each batch: a
// read that assembles them costs O(history). In the live 2,000 records/s run the control state grew
// to 174 MB and every authenticated query decoded it (perf of L2w20Admission6/s1: 73 % of the server's
// CPU after the restart). Authentication, authorization and the other reads of the auth service never
// look at the books, so none of them may ask for them.
func TestAuthenticatedReadsDoNotAssembleTheAdmissionBooks(t *testing.T) {
	ctx := context.Background()
	disk, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	store := &bookReadingStore{Store: disk}
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, disk, t.TempDir())
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
	store.withBooks.Store(0)
	cred, e := service.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.Authorize(ctx, cred, org, nil, auth.Read); e != nil {
		t.Logf("authorize: %v", e) // the refusal is as costly to compute as a grant
	}
	if _, e = service.RestorePending(ctx); e != nil {
		t.Fatal(e)
	}
	if n := store.withBooks.Load(); n != 0 {
		t.Fatalf("%d control reads of the auth service asked for the admission books, want none", n)
	}
}
