// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// updateOverride is the shape of the test doubles that count or fail the commits of the control
// store: it embeds the store and overrides Update. Every other method, UpdateAuditAppend and
// AppendAudit included, is the store's.
type updateOverride struct {
	*control.Store
	updates atomic.Int64
	fail    atomic.Pointer[error]
}

func (u *updateOverride) Update(ctx context.Context, fn func(*control.State) error) error {
	u.updates.Add(1)
	if e := u.fail.Load(); e != nil {
		return *e
	}
	return u.Store.Update(ctx, fn)
}

// The audit commits of elevation (the elevated_read row of ElevatedScope and the row of every
// released chunk, CommitElevatedRead) have optional faster paths on the real store. A service built
// over a type that embeds the store and overrides Update must still commit through that override,
// or the double proves nothing (the rule of SharedViewer, applied to the writes).
func TestAnOverriddenUpdateSeesEveryElevatedAudit(t *testing.T) {
	ctx := context.Background()
	disk, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	wrapped := &updateOverride{Store: disk}
	service, e := auth.NewService(auth.AuthDependencies{Control: wrapped})
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
	elev, e := service.Elevate(ctx, session, "audit override test", []model.ID{org})
	if e != nil {
		t.Fatal(e)
	}
	before := wrapped.updates.Load()
	scope, e := service.ElevatedScope(ctx, elev, org, nil, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	if got := wrapped.updates.Load() - before; got != 1 {
		t.Fatalf("ElevatedScope committed %d times through the store's Update, want 1: an override of Update is bypassed", got)
	}
	before = wrapped.updates.Load()
	if e = service.CommitElevatedRead(ctx, scope, "query.read", nil); e != nil {
		t.Fatal(e)
	}
	if got := wrapped.updates.Load() - before; got != 1 {
		t.Fatalf("CommitElevatedRead committed %d times through the store's Update, want 1: an override of Update is bypassed", got)
	}
	// Fault injection: a commit that fails refuses the release, on both paths.
	injected := errors.New("injected control commit failure")
	wrapped.fail.Store(&injected)
	if _, e = service.ElevatedScope(ctx, elev, org, nil, auth.Read); !errors.Is(e, injected) {
		t.Fatalf("ElevatedScope with a failing Update answered %v, want the injected failure", e)
	}
	if e = service.CommitElevatedRead(ctx, scope, "query.read", nil); !errors.Is(e, injected) {
		t.Fatalf("CommitElevatedRead with a failing Update answered %v, want the injected failure", e)
	}
	wrapped.fail.Store(nil)
}

// The store itself, not wrapped, takes the audit paths: CommitElevatedRead on the real store does
// not move AuthorityRevision (the audit log is evidence), and appends exactly one row per call.
func TestCommitElevatedReadOnTheStoreAppendsOneRowAndKeepsAuthority(t *testing.T) {
	ctx := context.Background()
	disk, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: disk})
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
	elev, e := service.Elevate(ctx, session, "audit authority test", []model.ID{org})
	if e != nil {
		t.Fatal(e)
	}
	scope, e := service.ElevatedScope(ctx, elev, org, nil, auth.Read)
	if e != nil {
		t.Fatal(e)
	}
	read := func() (rev, authority model.Revision, rows int) {
		if e := disk.View(ctx, func(st control.State) error {
			rev, authority, rows = st.Revision, st.AuthorityRevision, len(st.Audits)
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		return
	}
	rev0, auth0, rows0 := read()
	for i := range 3 {
		if e = service.CommitElevatedRead(ctx, scope, "query.read", []model.ID{model.NewID()}); e != nil {
			t.Fatal(e)
		}
		rev, authority, rows := read()
		if rev != rev0+model.Revision(i+1) || authority != auth0 || rows != rows0+i+1 {
			t.Fatalf("chunk %d: revision %d->%d, authority %d->%d, audit rows %d->%d: want one revision and one row per chunk, authority unmoved", i, rev0, rev, auth0, authority, rows0, rows)
		}
	}
}
