// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// viewOverride is the shape of the test doubles that count or fail the reads of the control store:
// it embeds the store and overrides View. Every other method, ViewShared included, is the store's.
type viewOverride struct {
	*control.Store
	views atomic.Int64
	fail  atomic.Pointer[error]
}

func (v *viewOverride) View(ctx context.Context, fn func(model.ControlState) error) error {
	v.views.Add(1)
	if e := v.fail.Load(); e != nil {
		return *e
	}
	return v.Store.View(ctx, fn)
}

// A reader of the control state that is offered the shared decode (Revalidate, AuthorizeSystem)
// must not skip an override of View on the store the service was given: a double that injects a
// fault or counts reads sees every read of the service, or the double proves nothing.
func TestAnOverriddenViewSeesEveryRevalidationAndSystemAuthorization(t *testing.T) {
	ctx := context.Background()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	wrapped := &viewOverride{Store: store}
	service, e := auth.NewService(auth.AuthDependencies{Control: wrapped})
	if e != nil {
		t.Fatal(e)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	admin, e := service.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload, at model.ID) {
		t.Helper()
		var rev model.Revision
		_ = store.View(ctx, func(st control.State) error { rev = st.Revision; return nil })
		p.Reason = "shared view override test"
		raw, _ := json.Marshal(p)
		if _, e := service.AdminCommand(ctx, admin, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: at, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "org"}, org)
	command("create_project", auth.AdminPayload{ID: project, Name: "project"}, org)
	scope, e := service.AuthorizeSystem(ctx, org, []model.ID{project}, auth.Read)
	if e != nil {
		t.Fatal(e)
	}

	// Counting: each call reads through the override.
	before := wrapped.views.Load()
	if e = service.Revalidate(ctx, scope); e != nil {
		t.Fatal(e)
	}
	if got := wrapped.views.Load() - before; got == 0 {
		t.Fatal("Revalidate read the control state without going through the store's View: an override of View is bypassed")
	}
	before = wrapped.views.Load()
	if _, e = service.AuthorizeSystem(ctx, org, []model.ID{project}, auth.Read); e != nil {
		t.Fatal(e)
	}
	if got := wrapped.views.Load() - before; got == 0 {
		t.Fatal("AuthorizeSystem read the control state without going through the store's View: an override of View is bypassed")
	}

	// Fault injection: a read that fails is a refusal, not a pass.
	injected := errors.New("injected control read failure")
	wrapped.fail.Store(&injected)
	if e = service.Revalidate(ctx, scope); !errors.Is(e, injected) {
		t.Fatalf("Revalidate with a failing View answered %v, want the injected failure", e)
	}
	if _, e = service.AuthorizeSystem(ctx, org, []model.ID{project}, auth.Read); !errors.Is(e, injected) {
		t.Fatalf("AuthorizeSystem with a failing View answered %v, want the injected failure", e)
	}
	wrapped.fail.Store(nil)
}
