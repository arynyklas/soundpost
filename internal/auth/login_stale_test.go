// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// staleOnLogin is a control store whose session-creating write answers the typed retryable
// `stale` for its first `refuse` calls, as a replicated control write does while the node is
// still catching up with the cluster or has lost the race for its index to another write.
// Nothing is committed by a refused call.
type staleOnLogin struct {
	*control.Store
	refuse int32
	calls  atomic.Int32
}

func (s *staleOnLogin) UpdateSessionCreate(ctx context.Context, fn func(*model.ControlState) error) error {
	if s.calls.Add(1) <= s.refuse {
		return model.Fail(model.Stale)
	}
	return s.Store.UpdateSessionCreate(ctx, fn)
}

func loginFixture(t *testing.T, refuse int32) (*auth.Service, *staleOnLogin) {
	t.Helper()
	directory := t.TempDir()
	disk, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disk.Close() })
	store := &staleOnLogin{Store: disk}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, disk, directory)
	token, _ := disk.BootstrapToken()
	if _, err = service.Bootstrap(context.Background(), token, "stale-login@example.test", "stale login password 2026"); err != nil {
		t.Fatal(err)
	}
	store.refuse = refuse
	store.calls.Store(0)
	return service, store
}

// A login that meets the typed retryable `stale` of the control write (a node that has just
// restarted and is still catching up, or a write that lost the race for its index) waits, within
// a bound, for the applied control state and succeeds, instead of handing the caller a refusal
// that nothing was wrong with. The refused calls committed nothing, so the retry creates exactly
// one session.
func TestLoginWaitsOutAStaleControlWriteInsteadOfAnsweringIt(t *testing.T) {
	service, store := loginFixture(t, 3)
	session, err := service.Login(context.Background(), "stale-login@example.test", "stale login password 2026", "")
	if err != nil {
		t.Fatalf("login answered %v after %d control write attempts, want success once the write stops being stale", err, store.calls.Load())
	}
	if store.calls.Load() != 4 {
		t.Fatalf("%d control write attempts, want 3 refused and 1 committed", store.calls.Load())
	}
	if _, err = service.Authenticate(context.Background(), session.Token); err != nil {
		t.Fatalf("the session the login returned does not authenticate: %v", err)
	}
}

// The wait is bounded and wrong credentials are never retried: a stale write that does not clear
// ends with the context, and a refused password is answered at once.
func TestLoginStaleWaitIsBoundedAndWrongPasswordsAreNotRetried(t *testing.T) {
	service, _ := loginFixture(t, 1<<30)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := service.Login(ctx, "stale-login@example.test", "stale login password 2026", "")
	var fault *model.Fault
	if err == nil || !errors.As(err, &fault) || (fault.Code != model.Stale && fault.Code != model.Timeout && fault.Code != model.Cancelled) {
		t.Fatalf("a login that never stops being stale answered %v, want a typed stale/timeout refusal", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the wait ran %s past its context", elapsed)
	}

	service, store := loginFixture(t, 0)
	_, err = service.Login(context.Background(), "stale-login@example.test", "not the right password at all", "")
	assertCode(t, err, model.Unauthenticated)
	if store.calls.Load() != 1 {
		t.Fatalf("a refused password was attempted %d times", store.calls.Load())
	}
}
