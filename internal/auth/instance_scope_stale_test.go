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

// staleOnUpdate is a control store whose plain write answers the typed `stale` for its first `refuse`
// calls, as a replicated control write does when it lost the race for its index to another control
// commit (every node runs background writers). Nothing is committed by a refused call.
type staleOnUpdate struct {
	*control.Store
	refuse atomic.Int32
	calls  atomic.Int32
}

func (s *staleOnUpdate) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	s.calls.Add(1)
	if s.refuse.Add(-1) >= 0 {
		return model.Fail(model.Stale)
	}
	return s.Store.Update(ctx, fn)
}

// instanceScopeFixture is a service over a control store with one bootstrapped administrator and a fresh
// credential of it: what `soundpost backup create` holds when it asks for its instance scope.
func instanceScopeFixture(t *testing.T) (*auth.Service, *staleOnUpdate, auth.Credential) {
	t.Helper()
	directory := t.TempDir()
	disk, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disk.Close() })
	store := &staleOnUpdate{Store: disk}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, disk, directory)
	token, _ := disk.BootstrapToken()
	if _, err = service.Bootstrap(context.Background(), token, "instance-scope@example.test", "instance scope password 2026"); err != nil {
		t.Fatal(err)
	}
	session, err := service.Login(context.Background(), "instance-scope@example.test", "instance scope password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := service.Authenticate(context.Background(), session.Token)
	if err != nil {
		t.Fatal(err)
	}
	store.calls.Store(0)
	return service, store, credential
}

// The instance scope of `soundpost backup create` is one control write (it records the grant in the audit
// log). A write that lost the race for its index to another control commit is the same retryable `stale`
// a login waits out (docs/operations/distributed.md, "Login waits out a stale control write"): the scope
// waits for it too, within a bound, instead of failing a backup of a healthy cluster with
// `soundpost backup failed: stale` (the deletion-cluster smoke, lag 1: 2 s after the node stopped).
// The refused calls committed nothing, so the scope is granted and audited exactly once.
func TestInstanceScopeWaitsOutAStaleControlWriteInsteadOfAnsweringIt(t *testing.T) {
	service, store, credential := instanceScopeFixture(t)
	store.refuse.Store(3)
	scope, err := service.InstanceScope(context.Background(), credential, "older backup")
	if err != nil {
		t.Fatalf("the instance scope answered %v after %d control write attempts, want success once the write stops being stale", err, store.calls.Load())
	}
	if store.calls.Load() != 4 {
		t.Fatalf("%d control write attempts, want 3 refused and 1 committed", store.calls.Load())
	}
	if err = service.RevalidateInstance(context.Background(), scope); err != nil {
		t.Fatalf("the scope the call returned does not revalidate: %v", err)
	}
	granted := 0
	if err = store.View(context.Background(), func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "instance.scope" {
				granted++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if granted != 1 {
		t.Fatalf("%d instance.scope audit entries, want exactly one", granted)
	}
}

// The wait is bounded by the caller's context and by the stale-wait slots: a write that never stops being
// stale ends with the context, and other refusals are answered at once, not repeated.
func TestInstanceScopeStaleWaitIsBoundedAndOtherRefusalsAreNotRetried(t *testing.T) {
	service, store, credential := instanceScopeFixture(t)
	store.refuse.Store(1 << 30)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := service.InstanceScope(ctx, credential, "never fresh")
	var fault *model.Fault
	if err == nil || !errors.As(err, &fault) || (fault.Code != model.Stale && fault.Code != model.Timeout && fault.Code != model.Cancelled) {
		t.Fatalf("a scope that never stops being stale answered %v, want a typed stale/timeout refusal", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the wait ran %s past its context", elapsed)
	}

	store.refuse.Store(0)
	store.calls.Store(0)
	_, err = service.InstanceScope(context.Background(), credential, "")
	assertCode(t, err, model.Forbidden)
	if store.calls.Load() != 0 {
		t.Fatalf("a refused scope request reached the control write %d times", store.calls.Load())
	}
}
