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
// commit (every node runs background writers). Nothing is committed by a refused call. When cutOff is
// set, a call after the refused ones does not commit either: it waits for its context to end and
// answers cutOff, as a proposal the stale-wait budget cut off midway does.
type staleOnUpdate struct {
	*control.Store
	refuse atomic.Int32
	calls  atomic.Int32
	cutOff error
}

func (s *staleOnUpdate) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	s.calls.Add(1)
	if s.refuse.Add(-1) >= 0 {
		return model.Fail(model.Stale)
	}
	if s.cutOff != nil {
		<-ctx.Done()
		return s.cutOff
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

// A wait whose budget ends INSIDE an attempt used to answer whatever stage the deadline cut: the
// proposal's own context error (`unavailable`), the read fence's (`timeout`), a cancelled validation.
// `soundpost backup failed: unavailable` tells an operator the cluster is down when it is healthy and
// only kept losing the race for its index (measured: the instance scope on a voter against a
// saturating competing writer, -race, 15 s budget: of 300 scopes 3 ended `unavailable` and 2 `stale`,
// all at 15.01 s after 317 to 324 stale answers: one cause, two answers). The documented
// answer of a spent budget is the typed `stale` (docs/operations/distributed.md).
func TestInstanceScopeWhoseBudgetEndsInsideAnAttemptAnswersStale(t *testing.T) {
	for _, cut := range []model.Code{model.Unavailable, model.Timeout, model.Cancelled} {
		t.Run(string(cut), func(t *testing.T) {
			service, store, credential := instanceScopeFixture(t)
			service.SetLoginStaleBudget(300 * time.Millisecond)
			store.refuse.Store(3)
			store.cutOff = model.Fail(cut)
			start := time.Now()
			_, err := service.InstanceScope(context.Background(), credential, "a budget cut off inside an attempt")
			assertCode(t, err, model.Stale)
			if elapsed := time.Since(start); elapsed < 300*time.Millisecond || elapsed > 5*time.Second {
				t.Fatalf("the wait ended after %s, want its 300 ms budget", elapsed)
			}
			if calls := store.calls.Load(); calls != 4 {
				t.Fatalf("%d control write attempts, want 3 refused and the one the budget cut off", calls)
			}
		})
	}
}

// The answer of a spent budget is the stale only when an index race was seen. A first attempt that finds
// the cluster unavailable is not turned into one, and a caller that gave up gets its own cancellation.
func TestInstanceScopeKeepsItsAnswerWhenNoIndexRaceWasSeenOrTheCallerGaveUp(t *testing.T) {
	service, store, credential := instanceScopeFixture(t)
	service.SetLoginStaleBudget(300 * time.Millisecond)
	store.cutOff = model.Fail(model.Unavailable)
	_, err := service.InstanceScope(context.Background(), credential, "the cluster is down")
	assertCode(t, err, model.Unavailable)

	store.refuse.Store(3)
	store.cutOff = model.Fail(model.Timeout)
	service.SetLoginStaleBudget(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = service.InstanceScope(ctx, credential, "the caller's own deadline")
	assertCode(t, err, model.Timeout)
}
