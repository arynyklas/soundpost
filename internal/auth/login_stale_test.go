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
// Nothing is committed by a refused call. kdfInside counts the password-KDF runs made while a
// write's transition runs (the window in which another commit makes the write stale), and
// beforeWrite, when set, runs once before the first write reaches the store.
type staleOnLogin struct {
	*control.Store
	refuse      int32
	calls       atomic.Int32
	kdfInside   atomic.Int64
	beforeWrite func(context.Context, *control.Store)
}

func (s *staleOnLogin) UpdateSessionCreate(ctx context.Context, fn func(*model.ControlState) error) error {
	if s.calls.Add(1) <= s.refuse {
		return model.Fail(model.Stale)
	}
	if hook := s.beforeWrite; hook != nil {
		s.beforeWrite = nil
		hook(ctx, s.Store)
	}
	return s.Store.UpdateSessionCreate(ctx, func(st *model.ControlState) error {
		before := auth.KDFRuns()
		defer func() { s.kdfInside.Add(auth.KDFRuns() - before) }()
		return fn(st)
	})
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
	// A wrong password is refused against the read of the account, before any control write: it is
	// neither written nor retried.
	if store.calls.Load() != 0 {
		t.Fatalf("a refused password reached the control write %d times", store.calls.Load())
	}
}

// The password KDF (about 100 ms) never runs inside the control write. A replicated write is
// computed from one revision and proposed with it, so any other control commit while it runs makes
// it lose the race for its index (`stale`): with the KDF inside, almost every login of a cluster
// whose nodes run background writers answered stale once and had to be repeated (the
// install-distributed smoke measured login_stale_retries_before_success of 5 and 6).
func TestLoginPasswordKDFRunsOutsideTheControlWrite(t *testing.T) {
	service, store := loginFixture(t, 0)
	runs := auth.KDFRuns()
	if _, err := service.Login(context.Background(), "stale-login@example.test", "stale login password 2026", ""); err != nil {
		t.Fatal(err)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("%d control write attempts, want 1", store.calls.Load())
	}
	if got := auth.KDFRuns() - runs; got != 1 {
		t.Fatalf("one login ran the password KDF %d times, want exactly 1", got)
	}
	if inside := store.kdfInside.Load(); inside != 0 {
		t.Fatalf("the password KDF ran %d time(s) inside the control write that creates the session", inside)
	}
}

// The account is verified against a read and committed later, so a change in between (the account
// disabled by an administrator) must not let the verified password log in: the write sees the
// fresher state, refuses to commit a session for a record it was not verified against, and the
// repeated attempt answers like any login to a disabled account.
func TestLoginDoesNotCommitASessionForAnAccountChangedAfterItsPasswordWasVerified(t *testing.T) {
	service, store := loginFixture(t, 0)
	store.beforeWrite = func(ctx context.Context, s *control.Store) {
		if err := s.Update(ctx, func(st *model.ControlState) error {
			for k, u := range st.Users {
				u.Disabled = true
				st.Users[k] = u
			}
			return nil
		}); err != nil {
			t.Error("disabling the account:", err)
		}
	}
	session, err := service.Login(context.Background(), "stale-login@example.test", "stale login password 2026", "")
	assertCode(t, err, model.Unauthenticated)
	if session.Token != "" {
		if _, err = service.Authenticate(context.Background(), session.Token); err == nil {
			t.Fatal("a session was committed for an account disabled after its password was verified")
		}
	}
}

// The wait is bounded CPU as well as time: the retries of one login against the same password hash
// run the KDF once, not once per attempt (independent review, wave 11, finding M1).
func TestLoginRetriesDoNotRepeatThePasswordKDF(t *testing.T) {
	service, store := loginFixture(t, 5)
	runs := auth.KDFRuns()
	if _, err := service.Login(context.Background(), "stale-login@example.test", "stale login password 2026", ""); err != nil {
		t.Fatal(err)
	}
	if store.calls.Load() != 6 {
		t.Fatalf("%d control write attempts, want 5 refused and 1 committed", store.calls.Load())
	}
	if got := auth.KDFRuns() - runs; got != 1 {
		t.Fatalf("six attempts of one login ran the password KDF %d times, want 1", got)
	}
}
