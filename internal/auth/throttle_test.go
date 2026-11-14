// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"sync"
	"testing"
	"time"
)

const throttleOwnerPassword = "correct horse battery staple 2026"

type throttleFixture struct {
	service *auth.Service
	now     *time.Time
	mu      *sync.Mutex
}

func newThrottleFixture(t *testing.T) throttleFixture {
	t.Helper()
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Unix(1800000000, 0)
	mu := &sync.Mutex{}
	service, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	if _, err = service.Bootstrap(context.Background(), token, "owner@example.test", throttleOwnerPassword); err != nil {
		t.Fatal(err)
	}
	return throttleFixture{service: service, now: &now, mu: mu}
}

func (f throttleFixture) advance(d time.Duration) { f.mu.Lock(); *f.now = f.now.Add(d); f.mu.Unlock() }

func TestUnknownAddressLoginDoesTheSameKDFWorkAsWrongPassword(t *testing.T) {
	f := newThrottleFixture(t)
	ctx := context.Background()
	run := func(email string) (int64, error) {
		before := auth.KDFRuns()
		_, err := f.service.Login(ctx, email, "wrong password entirely", "")
		return auth.KDFRuns() - before, err
	}
	// The dummy digest is derived once, lazily; that single derivation is not
	// per-attempt work.
	_, _ = f.service.Login(ctx, "warmup@example.test", "wrong password entirely", "")
	known, kerr := run("owner@example.test")
	unknown, uerr := run("nobody@example.test")
	if known == 0 || known != unknown {
		t.Fatalf("KDF work differs: known=%d unknown=%d", known, unknown)
	}
	var kf, uf *model.Fault
	if !errors.As(kerr, &kf) || !errors.As(uerr, &uf) || kf.Code != model.Unauthenticated || kf.Code != uf.Code || kf.SafeDetail != uf.SafeDetail || kf.Retryable != uf.Retryable {
		t.Fatalf("denials differ: %v / %v", kerr, uerr)
	}
}

func TestLoginThrottleIsIndistinguishableAndBounded(t *testing.T) {
	f := newThrottleFixture(t)
	ctx := auth.WithSource(context.Background(), "203.0.113.7")
	for _, email := range []string{"owner@example.test", "ghost@example.test"} {
		for i := 0; i < 10; i++ {
			if _, err := f.service.Login(ctx, email, "wrong password entirely", ""); err == nil {
				t.Fatal("wrong password accepted")
			}
		}
	}
	// Both an existing and a missing address are now refused identically,
	// before any KDF work, even with the right password.
	var waits []time.Duration
	for _, email := range []string{"owner@example.test", "ghost@example.test"} {
		before := auth.KDFRuns()
		_, err := f.service.Login(auth.WithSource(context.Background(), "198.51.100.9"), email, throttleOwnerPassword, "")
		var rl *auth.RateLimitedError
		if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > 5*time.Minute {
			t.Fatalf("%s: want rate limit, got %v", email, err)
		}
		if auth.KDFRuns() != before {
			t.Fatal("throttled attempt still ran the KDF")
		}
		waits = append(waits, rl.RetryAfter)
	}
	if waits[0] != waits[1] {
		t.Fatalf("existing and missing differ: %v", waits)
	}
	// The block ends with the window: not a lockout.
	f.advance(5*time.Minute + time.Second)
	if _, err := f.service.Login(context.Background(), "owner@example.test", throttleOwnerPassword, ""); err != nil {
		t.Fatalf("window did not expire: %v", err)
	}
}

func TestLoginThrottleSourceLimitAndSuccessClearsOnlyThatAddress(t *testing.T) {
	f := newThrottleFixture(t)
	src := auth.WithSource(context.Background(), "192.0.2.1")
	for i := 0; i < 9; i++ {
		_, _ = f.service.Login(src, "owner@example.test", "wrong password entirely", "")
	}
	for i := 0; i < 9; i++ {
		_, _ = f.service.Login(context.Background(), "other@example.test", "wrong password entirely", "")
	}
	if _, err := f.service.Login(src, "owner@example.test", throttleOwnerPassword, ""); err != nil {
		t.Fatal(err)
	}
	// owner counter cleared: nine more failures still leave it below the limit.
	for i := 0; i < 9; i++ {
		_, _ = f.service.Login(context.Background(), "owner@example.test", "wrong password entirely", "")
	}
	var rl *auth.RateLimitedError
	_, _ = f.service.Login(context.Background(), "other@example.test", "wrong password entirely", "")
	if _, err := f.service.Login(context.Background(), "other@example.test", "x", ""); !errors.As(err, &rl) {
		t.Fatalf("other address counter was cleared by owner success: %v", err)
	}
	if _, err := f.service.Login(context.Background(), "owner@example.test", throttleOwnerPassword, ""); err != nil {
		t.Fatalf("owner counter not cleared by success: %v", err)
	}
	// Source limit: many distinct addresses from one source.
	flood := auth.WithSource(context.Background(), "192.0.2.50")
	for i := 0; i < 50; i++ {
		_, _ = f.service.Login(flood, fmt.Sprintf("u%d@example.test", i), "wrong password entirely", "")
	}
	if _, err := f.service.Login(flood, "fresh@example.test", "x", ""); !errors.As(err, &rl) {
		t.Fatalf("source flood not limited: %v", err)
	}
}

func TestLoginThrottleTableIsBounded(t *testing.T) {
	f := newThrottleFixture(t)
	for i := 0; i < auth.ThrottleMaxKeys+200; i++ {
		ctx := auth.WithSource(context.Background(), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		_, _ = f.service.Login(ctx, fmt.Sprintf("flood%d@example.test", i), "wrong password entirely", "")
		f.advance(time.Millisecond)
	}
	a, s := f.service.ThrottleKeys()
	if a > auth.ThrottleMaxKeys || s > auth.ThrottleMaxKeys {
		t.Fatalf("unbounded: address=%d source=%d", a, s)
	}
}
