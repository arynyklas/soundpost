// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type throttleClock struct{ now time.Time }

func (c *throttleClock) read() time.Time { return c.now }
func (c *throttleClock) tick()           { c.now = c.now.Add(time.Millisecond) }

// A flood of throwaway addresses must not be able to free an address that is
// currently refusing attempts: the key table is bounded, and when it is full a
// key that is not blocking anyone is evicted before a blocked one. Otherwise an
// attacker guessing one account's password could reset its counter by filling
// the table. This runs on the table directly (no password KDF), so it is fast.
func TestThrottleEvictionKeepsBlockedKeysWhileSlackKeysExist(t *testing.T) {
	c := &throttleClock{now: time.Unix(1800000000, 0)}
	l := newLoginThrottle(c.read)
	ctx := context.Background()
	for range throttleAddressLimit {
		l.failure(ctx, "victim@example.test")
		c.tick()
	}
	var limited *RateLimitedError
	if err := l.check(ctx, "victim@example.test"); !errors.As(err, &limited) {
		t.Fatalf("setup: the victim address is not blocked: %v", err)
	}
	for i := range throttleMaxKeys + 200 {
		l.failure(ctx, fmt.Sprintf("flood%d@example.test", i))
		c.tick()
	}
	if err := l.check(ctx, "victim@example.test"); !errors.As(err, &limited) {
		t.Fatalf("a flood of throwaway addresses freed a blocked address: %v", err)
	}
	if n := len(l.address.keys); n > throttleMaxKeys {
		t.Fatalf("the address table grew past its cap: %d", n)
	}
}

// When every tracked key is blocked nothing is evicted: the table never exceeds
// its cap, every blocked key (the oldest included) keeps refusing, and a NEW key
// is refused with a typed rate limit instead of being tracked. A flood of
// throwaway keys therefore cannot reset any block (09.06x-W1).
func TestThrottleNeverEvictsABlockedKeyAtCap(t *testing.T) {
	c := &throttleClock{now: time.Unix(1800000000, 0)}
	l := newLoginThrottle(c.read)
	ctx := context.Background()
	for i := range throttleMaxKeys + 10 {
		email := fmt.Sprintf("blocked%d@example.test", i)
		for range throttleAddressLimit {
			l.failure(ctx, email)
			c.tick()
		}
	}
	if n := len(l.address.keys); n != throttleMaxKeys {
		t.Fatalf("the address table holds %d keys, want exactly the cap %d", n, throttleMaxKeys)
	}
	var limited *RateLimitedError
	for _, i := range []int{0, 1, throttleMaxKeys - 1} {
		email := fmt.Sprintf("blocked%d@example.test", i)
		if _, tracked := l.address.keys[addressDigest(email)]; !tracked {
			t.Fatalf("blocked%d was evicted from the table at cap", i)
		}
		if err := l.check(ctx, email); !errors.As(err, &limited) {
			t.Fatalf("blocked%d was released at cap: %v", i, err)
		}
	}
	// The keys past the cap were never tracked; they are refused as new keys.
	err := l.check(ctx, fmt.Sprintf("blocked%d@example.test", throttleMaxKeys+9))
	if !errors.As(err, &limited) || limited.RetryAfter <= 0 || limited.RetryAfter > throttleWindow {
		t.Fatalf("a new key at cap was not refused with a bounded wait: %v", err)
	}
	if err := l.check(ctx, "stranger@example.test"); !errors.As(err, &limited) {
		t.Fatalf("a stranger was let through a saturated table: %v", err)
	}
	// Blocks are bounded by the window: once the first expires, new keys are admitted again.
	c.now = c.now.Add(throttleWindow + time.Hour)
	if err := l.check(ctx, "stranger@example.test"); err != nil {
		t.Fatalf("the table never recovered after the window: %v", err)
	}
	l.failure(ctx, "stranger@example.test")
	if len(l.address.keys) > throttleMaxKeys {
		t.Fatal("table exceeded cap after recovery")
	}
}
