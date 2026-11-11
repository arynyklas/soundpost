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

// When every tracked key is blocked there is no slack key to give up: the table
// still never exceeds its cap, and the blocked key whose latest failure is
// oldest goes first.
func TestThrottleEvictionIsBoundedWhenEveryKeyIsBlocked(t *testing.T) {
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
	if n := len(l.address.keys); n > throttleMaxKeys {
		t.Fatalf("the address table grew past its cap: %d", n)
	}
	var limited *RateLimitedError
	if err := l.check(ctx, fmt.Sprintf("blocked%d@example.test", throttleMaxKeys+9)); !errors.As(err, &limited) {
		t.Fatalf("the newest blocked address was dropped: %v", err)
	}
	if err := l.check(ctx, "blocked0@example.test"); err != nil {
		t.Fatalf("the oldest blocked address should have been evicted: %v", err)
	}
}
