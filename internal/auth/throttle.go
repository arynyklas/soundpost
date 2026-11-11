// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"time"
)

// Login throttle policy: a sliding window of failed attempts is counted per
// normalized address and per remote source. Once a key holds its limit of
// failures inside the window, further attempts on it are refused (before any
// password work) until the oldest failure leaves the window. The refusal does
// not depend on whether the address exists. A success clears only that
// address's counter. The block is bounded by the window, never indefinite, and
// an already issued session is never touched; the tradeoff is that an attacker
// who can reach the login route can delay a victim's NEW login by up to one
// window.
const (
	throttleWindow       = 5 * time.Minute
	throttleAddressLimit = 10
	throttleSourceLimit  = 50
	throttleMaxKeys      = 4096
)

// RateLimitedError is the typed refusal of a throttled attempt.
type RateLimitedError struct{ RetryAfter time.Duration }

func (*RateLimitedError) Error() string { return "rate_limited: too many failed attempts" }

type sourceKey struct{}

// WithSource tags ctx with the remote source (for example the client IP) a
// login attempt came from.
func WithSource(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, sourceKey{}, source)
}

type failureWindow struct {
	times []time.Time
}

type throttleTable struct {
	limit int
	keys  map[[32]byte]*failureWindow
}

type loginThrottle struct {
	mu      sync.Mutex
	now     func() time.Time
	address throttleTable
	source  throttleTable
}

func newLoginThrottle(now func() time.Time) *loginThrottle {
	return &loginThrottle{
		now:     now,
		address: throttleTable{limit: throttleAddressLimit, keys: map[[32]byte]*failureWindow{}},
		source:  throttleTable{limit: throttleSourceLimit, keys: map[[32]byte]*failureWindow{}},
	}
}

func throttleDigest(kind, v string) [32]byte {
	return sha256.Sum256([]byte(kind + "\x00" + v))
}

func addressDigest(email string) [32]byte {
	return throttleDigest("address", strings.ToLower(strings.TrimSpace(email)))
}

func sourceDigest(ctx context.Context) (d [32]byte, ok bool) {
	s, _ := ctx.Value(sourceKey{}).(string)
	if s == "" {
		return d, false
	}
	return throttleDigest("source", s), true
}

func (t *throttleTable) prune(k [32]byte, w *failureWindow, now time.Time) {
	cut := now.Add(-throttleWindow)
	i := 0
	for i < len(w.times) && !w.times[i].After(cut) {
		i++
	}
	w.times = w.times[i:]
	if len(w.times) == 0 {
		delete(t.keys, k)
	}
}

// wait returns how long until key may try again; zero when allowed.
func (t *throttleTable) wait(k [32]byte, now time.Time) time.Duration {
	w := t.keys[k]
	if w == nil {
		return 0
	}
	t.prune(k, w, now)
	if len(w.times) < t.limit {
		return 0
	}
	return w.times[0].Add(throttleWindow).Sub(now)
}

func (t *throttleTable) fail(k [32]byte, now time.Time) {
	w := t.keys[k]
	if w == nil {
		if len(t.keys) >= throttleMaxKeys {
			t.makeRoom(now)
		}
		w = &failureWindow{}
		t.keys[k] = w
	}
	if len(w.times) >= t.limit {
		w.times = w.times[1:]
	}
	w.times = append(w.times, now)
}

// makeRoom drops expired keys, then, if the table is still full, one more key:
// the key with the oldest latest failure among those that are not blocking
// anyone yet (fewer failures than the limit), and only when every tracked key is
// blocked, the blocked key whose latest failure is oldest. A flood of throwaway
// addresses therefore cannot free an address that is currently refusing attempts
// while slack keys exist. The table never exceeds throttleMaxKeys. The cost of a
// full table of blocked keys is that the oldest of them is released.
func (t *throttleTable) makeRoom(now time.Time) {
	for k, w := range t.keys {
		t.prune(k, w, now)
	}
	if len(t.keys) < throttleMaxKeys {
		return
	}
	var oldest [32]byte
	var at time.Time
	found, slack := false, false
	for k, w := range t.keys {
		last := w.times[len(w.times)-1]
		isSlack := len(w.times) < t.limit
		switch {
		case !found, isSlack && !slack, isSlack == slack && last.Before(at):
			oldest, at, found, slack = k, last, true, isSlack
		}
	}
	delete(t.keys, oldest)
}

// check refuses with the longer of the address and source waits.
func (l *loginThrottle) check(ctx context.Context, email string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	wait := l.address.wait(addressDigest(email), now)
	if sd, ok := sourceDigest(ctx); ok {
		if w := l.source.wait(sd, now); w > wait {
			wait = w
		}
	}
	if wait <= 0 {
		return nil
	}
	return &RateLimitedError{RetryAfter: wait}
}

func (l *loginThrottle) failure(ctx context.Context, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.address.fail(addressDigest(email), now)
	if sd, ok := sourceDigest(ctx); ok {
		l.source.fail(sd, now)
	}
}

func (l *loginThrottle) success(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.address.keys, addressDigest(email))
}
