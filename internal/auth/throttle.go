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
//
// Each table holds at most throttleMaxKeys keys. A blocked key is never evicted
// to make room: when the table is full of blocked keys a NEW key is refused with
// the same 429 until the earliest block expires, so a flood of throwaway keys
// can never reset a victim's block. Blocks live in memory only and are per
// process: with N nodes each node applies the limits independently, so the
// cluster-wide limit is up to N times the per-node one (decision proposed by
// lane 1 wave 7, recommendation: accept; see docs/operations/bootstrap.md).
//
// Elevation start and elevation read are throttled per credential (the session
// token digest), separately from login: start counts every attempt, read counts
// only lookups that found no usable elevation (guessing).
const (
	throttleWindow       = 5 * time.Minute
	throttleAddressLimit = 10
	throttleSourceLimit  = 50
	throttleMaxKeys      = 4096

	throttleElevationStartLimit    = 10
	throttleElevationReadMissLimit = 30
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

// SourceFrom is the source WithSource tagged ctx with, or "".
func SourceFrom(ctx context.Context) string {
	s, _ := ctx.Value(sourceKey{}).(string)
	return s
}

type failureWindow struct {
	times []time.Time
}

type throttleTable struct {
	limit int
	keys  map[[32]byte]*failureWindow
}

type loginThrottle struct {
	mu        sync.Mutex
	now       func() time.Time
	address   throttleTable
	source    throttleTable
	elevStart throttleTable // per credential: every elevation start
	elevRead  throttleTable // per credential: elevation reads that found nothing
}

func newLoginThrottle(now func() time.Time) *loginThrottle {
	table := func(limit int) throttleTable {
		return throttleTable{limit: limit, keys: map[[32]byte]*failureWindow{}}
	}
	return &loginThrottle{
		now:       now,
		address:   table(throttleAddressLimit),
		source:    table(throttleSourceLimit),
		elevStart: table(throttleElevationStartLimit),
		elevRead:  table(throttleElevationReadMissLimit),
	}
}

// credentialCheck refuses with 429 when the credential already holds the limit
// of attempts in the table inside the window.
func (l *loginThrottle) credentialCheck(t *throttleTable, kind, token string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := t.wait(throttleDigest(kind, hashToken(token)), l.now()); wait > 0 {
		return &RateLimitedError{RetryAfter: wait}
	}
	return nil
}

// credentialRecord counts one attempt against the credential.
func (l *loginThrottle) credentialRecord(t *throttleTable, kind, token string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t.fail(throttleDigest(kind, hashToken(token)), l.now())
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

// wait returns how long until key may try again; zero when allowed. A key the
// table does not track is refused too while the table is saturated (full of
// blocked keys, no slack key to give up): a new key cannot be recorded then, so
// it is refused instead of being let through unmetered.
func (t *throttleTable) wait(k [32]byte, now time.Time) time.Duration {
	w := t.keys[k]
	if w == nil {
		return t.saturatedWait(now)
	}
	t.prune(k, w, now)
	if len(w.times) < t.limit {
		return 0
	}
	return w.times[0].Add(throttleWindow).Sub(now)
}

// saturatedWait is zero unless the table is at its cap, holds no expired key
// and no slack key; then it is the time until the first blocked key expires.
func (t *throttleTable) saturatedWait(now time.Time) time.Duration {
	if len(t.keys) < throttleMaxKeys {
		return 0
	}
	var first time.Time
	for k, w := range t.keys {
		t.prune(k, w, now)
		if len(w.times) == 0 {
			continue
		}
		if len(w.times) < t.limit {
			return 0
		}
		if exp := w.times[0].Add(throttleWindow); first.IsZero() || exp.Before(first) {
			first = exp
		}
	}
	if len(t.keys) < throttleMaxKeys || first.IsZero() {
		return 0
	}
	return first.Sub(now)
}

func (t *throttleTable) fail(k [32]byte, now time.Time) {
	w := t.keys[k]
	if w == nil {
		if len(t.keys) >= throttleMaxKeys && !t.makeRoom(now) {
			return // saturated: wait() refuses this key, nothing is evicted
		}
		w = &failureWindow{}
		t.keys[k] = w
	}
	if len(w.times) >= t.limit {
		w.times = w.times[1:]
	}
	w.times = append(w.times, now)
}

// makeRoom drops expired keys, then, if the table is still full, the key with
// the oldest latest failure among those that are not blocking anyone yet (fewer
// failures than the limit). A blocked key is never evicted: when every tracked
// key is blocked makeRoom reports false and the caller refuses the new key (429)
// instead. A flood of throwaway addresses therefore can neither free a blocked
// address nor reset a victim's block; its cost is that new keys are refused for
// up to one window while the table holds throttleMaxKeys blocked keys.
func (t *throttleTable) makeRoom(now time.Time) bool {
	for k, w := range t.keys {
		t.prune(k, w, now)
	}
	if len(t.keys) < throttleMaxKeys {
		return true
	}
	var oldest [32]byte
	var at time.Time
	found := false
	for k, w := range t.keys {
		if len(w.times) >= t.limit {
			continue
		}
		if last := w.times[len(w.times)-1]; !found || last.Before(at) {
			oldest, at, found = k, last, true
		}
	}
	if !found {
		return false
	}
	delete(t.keys, oldest)
	return true
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
