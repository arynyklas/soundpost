// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import "sync"

// KDFRuns exposes the password-KDF evaluation counter to the external tests.
func KDFRuns() int64 { return kdfRuns.Load() }

// ColdDummyDigest makes the process-wide dummy digest un-derived again and
// returns the function that restores the previous one. Tests that assert how
// much work the first login after NewService does use it, so no earlier test
// can have warmed the digest for them. Not for parallel tests.
func ColdDummyDigest() (restore func()) {
	saved := dummyDigest
	dummyDigest = sync.OnceValue(deriveDummyDigest)
	return func() { dummyDigest = saved }
}

// ThrottleKeys reports how many address and source keys the login throttle holds.
func (s *Service) ThrottleKeys() (address, source int) {
	s.throttle.mu.Lock()
	defer s.throttle.mu.Unlock()
	return len(s.throttle.address.keys), len(s.throttle.source.keys)
}

// ThrottleMaxKeys is the hard cap per table.
const ThrottleMaxKeys = throttleMaxKeys

// LoginStaleRetries exposes the count of stale repeats login made (the bounded wait of loginStaleBudget).
func LoginStaleRetries() int64 { return loginStaleRetries.Load() }
