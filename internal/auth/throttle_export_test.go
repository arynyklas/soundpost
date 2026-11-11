// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

// KDFRuns exposes the password-KDF evaluation counter to the external tests.
func KDFRuns() int64 { return kdfRuns.Load() }

// ThrottleKeys reports how many address and source keys the login throttle holds.
func (s *Service) ThrottleKeys() (address, source int) {
	s.throttle.mu.Lock()
	defer s.throttle.mu.Unlock()
	return len(s.throttle.address.keys), len(s.throttle.source.keys)
}

// ThrottleMaxKeys is the hard cap per table.
const ThrottleMaxKeys = throttleMaxKeys
