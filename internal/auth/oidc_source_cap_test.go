// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"fmt"
	"testing"

	"soundpost/internal/auth"
)

// Decision D6: the pending-login cap is per client address inside the global ceiling, so one
// address that fills its share cannot block every other address.
func TestOIDCStartCapsPendingRecordsPerClientAddress(t *testing.T) {
	f := newSweepFixture(t)
	const perSource = 3
	t.Cleanup(auth.SetPendingOIDCSourceCap(perSource))
	greedy := auth.WithSource(f.ctx, "203.0.113.9")
	for i := range perSource {
		if _, err := f.service.OIDCStart(greedy, f.cfg, "binding"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, err := f.service.OIDCStart(greedy, f.cfg, "binding"); err == nil {
		t.Fatal("an address held more pending logins than its share")
	}
	if err := f.service.OIDCCapacity(greedy); err == nil {
		t.Fatal("the capacity probe passes for an address at its share")
	}
	if _, err := f.service.OIDCStart(auth.WithSource(f.ctx, "198.51.100.4"), f.cfg, "binding"); err != nil {
		t.Fatalf("another address was blocked by the greedy one: %v", err)
	}
	if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
		t.Fatalf("a request with no known source was blocked: %v", err)
	}
}

func TestOIDCGlobalCeilingStillBoundsAllAddresses(t *testing.T) {
	f := newSweepFixture(t)
	t.Cleanup(auth.SetPendingOIDCCap(4))
	for i := range 4 {
		if _, err := f.service.OIDCStart(auth.WithSource(f.ctx, fmt.Sprintf("198.51.100.%d", i+1)), f.cfg, "binding"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, err := f.service.OIDCStart(auth.WithSource(f.ctx, "192.0.2.77"), f.cfg, "binding"); err == nil {
		t.Fatal("the global ceiling did not hold")
	}
}
