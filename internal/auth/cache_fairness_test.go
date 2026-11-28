// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
)

// TestOnePrincipalCannotEvictAnotherPrincipalsWarmEntries pins review item M9: eviction at the
// capacity limit takes from whoever holds the most entries, so a principal cycling many keys
// thrashes only its own cache, never a quiet neighbour's.
func TestOnePrincipalCannotEvictAnotherPrincipalsWarmEntries(t *testing.T) {
	f := newCacheFixture(t)
	quiet, _ := f.reader("quiet@example.test", auth.Read)
	noisy, _ := f.reader("noisy@example.test", auth.Read)
	cache := f.cache(f.service.SourceLifecycleGenerations()) // capacity 8
	quietScope, noisyScope := f.scope(quiet, auth.Read), f.scope(noisy, auth.Read)
	if quietScope.VisibilityFingerprint() == noisyScope.VisibilityFingerprint() {
		t.Fatal("fixture needs two distinct visibilities")
	}
	store := func(scope auth.Scope, query string) {
		t.Helper()
		miss, err := cache.Lookup(f.ctx, scope, "p", query, "t")
		if err != nil || miss.Hit {
			t.Fatalf("%s: expected a cold miss: %v", query, err)
		}
		if err = cache.Store(f.ctx, scope, miss.Fill, []byte(query), false); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		store(quietScope, fmt.Sprintf("quiet-%d", i))
	}
	for i := range 64 {
		store(noisyScope, fmt.Sprintf("noisy-%d", i))
	}
	for i := range 3 {
		hit, err := cache.Lookup(f.ctx, quietScope, "p", fmt.Sprintf("quiet-%d", i), "t")
		if err != nil || !hit.Hit {
			t.Fatalf("quiet principal's warm entry %d was evicted by another principal's traffic (err %v)", i, err)
		}
	}
	// The noisy principal still gets a bounded cache of its own.
	hits := 0
	for i := range 64 {
		if hit, err := cache.Lookup(f.ctx, noisyScope, "p", fmt.Sprintf("noisy-%d", i), "t"); err == nil && hit.Hit {
			hits++
		}
	}
	if hits == 0 || hits > 8 {
		t.Fatalf("noisy principal holds %d entries, want 1..8", hits)
	}
}
