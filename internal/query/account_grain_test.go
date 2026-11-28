// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

// Every sample a query holds is charged to its account, but the process-wide pool is charged in grains:
// ten thousand 100-byte reservations are a handful of pool operations, not ten thousand compare-and-swaps
// on one counter shared by every worker (6 % of the CPU of the gate mix).
func TestAccountChargesThePoolInGrains(t *testing.T) {
	pool := newMemoryPool(1 << 30)
	a := newQueryAccount(pool, 256<<20)
	const n, size = 10_000, 100
	for range n {
		if err := a.Reserve(size); err != nil {
			t.Fatal(err)
		}
	}
	if got, max := pool.charges.Load(), uint64(n*size/creditGrain+2); got > max {
		t.Fatalf("%d pool charges for %d reservations, want at most %d", got, n, max)
	}
	if used, _ := pool.snapshot(); used < n*size || used > n*size+2*creditGrain {
		t.Fatalf("pool holds %d for an account that handed out %d (grain %d)", used, n*size, creditGrain)
	}
	if a.peakBytes() != n*size {
		t.Fatalf("account peak %d, want %d: the grain is not the query's own use", a.peakBytes(), n*size)
	}
	for range n {
		a.Release(size)
	}
	if used, _ := pool.snapshot(); used > 2*creditGrain {
		t.Fatalf("pool keeps %d after the account released everything, want at most two grains", used)
	}
	if leaked, over := a.finish(); leaked != 0 || over != 0 {
		t.Fatalf("leaked %d over-released %d", leaked, over)
	}
	if used, _ := pool.snapshot(); used != 0 {
		t.Fatalf("pool holds %d after finish", used)
	}
}

// A pool with less than a grain left still serves exactly what an account needs, and the per-query cap and
// the pool limit stay exact.
func TestAccountNearTheLimitsChargesExactly(t *testing.T) {
	pool := newMemoryPool(1000)
	a := newQueryAccount(pool, 800)
	if err := a.Reserve(700); err != nil {
		t.Fatalf("700 of a 1000-byte pool: %v", err)
	}
	if err := a.Reserve(101); err == nil {
		t.Fatal("a reservation over the per-query cap was accepted")
	}
	b := newQueryAccount(pool, 800)
	if err := b.Reserve(301); err == nil {
		t.Fatal("a reservation over the pool limit was accepted")
	}
	// a holds 100 bytes of credit beyond its 700 (its grain was cut to its cap of 800): the slack is at most
	// one grain per account and is returned when the account finishes.
	if err := b.Reserve(200); err != nil {
		t.Fatalf("what is left of the pool beside a's credit: %v", err)
	}
	if err := b.Reserve(1); err == nil {
		t.Fatal("a reservation on a full pool was accepted")
	}
	a.finish()
	b.finish()
	if used, _ := pool.snapshot(); used != 0 {
		t.Fatalf("pool holds %d after both accounts finished", used)
	}
}
