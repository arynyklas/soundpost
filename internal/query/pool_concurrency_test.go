// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"sync"
	"sync/atomic"
	"testing"
)

// The process-wide memory pool is charged and released by every query on every sample it holds. Many
// concurrent holders never get more than the limit between them, a refused charge changes nothing, and
// when all have released the pool is empty again, with a peak that never passed the limit.
func TestMemoryPoolConcurrentChargesStayWithinTheLimit(t *testing.T) {
	const limit, holders, rounds = 1 << 20, 16, 20000
	pool := newMemoryPool(limit)
	var held, refused atomic.Int64
	var wg sync.WaitGroup
	for h := range holders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			size := int64(1+h) * 997
			for range rounds {
				if err := pool.reserve(size); err != nil {
					refused.Add(1)
					continue
				}
				if now := held.Add(size); now > limit {
					t.Errorf("%d bytes held against a limit of %d", now, limit)
				}
				held.Add(-size)
				pool.release(size)
			}
		}()
	}
	wg.Wait()
	if used, peak := pool.snapshot(); used != 0 || peak > limit || peak == 0 {
		t.Fatalf("used %d, peak %d after every holder released (limit %d, %d charges refused)", used, peak, limit, refused.Load())
	}
	if err := pool.reserve(limit + 1); err == nil {
		t.Fatal("a charge over the limit was accepted")
	}
	if err := pool.reserve(limit); err != nil {
		t.Fatalf("a charge of exactly the limit on an empty pool: %v", err)
	}
	if err := pool.reserve(1); err == nil {
		t.Fatal("a charge on a full pool was accepted")
	}
	pool.release(limit + 5)
	if used, _ := pool.snapshot(); used != 0 {
		t.Fatalf("a release beyond what is held left %d used", used)
	}
}
