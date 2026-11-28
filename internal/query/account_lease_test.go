// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"errors"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A project worker of a log query reserves the cost of a row and releases it at the next row: tens of
// thousands of times a second, by ten workers, on one mutex of the query's account (45 CPU seconds of the
// 24 h log class in the gate mix). A project view leases a few KiB from the query account and serves the
// small charges itself.
func TestProjectAccountServesSmallChargesFromALease(t *testing.T) {
	pool := newMemoryPool(1 << 30)
	q := newQueryAccount(pool, 256<<20)
	p := &projectAccount{q: q}
	const n, size = 10_000, 400
	for range n {
		if err := p.Reserve(size); err != nil {
			t.Fatal(err)
		}
		p.Release(size)
	}
	if got := q.ops.Load(); got > 8 {
		t.Fatalf("%d calls on the query account for %d reserve/release pairs, want at most 8", got, n)
	}
	if p.peakBytes() != size {
		t.Fatalf("project peak %d, want %d: the lease is not the project's own use", p.peakBytes(), size)
	}
	p.flush()
	if leaked, over := q.finish(); leaked != 0 || over != 0 {
		t.Fatalf("leaked %d over-released %d", leaked, over)
	}
	if used, _ := pool.snapshot(); used != 0 {
		t.Fatalf("pool holds %d after finish", used)
	}
}

// The per-query cap stays exact for what a project really holds, a latched failure stops a project that
// is served from its lease, and what the project still holds is leaked, not hidden in the lease.
func TestProjectAccountKeepsTheQueryCapAndFailureExact(t *testing.T) {
	pool := newMemoryPool(1 << 30)
	q := newQueryAccount(pool, 10_000)
	p := &projectAccount{q: q}
	if err := p.Reserve(9_000); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve(1_001); err == nil {
		t.Fatal("a reservation over the query cap was accepted")
	}
	if err := p.Reserve(1_000); err != nil {
		t.Fatalf("what is left under the cap: %v", err)
	}
	if err := p.Reserve(1); err == nil {
		t.Fatal("a reservation on a full account was accepted")
	}
	p.Release(10_000)
	if err := p.Reserve(10); err != nil {
		t.Fatal(err)
	}
	want := model.Fail(model.Cancelled)
	q.fail(want)
	if err := p.Reserve(10); !errors.Is(err, want) {
		t.Fatalf("reserve after a latched failure: %v, want %v", err, want)
	}
	p.flush()
	if leaked, _ := q.finish(); leaked != 10 {
		t.Fatalf("leaked %d, want the 10 bytes the project still held", leaked)
	}
}

// Concurrent project views of one query never exceed the query's cap and return everything.
func TestProjectAccountsOfOneQueryStayWithinTheCap(t *testing.T) {
	pool := newMemoryPool(1 << 30)
	q := newQueryAccount(pool, 1<<20)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &projectAccount{q: q}
			defer p.flush()
			for range 5_000 {
				if err := p.Reserve(500); err == nil {
					if q.peakBytes() > 1<<20 {
						t.Error("the query cap was exceeded")
					}
					p.Release(500)
				}
			}
		}()
	}
	wg.Wait()
	if leaked, over := q.finish(); leaked != 0 || over != 0 {
		t.Fatalf("leaked %d over-released %d", leaked, over)
	}
}
