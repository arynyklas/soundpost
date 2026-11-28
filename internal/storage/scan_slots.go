// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
)

// ScanSlots is the number of row iterators (Scan) the engine holds open at once. The query admission
// scheduler is the one place that limits concurrency (internal/query/limits.go: MaxConcurrent running
// queries, each selecting at most MaxProjects projects and holding at most one iterator per selected
// project), so the pool is sized for every admitted query: MaxConcurrent x MaxProjects = 16 x 128. A
// Scan that finds no free slot waits for one, in arrival order, until its context ends; a request is
// never answered too_large because other queries are running. query.Limits.validate refuses limits
// whose product exceeds this number.
const ScanSlots = 2048

// LiveSlots is the separate budget of live subscriptions (Subscribe). A subscription is long-lived, so
// it never shares the scan budget: a full set of tails cannot starve a scan, and a scan burst cannot
// starve a tail. It covers the live service's default MaxStreams (24) with headroom.
const LiveSlots = 32

// slotPool is a counting semaphore that grants in arrival order and honours the context of every
// waiter. Its lock is a leaf: nothing is called under it, so a slot may be released with e.mu held,
// and acquire must be called with no engine lock.
type slotPool struct {
	mu      sync.Mutex
	limit   int
	used    int
	waiters list.List // of *slotWaiter, front = oldest
}
type slotWaiter struct {
	ready   chan struct{}
	granted bool
}

// setLimit resizes the pool (tests); a pool never resized takes the limit its first acquire names.
func (p *slotPool) setLimit(n int) {
	p.mu.Lock()
	p.limit = n
	p.releaseLocked(0)
	p.mu.Unlock()
}

// acquire takes a slot, waiting for one in arrival order. A context that ends first answers
// cancelled (or timeout when its deadline passed); the slot is then not held.
func (p *slotPool) acquire(ctx context.Context, limit int) error {
	if err := ctx.Err(); err != nil {
		return slotFault(err)
	}
	p.mu.Lock()
	if p.limit == 0 {
		p.limit = limit
	}
	if p.used < p.limit && p.waiters.Len() == 0 {
		p.used++
		p.mu.Unlock()
		return nil
	}
	w := &slotWaiter{ready: make(chan struct{})}
	el := p.waiters.PushBack(w)
	p.mu.Unlock()
	select {
	case <-w.ready:
		return nil
	case <-ctx.Done():
	}
	p.mu.Lock()
	if w.granted {
		// Granted as the wait ended: the context decides, so hand the slot on.
		p.releaseLocked(1)
		p.mu.Unlock()
		return slotFault(ctx.Err())
	}
	p.waiters.Remove(el)
	p.mu.Unlock()
	return slotFault(ctx.Err())
}

func slotFault(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.Fail(model.Timeout)
	}
	return model.Fail(model.Cancelled)
}

// release returns one slot and grants it to the oldest waiter.
func (p *slotPool) release() {
	p.mu.Lock()
	p.releaseLocked(1)
	p.mu.Unlock()
}
func (p *slotPool) releaseLocked(n int) {
	p.used -= n
	for p.used < p.limit && p.waiters.Len() > 0 {
		front := p.waiters.Front()
		w := p.waiters.Remove(front).(*slotWaiter)
		w.granted = true
		p.used++
		close(w.ready)
	}
}

// slotUse reports the slots held and the waiters queued (tests and diagnostics).
func (p *slotPool) slotUse() (used, waiting int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used, p.waiters.Len()
}
