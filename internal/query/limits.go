// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"soundpost/internal/model"
	"sync"
	"sync/atomic"
	"time"
)

// Limits owns every operator-visible bound of the C06 service. Defaults follow
// the approved design: 30 seconds, 256 MiB of working memory and 5 million
// returned samples or logs per query. Each Max* field is the operator's explicit
// grant ceiling: a request may ask for less than the default, or for more up to
// the ceiling, and anything above it is rejected before work starts.
type Limits struct {
	DefaultTimeout, MaxTimeout   time.Duration
	DefaultMemory, MaxMemory     int64
	DefaultReturned, MaxReturned uint64

	MaxProjects        int
	MaxExpressionBytes int
	MaxDiscoveryItems  uint32
	MaxDiagnostics     int
	MaxMinCursors      int

	// ProjectParallelism bounds the project fan-out of one query.
	ProjectParallelism int

	// GlobalMemory bounds the accounted working memory of every running query
	// together; it must be able to hold one maximum-budget query.
	GlobalMemory int64

	// MaxConcurrent, MaxPerOrg and MaxPerPrincipal bound running queries. Waiting
	// queries are queued per organization (at most MaxQueuedPerOrg, for at most
	// MaxQueueWait) and admitted round-robin across organizations.
	MaxConcurrent, MaxPerOrg, MaxPerPrincipal int
	MaxQueuedPerOrg                           int
	MaxQueueWait                              time.Duration

	// RevalidateInterval is how often a running query revalidates its scope and
	// delete generation while it computes; it must not exceed five seconds.
	RevalidateInterval time.Duration

	// CacheSettle is how far behind the clock the newest evaluated time must be
	// before a PromQL, discovery or exemplar response may be cached. A fresher
	// window could still receive late data, so it is always recomputed.
	CacheSettle time.Duration
}

const (
	defaultMemory   int64 = 256 << 20
	defaultReturned       = 5_000_000
	maxRevalidate         = 5 * time.Second
)

func DefaultLimits() Limits {
	return Limits{
		DefaultTimeout: 30 * time.Second, MaxTimeout: 30 * time.Second,
		DefaultMemory: defaultMemory, MaxMemory: defaultMemory,
		DefaultReturned: defaultReturned, MaxReturned: defaultReturned,
		MaxProjects: 128, MaxExpressionBytes: 32 << 10, MaxDiscoveryItems: 10000, MaxDiagnostics: 256, MaxMinCursors: 1024,
		ProjectParallelism: 4,
		GlobalMemory:       1 << 30,
		MaxConcurrent:      8, MaxPerOrg: 4, MaxPerPrincipal: 2,
		MaxQueuedPerOrg: 16, MaxQueueWait: 10 * time.Second,
		RevalidateInterval: 2 * time.Second,
		CacheSettle:        time.Minute,
	}
}

func (l Limits) validate() error {
	switch {
	case l.DefaultTimeout <= 0 || l.MaxTimeout < l.DefaultTimeout,
		l.DefaultMemory <= 0 || l.MaxMemory < l.DefaultMemory,
		l.DefaultReturned == 0 || l.MaxReturned < l.DefaultReturned,
		l.MaxProjects < 1 || l.MaxProjects > 128,
		l.MaxExpressionBytes < 1 || l.MaxExpressionBytes > 60<<10,
		l.MaxDiscoveryItems < 1,
		l.MaxDiagnostics < 1,
		l.MaxMinCursors < 1,
		l.ProjectParallelism < 1,
		l.GlobalMemory < l.MaxMemory,
		l.MaxConcurrent < 1, l.MaxPerOrg < 1 || l.MaxPerOrg > l.MaxConcurrent, l.MaxPerPrincipal < 1 || l.MaxPerPrincipal > l.MaxPerOrg,
		l.MaxQueuedPerOrg < 0, l.MaxQueueWait <= 0,
		l.RevalidateInterval <= 0 || l.RevalidateInterval > maxRevalidate,
		l.CacheSettle < 0:
		return model.Fail(model.Invalid)
	}
	return nil
}

// resolve applies the defaults to a requested budget and rejects any request
// above the operator ceiling.
func (l Limits) resolve(b Budget) (timeout time.Duration, memory int64, returned uint64, err error) {
	timeout, memory, returned = l.DefaultTimeout, l.DefaultMemory, l.DefaultReturned
	if b.TimeoutNS < 0 {
		return 0, 0, 0, model.Fail(model.Invalid)
	}
	if b.TimeoutNS != 0 {
		if time.Duration(b.TimeoutNS) > l.MaxTimeout || int64(b.TimeoutNS) < 0 {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		timeout = time.Duration(b.TimeoutNS)
	}
	if b.MemoryBytes != 0 {
		if uint64(b.MemoryBytes) > uint64(l.MaxMemory) {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		memory = int64(b.MemoryBytes)
	}
	if b.MaxReturned != 0 {
		if uint64(b.MaxReturned) > l.MaxReturned {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		returned = uint64(b.MaxReturned)
	}
	return timeout, memory, returned, nil
}

// memoryPool is the process-wide aggregate of every query account. A query
// charges it before allocating and releases on every path, so the sum of all
// concurrent working memory never exceeds the limit.
type memoryPool struct {
	mu                sync.Mutex
	limit, used, peak int64
}

func newMemoryPool(limit int64) *memoryPool { return &memoryPool{limit: limit} }
func (p *memoryPool) reserve(n int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n < 0 || n > p.limit-p.used {
		return model.Fail(model.Quota)
	}
	p.used += n
	if p.used > p.peak {
		p.peak = p.used
	}
	return nil
}
func (p *memoryPool) release(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used -= n
	if p.used < 0 {
		p.used = 0
	}
}
func (p *memoryPool) snapshot() (used, peak int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used, p.peak
}

// queryAccount is the single value.Account shared by every worker, parser,
// planner, regex scope, scan, merge and result conversion of one query, so the
// per-query cap applies to the aggregate of all of them. Reserve is charged
// before allocation. A latched failure (a revocation, a deletion) makes every
// later Reserve and Check fail with that typed error, so compute stops even
// where it is not watching its context.
type queryAccount struct {
	pool  *memoryPool
	limit int64

	mu           sync.Mutex
	used, peak   int64
	overReleased int64

	failure atomic.Pointer[accountFailure]
}
type accountFailure struct{ err error }

func newQueryAccount(pool *memoryPool, limit int64) *queryAccount {
	return &queryAccount{pool: pool, limit: limit}
}
func (a *queryAccount) Reserve(n int64) error {
	if f := a.failure.Load(); f != nil {
		return f.err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || n > a.limit-a.used {
		return model.Fail(model.Quota)
	}
	if err := a.pool.reserve(n); err != nil {
		return err
	}
	a.used += n
	if a.used > a.peak {
		a.peak = a.used
	}
	return nil
}
func (a *queryAccount) Release(n int64) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > a.used {
		a.overReleased += n - a.used
		n = a.used
	}
	a.used -= n
	a.pool.release(n)
}
func (a *queryAccount) Check(ctx context.Context) error {
	if f := a.failure.Load(); f != nil {
		return f.err
	}
	return ctx.Err()
}

// fail latches the first failure.
func (a *queryAccount) fail(err error) { a.failure.CompareAndSwap(nil, &accountFailure{err}) }
func (a *queryAccount) latched() error {
	if f := a.failure.Load(); f != nil {
		return f.err
	}
	return nil
}

// finish returns whatever was still charged to the pool and reports it so a
// leaking path is visible to tests and operators.
func (a *queryAccount) finish() (leaked, overReleased int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	leaked, overReleased = a.used, a.overReleased
	a.pool.release(a.used)
	a.used = 0
	return leaked, overReleased
}
func (a *queryAccount) peakBytes() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peak
}

// projectAccount is one project worker's view of the shared account: every
// charge lands on the query account, and the view additionally measures the
// project's own current and peak bytes for its Stats.
type projectAccount struct {
	q          *queryAccount
	mu         sync.Mutex
	used, peak int64
}

func (a *projectAccount) Reserve(n int64) error {
	if err := a.q.Reserve(n); err != nil {
		return err
	}
	a.mu.Lock()
	a.used += n
	if a.used > a.peak {
		a.peak = a.used
	}
	a.mu.Unlock()
	return nil
}
func (a *projectAccount) Release(n int64) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	over := int64(0)
	if n > a.used {
		over = n - a.used
		n = a.used
	}
	a.used -= n
	a.mu.Unlock()
	if over > 0 {
		a.q.mu.Lock()
		a.q.overReleased += over
		a.q.mu.Unlock()
	}
	a.q.Release(n)
}
func (a *projectAccount) Check(ctx context.Context) error { return a.q.Check(ctx) }
func (a *projectAccount) peakBytes() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peak
}
