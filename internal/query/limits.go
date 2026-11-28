// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
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
	// MaxMinCursors bounds the engine's own input. Over HTTP the 64 KiB request
	// body cap is reached first (a cursor is about 90 bytes of JSON, so roughly
	// 600 fit), which fails closed as an oversize body: 1024 is the ceiling the
	// engine accepts, not one the HTTP route can deliver.
	MaxMinCursors int

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
	creditGrain     int64 = 2 << 10 // the pool is charged by a query account in grains of this size
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
		// Sixteen running queries, eight per organization, four per principal: the former 8/4/2 made the
		// ninth and later concurrent query wait behind long ones (at the Queries gate 51 % of the queries
		// queued, 85 % of those on the global limit, and the wait was the p95 of every short class), while
		// the CPU is shared by the Go scheduler either way. The bound that protects the node is the memory
		// pool (GlobalMemory), not the number of running queries. See docs/queries/admission.md.
		MaxConcurrent: 16, MaxPerOrg: 8, MaxPerPrincipal: 4,
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
		// Every admitted query must be able to hold one storage iterator per selected project (D105).
		l.MaxConcurrent > storage.ScanSlots/l.MaxProjects,
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
// concurrent working memory never exceeds the limit. It is lock-free: every
// query of the process charges and releases it on every sample or row it holds, and
// a mutex here was 15 % of the CPU of ten concurrent queries.
type memoryPool struct {
	limit      int64
	used, peak atomic.Int64
	charges    atomic.Uint64 // successful reserves (the accounts charge in grains, so this stays small)
}

func newMemoryPool(limit int64) *memoryPool { return &memoryPool{limit: limit} }
func (p *memoryPool) reserve(n int64) error {
	for {
		used := p.used.Load()
		if n < 0 || n > p.limit-used {
			return model.Fail(model.Quota)
		}
		if p.used.CompareAndSwap(used, used+n) {
			for peak := p.peak.Load(); used+n > peak && !p.peak.CompareAndSwap(peak, used+n); peak = p.peak.Load() {
			}
			p.charges.Add(1)
			return nil
		}
	}
}
func (p *memoryPool) release(n int64) {
	for {
		used := p.used.Load()
		if p.used.CompareAndSwap(used, max(used-n, 0)) {
			return
		}
	}
}
func (p *memoryPool) snapshot() (used, peak int64) { return p.used.Load(), p.peak.Load() }

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
	// credit is memory the account holds in the pool beyond what it has handed out: the pool is charged
	// in grains of creditGrain, not on every sample, because a compare-and-swap on one shared counter by
	// every worker was 6 % of the CPU of the gate mix. used + credit never exceeds limit.
	credit int64

	failure atomic.Pointer[accountFailure]
	// ops counts Reserve and Release calls that took mu: the contention on one query's account.
	ops atomic.Uint64
}
type accountFailure struct{ err error }

func newQueryAccount(pool *memoryPool, limit int64) *queryAccount {
	return &queryAccount{pool: pool, limit: limit}
}
func (a *queryAccount) Reserve(n int64) error {
	if f := a.failure.Load(); f != nil {
		return f.err
	}
	a.ops.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || n > a.limit-a.used {
		return model.Fail(model.Quota)
	}
	if a.credit < n {
		need := n - a.credit
		grain := min(max(need, creditGrain), a.limit-a.used-a.credit)
		if err := a.pool.reserve(grain); err != nil {
			if grain == need {
				return err
			}
			grain = need // the pool cannot spare a whole grain: charge exactly what is needed
			if err = a.pool.reserve(grain); err != nil {
				return err
			}
		}
		a.credit += grain
	}
	a.credit -= n
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
	a.ops.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > a.used {
		a.overReleased += n - a.used
		n = a.used
	}
	a.used -= n
	a.credit += n
	if a.credit > 2*creditGrain {
		a.pool.release(a.credit - creditGrain)
		a.credit = creditGrain
	}
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
	a.pool.release(a.used + a.credit)
	a.used, a.credit = 0, 0
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
//
// The view leases bytes from the query account in grains of leaseGrain and serves the small charges of its
// own worker from the lease: a log query reserves the cost of every row and releases it at the next, and
// those calls by ten project workers on the one mutex of the query account were 45 CPU seconds of the gate
// mix. The bytes of a lease count as used by the query account, so the per-query cap and the pool limit are
// never exceeded; the slack is at most two grains per project view, a lease that does not fit under the cap
// is cut to exactly what is needed, and flush hands the rest back when the project is done.
type projectAccount struct {
	q                 *queryAccount
	mu                sync.Mutex
	used, peak, lease int64
}

const leaseGrain int64 = 4 << 10

func (a *projectAccount) Reserve(n int64) error {
	if f := a.q.failure.Load(); f != nil {
		return f.err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 {
		return model.Fail(model.Quota)
	}
	if a.lease < n {
		need := n - a.lease
		grain := max(need, leaseGrain)
		err := a.q.Reserve(grain)
		if err != nil && grain > need {
			grain = need // the account cannot spare a whole grain: lease exactly what is needed
			err = a.q.Reserve(grain)
		}
		if err != nil {
			return err
		}
		a.lease += grain
	}
	a.lease -= n
	a.used += n
	if a.used > a.peak {
		a.peak = a.used
	}
	return nil
}
func (a *projectAccount) Release(n int64) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > a.used {
		a.q.mu.Lock()
		a.q.overReleased += n - a.used
		a.q.mu.Unlock()
		n = a.used
	}
	a.used -= n
	a.lease += n
	if a.lease > 2*leaseGrain {
		a.q.Release(a.lease - leaseGrain)
		a.lease = leaseGrain
	}
}
func (a *projectAccount) Check(ctx context.Context) error { return a.q.Check(ctx) }
func (a *projectAccount) peakBytes() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peak
}

// flush returns the unused part of the lease to the query account; what the view still holds stays charged.
func (a *projectAccount) flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.q.Release(a.lease)
	a.lease = 0
}
