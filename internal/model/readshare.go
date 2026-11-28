// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"context"
	"sync/atomic"
	"time"
)

// A request that asks the control state several questions in a row (an ingest request: who is the source, is it still
// the source, is the scope still valid, what retention applies, is the reservation there) paid a linearizable read (a
// ReadIndex round of the control group) for each of them: 6 to 8 per request, each of which waits for a quorum
// confirmation (140 ms at the leader, 410-447 ms at a follower on the cluster at 1750 records/s, 43 % of the follower's
// calls given up at the 1 s round timeout).
//
// A ReadShare is the one read such a request makes for all the checks that precede a change: the first check runs the
// barrier, the checks after it read the state the node has applied, which is at least what the barrier confirmed (the
// applied state only moves forward), without a barrier of their own. What a check that shares is told is therefore
// the committed state as of the barrier, which began after the request did, and no older than readShareMaxAge.
//
// What stays linearizable, each with a barrier of its own (WithoutReadShare, InvalidateReadShare):
//   - the check that a batch is still admissible after everything was done for it (the revalidation before the receipt
//     is answered): a source revoked before the answer is made is never answered, and a revocation that returned before
//     the request began is seen by its first check;
//   - the first check after a transition of the request itself (the reservation): it has to see it;
//   - the rounds that commit a transition (they are proposals against the application index, judged by the leader).
type ReadShare struct {
	sem   chan struct{}
	at    atomic.Int64 // when the newest completed barrier began, as readClock; 0 = none
	floor atomic.Int64 // when the share was last invalidated: a barrier that began before it does not count
}

type readShareKey struct{}

// readShareMaxAge is how old the barrier a check may rest on can be.
const readShareMaxAge = 2 * time.Second

var readClockBase = time.Now()

func readClock() int64 { return int64(time.Since(readClockBase)) + 1 }

// WithReadShare marks ctx so that the control reads made under it share one barrier (a ctx that already shares keeps its share).
func WithReadShare(ctx context.Context) context.Context {
	if ctx.Value(readShareKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, readShareKey{}, &ReadShare{sem: make(chan struct{}, 1)})
}

// WithoutReadShare marks ctx so that the control reads made under it each make a barrier of their own, whatever ctx shared before.
func WithoutReadShare(ctx context.Context) context.Context {
	if ctx.Value(readShareKey{}) == nil {
		return ctx
	}
	return context.WithValue(ctx, readShareKey{}, (*ReadShare)(nil))
}

// InvalidateReadShare makes the next read under ctx make a barrier: the request changed the state its next check is to see.
func InvalidateReadShare(ctx context.Context) {
	if s, _ := ctx.Value(readShareKey{}).(*ReadShare); s != nil {
		s.floor.Store(readClock())
	}
}

// SharedReadBarrier runs barrier, the confirmation a control read makes before it reads, unless ctx shares one that was made and still
// counts: then it returns without a barrier. Callers wait for the barrier that is running (they would wait for the same quorum
// round); a barrier that failed is not kept.
func SharedReadBarrier(ctx context.Context, barrier func(context.Context) error) error {
	s, _ := ctx.Value(readShareKey{}).(*ReadShare)
	if s == nil {
		return barrier(ctx)
	}
	if s.fresh() {
		return nil
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.sem }()
	if s.fresh() {
		return nil
	}
	began := readClock()
	if err := barrier(ctx); err != nil {
		return err
	}
	s.at.Store(began)
	return nil
}

func (s *ReadShare) fresh() bool {
	at := s.at.Load()
	return at != 0 && at > s.floor.Load() && readClock()-at < int64(readShareMaxAge)
}
