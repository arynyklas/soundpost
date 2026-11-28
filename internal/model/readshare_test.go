// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent checks of one request that share a barrier wait for the one barrier that runs and make no other; a failed
// barrier is not kept; an invalidation, and a context that does not share, make a barrier of their own.
func TestReadShareMakesOneBarrierForConcurrentChecks(t *testing.T) {
	var barriers atomic.Int64
	slow := func(context.Context) error { barriers.Add(1); time.Sleep(30 * time.Millisecond); return nil }
	ctx := WithReadShare(context.Background())
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := SharedReadBarrier(ctx, slow); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := barriers.Load(); got != 1 {
		t.Fatalf("16 concurrent checks made %d barriers, want 1", got)
	}

	InvalidateReadShare(ctx)
	if err := SharedReadBarrier(ctx, slow); err != nil || barriers.Load() != 2 {
		t.Fatalf("after an invalidation: %d barriers (%v), want 2", barriers.Load(), err)
	}
	if err := SharedReadBarrier(ctx, slow); err != nil || barriers.Load() != 2 {
		t.Fatalf("a check after the new barrier made one: %d", barriers.Load())
	}
	fresh := WithoutReadShare(ctx)
	for want := int64(3); want <= 4; want++ {
		if err := SharedReadBarrier(fresh, slow); err != nil || barriers.Load() != want {
			t.Fatalf("a check that does not share: %d barriers (%v), want %d", barriers.Load(), err, want)
		}
	}
	if err := SharedReadBarrier(context.Background(), slow); err != nil || barriers.Load() != 5 {
		t.Fatalf("a check with no share: %d barriers (%v), want 5", barriers.Load(), err)
	}
}

func TestAFailedBarrierIsNotKeptAndAWaiterThatLeavesIsLeftAlone(t *testing.T) {
	ctx := WithReadShare(context.Background())
	boom := errors.New("no quorum")
	if err := SharedReadBarrier(ctx, func(context.Context) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	var ran bool
	if err := SharedReadBarrier(ctx, func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("the barrier after a failed one did not run: %v", err)
	}

	// A check that waits for the barrier another is making leaves when its context ends.
	InvalidateReadShare(ctx)
	release := make(chan struct{})
	running := make(chan struct{})
	go SharedReadBarrier(ctx, func(context.Context) error { close(running); <-release; return nil })
	<-running
	waiter, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := SharedReadBarrier(waiter, func(context.Context) error { t.Error("a second barrier ran"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the waiter got %v, want its deadline", err)
	}
	close(release)
}
