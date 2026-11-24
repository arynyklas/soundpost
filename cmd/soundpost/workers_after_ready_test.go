// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/health"
)

// The background runner starts only once the node is ready: its first passes catch up on everything admitted
// since it last ran (decoding and committing to the control state again and again), and on a restart that
// competed with the readiness probe for the same cores and the same state. A probe that fails is a node that
// is not ready; the runner starts once, when it answers ready, and not at all when the process stops first.
func TestWorkersStartOnlyOnceTheNodeIsReady(t *testing.T) {
	var asks, ran atomic.Int64
	var up atomic.Bool
	probe := func(context.Context) (health.Readiness, error) {
		asks.Add(1)
		switch asks.Load() {
		case 1:
			return health.Readiness{}, errors.New("state unavailable")
		case 2:
			return health.Readiness{Reason: health.ReasonApplyLag}, nil
		}
		return health.Readiness{Ready: up.Load()}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 2)
	afterReady(ctx, probe, time.Millisecond, func() { ran.Add(1); started <- struct{}{} })
	time.Sleep(100 * time.Millisecond)
	if ran.Load() != 0 || asks.Load() < 3 {
		t.Fatalf("the runner started %d times while the node was not ready (%d probes)", ran.Load(), asks.Load())
	}
	up.Store(true)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not start after the node became ready")
	}
	time.Sleep(50 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("the runner started %d times, want once", ran.Load())
	}
}

func TestWorkersDoNotStartWhenTheProcessStopsBeforeReady(t *testing.T) {
	var ran atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	afterReady(ctx, func(context.Context) (health.Readiness, error) { return health.Readiness{}, nil }, time.Millisecond, func() { ran.Add(1) })
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
	if ran.Load() != 0 {
		t.Fatalf("the runner started %d times on a node that was never ready", ran.Load())
	}
}
