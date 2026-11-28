// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
)

// maxSlotWaiters bounds the appends that wait for one slot's lock. The lock is held for the checks of an append and for the
// time its command takes to be queued (and, for an append a member makes without leading the slot, for one replicated commit:
// tens of milliseconds on a healthy group, a few hundred under load), so a queue this deep is seconds: an append behind it would
// be answered after its caller's budget, and every caller that gave up and asked again (the senders retry) would only add to it.
// An append that finds the queue full is refused at once as a timeout, which a sender retries after its own backoff, at another
// member.
const maxSlotWaiters = 64

// maxSlotInflight bounds the appends of one slot that are queued and not yet decided (append_queue.go).
const maxSlotInflight = 256

// slotLock orders the appends of one slot (Engine.slotMu): a lock a caller can stop waiting for, so that an append whose
// request has gone is not carried out behind the others, and with a bound on how many wait.
type slotLock struct {
	once    sync.Once
	token   chan struct{}
	waiting atomic.Int32
	// flight is what the leader of the slot has queued and not yet seen decided.
	flight slotFlight
}

func (l *slotLock) init() { l.once.Do(func() { l.token = make(chan struct{}, 1) }) }

// acquire takes the lock, waiting in arrival order until ctx ends (cancelled) or maxSlotWaiters are waiting (timeout: the append
// did not get its turn, which a caller that asks the leader takes for the leader's answer, not for a leader that does not
// serve the call).
func (l *slotLock) acquire(ctx context.Context) error {
	l.init()
	select {
	case l.token <- struct{}{}:
		return nil
	default:
	}
	if l.waiting.Add(1) > maxSlotWaiters {
		l.waiting.Add(-1)
		return model.Fail(model.Timeout)
	}
	defer l.waiting.Add(-1)
	select {
	case l.token <- struct{}{}:
		return nil
	case <-ctx.Done():
		return model.Fail(model.Cancelled)
	}
}

func (l *slotLock) release() { <-l.token }
