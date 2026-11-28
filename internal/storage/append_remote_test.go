// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// An append that enters at a voter that does not lead the slot is made by the leader of the slot: the follower proposes
// nothing, the receipt it answers is the one the leader stored, and the follower has applied the append when it answers (a
// read it serves next sees what it acknowledged). A refusal of the leader's checks reaches the follower's caller as the
// refusal, not as an unavailable member.
func TestAnAppendThatEntersAtAFollowerIsMadeByTheLeaderOfItsSlot(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	v := openVoters(t, service, store)
	for node := uint64(1); node <= 3; node++ {
		if err := v.engines[node].BindAppendScopes(service); err != nil {
			t.Fatal(err)
		}
	}
	v.lead(t, func(int) uint64 { return 1 })
	scope, b := normalized(t, store, service, credential, descriptor)

	calls, served, forwarded := remoteAppends.calls.Load(), remoteAppends.served.Load(), appendTimes.fwdN.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	receipt, err := v.engines[2].Append(ctx, scope, b)
	if err != nil {
		t.Fatalf("append at a follower: %v", err)
	}
	if got := remoteAppends.calls.Load() - calls; got != 1 {
		t.Fatalf("the follower made %d calls to the leader, want 1", got)
	}
	if got := remoteAppends.served.Load() - served; got != 1 {
		t.Fatalf("the leader served %d calls, want 1", got)
	}
	if got := appendTimes.fwdN.Load() - forwarded; got != 0 {
		t.Fatalf("the follower forwarded %d proposals of its own: the leader did not make the append", got)
	}
	// What the follower acknowledged it has applied: no wait for the cursor.
	v.engines[2].mu.Lock()
	applied := v.engines[2].indexes[b.RouteSlot]
	v.engines[2].mu.Unlock()
	if applied < uint64(receipt.Cursor.Index) {
		t.Fatalf("the follower answered with the receipt at index %d and has applied only %d", receipt.Cursor.Index, applied)
	}
	// The leader stored it and every voter holds the same bytes.
	v.converge(t, map[uint16]uint64{b.RouteSlot: uint64(receipt.Cursor.Index)})
	reference, stored := storedBatch(t, v.engines[1], b)
	for node := uint64(2); node <= 3; node++ {
		batch, rec := storedBatch(t, v.engines[node], b)
		if !bytes.Equal(batch, reference) || !bytes.Equal(rec, stored) {
			t.Fatalf("node %d holds other bytes for the batch than the leader", node)
		}
	}
	// A retry anywhere answers the original receipt.
	again, err := v.engines[3].Append(ctx, scope, b)
	if err != nil || !bytes.Equal(mustJSON(t, again), mustJSON(t, receipt)) {
		t.Fatalf("retry at another follower: %+v, %v (first %+v)", again, err, receipt)
	}

	// The leader's checks decide: a reservation that is not the batch's is refused by it, as forbidden.
	_, other := normalized(t, store, service, credential, descriptor)
	other.Reservation = b.Reservation
	_, err = v.engines[2].Append(ctx, scope, other)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Forbidden {
		t.Fatalf("a batch with another batch's reservation was answered %v, want the leader's refusal (forbidden)", err)
	}
}

// An append waits for its slot's lock only while its caller does: a caller that has gone is not carried out behind the others,
// and a queue that is full refuses the next one at once.
func TestASlotLockIsLeftByACallerThatGaveUpAndBoundsItsQueue(t *testing.T) {
	var l slotLock
	if err := l.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gone := make(chan error, 1)
	go func() { gone <- l.acquire(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for l.waiting.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the waiter never queued")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	var fault *model.Fault
	if err := <-gone; !errors.As(err, &fault) || fault.Code != model.Cancelled {
		t.Fatalf("a caller whose context ended was answered %v, want cancelled", err)
	}
	if n := l.waiting.Load(); n != 0 {
		t.Fatalf("%d waiters left after the caller gave up", n)
	}

	// maxSlotWaiters wait; the next is refused at once, and the ones queued are served in arrival order.
	order := make(chan int, maxSlotWaiters)
	for i := range maxSlotWaiters {
		go func() {
			if err := l.acquire(context.Background()); err == nil {
				order <- i
				l.release()
			}
		}()
		for l.waiting.Load() != int32(i+1) {
			time.Sleep(time.Millisecond)
		}
	}
	start := time.Now()
	if err := l.acquire(context.Background()); !errors.As(err, &fault) || fault.Code != model.Timeout || time.Since(start) > time.Second {
		t.Fatalf("the append behind a full queue was answered %v after %v, want an immediate timeout", err, time.Since(start))
	}
	l.release()
	for want := range maxSlotWaiters {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("waiter %d was served before waiter %d", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("waiter %d never took the lock", want)
		}
	}
}
