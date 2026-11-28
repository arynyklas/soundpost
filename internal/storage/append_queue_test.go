// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The appends of one slot that its leader makes are queued behind each other and committed together: while the commit of the
// first is in flight the others are in the leader's log, each naming the index after the one before it, and every one is answered
// after its own command is committed and applied. A slot that held its lock for a whole commit put one append in the log per
// round trip.
func TestTheAppendsOfOneSlotAreQueuedWithoutWaitingForEachOthersCommit(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	v := openVoters(t, service, store)
	v.lead(t, func(int) uint64 { return 1 })
	const n = 12
	producer := model.NewID()
	scopes := make([]auth.Scope, n)
	batches := make([]model.NormalizedBatch, n)
	for i := range n {
		scopes[i], batches[i] = normalizedAs(t, store, service, credential, descriptor, producer, model.UnixNano(i+1))
	}
	slot := batches[0].RouteSlot
	delay := 6 * voterTick()
	v.mesh.mu.Lock()
	v.mesh.appDelay[2], v.mesh.appDelay[3] = delay, delay
	v.mesh.mu.Unlock()
	v.engines[1].mu.Lock()
	applied := v.engines[1].indexes[slot]
	v.engines[1].mu.Unlock()
	base := v.groups[1][slot].Status().LastIndex

	type outcome struct {
		receipt model.Receipt
		err     error
	}
	outcomes := make(chan outcome, n)
	started := time.Now()
	for i := range n {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r, err := v.engines[1].Append(ctx, scopes[i], batches[i])
			outcomes <- outcome{r, err}
		}()
	}
	// A slot that commits one append at a time needs n round trips, each of them a delay, to have n entries in its log.
	for v.groups[1][slot].Status().LastIndex < base+n {
		if time.Since(started) > 6*delay {
			t.Fatalf("after %v (6 delays of a follower's append) the leader's log holds %d of the %d appends: the slot waits for each commit before it queues the next", time.Since(started), v.groups[1][slot].Status().LastIndex-base, n)
		}
		time.Sleep(time.Millisecond)
	}
	var indexes []uint64
	for range n {
		o := <-outcomes
		if o.err != nil {
			t.Fatalf("append: %v", o.err)
		}
		indexes = append(indexes, uint64(o.receipt.Cursor.Index))
	}
	slices.Sort(indexes)
	for i, index := range indexes {
		if index != applied+uint64(i)+1 {
			t.Fatalf("the receipts name indexes %v, want %d..%d in a row", indexes, applied+1, applied+n)
		}
	}
	v.converge(t, map[uint16]uint64{slot: applied + n})
}

// A retry of a batch whose first append is still being committed waits for that append and is answered its receipt: the batch is
// queued once.
func TestARetryOfAQueuedAppendIsAnsweredByTheFirst(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	v := openVoters(t, service, store)
	v.lead(t, func(int) uint64 { return 1 })
	scope, b := normalized(t, store, service, credential, descriptor)
	delay := 6 * voterTick()
	v.mesh.mu.Lock()
	v.mesh.appDelay[2], v.mesh.appDelay[3] = delay, delay
	v.mesh.mu.Unlock()
	base := v.groups[1][b.RouteSlot].Status().LastIndex

	type outcome struct {
		receipt model.Receipt
		err     error
	}
	outcomes := make(chan outcome, 2)
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		r, err := v.engines[1].Append(ctx, scope, b)
		outcomes <- outcome{r, err}
	}
	go run()
	for v.groups[1][b.RouteSlot].Status().LastIndex < base+1 {
		time.Sleep(time.Millisecond)
	}
	go run()
	first, second := <-outcomes, <-outcomes
	if first.err != nil || second.err != nil {
		t.Fatalf("append and its retry: %v, %v", first.err, second.err)
	}
	if string(mustJSON(t, first.receipt)) != string(mustJSON(t, second.receipt)) {
		t.Fatalf("the retry was answered %+v, the first append %+v", second.receipt, first.receipt)
	}
	if got := v.groups[1][b.RouteSlot].Status().LastIndex; got != base+1 {
		t.Fatalf("the batch was queued %d times", got-base)
	}
	var fault *model.Fault
	other := b
	other.Hash[0] ^= 1
	if _, err := v.engines[1].Append(context.Background(), scope, other); !errors.As(err, &fault) {
		t.Fatalf("the batch under another hash was answered %v, want a refusal", err)
	}
}
