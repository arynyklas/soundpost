// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// meshCallLost makes the in-process leader calls of the test voters run at the leader and lose their answer
// (meshTransport.CallLeader): a connection that dropped after the request was sent.
var meshCallLost atomic.Bool

// An append whose request reached the leader of the slot and whose answer was lost was made: the follower answers the retryable
// unavailable (the append is idempotent under a retry of the same batch, appendOwn answers the stored receipt), and the sender's
// retry of the same batch is answered the receipt of the first run without a second append of it: the slot's log is as long as
// after the first run, and every voter holds the one stored copy.
func TestAnAppendWhoseAnswerWasLostIsFoundByItsRetry(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	v := openVoters(t, service, store)
	for node := uint64(1); node <= 3; node++ {
		if err := v.engines[node].BindAppendScopes(service); err != nil {
			t.Fatal(err)
		}
	}
	v.lead(t, func(int) uint64 { return 1 })
	scope, b := normalized(t, store, service, credential, descriptor)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	meshCallLost.Store(true)
	_, err := v.engines[2].Append(ctx, scope, b)
	meshCallLost.Store(false)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("an append whose answer was lost was answered %v, want unavailable with retryable true", err)
	}
	logLength := func(node uint64) uint64 {
		v.engines[node].mu.Lock()
		defer v.engines[node].mu.Unlock()
		return v.engines[node].indexes[b.RouteSlot]
	}
	afterFirst := logLength(1)
	if afterFirst == 0 {
		t.Fatal("the leader did not make the append of the call it ran")
	}
	receipt, err := v.engines[2].Append(ctx, scope, b)
	if err != nil {
		t.Fatalf("the sender's retry: %v", err)
	}
	if uint64(receipt.Cursor.Index) != afterFirst || logLength(1) != afterFirst {
		t.Fatalf("the retry's receipt is at index %d and the slot's log is %d long, want both %d: the batch was appended twice", receipt.Cursor.Index, logLength(1), afterFirst)
	}
	v.converge(t, map[uint16]uint64{b.RouteSlot: afterFirst})
	reference, stored := storedBatch(t, v.engines[1], b)
	for node := uint64(2); node <= 3; node++ {
		batch, rec := storedBatch(t, v.engines[node], b)
		if !bytes.Equal(batch, reference) || !bytes.Equal(rec, stored) {
			t.Fatalf("node %d holds other bytes for the batch than the leader", node)
		}
	}
}
