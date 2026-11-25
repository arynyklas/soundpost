// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Two unavailable answers differ in what a client may do. A write that meets a leader that is another member (the
// in-process mesh has no proposal forwarder, as a leader gap has none for a follower that cannot reach its leader)
// is the unavailable a retry outlasts: retryable. A write on an engine that failed closed is unavailable until an
// operator acts: not retryable, or every client would retry it forever.
func TestUnavailableIsRetryableOnlyForAMomentWithoutALeader(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	v := openVoters(t, service, store)
	v.lead(t, func(int) uint64 { return 1 })
	scope, batch := normalized(t, store, service, credential, descriptor)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var fault *model.Fault
	_, err := v.engines[2].Append(ctx, scope, batch)
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("a write on a voter whose leader is another member answered %v, want unavailable with retryable true", err)
	}

	v.engines[1].mu.Lock()
	v.engines[1].failLocked()
	v.engines[1].mu.Unlock()
	fault = nil
	_, err = v.engines[1].Append(ctx, scope, batch)
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || fault.Retryable {
		t.Fatalf("a write on an engine that failed closed answered %v, want unavailable with retryable false", err)
	}
}
