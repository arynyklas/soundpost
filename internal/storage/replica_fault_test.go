// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// What a replica error becomes for the caller of a storage call: a moment without a leader and a fence that no
// quorum answered in time are retryable (unavailable, stale, and the timeout of a caller whose deadline passed
// while it waited); a closed or failed group, an optimistic refusal and the caller's own cancellation are not.
func TestStorageReplicaFaultsAreRetryableOnlyForAMomentWithoutAQuorum(t *testing.T) {
	expired, stop := context.WithTimeout(context.Background(), 0)
	defer stop()
	<-expired.Done()
	for _, c := range []struct {
		name      string
		ctx       context.Context
		err       error
		code      model.Code
		retryable bool
	}{
		{"no leader", context.Background(), replica.ErrNoLeader, model.Unavailable, true},
		{"closed or failed group", context.Background(), replica.ErrUnavailable, model.Unavailable, false},
		{"optimistic stale", context.Background(), replica.ErrStale, model.Stale, false},
		{"no quorum fence", context.Background(), fmt.Errorf("read: %w", replica.ErrNoQuorum), model.Stale, true},
		{"no quorum before the deadline", expired, replica.ErrNoQuorum, model.Timeout, true},
		{"plain stale at the deadline", expired, replica.ErrStale, model.Timeout, false},
	} {
		var f *model.Fault
		if err := replicaFaultUnder(c.ctx, c.err); !errors.As(err, &f) || f.Code != c.code || f.Retryable != c.retryable {
			t.Errorf("%s: %v, want code %s retryable %t", c.name, err, c.code, c.retryable)
		}
	}
}
