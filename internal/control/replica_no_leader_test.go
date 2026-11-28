// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A moment without a leader (replica.ErrNoLeader) reaches the caller of a control write as the retryable
// unavailable; a group that failed closed or was closed (plain replica.ErrUnavailable) reaches it as the
// unavailable that no retry mends. Every other replica error keeps its own code and no retry flag.
func TestControlWriteFaultIsRetryableOnlyForAMomentWithoutALeader(t *testing.T) {
	for _, c := range []struct {
		name      string
		err       error
		code      model.Code
		retryable bool
	}{
		{"no leader", replica.ErrNoLeader, model.Unavailable, true},
		{"no leader, wrapped", fmt.Errorf("propose: %w", replica.ErrNoLeader), model.Unavailable, true},
		{"failed or closed group", replica.ErrUnavailable, model.Unavailable, false},
		{"failed group, wrapped", fmt.Errorf("propose: %w", replica.ErrUnavailable), model.Unavailable, false},
		{"stale, optimistic refusal", replica.ErrStale, model.Stale, false},
		{"stale, fence no quorum reached", replica.ErrNoQuorum, model.Stale, true},
		{"stale, fence no quorum reached, wrapped", fmt.Errorf("read: %w", replica.ErrNoQuorum), model.Stale, true},
		{"conflict", replica.ErrConflict, model.Conflict, false},
		{"not a replica error", errors.New("disk"), model.Unavailable, false},
	} {
		for _, under := range []struct {
			name  string
			fault func() error
		}{
			{"replicaFault", func() error { return replicaFault(c.err) }},
			{"replicaFaultUnder", func() error { return replicaFaultUnder(context.Background(), c.err) }},
		} {
			var f *model.Fault
			if err := under.fault(); !errors.As(err, &f) || f.Code != c.code || f.Retryable != c.retryable {
				t.Errorf("%s of %s: %v, want code %s retryable %t", under.name, c.name, err, c.code, c.retryable)
			}
		}
	}
}

// A read that waited for a quorum until the caller's deadline passed is the timeout of docs/operations/upgrade.md,
// retryable as it is; an ErrStale that is not that wait (an optimistic refusal) under the same deadline is a plain
// timeout, and the caller's own cancellation is never retryable.
func TestControlTimeoutIsRetryableOnlyWhenAQuorumDidNotAnswer(t *testing.T) {
	expired, stop := context.WithTimeout(context.Background(), 0)
	defer stop()
	<-expired.Done()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		name      string
		ctx       context.Context
		err       error
		code      model.Code
		retryable bool
	}{
		{"no quorum before the deadline", expired, replica.ErrNoQuorum, model.Timeout, true},
		{"plain stale at the deadline", expired, replica.ErrStale, model.Timeout, false},
		{"no quorum, caller cancelled", cancelled, replica.ErrNoQuorum, model.Cancelled, false},
	} {
		var f *model.Fault
		if err := replicaFaultUnder(c.ctx, c.err); !errors.As(err, &f) || f.Code != c.code || f.Retryable != c.retryable {
			t.Errorf("%s: %v, want code %s retryable %t", c.name, err, c.code, c.retryable)
		}
	}
}
