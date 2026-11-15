// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Group.ReadIndex answers replica.ErrStale when the context it waits under ends before its freshness
// fence is reached. That is the caller giving up (the query engine cancels the other projects of a
// request one of them failed), never evidence that the data moved: read as the typed Stale it is
// fatal for the whole request and, when that project sorts first, replaces the failure that caused
// the cancellation (a corrupt page answered as stale).
func TestReplicaFenceUnderAnEndedContextIsCancelledNeverStale(t *testing.T) {
	store, service, _, _ := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	marks, _, err := engine.replicaReadFence(context.Background(), nil, false)
	if err != nil || len(marks) == 0 {
		t.Fatalf("the fence of a live request: %d marks, %v", len(marks), err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, release := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer release()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want model.Code
	}{{"cancelled", cancelled, model.Cancelled}, {"deadline", expired, model.Timeout}} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := engine.replicaReadFence(tc.ctx, nil, false)
			if got := faultCode(err); got != tc.want {
				t.Errorf("read fence: %q (%v), want %q", got, err, tc.want)
			}
			engine.mu.Lock()
			err = engine.replicaReleaseFenceLocked(tc.ctx, marks)
			engine.mu.Unlock()
			if got := faultCode(err); got != tc.want {
				t.Errorf("release fence: %q (%v), want %q", got, err, tc.want)
			}
			if got := faultCode(engine.replicaBeforeCursor(tc.ctx, marks[0])); got != tc.want {
				t.Errorf("before-cursor fence: %q, want %q", got, tc.want)
			}
		})
	}
}

// Only an ended caller context turns the freshness failure into a cancellation: with the caller
// still waiting, ErrStale stays the typed Stale, and nothing else is rewritten.
func TestReplicaFaultUnderLiveContextKeepsItsMeaning(t *testing.T) {
	live := context.Background()
	for _, tc := range []struct {
		err  error
		want model.Code
	}{{replica.ErrStale, model.Stale}, {replica.ErrConflict, model.Conflict}, {replica.ErrInvalid, model.Invalid}, {replica.ErrUnavailable, model.Unavailable}} {
		if got := faultCode(replicaFaultUnder(live, tc.err)); got != tc.want {
			t.Errorf("%v under a live context: %q, want %q", tc.err, got, tc.want)
		}
	}
	if replicaFaultUnder(live, nil) != nil {
		t.Error("nil became an error")
	}
	cancelled, cancel := context.WithCancel(live)
	cancel()
	if got := faultCode(replicaFaultUnder(cancelled, replica.ErrConflict)); got != model.Conflict {
		t.Errorf("a conflict under a cancelled context: %q, want %q", got, model.Conflict)
	}
}
