// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func codeOf(err error) model.Code {
	if f, ok := err.(*model.Fault); ok {
		return f.Code
	}
	return ""
}

// Group.ReadIndex answers replica.ErrStale when ctx ends before its freshness fence is reached. That is
// the caller giving up (a query that failed one project cancels the others), never evidence that the
// data moved: read as the typed Stale it is fatal for the whole request and, when that project sorts
// first, replaces the failure that caused the cancellation (a corrupt page answered as stale).
func TestControlReadUnderAnEndedContextIsCancelledNeverStale(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := codeOf(replicaFaultUnder(cancelled, replica.ErrStale)); got != model.Cancelled {
		t.Errorf("a stale fence under a cancelled context: %q, want %q", got, model.Cancelled)
	}
	expired, stop := context.WithTimeout(context.Background(), 0)
	defer stop()
	<-expired.Done()
	if got := codeOf(replicaFaultUnder(expired, replica.ErrStale)); got != model.Timeout {
		t.Errorf("a stale fence under an expired context: %q, want %q", got, model.Timeout)
	}
}

// With the caller still waiting, ErrStale stays the typed Stale and nothing else is rewritten.
func TestControlReadUnderALiveContextKeepsItsMeaning(t *testing.T) {
	live := context.Background()
	for _, tc := range []struct {
		err  error
		want model.Code
	}{{replica.ErrStale, model.Stale}, {replica.ErrConflict, model.Conflict}, {replica.ErrInvalid, model.Invalid}, {replica.ErrUnavailable, model.Unavailable}} {
		if got := codeOf(replicaFaultUnder(live, tc.err)); got != tc.want {
			t.Errorf("%v under a live context: %q, want %q", tc.err, got, tc.want)
		}
	}
	if replicaFaultUnder(live, nil) != nil {
		t.Error("nil became an error")
	}
	cancelled, cancel := context.WithCancel(live)
	cancel()
	if got := codeOf(replicaFaultUnder(cancelled, replica.ErrConflict)); got != model.Conflict {
		t.Errorf("a conflict under a cancelled context: %q, want %q", got, model.Conflict)
	}
}
