// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A freshness fence that waited and was not reached (a follower that hears no leader, a quorum that does not
// answer) is ErrNoQuorum, which is still an ErrStale; the refusal of a command that names an application index
// that is no longer the current one is a plain ErrStale: asked again unchanged it is refused again, so the two
// must not be told apart by their code alone.
func TestAFenceNoQuorumReachedIsNoQuorumAndAnOptimisticRefusalIsPlainStale(t *testing.T) {
	wire, _ := leaderlessFollowerCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := wire.nodes[2].ReadIndex(ctx); !errors.Is(err, ErrNoQuorum) || !errors.Is(err, ErrStale) {
		t.Fatalf("ReadIndex on a member that hears no leader answered %v, want ErrNoQuorum (and ErrStale)", err)
	}

	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	s.propose(Barrier, "a")
	s.propose(Barrier, "b")
	_, err := s.tryPropose(Entry{ID: model.NewID(), Kind: Barrier, Payload: []byte("c"), ApplicationIndex: 1})
	if !errors.Is(err, ErrStale) || errors.Is(err, ErrNoQuorum) {
		t.Fatalf("a command naming an old application index answered %v, want ErrStale and not ErrNoQuorum", err)
	}
}

// The distinction crosses the proposal forward wire without a change of its format: a no-quorum fence travels as
// a timeout, the optimistic refusal keeps its stale.
func TestNoQuorumAndOptimisticStaleKeepApartOverTheForwardWire(t *testing.T) {
	if got := forwardedCode(ErrNoQuorum); got != model.Timeout {
		t.Fatalf("ErrNoQuorum travels as %q, want timeout", got)
	}
	if got := forwardedCode(ErrStale); got != model.Stale {
		t.Fatalf("ErrStale travels as %q, want stale", got)
	}
	retryable := model.Fail(model.Stale)
	retryable.Retryable = true
	if got := forwardedCode(retryable); got != model.Timeout {
		t.Fatalf("a retryable stale fault travels as %q, want timeout", got)
	}
	if got := forwardedCode(model.Fail(model.Stale)); got != model.Stale {
		t.Fatalf("a stale fault travels as %q, want stale", got)
	}
	if err := forwardedError(model.Timeout); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("a forwarded timeout became %v, want ErrNoQuorum", err)
	}
	if err := forwardedError(model.Stale); errors.Is(err, ErrNoQuorum) || !errors.Is(err, ErrStale) {
		t.Fatalf("a forwarded stale became %v, want plain ErrStale", err)
	}
}
