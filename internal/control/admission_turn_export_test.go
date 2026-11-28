// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"time"
)

// RetryingUpdateForTest runs fn as one control transition that, like a retention command, reads, computes and proposes
// again on a fresh read while its proposal loses the application-index race (retryLostProposals). It changes nothing of the
// state but the revision.
func (s *Store) RetryingUpdateForTest(ctx context.Context, fn func()) error {
	return s.replicatedUpdate(retryLostProposals(ctx), false, nil, 0, func(*State) error { fn(); return nil })
}

// PlainUpdateForTest commits one transition that is proposed once and answered with its refusal when it loses (an
// ordinary writer): it changes nothing of the state but the revision.
func (s *Store) PlainUpdateForTest(ctx context.Context) error {
	return s.replicatedUpdate(ctx, false, nil, 0, func(*State) error { return nil })
}

// AttemptCountsForTest is how many writers that retry lost proposals were answered after n attempts, per bucket of
// AttemptBoundsForTest (the last bucket counts the rest).
func (s *Store) AttemptCountsForTest() []uint64 { return s.turn.attemptCounts() }

// MostAttemptsForTest is the most attempts one writer that retries lost proposals needed, exactly.
func (s *Store) MostAttemptsForTest() int { return s.turn.mostAttempts() }

// AttemptBoundsForTest are the upper bounds of the buckets AttemptCountsForTest reads.
func AttemptBoundsForTest() []int { return attemptBounds[:] }

// MaxLostProposalsForTest is the budget of attempts of a writer that retries lost proposals: the one after which it is refused.
const MaxLostProposalsForTest = maxLostProposals

// TurnStatsForTest reads the leader's turn counters (this store as the leader).
func (s *Store) TurnStatsForTest() (granted, refused, stale uint64, held, maxHold time.Duration) {
	st := s.turn.stats(time.Now())
	return st.Granted, st.Refused, st.Stale, st.Held, st.MaxHold
}
