// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	raft "go.etcd.io/raft/v3"
	"time"
)

// WithLeaderFences serializes a local physical-layout publication against each
// owning RawNode's term transition. The callback must not call Raft or control,
// and must check ctx before its durable compare-and-swap. Group order must be
// stable for this installation. External destinations still require their own
// durable fencing/idempotency protocol; this is not a network-send lease.
func WithLeaderFences(ctx context.Context, groups []*Group, publish func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if len(groups) == 0 || publish == nil {
		return ErrInvalid
	}
	tokens := make([]FenceToken, len(groups))
	for i, group := range groups {
		token, err := group.Fence(ctx)
		if err != nil {
			return err
		}
		tokens[i] = token
	}
	for _, group := range groups {
		group.mu.Lock()
	}
	defer func() {
		for i := len(groups) - 1; i >= 0; i-- {
			groups[i].mu.Unlock()
		}
	}()
	if ctx.Err() != nil {
		return ErrStale
	}
	for i, group := range groups {
		status := group.raw.BasicStatus()
		token := tokens[i]
		if group.failed || group.closed || status.RaftState != raft.StateLeader || status.Lead != group.id || status.HardState.GetTerm() != token.Term || group.members.Revision != token.Revision {
			return ErrStale
		}
	}
	return publish(ctx)
}
