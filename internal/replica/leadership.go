// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"time"
)

func (g *Group) TransferLeadership(ctx context.Context, to uint64) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := g.ReadIndex(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	if g.raw.BasicStatus().Lead != g.id {
		g.mu.Unlock()
		return ErrUnavailable
	}
	allowed := false
	for _, member := range g.members.Nodes {
		if member.ID == to && !member.Learner {
			allowed = true
		}
	}
	if !allowed {
		g.mu.Unlock()
		return ErrInvalid
	}
	g.raw.TransferLeader(to)
	err := g.processReady()
	g.mu.Unlock()
	if err != nil {
		return err
	}
	for {
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return ErrUnavailable
		}
		if g.raw.BasicStatus().Lead == to {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ErrStale
		}
	}
}
