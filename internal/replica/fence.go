// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
)

type FenceToken struct {
	Group    model.ID       `json:"group"`
	Term     uint64         `json:"term,string"`
	Revision model.Revision `json:"revision"`
}
type CommitSetWatermark struct {
	Group              model.ID `json:"group"`
	Term               uint64   `json:"term,string"`
	PhysicalCommit     uint64   `json:"physical_commit,string"`
	PhysicalLast       uint64   `json:"physical_last,string"`
	ApplicationApplied uint64   `json:"application_applied,string"`
	Reservation        model.ID `json:"reservation"`
}

func (g *Group) Fence(ctx context.Context) (FenceToken, error) {
	if _, err := g.ReadIndex(ctx); err != nil {
		return FenceToken{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.raw.BasicStatus()
	if g.failed || g.closed || s.RaftState != raft.StateLeader || s.Lead != g.id {
		return FenceToken{}, ErrUnavailable
	}
	return FenceToken{Group: g.group, Term: s.HardState.GetTerm(), Revision: g.members.Revision}, nil
}

// ValidateFence requires a fresh quorum observation immediately before each
// publication/send. A past election term or a clock lease alone is insufficient.
func (g *Group) ValidateFence(ctx context.Context, f FenceToken) error {
	if f.Group != g.group {
		return ErrInvalid
	}
	if _, err := g.ReadIndex(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.raw.BasicStatus()
	if g.failed || g.closed || s.RaftState != raft.StateLeader || s.Lead != g.id || s.HardState.GetTerm() != f.Term || g.members.Revision != f.Revision {
		return ErrStale
	}
	return nil
}

// Absent is deliberately conservative about known, uncommitted proposals. A
// receipt lookup alone cannot prove absence. Ready persistence rebuilt known
// proposals before this quorum/application fence, and cancellation checks the
// ledger again under the same proposal lock before its own committed fence.
func (g *Group) Absent(ctx context.Context, reservation model.ID) (CommitSetWatermark, error) {
	if reservation == (model.ID{}) {
		return CommitSetWatermark{}, ErrInvalid
	}
	if _, err := g.ReadIndex(ctx); err != nil {
		return CommitSetWatermark{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.raw.BasicStatus()
	if g.failed || g.closed || s.RaftState != raft.StateLeader || s.Lead != g.id {
		return CommitSetWatermark{}, ErrUnavailable
	}
	if len(g.known[reservation]) != 0 {
		return CommitSetWatermark{}, ErrConflict
	}
	last, err := g.memory.LastIndex()
	if err != nil {
		return CommitSetWatermark{}, err
	}
	return CommitSetWatermark{Group: g.group, Term: s.HardState.GetTerm(), PhysicalCommit: s.HardState.GetCommit(), PhysicalLast: last, ApplicationApplied: g.application, Reservation: reservation}, nil
}
