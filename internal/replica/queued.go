// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
)

// Queued proposals: a command that is ordered by the place it takes in the leader's queue and not by waiting for the
// command before it.
//
// Propose returns when its command is committed on a quorum and applied here, so a caller that must keep two commands in
// order (the storage engine orders the appends of a slot by the application index each names) holds a lock for a whole
// commit. The queue of the group is already ordered and the cycle that takes it proposes every command in it in one
// journal write (intake), each against the application index the commands before it left in the log
// (proposeOneLocked), so a caller that queues its commands in order under its own lock can release the lock when the
// command is queued and wait for the commit outside it: the commands of a burst share one journal write, one append per
// follower and one round trip, and the order is the order of the queue.
//
// A queued command is ordered by the leader that queues it: ProposeQueued refuses on a member that does not lead the group,
// never forwards, and does not take a ReadIndex round (the caller has made the read its checks rest on). A command refused
// in the queue (the application index it names is not the next of the log) is refused with ErrStale, and so is every
// command queued after it.

// queuedBudget is how long a queued command is kept in the queue and waited for.
const queuedBudget = 10 * time.Second

// Pending is a command queued by ProposeQueued.
type Pending struct {
	g      *Group
	id     model.ID
	req    *proposal
	ctx    context.Context
	cancel context.CancelFunc
}

// ProposeQueued puts e in the queue of the group, behind every command queued before it, and returns at once. e is
// proposed by the next cycle together with what queued with it. The command lives for queuedBudget whether or not its
// caller still waits: a caller that gives up does not take its command out of the queue (a command behind it names the
// application index after it).
func (g *Group) ProposeQueued(ctx context.Context, e Entry) (*Pending, error) {
	e.Proposer = nil
	if !e.valid() {
		return nil, ErrInvalid
	}
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	status := g.raw.BasicStatus()
	if status.Lead != g.id || status.RaftState != raft.StateLeader {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	e.Proposer = g.proposerLocked(g.id)
	g.mu.Unlock()
	queued, cancel := context.WithTimeout(context.WithoutCancel(ctx), queuedBudget)
	req := &proposal{ctx: queued, entry: e, done: make(chan proposalResult, 1)}
	if !g.enqueue(req) {
		cancel()
		return nil, ErrUnavailable
	}
	if err := g.kick(); err != nil {
		cancel()
		return nil, err
	}
	return &Pending{g: g, id: e.ID, req: req, ctx: queued, cancel: cancel}, nil
}

// Wait returns the outcome of the command: committed on a quorum and applied here, or the error that refused it. A caller
// whose ctx ends first is answered ErrUnavailable and the command stays queued.
func (p *Pending) Wait(ctx context.Context) (CommittedEntry, error) {
	select {
	case result := <-p.req.done:
		p.cancel()
		return result.entry, result.err
	case <-p.ctx.Done():
		p.req.gone.Store(true)
		p.g.mu.Lock()
		p.g.removeWaiter(p.id, p.req.done)
		p.g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	case <-ctx.Done():
		return CommittedEntry{}, ErrUnavailable
	}
}
