// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"go.etcd.io/raft/v3/tracker"
	"google.golang.org/protobuf/proto"
)

// Proposal batching and the group's locks.
//
// A group has three locks and a fixed order, redactMu, then ioMu, then mu, then propMu:
//
//   - mu guards the Raft state machine (RawNode), the waiters and every field of the group that a caller can ask
//     about (Status, WaitApplied, Fence ...). It is only ever held for memory work: Tick, Step, Status and the
//     bookkeeping of the stage never wait behind a journal fsync, the machine's Apply or a proposal's encoding.
//   - ioMu is the ready stage: one cycle (propose a batch, take a Ready, persist it, send its messages, apply its
//     committed entries, Advance) holds it from start to end, and so does everything that must not run beside a
//     cycle (snapshot cuts, journal compaction and redaction, Close: lockAll). The journal, the machine and the
//     fields only a cycle writes (applied, application, completed, known, logCommands ...) belong to its holder; a
//     cycle writes them under mu as well, so a reader that holds mu alone sees them whole.
//   - propMu guards the queue of proposals.
//
// The proposers do not touch mu or ioMu: they put their command in the queue and the next cycle proposes every
// command that is waiting in one go (one Ready, one journal write and fsync, one append per follower for all of
// them), where each of 200 concurrent proposers used to take the group lock in turn and persist and apply its own.

// maxBatchBytes bounds what one cycle proposes: a batch beyond it is left to the next cycle, so that the journal record
// of the Ready (and the time the stage spends on it before the next Ready's messages can leave) stays small.
const maxBatchBytes = 1 << 20

// proposal is a command a proposer has queued and is waiting on.
type proposal struct {
	ctx    context.Context
	entry  Entry
	done   chan proposalResult // answered once: by the cycle that refused or proposed it, or by the apply of its entry
	gone   atomic.Bool         // the proposer stopped waiting: a queued proposal is dropped, not proposed
	queued time.Time
}

// enqueue puts p in the queue; false when the group is failed or closed.
func (g *Group) enqueue(p *proposal) bool {
	p.queued = time.Now()
	g.propMu.Lock()
	defer g.propMu.Unlock()
	if g.propClosed {
		return false
	}
	g.propQ = append(g.propQ, p)
	return true
}

// closeProposals refuses every queued proposal and every later one. g.mu is held (fail).
func (g *Group) closeProposals() {
	g.propMu.Lock()
	g.propClosed = true
	queue := g.propQ
	g.propQ = nil
	g.propMu.Unlock()
	for _, p := range queue {
		p.done <- proposalResult{err: ErrUnavailable}
	}
}

// takeProposals removes the proposals the next batch proposes from the queue.
func (g *Group) takeProposals() []*proposal {
	g.propMu.Lock()
	defer g.propMu.Unlock()
	if len(g.propQ) == 0 {
		return nil
	}
	size, n := 0, 0
	for _, p := range g.propQ {
		size += len(p.entry.Payload)
		if n > 0 && size > maxBatchBytes {
			break
		}
		n++
	}
	taken := make([]*proposal, n)
	copy(taken, g.propQ)
	if n == len(g.propQ) {
		g.propQ = nil
	} else {
		g.propQ = append(g.propQ[:0:0], g.propQ[n:]...)
	}
	return taken
}

// batchView is what the proposals of one batch have already told the group, which the log and the tables do not
// hold yet: the entries are persisted after the batch is proposed.
type batchView struct {
	entries      map[model.ID]Entry
	reservations map[model.ID]struct{}
}

// intake proposes the queued commands. The caller holds ioMu: no cycle is in flight, so everything the previous batch
// proposed is in the log and in the tables. mu is taken for one command at a time (encoding a payload is the longest
// thing done under it), so a tick or a step that arrives meanwhile waits for one command, not for the batch.
func (g *Group) intake() {
	batch := g.takeProposals()
	if len(batch) == 0 {
		return
	}
	view := batchView{entries: map[model.ID]Entry{}, reservations: map[model.ID]struct{}{}}
	for _, p := range batch {
		g.phases.proposeN.Add(1)
		sinceMax(&g.phases.proposeWaitNS, &g.phases.proposeWaitMax, p.queued)
		if p.gone.Load() || p.ctx.Err() != nil {
			p.done <- proposalResult{err: ErrUnavailable}
			continue
		}
		g.mu.Lock()
		g.proposeOneLocked(p, g.raw.BasicStatus(), &view)
		g.mu.Unlock()
	}
}

// proposeOneLocked is what propose does under the group lock: the checks that need the leader's own view of the log
// and the tables, then the Raft proposal. It answers p when it refuses it or finds it already decided.
func (g *Group) proposeOneLocked(p *proposal, status raft.BasicStatus, view *batchView) {
	e := p.entry
	refuse := func(err error) { p.done <- proposalResult{err: err} }
	if g.failed || g.closed {
		refuse(ErrUnavailable)
		return
	}
	if status.Lead != g.id || status.RaftState != raft.StateLeader {
		refuse(ErrUnavailable)
		return
	}
	if old, ok := g.completed[e.ID]; ok {
		switch {
		case !sameProposal(old.Entry, e):
			refuse(ErrConflict)
		case old.Outcome == "conflict":
			p.done <- proposalResult{entry: old, err: ErrConflict}
		default:
			p.done <- proposalResult{entry: old}
		}
		return
	}
	if old, ok := g.logCommands[e.ID]; ok && old.Index > g.applied {
		if !sameProposal(old.Entry, e) {
			refuse(ErrConflict)
			return
		}
		g.pending[e.ID] = append(g.pending[e.ID], p.done)
		return
	}
	if old, ok := view.entries[e.ID]; ok {
		if !sameProposal(old, e) {
			refuse(ErrConflict)
			return
		}
		g.pending[e.ID] = append(g.pending[e.ID], p.done)
		return
	}
	if e.Kind == Cancellation && e.ReservationID != nil {
		if _, ok := view.reservations[*e.ReservationID]; ok || len(g.known[*e.ReservationID]) != 0 {
			refuse(ErrConflict)
			return
		}
	}
	last, err := g.memory.LastIndex()
	if err != nil || last == ^uint64(0) {
		refuse(ErrUnavailable)
		return
	}
	application := g.logApplication
	if application == ^uint64(0) {
		refuse(ErrUnavailable)
		return
	}
	if e.ApplicationIndex != 0 && e.ApplicationIndex != application+1 {
		refuse(ErrStale)
		return
	}
	if g.digestKind(e.Kind) {
		e.At = g.now().UnixNano()
	} else {
		e.At = 0
	}
	e.ApplicationIndex = application + 1
	if e.Kind == Cancellation {
		if e.ReservationID == nil {
			refuse(ErrInvalid)
			return
		}
		e.CommitSet = &CommitSetWatermark{Group: g.group, Term: status.HardState.GetTerm(), PhysicalCommit: status.HardState.GetCommit(), PhysicalLast: last, ApplicationApplied: g.application, Reservation: *e.ReservationID}
	}
	raw, err := encodeEntry(e)
	if err != nil {
		refuse(err)
		return
	}
	g.pending[e.ID] = append(g.pending[e.ID], p.done)
	if err = g.raw.Propose(raw); err != nil {
		g.removeWaiter(e.ID, p.done)
		refuse(ErrUnavailable)
		return
	}
	g.logApplication = e.ApplicationIndex
	view.entries[e.ID] = e
	if e.ReservationID != nil && e.Kind != Cancellation {
		view.reservations[*e.ReservationID] = struct{}{}
	}
	if len(raw) > 0 {
		if g.fresh == nil {
			g.fresh = map[*byte]Entry{}
		}
		known := e
		known.Payload = bytes.Clone(e.Payload) // the caller owns the slice it passed
		g.fresh[&raw[0]] = known
	}
}

// lockAll takes the group for work that must not run beside a cycle: the journal, the machine and the tables are
// then at rest and Raft's state is as the last cycle left it.
func (g *Group) lockAll() {
	g.ioMu.Lock()
	g.mu.Lock()
}

func (g *Group) unlockAll() {
	g.mu.Unlock()
	g.ioMu.Unlock()
}

// wakeLocked tells the stage goroutine of a group that ticks by itself that Raft has something to hand out. A group
// its owner ticks (TickInterval 0) has no stage goroutine: its callers run the cycle themselves (settle).
func (g *Group) wakeLocked() {
	if g.wake == nil || !g.raw.HasReady() {
		return
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// settle is what a caller does after it changed Raft's state and released the lock: a group with a stage goroutine
// leaves the work to it, a group without one is driven here, so that the Ready is processed when the call returns.
func (g *Group) settle() error {
	if g.wake != nil {
		return nil
	}
	return g.drive()
}

// kick queues the stage after a proposal was enqueued.
func (g *Group) kick() error {
	if g.wake != nil {
		select {
		case g.wake <- struct{}{}:
		default:
		}
		return nil
	}
	return g.drive()
}

// stageLoop is the stage goroutine: it runs the cycles whenever Raft or a proposer has work. It never takes part
// in ticking, so a long persist or apply delays the messages of the next Ready and nothing else.
func (g *Group) stageLoop() {
	defer close(g.stageDone)
	for {
		select {
		case <-g.stop:
			return
		case <-g.wake:
		}
		_ = g.drive() // a failure has already failed the group
	}
}

// heartbeatNowLocked sends the leader's heartbeats at once, from the tick, while a cycle runs: the heartbeats Raft makes
// for the same tick leave with the next Ready, and a cycle that persists a batch and applies a full append lasts a
// good part of an election timeout under load, so a follower would campaign against a leader that is only busy. A
// leader's heartbeat depends on nothing this member has still to persist: its term and its vote were made durable
// before it sent a single vote request, and the commit index it carries is the one the follower already holds the entries
// for (the lower of the follower's match and the leader's commit, as Raft's own). A duplicate of the heartbeat of the
// next Ready is harmless: a follower takes it as it does any heartbeat, and its answer is stepped as any answer is.
// g.mu is held.
func (g *Group) heartbeatNowLocked() {
	status := g.raw.BasicStatus()
	if status.RaftState != raft.StateLeader || status.Lead != g.id || !g.termDurable(status.HardState.GetTerm()) {
		return
	}
	term, commit := status.HardState.GetTerm(), status.HardState.GetCommit()
	g.raw.WithProgress(func(id uint64, _ raft.ProgressType, pr tracker.Progress) {
		if id == g.id {
			return
		}
		_ = g.transport.Send(g.group, &pb.Message{Type: pb.MsgHeartbeat.Enum(), From: proto.Uint64(g.id), To: proto.Uint64(id), Term: proto.Uint64(term), Commit: proto.Uint64(min(pr.Match, commit))})
	})
}

// termDurable reports whether the journal holds term as this member's term: a message that depends on nothing else
// than the term can leave before the Ready that carries a newer one is persisted only when it is the durable one.
func (g *Group) termDurable(term uint64) bool {
	hard, _, err := g.memory.InitialState()
	return err == nil && hard.GetTerm() == term
}

// heartbeatFromLeaderLocked reports whether m is a heartbeat of the leader this follower follows in its current, durable
// term: stepping it changes nothing that is still to be persisted, so its answer can leave at once (answerHeartbeatNow).
// g.mu is held, before m is stepped.
func (g *Group) heartbeatFromLeaderLocked(m *pb.Message) bool {
	status := g.raw.BasicStatus()
	return status.RaftState == raft.StateFollower && status.Lead == m.GetFrom() && status.HardState.GetTerm() == m.GetTerm() && g.termDurable(m.GetTerm())
}

// answerHeartbeatNow answers the heartbeat m the way Raft does (the same term and context) without waiting for the
// cycle in flight, whose Ready carries the same answer again: a leader's CheckQuorum counts the members that answered
// within an election timeout, and a follower that is busy persisting and applying would otherwise cost it its leadership.
func (g *Group) answerHeartbeatNow(m *pb.Message) {
	_ = g.transport.Send(g.group, &pb.Message{Type: pb.MsgHeartbeatResp.Enum(), From: proto.Uint64(g.id), To: proto.Uint64(m.GetFrom()), Term: proto.Uint64(m.GetTerm()), Context: m.GetContext()})
}
