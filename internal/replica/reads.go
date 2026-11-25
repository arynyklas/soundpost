// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A ReadIndex is a question to the group's leader ("what had you committed when you were still the leader?"):
// a round trip to the leader and a heartbeat round of its followers. Every write of the storage engine asks it
// before it is proposed, so at 5,000 records a second a member sent the leaders of its groups thousands of them
// a second, one message and one leader heartbeat round each, on the lanes of the transport that carry a group's
// appends too (8-22 thousand refusals per node on the ReadIndex lanes).
//
// The answer to a question asked at time t only has to cover what was committed before t, and an answer given to
// a question that was put later does (the index only grows while the group's leadership holds, and the quorum
// that confirmed the leadership confirmed it after t). So a group keeps ONE ReadIndex in flight and every call that
// arrives meanwhile joins the next one, which is put when the first is answered, and all of them are given its
// answer. A call never joins a round that was already in flight when it arrived: that one may have been confirmed
// before the call began, and answering it from it would not be linearizable.
//
// A round that is not answered (the message was refused, the leader changed without the term changing at this
// member) is given up after readRoundTimeout with ErrStale and its callers ask again, which puts a later
// question: the answer of a later one supersedes it.

// readRoundTimeout is how long a ReadIndex put to the leader may stay without an answer before its callers ask again.
// A leader answers in a few milliseconds; an election takes two to three election timeouts (1 s each at the
// 100 ms tick), after which a round of the old term is finished with ErrStale by its term anyway.
const readRoundTimeout = time.Second

// readRequest is one ReadIndex round and everything waiting on it.
type readRequest struct {
	index  uint64
	term   uint64
	issued time.Time
	done   chan struct{} // closed by finish
	result proposalResult
	over   bool
}

func newReadRequest() *readRequest { return &readRequest{done: make(chan struct{})} }

// finish answers every caller of the round; the first answer stands. g.mu is held.
func (r *readRequest) finish(res proposalResult) {
	if r.over {
		return
	}
	r.over, r.result = true, res
	close(r.done)
}

// joinReadLocked is the round a ReadIndex arriving now waits on: the one still to be put (a round in flight began
// before this call and cannot answer it). It is put at once when none is in flight. g.mu is held.
func (g *Group) joinReadLocked() *readRequest {
	if g.readNext == nil {
		g.readNext = newReadRequest()
	}
	round := g.readNext
	g.issueReadLocked()
	return round
}

// issueReadLocked puts the waiting round to the leader when no other round is in flight and a leader is known.
// g.mu is held.
func (g *Group) issueReadLocked() {
	if len(g.reads) != 0 || g.readNext == nil {
		return
	}
	status := g.raw.BasicStatus()
	if status.Lead == 0 {
		return // a Tick puts it once a leader is known
	}
	round := g.readNext
	g.readNext = nil
	round.term, round.issued = status.HardState.GetTerm(), time.Now()
	id := model.NewID().String()
	g.reads[id] = round
	g.phases.readRounds.Add(1)
	g.raw.ReadIndex([]byte(id))
}

// expireReadsLocked finishes a round that has had no answer for readRoundTimeout and puts the next one. g.mu is held.
func (g *Group) expireReadsLocked() {
	now := time.Now()
	for id, r := range g.reads {
		if r.index == 0 && now.Sub(r.issued) >= readRoundTimeout {
			r.finish(proposalResult{err: ErrStale})
			delete(g.reads, id)
		}
	}
	g.issueReadLocked()
}

// failReadsLocked answers every round, in flight or waiting, with err. g.mu is held.
func (g *Group) failReadsLocked(err error) {
	for id, r := range g.reads {
		r.finish(proposalResult{err: err})
		delete(g.reads, id)
	}
	if g.readNext != nil {
		g.readNext.finish(proposalResult{err: err})
		g.readNext = nil
	}
}
