// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
)

// Appends queued by the leader of their slot.
//
// An append is ordered after the one before it in its slot: it names the application index after the last, and the slot's lock
// orders the appends that name them. The lock used to be held until the append was committed on a quorum and applied here, so
// a slot made one commit at a time: the journal write and fsync, the round trip to the followers, their fsync, the apply, each
// of them waited for by an append that had nothing to do with the one in front of it (measured on three voters at 1750 records
// a second: 83-127 ms a commit under load, 64 slots, 377 appends a second for the whole cluster, 6 s of waiting for the lock
// on average).
//
// The leader of a slot now holds the lock for what is ordered, the checks and the place in the replica group's queue
// (replica.Group.ProposeQueued), and waits for the commit outside it: the appends that arrive while a commit is in flight
// are queued behind it, each naming the next index of the log, and the cycle that takes the queue proposes all of them in one
// journal write, one append per follower and one round trip. The group still applies them in order, one command at a time; what
// is acknowledged is the same (the receipt of an append is answered after its command is committed on a quorum and applied),
// and so is what is replicated (every command is the one the append made before, naming the index it named).
//
// The checks a later append makes against the store (the receipt it may already have, the ordering rules) see what the
// earlier ones have applied, not what they have queued: the group's apply judges the ordering rules again against the store
// as the commands before it left it and refuses a command that now conflicts (planApply), which answers the append that made it,
// as it always did. A retry of a batch whose first append is still in flight waits for that append (flightAppend) instead of
// queueing the batch twice.
//
// Only the leader of the slot queues. An append that a member makes without leading the slot is a forwarded proposal, whose
// order the leader decides on arrival: it starts when every queued append of the slot has been decided and holds the lock for
// its own commit, as before.

// slotFlight is the appends of one slot that were queued and not yet decided, in the order they were queued.
type slotFlight struct {
	mu       sync.Mutex
	next     uint64 // the index the next queued append names; meaningful while inflight > 0
	inflight int
	batches  map[string]*flightAppend
	idle     chan struct{} // closed when inflight returns to 0
}

// flightAppend is one queued append: what a retry of its batch waits for.
type flightAppend struct {
	hash    model.Hash
	done    chan struct{}
	receipt model.Receipt
	err     error
	over    bool
}

// find is the queued append of the batch named key, nil when there is none. The slot lock is held.
func (f *slotFlight) find(key string) *flightAppend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.batches[key]
}

// begin registers an append of the batch named key and returns the index it names: the one after the last append queued, or
// after the last applied when none is in flight. The slot lock is held, and the append is queued before it is released.
func (f *slotFlight) begin(key string, hash model.Hash, applied uint64) (uint64, *flightAppend, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inflight >= maxSlotInflight {
		return 0, nil, model.Fail(model.Timeout)
	}
	if f.inflight == 0 || f.next <= applied {
		f.next = applied + 1
	}
	index := f.next
	f.next++
	f.inflight++
	fa := &flightAppend{hash: hash, done: make(chan struct{})}
	if f.batches == nil {
		f.batches = map[string]*flightAppend{}
	}
	f.batches[key] = fa
	return index, fa, nil
}

// finish records the outcome of a queued append and lets the retries that waited for it, and the appends that waited for the
// slot to be idle, go on.
func (f *slotFlight) finish(key string, fa *flightAppend, r model.Receipt, err error) {
	f.mu.Lock()
	if fa.over {
		f.mu.Unlock()
		return
	}
	fa.over, fa.receipt, fa.err = true, r, err
	if f.batches[key] == fa {
		delete(f.batches, key)
	}
	f.inflight--
	if f.inflight == 0 && f.idle != nil {
		close(f.idle)
		f.idle = nil
	}
	f.mu.Unlock()
	close(fa.done)
}

// abandon is finish for an append that was registered and never queued; fa may be nil (an append that was not registered).
func (f *slotFlight) abandon(key string, fa *flightAppend) {
	if fa != nil {
		f.finish(key, fa, model.Receipt{}, model.Fail(model.Unavailable))
	}
}

// waitIdle returns when no queued append of the slot is in flight.
func (f *slotFlight) waitIdle(ctx context.Context) error {
	for {
		f.mu.Lock()
		if f.inflight == 0 {
			f.mu.Unlock()
			return nil
		}
		if f.idle == nil {
			f.idle = make(chan struct{})
		}
		idle := f.idle
		f.mu.Unlock()
		select {
		case <-idle:
		case <-ctx.Done():
			return model.Fail(model.Cancelled)
		}
	}
}

// wait is the answer a retry of the queued append's batch is given: its receipt when the append was decided and stored the batch,
// unavailable when it was not (the retry's caller asks again and is judged against what the store holds then), conflict when the
// batch ID is held with another hash.
func (a *flightAppend) wait(ctx context.Context, hash model.Hash) (model.Receipt, error) {
	if a.hash != hash {
		return model.Receipt{}, model.Fail(model.Conflict)
	}
	select {
	case <-a.done:
	case <-ctx.Done():
		return model.Receipt{}, model.Fail(model.Cancelled)
	}
	if a.err != nil {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	return a.receipt, nil
}
