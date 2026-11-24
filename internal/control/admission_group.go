// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// Group commit of admission transitions.
//
// A control command costs a replicated commit: the journal record and its fsync, the application of the
// patch to control.db and its two fsyncs (about 2.5 ms on the single-host gate's virtual disk, whatever
// the command carries), and every command takes the application index, so commands are strictly one at a
// time. An admission needs two of them (reserve, finalize), so one writer at a time capped the whole
// installation at about 200 batches per second before anything else was done, and the single-host gate
// offers 218 batches per second.
//
// The transitions that wait for a commit are therefore committed together. The first transition to arrive
// starts a runner; the transitions that arrive while it is committing wait in the queue and are the next
// round, so an idle installation pays no delay at all and a busy one pays one commit's time, and what a
// commit costs is shared by everything that waited for it. A round reads the ledger once
// (a linearizable read barrier and one read transaction), runs the transitions in arrival order, each
// against the books as the ones before it in the round left them (ledgerBooks.child), keeps the writes of
// the ones that succeed and answers the others with their own refusal, and proposes the writes of the
// round as one state patch. The patch is exactly what the same transitions would have proposed one by one,
// with one revision step instead of one per transition: a quota head that several transitions charged is
// written once, with the final value.
//
// A transition that fails does not fail the round: a quota refusal, a source that was disabled, a batch
// that conflicts are that batch's answer. The round as a whole fails only as one command can: the
// proposal lost the application-index race (another writer committed first, or the leader is holding
// admission for a writer that lost: admission_yield.go), which reads and judges the round again, up to
// maxLostProposals times, a millisecond apart (every build re-judges the records it is given, so a retry
// cannot apply a stale decision); or the group refused it, which every transition of the round is told.
//
// The sparse transitions of the workers' books (a job update, an issue commit: sparse.go) are items of the same
// queue. They read the same transaction and their records are ops of the same patch; their tables are never
// the admission's, so the only thing a round has to keep apart is two of them that touch the same records
// (sparseRound.admit): the later one waits for the next round, at the head of the queue. They are not a second
// commit path with a lock of their own: the lock and the application index are one, and what a commit costs
// is the thing to share, so a worker's commit rides in the round that is running anyway instead of holding the
// lock for a commit of its own in front of the next round.

// maxRoundTransitions bounds the transitions of one round, so that a patch stays small (about 1.5 KiB per
// transition, 768 KiB for a full round, far below the replica's entry limit) and the first answer of a deep
// queue is not held for the whole queue. A round is one commit: the more transitions it carries, the fewer
// commits (journal fsync, bolt pages, the per-command costs) each of them pays.
const maxRoundTransitions = 512

// admissionItem is one transition waiting for a round: an admission transition (build) or a sparse one of the
// workers' books (plan, sparse.go), which rides in the same commit.
type admissionItem struct {
	ctx      context.Context
	build    func(*State, admissionBooks) error
	plan     sparsePlan // set instead of build: the update of a job or an issue
	done     chan error // the outcome, one value
	answered bool       // done has its value (the runner's alone)
	deferred bool       // the round did not judge it (it read what an earlier plan of the round writes): the next round does
}

func (it *admissionItem) answer(err error) {
	it.answered = true
	it.done <- err
}

// admissionQueue is the transitions waiting for a round and whether a runner is working through them.
type admissionQueue struct {
	mu      sync.Mutex
	pending []*admissionItem
	running bool
}

// submitAdmission queues build and waits for its round. The caller does not stop waiting when its context
// ends: build captures the caller's variables, and the round may be running it; a transition whose context
// ended before its round started is answered with that error and never run.
func (s *Store) submitAdmission(ctx context.Context, build func(*State, admissionBooks) error) error {
	return s.enqueue(&admissionItem{ctx: ctx, build: build, done: make(chan error, 1)})
}

func (s *Store) enqueue(it *admissionItem) error {
	q := &s.admissions
	q.mu.Lock()
	q.pending = append(q.pending, it)
	start := !q.running
	q.running = true
	q.mu.Unlock()
	if start {
		go s.runAdmissions()
	}
	return <-it.done
}

// requeue puts the transitions a round left for the next one at the head of the queue, in their order: they
// are the oldest, and the first sparse transition of a round is never deferred, so each of them is judged in
// the next round at the latest.
func (s *Store) requeue(items []*admissionItem) {
	if len(items) == 0 {
		return
	}
	q := &s.admissions
	q.mu.Lock()
	q.pending = append(slices.Clone(items), q.pending...)
	q.mu.Unlock()
}

// runAdmissions commits the queue, one round at a time, until it is empty.
func (s *Store) runAdmissions() {
	q := &s.admissions
	for {
		q.mu.Lock()
		n := min(len(q.pending), maxRoundTransitions)
		if n == 0 {
			q.pending, q.running = nil, false
			q.mu.Unlock()
			return
		}
		round := slices.Clone(q.pending[:n])
		q.pending = q.pending[n:]
		if len(q.pending) == 0 {
			q.pending = nil
		}
		q.mu.Unlock()
		s.commitRound(round)
	}
}

// commitRound commits the transitions of a round, reading and judging them again while the proposal is
// lost, and answers each.
func (s *Store) commitRound(items []*admissionItem) {
	for attempt := 1; ; attempt++ {
		proposed, lost, err := s.roundOnce(items)
		if len(proposed) == 0 {
			return
		}
		if err == nil || !lost || attempt >= maxLostProposals {
			for _, it := range proposed {
				it.answer(err)
			}
			return
		}
		items = proposed
		time.Sleep(time.Millisecond)
	}
}

// roundOnce is one read-compute-propose round. It answers the transitions that did not run (their context
// ended) and the ones that refused; it returns the ones that are left to answer, which are those the
// proposal carried (or would have carried: nothing to write is nothing to propose), whether it was lost,
// and its outcome.
func (s *Store) roundOnce(items []*admissionItem) (left []*admissionItem, lost bool, err error) {
	live := make([]*admissionItem, 0, len(items))
	for _, it := range items {
		if e := it.ctx.Err(); e != nil {
			it.answer(e)
			continue
		}
		it.deferred = false
		live = append(live, it)
	}
	if len(live) == 0 {
		return nil, false, nil
	}
	var deferred []*admissionItem
	unanswered := func() []*admissionItem {
		out := live[:0:0]
		for _, it := range live {
			if !it.answered && !it.deferred {
				out = append(out, it)
			}
		}
		return out
	}
	sparse := slices.ContainsFunc(live, func(it *admissionItem) bool { return it.plan != nil })
	if sparse {
		s.warmCore()
	}
	defer s.lockUpdates()()
	r := s.repl
	ctx := context.Background()
	if _, e := r.group.ReadIndex(ctx); e != nil {
		return live, false, replicaFaultUnder(ctx, e)
	}
	var expected model.Revision
	var installation model.ID
	var ops []patchOp
	var base string
	var carried []*admissionItem
	admitted, wrote := 0, 0 // the admission transitions and the sparse ones with records that the proposal carries
	e := s.db.View(func(tx *bolt.Tx) error {
		decodes := s.db.decodes.Load() + s.db.memberDecodes.Load()
		core, err := s.coreState(tx)
		if err != nil {
			return err
		}
		if sparse && s.db.decodes.Load()+s.db.memberDecodes.Load() != decodes {
			s.sparseLockedDecodes.Add(1) // the decode warmCore did not leave: the round made it under the lock
		}
		if !ledgerLayout(tx.Bucket([]byte("control"))) || !s.StatePatch() {
			return errNotLedgerLayout
		}
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		expected, installation = core.Revision, core.Installation
		round := newLedgerBooks(l)
		var sr sparseRound
		for _, it := range live {
			if it.plan != nil {
				written, wait, err := sr.admit(it.plan, core, l)
				switch {
				case wait:
					it.deferred = true
					deferred = append(deferred, it)
				case err != nil:
					it.answer(err)
				default:
					if len(written) != 0 {
						wrote++
					}
					carried = append(carried, it)
				}
				continue
			}
			books := round.child()
			if err := it.build(core, books); err != nil {
				it.answer(err)
				continue
			}
			round.merge(books)
			admitted++
			carried = append(carried, it)
		}
		if len(carried) == 0 {
			return nil
		}
		written := append(round.ops(), sr.ops()...)
		if len(written) == 0 {
			return nil // every transition found its answer already committed
		}
		ctrl := tx.Bucket([]byte("control"))
		if _, revision, err := stateHead(ctrl); err != nil || revision != expected {
			return model.Fail(model.Corrupt)
		}
		base = layoutBase(ctrl, l.acc)
		step, err := s.stepOps(ctrl, expected)
		if err != nil {
			return err
		}
		ops = append(step, written...)
		sortOps(ops)
		return nil
	})
	s.requeue(deferred)
	if e != nil {
		return unanswered(), false, e
	}
	if len(carried) == 0 {
		return nil, false, nil
	}
	if len(ops) == 0 {
		return carried, false, nil
	}
	payload, e := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: installation, Expected: expected, Base: base, Keys: map[string][]byte{}, Ops: ops}})
	if e != nil {
		return carried, false, model.Fail(model.Invalid)
	}
	s.statePatches.Add(1)
	s.statePatchBytes.Add(uint64(len(payload)))
	if admitted != 0 {
		s.admissionRounds.Add(1)
		s.admissionRoundItems.Add(uint64(admitted))
	}
	s.sparseCommits.Add(uint64(wrote))
	_, e = r.group.Propose(ctx, replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload, ApplicationIndex: uint64(expected + 1)})
	var fault *model.Fault
	if errors.Is(e, replica.ErrStale) || errors.As(e, &fault) && fault.Code == model.Stale {
		lost = true
	}
	return carried, lost, replicaFault(e)
}
