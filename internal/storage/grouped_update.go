// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

// groupedUpdates folds the write transactions of concurrent callers into one bbolt commit (its two
// fdatasyncs) without ever delaying a lone caller: the caller that finds no commit in progress
// commits at once, the callers that arrive while it fsyncs form the next commit together. Every
// caller returns only after the transaction that holds its writes is durable. A function that fails
// is rolled back alone: the others re-run without it and it runs by itself, so its error is its
// own (the contract of bolt's own Batch minus its fixed delay).
type groupedUpdates struct {
	mu      sync.Mutex
	pending []*groupedCall
	running bool
	// rounds is the bolt write transactions the engine committed through here, calls the functions they
	// carried and heldNS the time they were open (their functions, the page writes and the two fdatasyncs):
	// the share of the wall clock the one writer of apply.db was held.
	rounds, calls, heldNS atomic.Uint64
}

type groupedCall struct {
	fn   func(*bolt.Tx) error
	done chan error
}

// updateGrouped is Update for a function that is safe to run more than once (a failed sibling
// re-runs it) and beside the functions of other callers in one transaction.
func (d *trackedDB) updateGrouped(fn func(*bolt.Tx) error) error {
	g := &d.grouped
	call := &groupedCall{fn: fn, done: make(chan error, 1)}
	g.mu.Lock()
	g.pending = append(g.pending, call)
	if g.running {
		g.mu.Unlock()
		return <-call.done
	}
	g.running = true
	g.mu.Unlock()
	g.commitNext(d)
	return <-call.done
}

// commitNext commits the pending calls as one transaction. What arrives meanwhile is committed by
// a goroutine that takes over, so the caller that started the commit never serves a queue that
// outlives its own call.
func (g *groupedUpdates) commitNext(d *trackedDB) {
	g.mu.Lock()
	batch := g.pending
	g.pending = nil
	g.mu.Unlock()
	g.run(d, batch)
	g.mu.Lock()
	if len(g.pending) == 0 {
		g.running = false
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	go g.commitNext(d)
}

// run commits batch in one transaction; the calls that fail are removed and run by themselves.
func (g *groupedUpdates) run(d *trackedDB, batch []*groupedCall) {
	var solo []*groupedCall
	for len(batch) > 0 {
		failed := -1
		began := time.Now()
		err := d.DB.Update(func(tx *bolt.Tx) error {
			return withIndexRun(tx, func() error {
				for i, c := range batch {
					if err := c.fn(tx); err != nil {
						failed = i
						return err
					}
				}
				return nil
			})
		})
		g.heldNS.Add(uint64(time.Since(began)))
		g.rounds.Add(1)
		g.calls.Add(uint64(len(batch)))
		switch {
		case err == nil:
			for _, c := range batch {
				c.done <- nil
			}
			batch = nil
		case failed >= 0:
			solo = append(solo, batch[failed])
			batch = append(batch[:failed:failed], batch[failed+1:]...)
		default: // the commit itself failed: every call of the batch shares the error
			for _, c := range batch {
				c.done <- err
			}
			batch = nil
		}
	}
	for _, c := range solo {
		c.done <- d.DB.Update(func(tx *bolt.Tx) error { return withIndexRun(tx, func() error { return c.fn(tx) }) })
	}
}
