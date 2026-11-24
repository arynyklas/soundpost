// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"sync"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
)

// trackedDB is the control store's bbolt handle with an exact count of the read transactions
// opened through View. bolt's own Stats().OpenTxN is updated after the transaction registered, so
// it can read zero while a reader that began before a writer is already walking pages: the scrub
// must not trust it alone (scrubChunk). It is the twin of internal/storage's trackedDB, which
// closed the same window for apply.db.
//
// Every read of control.db goes through View, so a reader bolt has registered is also counted
// here. Writers never need counting: the scrub itself is the single writer while it runs.
type trackedDB struct {
	*bolt.DB
	readers atomic.Int64
	// viewGap, when set, runs once in the next View after the reader was counted and before bolt
	// opened its transaction: tests hold a reader in the window the stat cannot see.
	viewGap atomic.Pointer[func()]
	// decodes counts the whole-state decodes of the state without the ledger (coreState), shared by
	// ViewCore, ViewAdmission and ViewShared. Tests only.
	decodes atomic.Uint64
	// core is the decode of the state without the ledger of the newest transaction a core read has
	// seen (coreState); coreAt is the newest transaction known to have changed the blob other than by
	// stepping the revision. An entry is used by a reader whose transaction is not older than the
	// entry and when no marked write is newer than it.
	core   atomic.Pointer[coreEntry]
	coreAt atomic.Int64
}

// View counts the reader before bolt registers it and until its transaction ended.
func (d *trackedDB) View(fn func(*bolt.Tx) error) error {
	d.readers.Add(1)
	defer d.readers.Add(-1)
	if gap := d.viewGap.Load(); gap != nil && d.viewGap.CompareAndSwap(gap, nil) {
		(*gap)()
	}
	return d.DB.View(fn)
}

// openReaders is the number of View calls in progress.
func (d *trackedDB) openReaders() int64 { return d.readers.Load() }

// trackedDBs maps a bolt handle to its trackedDB, so that putState, which sees only a bucket and its
// transaction, can mark the write.
var trackedDBs sync.Map

func registerTracked(d *trackedDB) { trackedDBs.Store(d.DB, d) }

// Close forgets the handle and closes it.
func (d *trackedDB) Close() error {
	trackedDBs.Delete(d.DB)
	forgetOverlay(d.DB)
	return d.DB.Close()
}

// syncFreelist writes the freelist with one commit (a graceful close): the file then carries it and a start reads it instead of walking
// the tree (durablefs.BoltOptions). The store opens control.db with NoFreelistSync, which only the writer that holds the write lock may
// change: the flag is cleared inside the transaction (no other commit is running and none reads it before this one has released the
// lock), and stays cleared, so a commit that races the close persists the freelist as well. Twin of the storage engine's.
func (d *trackedDB) syncFreelist() error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		tx.DB().NoFreelistSync = false
		return nil
	})
}

// markCoreChanged records, from inside the write transaction tx and before it commits, that the blob
// under control/state changed in a way a decode of the older blob does not reflect (coreState). The
// decode that is held is dropped with it: a state that was just rewritten (an erasure) is not kept in
// memory until the next read replaces it.
func markCoreChanged(tx *bolt.Tx) {
	v, ok := trackedDBs.Load(tx.DB())
	if !ok {
		return
	}
	d := v.(*trackedDB)
	id := int64(tx.ID())
	for {
		cur := d.coreAt.Load()
		if id <= cur || d.coreAt.CompareAndSwap(cur, id) {
			break
		}
	}
	d.core.Store(nil)
}

// publishCore keeps e as the shared decode of the blob unless a newer one is already there.
func (d *trackedDB) publishCore(e *coreEntry) {
	for {
		cur := d.core.Load()
		if cur != nil && cur.txid >= e.txid {
			return
		}
		if d.core.CompareAndSwap(cur, e) {
			return
		}
	}
}

func unregisterTracked(d *trackedDB) {
	trackedDBs.Delete(d.DB)
	forgetOverlay(d.DB)
}
