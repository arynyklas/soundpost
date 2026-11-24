// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
)

// trackedDB is the engine's bbolt handle with an exact count of the read transactions opened
// through View. bolt's own Stats().OpenTxN is updated after the transaction registered, so it can
// read zero while a reader that began before a writer is already walking pages: the scrub must
// not trust it alone (scrubChunk).
type trackedDB struct {
	*bolt.DB
	readers atomic.Int64
	// views counts every View ever started (tests assert how a scan splits into read transactions).
	views atomic.Int64
	// viewGap, when set, runs once in the next View after the reader was counted and before bolt
	// opened its transaction: tests hold a reader in the window the stat cannot see.
	viewGap atomic.Pointer[func()]
	// grouped folds the concurrent applies of the slot groups into one commit (grouped_update.go).
	grouped groupedUpdates
}

// View counts the reader before bolt registers it and until its transaction ended, so any reader
// bolt has registered is also counted here.
func (d *trackedDB) View(fn func(*bolt.Tx) error) error {
	d.views.Add(1)
	d.readers.Add(1)
	defer d.readers.Add(-1)
	if gap := d.viewGap.Load(); gap != nil && d.viewGap.CompareAndSwap(gap, nil) {
		(*gap)()
	}
	return d.DB.View(fn)
}

// openReaders is the number of View calls in progress.
func (d *trackedDB) openReaders() int64 { return d.readers.Load() }

// syncFreelist writes the freelist with one commit (a graceful close): the file then carries it and a start reads it instead of
// walking the tree (D91). The engine opens apply.db with NoFreelistSync, which only the writer that holds the write lock may change:
// the flag is cleared inside the transaction (no other commit is running and none reads it before this one has released the lock), and
// stays cleared, so a commit that races the close persists the freelist as well.
func (d *trackedDB) syncFreelist() error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		tx.DB().NoFreelistSync = false
		return nil
	})
}
