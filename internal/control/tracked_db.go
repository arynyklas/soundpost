// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
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
