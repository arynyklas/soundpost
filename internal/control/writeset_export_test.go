// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"hash/fnv"

	bolt "go.etcd.io/bbolt"
)

// WriteStats is what bolt wrote for control.db since Open: pages written (one per dirty page and
// one per meta page), the bytes of the pages those commits allocated, and the pages allocated.
type WriteStats struct{ Writes, AllocBytes, Pages int64 }

// BoltWriteStatsForTest reads the cumulative write counters of the control file. Test only.
func (s *Store) BoltWriteStatsForTest() WriteStats {
	st := s.db.DB.Stats().TxStats
	return WriteStats{Writes: int64(st.GetWrite()), AllocBytes: int64(st.GetPageAlloc()), Pages: int64(st.GetPageCount())}
}

// OverlayWrites is what the overlay of the admission ledger wrote since the process began: blobs of the log and their
// bytes, blocks of the folds and theirs. Test only.
type OverlayWrites struct{ Blobs, BlobBytes, Blocks, BlockBytes uint64 }

// OverlayWritesForTest reads the counters of the overlay (shared by every store of the process). Test only.
func OverlayWritesForTest() OverlayWrites {
	return OverlayWrites{ovCounters.blobs.Load(), ovCounters.blobBytes.Load(), ovCounters.blocks.Load(), ovCounters.blockBytes.Load()}
}

// KeyDump is the size and a hash of the value of one key of control.db.
type KeyDump struct {
	Size int
	Sum  uint64
}

// DumpForTest lists every key of every top-level bucket of control.db as "bucket/key" with the
// size and hash of its value, in one read transaction. Test only.
func (s *Store) DumpForTest() (map[string]KeyDump, error) {
	out := map[string]KeyDump{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return b.ForEach(func(k, v []byte) error {
				if v == nil {
					return nil
				}
				h := fnv.New64a()
				h.Write(v)
				out[string(name)+"/"+string(k)] = KeyDump{Size: len(v), Sum: h.Sum64()}
				return nil
			})
		})
	})
	return out, err
}
