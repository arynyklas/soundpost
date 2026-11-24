// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import bolt "go.etcd.io/bbolt"

// SharedDecodesForTest is how many whole-state decodes the shared reads (ViewShared and the other core
// reads) have made on this store.
func (s *Store) SharedDecodesForTest() uint64 { return s.db.decodes.Load() }

// SharedDecodeHeldForTest says whether a decoded state is being kept for the next shared read.
func (s *Store) SharedDecodeHeldForTest() bool { return s.db.core.Load() != nil }

// PublishSharedDecodeForTest keeps st as the shared decode of bolt transaction txid, the way a
// reader that has just decoded it does, and says whether it is the one kept.
func (s *Store) PublishSharedDecodeForTest(txid int, st *State) bool {
	e := &coreEntry{txid: int64(txid), state: st}
	s.db.publishCore(e)
	return s.db.core.Load() == e
}

// NewerDecodeServesAnOlderReaderForTest reads the core state through a read transaction, then replaces the
// shared decode by one that stands for a transaction newer than the reader's (another reader made it after a
// commit), reads through the same transaction again and returns how many whole-state decodes that second read
// made. No write changed the blob in between, so the answer is 0.
func (s *Store) NewerDecodeServesAnOlderReaderForTest() (uint64, error) {
	var decoded uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		s.db.core.Store(&coreEntry{txid: int64(tx.ID()) + 3, state: st})
		before := s.db.decodes.Load()
		if _, err = s.coreState(tx); err != nil {
			return err
		}
		decoded = s.db.decodes.Load() - before
		return nil
	})
	return decoded, err
}
