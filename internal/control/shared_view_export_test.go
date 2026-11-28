// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import bolt "go.etcd.io/bbolt"

// SharedDecodesForTest is how many whole-state decodes the shared reads (ViewShared and the other core
// reads) have made on this store.
func (s *Store) SharedDecodesForTest() uint64 { return s.db.decodes.Load() }

// SharedMemberDecodesForTest is how many members of the state the shared reads have decoded: a refresh after
// a commit decodes the members the commit changed, a whole-state decode counts every one.
func (s *Store) SharedMemberDecodesForTest() uint64 { return s.db.memberDecodes.Load() }

// BlobDecodesForTest is how many times the whole blob of the control state was decoded by any reader or
// writer (a reader's own State included), which a shared read does not do.
func (s *Store) BlobDecodesForTest() uint64 { return s.db.blobDecodes.Load() }

// SharedDecodeHeldForTest says whether a decoded state is being kept for the next shared read.
func (s *Store) SharedDecodeHeldForTest() bool { return s.db.core.Load() != nil }

// DropSharedDecodeForTest forgets the shared decode, as a restart does: the next shared read decodes what it reads.
func (s *Store) DropSharedDecodeForTest() { s.db.core.Store(nil) }

// SharedMemberHeldForTest says whether the shared decode holds the named member of the state.
func (s *Store) SharedMemberHeldForTest(name string) bool {
	e := s.db.core.Load()
	i, ok := coreByName[name]
	return ok && e != nil && e.at[i] != 0
}

// completeEntry is the shared decode that stands for st as the blob of bolt transaction txid has it: every member.
func completeEntry(txid int64, st *State) *coreEntry {
	e := &coreEntry{state: st}
	for i := range coreFields {
		e.at[i] = txid
	}
	return e
}

// PublishSharedDecodeForTest keeps st as the shared decode of bolt transaction txid, the way a
// reader that has just decoded it does, and says whether it is the one kept.
func (s *Store) PublishSharedDecodeForTest(txid int, st *State) bool {
	e := completeEntry(int64(txid), st)
	s.db.publishCore(e)
	return s.db.core.Load() == e
}

// NewerDecodeServesAnOlderReaderForTest reads the core state through a read transaction, then replaces the
// shared decode by one that stands for a transaction newer than the reader's (another reader made it after a
// commit), reads through the same transaction again and returns how many decodes (of the whole state or of
// a member of it) that second read made. No write changed the blob in between, so the answer is 0.
func (s *Store) NewerDecodeServesAnOlderReaderForTest() (uint64, error) {
	var decoded uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		s.db.core.Store(completeEntry(int64(tx.ID())+3, st))
		before := s.db.decodes.Load() + s.db.memberDecodes.Load()
		if _, err = s.coreState(tx); err != nil {
			return err
		}
		decoded = s.db.decodes.Load() + s.db.memberDecodes.Load() - before
		return nil
	})
	return decoded, err
}
