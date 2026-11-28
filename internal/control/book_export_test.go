// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"time"

	bolt "go.etcd.io/bbolt"
)

// UpdateLockStatsForTest is how many times a writer took the lock every control writer shares and for how
// long, in total, it was held.
func (s *Store) UpdateLockStatsForTest() (holds uint64, held time.Duration) {
	return s.updateHolds.Load(), time.Duration(s.updateHeldNS.Load())
}

// SparseCommitsForTest is how many commands this store proposed through sparseUpdate.
func (s *Store) SparseCommitsForTest() uint64 { return s.sparseCommits.Load() }

// AdmissionRoundsForTest is how many rounds of the group commit carried an admission transition.
func (s *Store) AdmissionRoundsForTest() uint64 { return s.admissionRounds.Load() }

// RemoteAdmissionForTest is how many admission transitions this store asked the leader to judge, how many of those it judged itself
// after all (no leader that serves the call), and how many calls it served as the leader.
func (s *Store) RemoteAdmissionForTest() (calls, fallbacks, served uint64) {
	return s.remoteCalls.Load(), s.remoteFallbacks.Load(), s.remoteServed.Load()
}

// AdmissionQueuedForTest is how many transitions wait in the queue of the group commit for a round.
func (s *Store) AdmissionQueuedForTest() int {
	s.admissions.mu.Lock()
	defer s.admissions.mu.Unlock()
	return len(s.admissions.pending)
}

// SetAdmissionYieldScaleForTest stretches the leader's fairness window toward the writers that lost (admission_yield.go) n times (n < 2: as it
// is). A test whose writers run several times slower than the window was sized for sets it, a race detector's; the product never does.
func (s *Store) SetAdmissionYieldScaleForTest(n int64) { s.admissionYieldScale.Store(n) }

// LedgerRecordForTest is a copy of the record under key in a bucket of control.db (nil: there is none).
func (s *Store) LedgerRecordForTest(bucket, key string) (record []byte) {
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(bucket)); b != nil {
			record = bytes.Clone(b.Get([]byte(key)))
		}
		return nil
	})
	return record
}

// LedgerCountForTest is how many records a bucket of control.db holds.
func (s *Store) LedgerCountForTest(bucket string) (n int) {
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(bucket)); b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return n
}

// BlobMemberForTest is the encoding of a member of the committed blob under control/state.
func (s *Store) BlobMemberForTest(name string) (encoding string) {
	_ = s.db.View(func(tx *bolt.Tx) error {
		members, err := decodeMembers(tx.Bucket([]byte("control")).Get(stateKey))
		if err == nil {
			encoding = string(members[name])
		}
		return nil
	})
	return encoding
}

// SparseLockedDecodesForTest is how many sparse commits decoded the whole state while they held the lock.
func (s *Store) SparseLockedDecodesForTest() uint64 { return s.sparseLockedDecodes.Load() }

// SettleScanRowsForTest is how many reservation rows the planning of settlements decoded.
func (s *Store) SettleScanRowsForTest() uint64 { return s.settleScanRows.Load() }

// IssueCodecCountsForTest is how many issue records the commits of this process decoded and encoded.
func (s *Store) IssueCodecCountsForTest() (decodes, encodes uint64) {
	return issueDecodes.Load(), issueMarshals.Load()
}
