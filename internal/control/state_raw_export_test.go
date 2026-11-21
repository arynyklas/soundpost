// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// StateBytesForTest is a copy of the encoding of the committed state, as the voter stores it.
func (s *Store) StateBytesForTest() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket([]byte("control")).Get([]byte("state")))
		return nil
	})
	return out, err
}

// ApplyPathStatsForTest is how many committed commands this store applied to the bytes of its state
// and how many it had to decode the state for.
func (s *Store) ApplyPathStatsForTest() (spliced, decoded uint64) {
	return s.rawApplies.Load(), s.decodedApplies.Load()
}
