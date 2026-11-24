// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// StateBytesForTest is a copy of the encoding of the committed state, as the voter holds it (a file of
// layout 2 keeps the revision beside the blob: it is joined).
func (s *Store) StateBytesForTest() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		raw, err := stateRaw(tx.Bucket([]byte("control")))
		out = bytes.Clone(raw)
		return err
	})
	return out, err
}

// ApplyPathStatsForTest is how many committed commands this store applied to the bytes of its state
// and how many it had to decode the state for.
func (s *Store) ApplyPathStatsForTest() (spliced, decoded uint64) {
	return s.rawApplies.Load(), s.decodedApplies.Load()
}
