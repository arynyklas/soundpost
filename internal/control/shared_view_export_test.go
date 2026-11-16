// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// SharedDecodesForTest is how many whole-state decodes ViewShared has made on this store.
func (s *Store) SharedDecodesForTest() uint64 { return s.db.decodes.Load() }

// SharedDecodeHeldForTest says whether a decoded state is being kept for the next shared read.
func (s *Store) SharedDecodeHeldForTest() bool { return s.db.decoded.Load() != nil }

// PublishSharedDecodeForTest keeps st as the shared decode of bolt transaction txid, the way a
// reader that has just decoded it does, and says whether it is the one kept.
func (s *Store) PublishSharedDecodeForTest(txid int, st *State) bool {
	ds := &decodedState{txid: txid, state: st}
	s.db.publish(ds)
	return s.db.decoded.Load() == ds
}
