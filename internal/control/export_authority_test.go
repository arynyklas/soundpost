// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// writeStateForTest replaces the committed control state bytes without a control transition. It
// exists to build the state a build without AuthorityRevision wrote.
func (s *Store) writeStateForTest(raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Put([]byte("state"), raw) })
}

// MakeLegacyAuthorityForTest rewrites the committed state as the pre-AuthorityRevision build wrote
// it (the field absent) and returns the revision it left. Test only.
func (s *Store) MakeLegacyAuthorityForTest() (model.Revision, error) {
	st, err := s.localState()
	if err != nil {
		return 0, err
	}
	st.AuthorityRevision = 0
	raw, err := json.Marshal(st)
	if err != nil {
		return 0, err
	}
	return st.Revision, s.writeStateForTest(raw)
}
