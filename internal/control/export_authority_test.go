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
	return s.db.Update(func(tx *bolt.Tx) error {
		markCoreChanged(tx)
		return tx.Bucket([]byte("control")).Put([]byte("state"), raw)
	})
}

// MakeLegacyAuthorityForTest rewrites the committed state as the pre-AuthorityRevision build wrote
// it (the field absent) and returns the revision it left. Only the blob is rewritten: the admission
// ledger (the books of the logical state) keeps living in its own records, which is where this build
// holds them. Test only.
func (s *Store) MakeLegacyAuthorityForTest() (model.Revision, error) {
	st, err := s.localState()
	if err != nil {
		return 0, err
	}
	st.AuthorityRevision = 0
	detachLedger(&st)
	raw, err := json.Marshal(st)
	if err != nil {
		return 0, err
	}
	return st.Revision, s.writeStateForTest(raw)
}

// ExpandForTest makes the installation one the previous release can still read: the contraction marks are
// removed from the stored state and the books return to the blob. Test only.
func (s *Store) ExpandForTest() error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		var st State
		if err := loadLogical(tx, &st); err != nil {
			return err
		}
		delete(st.OIDC, model.IndexesContractedKey)
		for k, o := range st.Orgs {
			delete(o.Settings, model.IndexesContractedKey)
			st.Orgs[k] = o
		}
		return putLogicalState(tx, st)
	})
	s.noteLayout()
	return err
}

// LedgerLayoutForTest says whether the file keeps its books in the ledger. Test only.
func (s *Store) LedgerLayoutForTest() bool { return s.layoutLedger.Load() }

// InstallationFloorForTest is the floor this release judges a retention command against besides the
// organization's own revision (installationFloor). Test only.
func InstallationFloorForTest(st State) model.Revision { return installationFloor(&st) }

// PreviousReleaseAcceptsForTest is the revision rule of the previous release (5475ef6) for a
// retention command: the view is no older than AuthorityRevision alone and no newer than Revision.
// It knows neither the organization's revision nor the pair of model.ScopedAuthorityKey. Test only.
func PreviousReleaseAcceptsForTest(st State, expected model.Revision) bool {
	return authorityFloor(&st) <= expected && expected <= st.Revision
}
