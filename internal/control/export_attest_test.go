// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// ApplyStaleCommandDirect hands the control state machine of s one committed control command that
// expects an older revision than the committed one, at the next replica index: the machine rejects
// it (replica.ErrConflict) and records its index, exactly as it does for a command a deposed
// leader had accepted. No public path commits such a command (the leader refuses a stale one before
// it commits, and a test cannot depose a leader at a chosen index), so the test applies it to the
// machine of the node that answers the receipt; that node's group does not know the index afterwards,
// so the test must not commit anything through it again. It returns the machine's answer.
func ApplyStaleCommandDirect(s *Store) error {
	st, err := s.localState()
	if err != nil {
		return err
	}
	keys, err := s.replicaKeyFiles()
	if err != nil {
		return err
	}
	physical, err := s.appliedIndex()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(controlReplacement{Expected: st.Revision - 1, State: st, Keys: keys})
	if err != nil {
		return err
	}
	g := s.ReplicaGroup().Status()
	return s.repl.Apply(replica.CommittedEntry{
		Group: g.Group, Term: g.Term, Index: physical + 1,
		ApplicationCursor: model.Cursor{Group: g.Group, Index: model.Uint64(st.Revision)},
		Entry:             replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload},
	})
}

// SignalInstallDirect tells the control machine of s that its group installed a snapshot at the
// next replica index, exactly as the group does after an install (replica.ProofWatcher). It
// changes no file: the node's own truth stays clean, so the test sees only what the signal does
// to the records that predate it.
func SignalInstallDirect(s *Store) error {
	physical, err := s.appliedIndex()
	if err != nil {
		return err
	}
	s.repl.ProofWithdrawn(replica.ProofWithdrawal{Index: physical + 1, Install: true})
	return nil
}
