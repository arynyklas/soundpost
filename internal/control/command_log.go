// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// viewCommand reads what the applied-command log holds for one command: the Result it committed and the
// binding of the principal that committed it. The state fn is given is the shared decode of the blob
// (coreState: not to be changed) with the committed revision. A log that is a table of the ledger is read by
// the key, so a retry of an applied command costs the same whatever the log holds (the log is as long as the
// dedup window); a file that keeps the log in its blob answers from the decode.
func (s *Store) viewCommand(ctx context.Context, id string, fn func(st *State, result Result, owner string, found bool) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreState(tx)
		if err != nil {
			return err
		}
		if !ledgerLayout(tx.Bucket([]byte("control"))) {
			result, found := st.Commands[id]
			return fn(st, result, st.CommandOwners[id], found)
		}
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		raw := l.t[tableCommands].Get([]byte(id))
		if raw == nil {
			return fn(st, Result{}, "", false)
		}
		var result Result
		if json.Unmarshal(raw, &result) != nil {
			return model.Fail(model.Corrupt)
		}
		return fn(st, result, string(l.t[tableCommandOwners].Get([]byte(id))), true)
	})
}
