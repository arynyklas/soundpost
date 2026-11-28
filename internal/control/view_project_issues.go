// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// ViewProjectIssues is ViewCore for a reader that also looks at the grouping issues of one project (the issue holds of the
// artifact lifecycle read the workflow of the issues they hold maps for): the state is the decode every concurrent core reader
// shares, its maps are not the reader's to change, and GroupingIssues holds the project's issues and no other. Reading them does
// not cost a decode of the control state: a file of the ledger layout gives them from the records under the project's key
// prefix, any other from the decoded member. The linearizable read barrier is View's.
func (s *Store) ViewProjectIssues(ctx context.Context, org, project model.ID, fn func(State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreMembers(tx, allCore)
		if err != nil {
			return err
		}
		issues := map[string]model.GroupingIssue{}
		if ledgerLayout(tx.Bucket([]byte("control"))) {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			src := ledgerBookSource{l}
			for _, key := range src.BookKeys(model.BookGroupingIssues, org.String()+":"+project.String()+":") {
				raw, ok := src.BookRecord(model.BookGroupingIssues, key)
				if !ok {
					continue
				}
				var gi model.GroupingIssue
				if json.Unmarshal(raw, &gi) != nil {
					return model.Fail(model.Corrupt)
				}
				if gi.Org == org && gi.Project == project {
					issues[key] = gi
				}
			}
		} else {
			for key, gi := range st.GroupingIssues {
				if gi.Org == org && gi.Project == project {
					issues[key] = gi
				}
			}
		}
		st.GroupingIssues = issues
		return fn(*st)
	})
}
