// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"

	bolt "go.etcd.io/bbolt"
)

// RuleLedgerForTest reports whether this store keeps the rule books and the rule outbox in the ledger (D108). Test only.
func (s *Store) RuleLedgerForTest() bool { return s.ruleLedger.Load() }

// The points of the apply of the mark a crash test stops at.
const (
	RuleMarkerBefore = ruleMarkerBefore
	RuleMarkerSplit  = ruleMarkerSplit
	RuleMarkerAfter  = ruleMarkerAfter
)

// SetRuleMarkerFaultForTest installs the stop of a crash test at a point of the apply of the mark (every store of the process)
// and returns what removes it.
func SetRuleMarkerFaultForTest(stop func(point string) error) (remove func()) {
	ruleMarkerFault.Store(&stop)
	return func() { ruleMarkerFault.Store(nil) }
}

// EnsureRuleLedgerForTest proposes the mark of the installation as the first rule command does, without a rule command, and
// says whether this call committed it.
func (s *Store) EnsureRuleLedgerForTest(ctx context.Context) bool {
	_, committed := s.ensureRuleLedger(ctx)
	return committed
}

// RuleTablesForTest is the records of the two rule tables of the ledger: "<table>/<key>" to the stored bytes.
func (s *Store) RuleTablesForTest() (map[string]string, error) {
	out := map[string]string{}
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, name := range []string{"rule_books", "rule_outputs"} {
			b := tx.Bucket([]byte(name))
			if b == nil {
				continue
			}
			if err := b.ForEach(func(k, v []byte) error { out[name+"/"+string(k)] = string(v); return nil }); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
