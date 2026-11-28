// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "encoding/json"

// RuleLedgerKey is the key of State.OIDC that says the rule books and the rule outbox (RuleBooks, RuleOutputs) are
// records of the control ledger instead of members of the state blob (D108). It is written by one replicated
// command, once every member of the control group declared protocol 10 and the installation is contracted, and
// every voter moves the two members out of its blob when it applies that command. The state a View, a snapshot
// or a backup carries is the same either way (the two members are in it); the keys of RuleOutputs differ: the
// blob keys an output by its ID, the ledger by "org:project:rule:id", so the outputs of one rule are one run of
// keys. The key is in the OIDC map, which every release carries and no release interprets for it.
const RuleLedgerKey = "rules:ledger"

// RuleLedgerLayoutVersion is what a member whose RUNNING binary reads the rule facts as records of the ledger answers to the
// live layout question (replica.MTLS.QueryLayout) instead of IndexLayoutVersion: the previous release and every build that
// predates D108 answer IndexLayoutVersion, and a member that answers less than this cannot read an installation that carries
// RuleLedgerKey. A binary that asks the question of a member requires IndexLayoutVersion only, so the larger answer is
// understood by every release that asks it.
const RuleLedgerLayoutVersion uint64 = 2

// RulesInLedger reports whether the rule books and the rule outbox are records of the ledger.
func (s *ControlState) RulesInLedger() bool {
	_, ok := s.OIDC[RuleLedgerKey]
	return ok
}

// ruleLedgerMark is the value of RuleLedgerKey: the revision of the command that wrote it, which every voter applies as the
// same revision, so a state names the point of the move (the one-way point) and not only that it happened.
type ruleLedgerMark struct {
	At uint64 `json:"at"`
}

// MarkRulesInLedger records the mark RulesInLedger reports, naming at as the revision of the command that writes it. A state
// that carries the mark keeps the one it has: the move happens once.
func (s *ControlState) MarkRulesInLedger(at Revision) {
	if s.RulesInLedger() {
		return
	}
	if s.OIDC == nil {
		s.OIDC = map[string]json.RawMessage{}
	}
	raw, _ := json.Marshal(ruleLedgerMark{At: uint64(at)})
	s.OIDC[RuleLedgerKey] = raw
}

// RulesMarkedAt is the revision of the command that wrote the mark; 0 when the state carries none or one that names no revision.
func (s *ControlState) RulesMarkedAt() uint64 {
	var m ruleLedgerMark
	if raw, ok := s.OIDC[RuleLedgerKey]; !ok || StrictJSON(raw, &m) != nil {
		return 0
	}
	return m.At
}

// RuleLedger reports whether the books of this read-only control are served from a ledger that holds the rule books
// and the rule outbox as records: the keys of RuleOutputs are then "org:project:rule:id" and a prefix of them is
// the outbox of a project or of one rule. False for a state that holds the two members itself.
func (r readOnlyControl) RuleLedger() bool {
	rl, ok := r.src.(interface{ RuleLedger() bool })
	return ok && rl.RuleLedger()
}
