// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// The bounded-state rules are the apply rules that keep the issue, incident, condition
// and notification books from growing without limit (D37): the issue book coalesces the
// 129th gap of a data group into its oldest and evicts the oldest command record at the
// 1025th; an incident pruned at the project cap leaves a stub; a condition creation past
// the project's byte budget collects settled conditions; and a notification policy's late
// counters saturate (notify.DecideRules). A release that does not have them applies the
// rule they replaced, which refuses (Quota) where these make room.
//
// A control command is decided by the member that proposes it, against the committed
// state it reads, and the group installs the resulting state on every member. A group
// that mixes the two generations of the rules therefore does not hold two states, but it
// would answer the same command differently depending on which member the caller reached,
// and the old member would later read and rewrite books holding fields it does not know
// (EvidenceGap.merged, IssueCommandEntry.rev, the stub marks, late_saturated), dropping
// them. So the new rules wait for the whole group, like the erase protocol: every member
// of the committed configuration declares the protocol (storage's boundsProtocol), and
// until then every member applies the previous rules. The gate is set once at
// construction by the application (appcore.enableReplication); a Store without a gate
// (no replication, a test) applies the bounded rules.

// SetBoundedRulesGate installs the function that says whether every member of the
// replica group declared the bounded-state protocol. It is read by the proposer each
// time a command is decided, never cached: declarations only accumulate, so a member
// that sees them all keeps seeing them.
func (s *Store) SetBoundedRulesGate(ready func() bool) {
	if ready == nil {
		s.boundedGate.Store(nil)
		return
	}
	s.boundedGate.Store(&ready)
}

// BoundedRules reports whether the bounded-state rules apply: true without a gate, else
// what the gate says.
func (s *Store) BoundedRules() bool {
	gate := s.boundedGate.Load()
	return gate == nil || (*gate)()
}
