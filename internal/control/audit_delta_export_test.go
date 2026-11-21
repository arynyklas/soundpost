// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// AuditDeltaStatsForTest is how many audit delta commands AppendAudit proposed and the bytes of
// their payloads.
func (s *Store) AuditDeltaStatsForTest() (commands, payloadBytes uint64) {
	return s.auditDeltas.Load(), s.auditDeltaBytes.Load()
}
