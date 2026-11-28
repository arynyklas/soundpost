// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package control

import (
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/diagstat"
	"github.com/arynyklas/soundpost/internal/replica"
)

// registerDiag reports the counters of the control store to a diagnostic build's endpoint (diagstat): the page nodes
// control.db wrote, how long the update lock was held, the admission rounds and the phases and cuts of the control
// group. directory is the control group's directory. It reads atomics and file sizes only: a count of the rows of the ledger
// tables (a full scan of 1.5 M keys under a read transaction, which a growing file's remap waits for) is not taken per poll.
func (s *Store) registerDiag(group *replica.Group, directory string) {
	diagstat.Register("control", func() map[string]any {
		return map[string]any{
			"bolt":             diagstat.Bolt(s.db.DB),
			"control_db_bytes": diagstat.FileSize(filepath.Join(s.dir, "control.db")),
			"group_dir_bytes":  diagstat.DirSize(directory),
			"group":            diagstat.Group(group),
			"lane_trace":       group.LaneTrace(),
			"overlay": map[string]any{
				"fold_steps": ovStats.foldSteps.Load(), "fold_ns": ovStats.foldNS.Load(), "max_fold_ns": ovStats.maxFoldNS.Load(),
				"drops": ovStats.drops.Load(), "drop_ns": ovStats.dropNS.Load(), "max_drop_ns": ovStats.maxDropNS.Load(),
				"loads": ovStats.loads.Load(), "load_ns": ovStats.loadNS.Load(), "max_load_ns": ovStats.maxLoadNS.Load(),
				"freezes": ovStats.freezes.Load(), "parked": ovStats.parked.Load(), "blobs": ovCounters.blobs.Load(), "blob_bytes": ovCounters.blobBytes.Load(),
				"blocks": ovCounters.blocks.Load(), "block_bytes": ovCounters.blockBytes.Load(),
			},
			"update_holds":          s.updateHolds.Load(),
			"update_held_ns":        s.updateHeldNS.Load(),
			"admission_rounds":      s.admissionRounds.Load(),
			"admission_round_items": s.admissionRoundItems.Load(),
			"remote":                map[string]any{"calls": s.remoteCalls.Load(), "call_ns": s.remoteCallNS.Load(), "fallbacks": s.remoteFallbacks.Load(), "served": s.remoteServed.Load(), "failures": failureCounts()},
			"round": map[string]any{
				"attempts": s.admissionStats.attempts.Load(), "lost": s.admissionStats.lost.Load(), "items": s.admissionStats.items.Load(), "bytes": s.admissionStats.bytes.Load(), "shed": s.admissionStats.shed.Load(), "reads_skipped": s.admissionStats.readsSkipped.Load(),
				"queue_n": s.admissionStats.queueN.Load(), "queue_ns": s.admissionStats.queueNS.Load(), "queue_max_ns": s.admissionStats.queueMaxNS.Load(),
				"lock_ns": s.admissionStats.lockNS.Load(), "read_ns": s.admissionStats.readNS.Load(), "build_ns": s.admissionStats.buildNS.Load(),
				"propose_ns": s.admissionStats.proposeNS.Load(), "propose_max_ns": s.admissionStats.proposeMaxNS.Load(),
				"kinds": s.admissionStats.kindCounts(), "settle_rounds": s.admissionStats.settleRounds.Load(), "settle_commands": s.admissionStats.settleCommands.Load(),
				"lane_busy_ns": s.admissionStats.laneBusyNS.Load(),
			},
			"steps":                 stepCounts(),
			"state_patches":         s.statePatches.Load(),
			"state_patch_bytes":     s.statePatchBytes.Load(),
			"raw_applies":           s.rawApplies.Load(),
			"decoded_applies":       s.decodedApplies.Load(),
			"sparse_commits":        s.sparseCommits.Load(),
			"sparse_locked_decodes": s.sparseLockedDecodes.Load(),
			"settle_scan_rows":      s.settleScanRows.Load(),
			"compact_reserves":      s.compactReserves.Load(),
			"compact_finalizes":     s.compactFinalizes.Load(),
			"compact_settles":       s.compactSettles.Load(),
			"compact_records":       s.compactRecords.Load(),
			// The inputs of the compact admission gate (SetCompactAdmissionGate): every member of the control group declared protocol
			// 10 (the gate itself: one read of the storage engine's declarations), the state patch gate, the ledger layout, and what
			// the rounds do with them. Each member's declared protocol is kept by the storage engine (capabilityOf), not by control.
			"compact_gate": map[string]any{
				"declared_by_all_10": func() bool { g := s.compactAdmissionGate.Load(); return g != nil && (*g)() }(),
				"state_patch_gate":   s.StatePatch(),
				"ledger_contracted":  s.layoutLedger.Load(),
				"compact_admission":  s.compactAdmission(),
			},
			// The turns the leader gave to writers that kept losing (admission_turn.go): granted, refused during the rest, the time
			// they held the other commands (total and longest), and the commands answered stale because of one. The duty bound
			// is held_ns <= 1/5 of the run.
			"turns": func() map[string]any {
				t := s.turn.stats(time.Now())
				return map[string]any{"granted": t.Granted, "refused_in_rest": t.Refused, "held_ns": int64(t.Held), "max_hold_ns": int64(t.MaxHold), "stale_answers": t.Stale}
			}(),
			// The attempts the writers that retry lost proposals needed (attemptBounds: upper bound of each bucket, the last the rest).
			"retry_attempts": map[string]any{"bounds": attemptBounds[:], "counts": s.turn.attemptCounts()},
			// The decodes of the control state (DecodeStats).
			"state_decodes":        s.DecodeStats().Whole,
			"state_member_decodes": s.DecodeStats().Members,
			"state_blob_decodes":   s.DecodeStats().Blobs,
			// Where the rule books and the rule outbox live (D108): "blob" until the marker command is applied, "ledger" after it, with
			// the revision of that command (the one-way point of the upgrade).
			"rule_layout":       func() string { l, _ := s.RuleLayout(); return l }(),
			"rule_marker_index": func() uint64 { _, at := s.RuleLayout(); return at }(),
		}
	})
}

// failureCounts is the failures of the steps of the admission transitions (noteFailure) by site and cause.
func failureCounts() map[string]any {
	out := map[string]any{}
	failures.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}
