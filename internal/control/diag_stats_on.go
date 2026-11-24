// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package control

import (
	"path/filepath"

	"github.com/arynyklas/soundpost/internal/diagstat"
	"github.com/arynyklas/soundpost/internal/replica"
)

// registerDiag reports the counters of the control store to a diagnostic build's endpoint (diagstat): the page nodes
// control.db wrote, how long the update lock was held, the admission rounds and the pipeline phases and cuts of the control
// group. directory is the control group's directory. It reads atomics and file sizes only: a count of the rows of the ledger
// tables (a full scan of 1.5 M keys under a read transaction, which a growing file's remap waits for) is not taken per poll.
func (s *Store) registerDiag(group *replica.Group, directory string) {
	diagstat.Register("control", func() map[string]any {
		return map[string]any{
			"bolt":             diagstat.Bolt(s.db.DB),
			"control_db_bytes": diagstat.FileSize(filepath.Join(s.dir, "control.db")),
			"group_dir_bytes":  diagstat.DirSize(directory),
			"group":            diagstat.Group(group),
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
			"state_patches":         s.statePatches.Load(),
			"state_patch_bytes":     s.statePatchBytes.Load(),
			"raw_applies":           s.rawApplies.Load(),
			"decoded_applies":       s.decodedApplies.Load(),
			"sparse_commits":        s.sparseCommits.Load(),
			"sparse_locked_decodes": s.sparseLockedDecodes.Load(),
			"settle_scan_rows":      s.settleScanRows.Load(),
		}
	})
}
