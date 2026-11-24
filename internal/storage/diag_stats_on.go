// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package storage

import (
	"path/filepath"
	"strings"

	"github.com/arynyklas/soundpost/internal/diagstat"
)

// registerDiag reports the counters of the data engine to a diagnostic build's endpoint (diagstat): the
// page nodes apply.db wrote, how long its one writer was held, and the cadence cuts, journal depth and
// pipeline phases of the 64 data groups (summed; the longest waits and holds as maxima; the cuts also by
// slot). It reads atomics and group counters only; it never takes e.mu, which a stalled engine would hold.
func (e *Engine) registerDiag(r *replicatedEngine) {
	diagstat.Register("storage", func() map[string]any {
		cuts := make([]uint64, 64)
		journal := make([]uint64, 64)
		sum := map[string]uint64{}
		maxima := map[string]uint64{}
		for slot, g := range r.groups {
			if g == nil {
				continue
			}
			s := diagstat.Group(g)
			cuts[slot], _ = s["cuts"].(uint64)
			first, _ := s["journal_first"].(uint64)
			last, _ := s["journal_last"].(uint64)
			journal[slot] = last - first
			for k, v := range s {
				n, ok := v.(uint64)
				if !ok {
					d, isDuration := v.(int64)
					if !isDuration {
						continue
					}
					n = uint64(d)
				}
				switch {
				case k == "longest_cut_ns" || k == "cut_envelope_bytes" || k == "cut_completed" || strings.HasPrefix(k, "max_"):
					maxima[k] = max(maxima[k], n)
				case k == "journal_first" || k == "journal_last":
				default:
					sum[k] += n
				}
			}
		}
		return map[string]any{
			"index_merge": map[string]any{
				"chunks": indexMergeStats.chunks.Load(), "chunk_ns": indexMergeStats.chunkNS.Load(), "max_chunk_ns": indexMergeStats.maxChunkNS.Load(),
				"merges":   [4]int64{indexMergeStats.merges[0].Load(), indexMergeStats.merges[1].Load(), indexMergeStats.merges[2].Load(), indexMergeStats.merges[3].Load()},
				"merge_ns": [4]int64{indexMergeStats.mergeNS[0].Load(), indexMergeStats.mergeNS[1].Load(), indexMergeStats.mergeNS[2].Load(), indexMergeStats.mergeNS[3].Load()},
				"in_bytes": [4]int64{indexMergeStats.inBytes[0].Load(), indexMergeStats.inBytes[1].Load(), indexMergeStats.inBytes[2].Load(), indexMergeStats.inBytes[3].Load()},
			},
			"engine_mu": engineMuReport(),
			"startup_verification": func() map[string]any {
				v := e.StartupVerification()
				return map[string]any{"full": v.Full, "reason": v.Reason, "commands": v.Commands, "index_entries": v.IndexEntries, "segments_hashed": v.SegmentsHashed}
			}(),
			"verify": map[string]any{
				"passes": verifyStats.passes.Load(), "read_ns": verifyStats.readNS.Load(), "max_read_ns": verifyStats.maxReadNS.Load(), "entries": verifyStats.entries.Load(),
				"records": verifyStats.records.Load(), "record_ns": verifyStats.recordNS.Load(), "max_record_ns": verifyStats.maxRecordNS.Load(),
				"full_passes": e.ver.fullPasses.Load(), "payload_reads": e.payload.nreads.Load(),
			},
			"bolt":                    diagstat.Bolt(e.db.DB),
			"apply_db_bytes":          diagstat.FileSize(filepath.Join(e.dir, "apply.db")),
			"grouped_rounds":          e.db.grouped.rounds.Load(),
			"grouped_calls":           e.db.grouped.calls.Load(),
			"grouped_held_ns":         e.db.grouped.heldNS.Load(),
			"groups_sum":              sum,
			"groups_max":              maxima,
			"cadence_cuts":            cuts,
			"journal_entries_by_slot": journal,
		}
	})
}
