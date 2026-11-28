// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

// Package diagstat is the counter registry of a diagnostic build (-tags soundpost_diag). Each component
// registers a function that reports its counters; the diagnostic endpoint of cmd/soundpost serves them
// together, so that a live investigation can read per-window counters next to the Go profiles. The shipped
// binaries are built without the tag: Register does nothing there and no counter is read.
package diagstat

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// Source reports the counters of one component at the moment it is called.
type Source func() map[string]any

var sources sync.Map // name -> Source

// Register adds (or replaces) the counters of the component name.
func Register(name string, s Source) { sources.Store(name, s) }

// Snapshot is every registered component's counters, by component name.
func Snapshot() map[string]any {
	out := map[string]any{}
	sources.Range(func(k, v any) bool {
		out[k.(string)] = v.(Source)()
		return true
	})
	return out
}

// Bolt is the cumulative statistics of a bbolt file: the page nodes its write transactions wrote, split,
// spilled and rebalanced, and the state of its freelist.
func Bolt(db *bolt.DB) map[string]any {
	s := db.Stats()
	t := &s.TxStats
	return map[string]any{
		"tx_n": s.TxN, "open_tx_n": s.OpenTxN, "free_page_n": s.FreePageN, "pending_page_n": s.PendingPageN, "freelist_inuse": s.FreelistInuse,
		"page_count": t.GetPageCount(), "page_alloc": t.GetPageAlloc(), "cursor_count": t.GetCursorCount(), "node_count": t.GetNodeCount(),
		"node_deref": t.GetNodeDeref(), "rebalance": t.GetRebalance(), "rebalance_ns": t.GetRebalanceTime().Nanoseconds(),
		"split": t.GetSplit(), "spill": t.GetSpill(), "spill_ns": t.GetSpillTime().Nanoseconds(),
		"write": t.GetWrite(), "write_ns": t.GetWriteTime().Nanoseconds(),
	}
}

// FileSize is the size of the file at path, -1 when it cannot be read.
func FileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// DirSize is the bytes of the regular files under dir, -1 when it cannot be read.
func DirSize(dir string) int64 {
	var n int64
	if err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a file removed while walking
		}
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	}); err != nil {
		return -1
	}
	return n
}

// Group is the cadence, journal and pipeline-phase counters of one replica group.
func Group(g *replica.Group) map[string]any {
	first, last := g.JournalRange()
	p := g.Phases()
	waitMax, lockMax, lock2Max, compactMax := g.PhaseMaxima()
	return map[string]any{
		"cuts": g.CadenceCuts(), "longest_cut_ns": g.CadenceLongestCut().Nanoseconds(), "applied_data_bytes": g.AppliedDataBytes(),
		"journal_first": first, "journal_last": last,
		"persist_n": p.PersistN, "persist_ns": p.PersistNS, "apply_n": p.ApplyN, "apply_ns": p.ApplyNS,
		"propose_n": p.ProposeN, "propose_wait_ns": p.ProposeWaitNS,
		"cut_lock_ns": p.CutLockNS, "cut_lock2_ns": p.CutLock2NS, "cut_envelope_ns": p.CutEnvelopeNS, "cut_store_ns": p.CutStoreNS,
		"cut_drop_ns": p.CutDropNS, "cut_compact_ns": p.CutCompactNS, "compact_verify_ns": p.CompactVerifyNS, "compact_lock_ns": p.CompactLockNS,
		"cut_envelope_bytes": p.CutEnvelopeBytes, "cut_completed": p.CutCompleted, "cut_retry_bytes": p.CutRetryBytes,
		"max_propose_wait_ns": waitMax, "max_cut_lock_ns": lockMax, "max_cut_lock2_ns": lock2Max, "max_compact_lock_ns": compactMax,
		"tick_lag_max_ns": g.TickLagMax().Nanoseconds(), "cycle_max_ns": g.CycleMax().Nanoseconds(), "term": g.Status().Term,
	}
}
