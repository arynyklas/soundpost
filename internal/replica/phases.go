// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"sync/atomic"
	"time"
)

// phaseCounters are the cumulative times a group spent in the stages of its pipeline, read by a diagnostic
// build (internal/diagstat) and by tests: how long the journal persist, the machine's apply and each step of
// a cadence cut took, how long proposals waited for the group lock and how long the cut held it. They are
// atomics beside the work, never a lock.
type phaseCounters struct {
	persistN, persistNS atomic.Uint64 // Ready batches persisted to the journal, and the time that took
	applyN, applyNS     atomic.Uint64 // commands the machine applied, and the time Apply took
	proposeN            atomic.Uint64 // proposals that took the group lock
	proposeWaitNS       atomic.Uint64 // the time they waited for it
	cutLockNS           atomic.Uint64 // time a cut held the group lock to build the snapshot's state and retry table
	cutLock2NS          atomic.Uint64 // time a cut held it to make the in-memory Raft snapshot
	cutEnvelopeNS       atomic.Uint64 // time a cut spent marshalling the envelope, the ledger and the configuration
	cutStoreNS          atomic.Uint64 // time a cut spent creating (writing and verifying) the snapshot directory
	cutDropNS           atomic.Uint64 // time a cut spent dropping the superseded snapshots
	cutCompactNS        atomic.Uint64 // time a cut spent compacting the journal onto the snapshot (verify and rewrite)
	compactVerifyNS     atomic.Uint64 // of it, the time spent verifying the snapshot (no lock held)
	compactLockNS       atomic.Uint64 // of it, the time the group lock was held to rewrite the journal
	cutEnvelopeBytes    atomic.Uint64 // the envelope of the newest cut
	cutCompleted        atomic.Uint64 // the retry-table entries the group held at the newest cut
	cutRetryBytes       atomic.Uint64 // the retry-part bytes the newest cut serialized (0 when the table is inline in the envelope)
	// The longest single waits and holds since they were last read (PhaseMaxima).
	proposeWaitMax, cutLockMax, cutLock2Max, compactLockMax atomic.Uint64
	// ReadIndex (reads.go): calls that were answered and the time they waited, the longest wait, the rounds put to the
	// leader, and the rounds that were given up (term changed, no answer in time).
	readN, readNS, readMaxNS, readRounds, readGaveUp atomic.Uint64
	// tickLagMax is the longest a tick of the group's ticker waited, since it was last read, between the moment it was due
	// and the moment Raft's clock was advanced (TickLagMax). It is raised under the group lock.
	tickLagMax atomic.Int64
	// cycleMax is the longest a cycle of the ready stage took from its Ready to its Advance since it was last read (CycleMax).
	cycleMax atomic.Int64
}

// Phases is a copy of a group's phase counters.
type Phases struct {
	PersistN, PersistNS, ApplyN, ApplyNS, ProposeN, ProposeWaitNS                                             uint64
	CutLockNS, CutLock2NS, CutEnvelopeNS, CutStoreNS, CutDropNS, CutCompactNS, CompactVerifyNS, CompactLockNS uint64
	CutEnvelopeBytes, CutCompleted, CutRetryBytes                                                             uint64
}

// Phases is how long the group has spent in each stage of its pipeline since it was opened.
func (g *Group) Phases() Phases {
	p := &g.phases
	return Phases{
		PersistN: p.persistN.Load(), PersistNS: p.persistNS.Load(), ApplyN: p.applyN.Load(), ApplyNS: p.applyNS.Load(),
		ProposeN: p.proposeN.Load(), ProposeWaitNS: p.proposeWaitNS.Load(),
		CutLockNS: p.cutLockNS.Load(), CutLock2NS: p.cutLock2NS.Load(), CutEnvelopeNS: p.cutEnvelopeNS.Load(),
		CutStoreNS: p.cutStoreNS.Load(), CutDropNS: p.cutDropNS.Load(), CutCompactNS: p.cutCompactNS.Load(),
		CompactVerifyNS: p.compactVerifyNS.Load(), CompactLockNS: p.compactLockNS.Load(),
		CutEnvelopeBytes: p.cutEnvelopeBytes.Load(), CutCompleted: p.cutCompleted.Load(), CutRetryBytes: p.cutRetryBytes.Load(),
	}
}

// PhaseMaxima is the longest single proposal wait for the group lock and the longest single holds of it by a
// cut and by a compaction (nanoseconds) since the previous call, which it resets.
func (g *Group) PhaseMaxima() (proposeWait, cutLock, cutLock2, compactLock uint64) {
	p := &g.phases
	return p.proposeWaitMax.Swap(0), p.cutLockMax.Swap(0), p.cutLock2Max.Swap(0), p.compactLockMax.Swap(0)
}

// since adds the time since began to c.
func since(c *atomic.Uint64, began time.Time) { c.Add(uint64(time.Since(began))) }

// sinceMax is since that also raises max to the elapsed time when it is the longest so far.
func sinceMax(c, max *atomic.Uint64, began time.Time) {
	d := uint64(time.Since(began))
	c.Add(d)
	for old := max.Load(); d > old && !max.CompareAndSwap(old, d); old = max.Load() {
	}
}

// TickLagMax is the longest a tick of the group's ticker was late (due, to Raft's clock advanced) since the previous
// call, which resets it. A group whose tick waits for its lock or its disk is one whose followers campaign against a
// healthy leader: it must stay far below the election timeout (electionTicks ticks).
func (g *Group) TickLagMax() time.Duration { return time.Duration(g.phases.tickLagMax.Swap(0)) }

// CycleMax is the longest one cycle of the group's ready stage (persist, send, apply, Advance of one Ready) took since the
// previous call, which resets it. The messages Tick and Step produce leave with the next Ready, so this is the longest a
// heartbeat can wait for the stage.
func (g *Group) CycleMax() time.Duration { return time.Duration(g.phases.cycleMax.Swap(0)) }
