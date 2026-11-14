// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// canaryByteCount counts the forms of the canary in the raw bytes.
func canaryByteCount(raw []byte, canary string) int {
	n := 0
	for _, form := range canaryForms(canary) {
		n += bytes.Count(raw, form)
	}
	return n
}

// voterFileHits scans voter node's own durable files: apply.db whole (free pages included), its
// segment files, the engine WALs and the whole raft directory (journal, snapshots, pins). It is
// the raw scan a per-voter "clean" claim must survive.
func voterFileHits(t *testing.T, f *maintenanceFixture, node uint64, canary string) []string {
	t.Helper()
	e := f.v.engines[node]
	var hits []string
	has := func(raw []byte, where string) {
		if canaryByteCount(raw, canary) > 0 {
			hits = append(hits, where)
		}
	}
	if raw, err := os.ReadFile(e.db.Path()); err == nil {
		has(raw, "apply.db")
	}
	for slot := range uint16(64) {
		if raw, err := os.ReadFile(filepath.Join(f.v.dirs[node], walName(slot))); err == nil {
			has(raw, "wal/"+walName(slot))
		}
	}
	_ = filepath.WalkDir(filepath.Join(f.v.dirs[node], "raft"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if raw, rerr := os.ReadFile(p); rerr == nil {
			has(raw, strings.TrimPrefix(p, f.v.dirs[node]+string(os.PathSeparator)))
		}
		return nil
	})
	return hits
}

// eventually polls cond until it holds or the budget is spent, and reports which.
func eventually(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// After every voter erased, scrubbed, cut its journal and snapshots, marked and acknowledged, a
// raw scan of every durable file of every voter (apply.db with its free pages, segments, engine
// WALs, the whole raft directory) must be empty: a receipt that answers clean over any surviving
// copy is a false clean.
func TestCleanReceiptSurvivesFullFileScanOfEveryVoter(t *testing.T) {
	f := canaryVoters(t, 6)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	for node := uint64(1); node <= 3; node++ {
		if hits := voterFileHits(t, f, node, votersCanary); len(hits) != 0 {
			t.Errorf("node %d: receipt clean but its files hold the canary: %v", node, hits)
		}
	}
}

// A voter that was cut off marks an operation whose data it never applied (the erase finds
// nothing and the marker would stand), then catches up with the slot history. If what it replays
// is the original payload while its marker and every acknowledgement stand, the receipt is a
// false clean. The leaders' stored commands are already redacted when it catches up, so the
// replayed history carries no erased row; this pins that no live canary survives behind a clean
// receipt in that order.
func TestLaggingVoterThatMarkedBeforeItsCatchUpLeavesNoLiveCanaryBehindACleanReceipt(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	f := &maintenanceFixture{t: t, store: store, service: service, descriptor: descriptor, acks: &ackLog{}}
	f.v = openVotersWith(t, service, acceptBarriers{store})
	f.v.lead(t, func(int) uint64 { return 1 })
	f.v.mesh.partition(3, true) // voter 3 applies nothing from here on
	var batches []model.NormalizedBatch
	for i := range 3 {
		scope, b := canaryBatch(t, store, service, credential, descriptor, i)
		f.scope = scope
		batches = append(batches, b)
	}
	f.ack(batches)
	deadline := time.Now().Add(60 * time.Second)
	for {
		f.v.engines[1].mu.Lock()
		i1 := f.v.engines[1].indexes
		f.v.engines[1].mu.Unlock()
		f.v.engines[2].mu.Lock()
		i2 := f.v.engines[2].indexes
		f.v.engines[2].mu.Unlock()
		if i1 == i2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("voters 1 and 2 never converged: %v vs %v", i1, i2)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := applyFileHits(t, f.v.engines[3], votersCanary); n != 0 {
		t.Fatalf("fixture invalid: voter 3 applied the canaries while partitioned (%d)", n)
	}
	// The tombstone in every slot, through voter 1; the appends above can move slot leaders.
	f.v.lead(t, func(int) uint64 { return 1 })
	pred := f.deletionPredicate()
	for slot := range uint16(64) {
		if _, err := f.v.engines[1].RecordDeleteBarrier(context.Background(), slot, pred); err != nil {
			t.Fatalf("barrier slot %d: %v", slot, err)
		}
	}
	// Voters 1 and 2 erase, checkpoint, mark and acknowledge: their stored commands are redacted.
	for node := uint64(1); node <= 2; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	f.waitResidual(1, pred.Operation, true) // voter 3 owes: honest
	// Voter 3's vacuous mark: the local erase finds nothing and the marker is set.
	if _, err := f.v.engines[3].EraseDeleted(context.Background(), []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.v.engines[3].MarkErased([]model.ID{pred.Operation}); err != nil {
		t.Fatal(err)
	}
	f.v.mesh.partition(3, false)
	f.v.converge(t, f.acks.perSlot())
	// The replayed commands owe their redaction to the retry table and journal until the
	// maintenance pass reconciles it; AckErasure refuses to state while ResidualStores is non-empty.
	if err := f.v.maintain(3); err != nil {
		t.Fatalf("maintain after catch-up: %v", err)
	}
	// If the leaders had compacted their journals the catch-up was a snapshot install, which
	// clears the voter's marker (the vacuous one included): the worker's next pass erases again.
	// If it was an append the marker stands and only the acknowledgement gate and the senders'
	// redaction protect the receipt.
	cleared := !f.v.engines[3].ErasedLocally(pred.Operation)
	t.Logf("voter 3's marker after the catch-up: cleared=%v", cleared)
	if cleared {
		f.voterErase(3, pred)
	}
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	hits := rawHits(t, f.v.engines[3], votersCanary)
	if len(hits) > 0 {
		t.Errorf("FALSE CLEAN: the lagging voter marked before its catch-up; after replaying the erased batch its live buckets hold %d canary keys while every receipt says done", len(hits))
	}
	if n := applyFileHits(t, f.v.engines[3], votersCanary); n != 0 {
		t.Errorf("voter 3's apply.db holds %d canary copies behind a clean receipt", n)
	}
}

// slotCut is one slot's snapshot as the install seam replays it: slotMachine.Restore, the seam a
// leader-sent snapshot install replays through. installSlotCuts rebuilds a voter's slots from cuts
// the way an install on an empty replica does: the derived state and the applied cursors are
// wiped, then every slot is replayed.
type slotCut struct {
	m    *slotMachine
	raw  []byte
	phys uint64
}

// cutAllSlots cuts every slot of e as a sender would, with the commands as they are stored now.
func cutAllSlots(t *testing.T, e *Engine) []slotCut {
	t.Helper()
	cuts := make([]slotCut, 0, 64)
	for slot := range uint16(64) {
		cuts = append(cuts, cutSlot(t, e, slot))
	}
	return cuts
}

func cutSlot(t *testing.T, e *Engine, slot uint16) slotCut {
	t.Helper()
	m := &slotMachine{engine: e, slot: slot}
	raw, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var phys uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		phys = getUint(tx.Bucket([]byte("replica_data")), metaKey(slot, "physical"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return slotCut{m: m, raw: raw, phys: phys}
}

// withLaterHistory is what a sender hands over whose stored commands up to the early cut are
// the ORIGINAL payloads (its own erasure had not redacted them when it cut) and whose log runs on
// to where e's group is now: the early commands, then every command e holds beyond them. The
// installed machine then agrees with the group's applied index, as an install followed by the
// leader's append does.
func withLaterHistory(t *testing.T, e *Engine, early []slotCut) []slotCut {
	t.Helper()
	out := make([]slotCut, 0, len(early))
	for _, c := range early {
		late := cutSlot(t, e, c.m.slot)
		var before, after slotSnapshot
		if err := json.Unmarshal(c.raw, &before); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(late.raw, &after); err != nil {
			t.Fatal(err)
		}
		if len(after.Entries) < len(before.Entries) {
			t.Fatalf("slot %d: the later history is shorter than the early cut", c.m.slot)
		}
		after.Entries = append(append([]json.RawMessage(nil), before.Entries...), after.Entries[len(before.Entries):]...)
		raw, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, slotCut{m: c.m, raw: raw, phys: late.phys})
	}
	return out
}

func installSlotCuts(t *testing.T, e *Engine, cuts []slotCut) {
	t.Helper()
	if err := e.db.Update(func(tx *bolt.Tx) error {
		for _, n := range []string{"batches", "receipts", "consumed", "metrics", "jobs", "scan_pages", "scan_time", "scan_postings", "scan_commits", "scan_integrity", "tombstones", "cancelled", "fences"} {
			b := tx.Bucket([]byte(n))
			if b == nil {
				continue
			}
			var keys [][]byte
			_ = b.ForEach(func(k, _ []byte) error { keys = append(keys, bytes.Clone(k)); return nil })
			for _, k := range keys {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
		}
		if integ := tx.Bucket([]byte("scan_integrity")); integ != nil {
			for _, n := range []string{"scan_time", "scan_postings"} {
				if err := integ.Put([]byte(n), digestBytes(IndexDigest{})); err != nil {
					return err
				}
			}
		}
		if cur := tx.Bucket([]byte("cursors")); cur != nil {
			for _, c := range cuts {
				if err := cur.Delete(slotKey(c.m.slot)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range cuts {
		e.mu.Lock()
		e.indexes[c.m.slot] = 0
		e.mu.Unlock()
		if err := c.m.Restore(c.raw, c.phys); err != nil {
			t.Fatalf("install restore slot %d: %v", c.m.slot, err)
		}
	}
}

// After every voter erased, marked and acknowledged (every receipt clean), voter 3's slots are
// rebuilt from snapshots cut BEFORE the erasure. The install puts the erased rows back into voter
// 3's live buckets, so the facts that said "voter 3 is clean" stop being true with the bytes: the
// install clears voter 3's erase markers and withdraws its acknowledgements, every voter's receipt
// names the data store again, and the receipt goes clean only after voter 3 erased again and
// acknowledged anew.
func TestInstalledSnapshotPredatingTheErasureReOwesItOnEveryVoter(t *testing.T) {
	f := canaryVoters(t, 6)
	for node := uint64(1); node <= 3; node++ {
		if applyFileHits(t, f.v.engines[node], votersCanary) == 0 {
			t.Fatalf("fixture invalid: node %d has no canary", node)
		}
	}
	pred := f.fencedPredicate()
	// A sender's cut after the tombstone and before its own erasure: its stored commands still
	// carry the erased payloads.
	early := cutAllSlots(t, f.v.engines[3])
	preCanary := 0
	for _, c := range early {
		preCanary += canaryByteCount(c.raw, votersCanary)
	}
	if preCanary == 0 {
		t.Fatal("fixture invalid: the pre-erase cuts carry no canary")
	}

	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	if n := applyFileHits(t, f.v.engines[3], votersCanary); n != 0 {
		t.Fatalf("fixture invalid: voter 3 kept %d canary copies in apply.db after its erase", n)
	}

	installSlotCuts(t, f.v.engines[3], withLaterHistory(t, f.v.engines[3], early))
	e3 := f.v.engines[3]
	live := rawHits(t, e3, votersCanary)
	if len(live) == 0 {
		t.Fatal("fixture invalid: the install did not bring the canary back")
	}
	t.Logf("after the install voter 3's live buckets hold the canary in %d keys", len(live))
	if e3.ErasedLocally(pred.Operation) {
		t.Errorf("the install put the erased rows back but voter 3 still says it erased the operation")
	}
	if got := e3.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Errorf("voter 3's receipt is clean right after an install that holds the payload in %d live keys", len(live))
	}

	// The withdrawal is a replicated proposal: the test mesh cannot forward, so voter 3 leads.
	f.v.lead(t, func(int) uint64 { return 3 })
	for _, node := range []uint64{1, 2} {
		if !eventually(30*time.Second, func() bool { return len(f.v.engines[node].ErasureResidual(pred.Operation)) > 0 }) {
			t.Errorf("FALSE CLEAN: voter %d's receipt stays clean while voter 3's live buckets hold %d canary keys after the install", node, len(live))
		}
	}

	// The worker's own post-install maintenance settles what the install owes; the receipts must
	// still name the data store while the live rows are there.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := f.v.maintain(3); err != nil {
		t.Logf("maintain after install: %v", err)
	} else {
		if _, err := e3.DropSupersededSnapshots(ctx); err != nil {
			t.Logf("drop after install: %v", err)
		}
		if err := e3.CompactJournals(ctx); err != nil {
			t.Logf("compact after install: %v", err)
		}
	}
	live = rawHits(t, e3, votersCanary)
	settled := e3.ResidualStores()
	res1 := f.v.engines[1].ErasureResidual(pred.Operation)
	t.Logf("settled: voter 3 live canary keys=%d ResidualStores=%v voter 1 ErasureResidual=%v", len(live), settled, res1)
	if len(live) > 0 && len(res1) == 0 && len(settled) == 0 {
		t.Errorf("FALSE CLEAN: after the install of a pre-erase snapshot voter 3's live buckets hold the erased rows (%d keys) while its own ResidualStores is empty and voter 1's ErasureResidual is nil; the worker skips the operation (PhysicalAt set, marker true) so the copy is never re-erased", len(live))
	}

	// Voter 3's worker erases again (the marker is gone, so it selects the operation), marks and
	// acknowledges anew; only then is every receipt clean and the bytes gone.
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	if hits := rawHits(t, e3, votersCanary); len(hits) != 0 {
		t.Errorf("voter 3's live keys remain after its second erase: %v", hits)
	}
	if hits := voterFileHits(t, f, 3, votersCanary); len(hits) != 0 {
		t.Errorf("voter 3's files hold the canary behind a clean receipt after its second erase: %v", hits)
	}
}

// An erase_ack names the node that measured itself clean, and the replicated log is the only
// authority the receipt trusts, so the author of an acknowledgement is the proposer, never a name
// inside the payload. Voter 1 proposes an acknowledgement that names voter 2 for an operation
// voter 2 never erased: it is refused, voter 2's copy stays named in every receipt, and the
// receipt goes clean only when voter 2 itself acknowledges.
func TestAnEraseAckProposedByAnotherVoterIsRefused(t *testing.T) {
	f := canaryVoters(t, 6)
	pred := f.fencedPredicate()
	f.voterErase(1, pred)
	f.ackErasure(1)
	f.voterErase(3, pred)
	f.ackErasure(3)
	f.waitResidual(1, pred.Operation, true) // voter 2 owes: honest
	if n := applyFileHits(t, f.v.engines[2], votersCanary); n == 0 {
		t.Fatal("fixture invalid: voter 2 lost the canary without erasing")
	}
	e1 := f.v.engines[1]
	f.v.lead(t, func(int) uint64 { return 1 })
	e1.mu.Lock()
	next := e1.indexes[eraseAckSlot] + 1
	e1.mu.Unlock()
	ack := &eraseAck{
		Node:       model.Uint64(2),
		Identity:   "node-2",
		Operations: []model.ID{pred.Operation},
		Cursor:     model.Cursor{Group: e1.group(eraseAckSlot), Index: model.Uint64(next)},
	}
	cmd := replica.Entry{ID: model.NewID(), Kind: replica.Barrier, Payload: mustJSON(t, walEntry{Type: "erase_ack", EraseAck: ack}), ApplicationIndex: uint64(next)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.v.groups[1][eraseAckSlot].Propose(ctx, cmd); err == nil {
		t.Errorf("a proposal by voter 1 that names voter 2 was accepted")
	}
	// Whatever the proposal did, voter 2 never erased: no receipt may be clean while it holds the bytes.
	if eventually(5*time.Second, func() bool { return len(f.v.engines[1].ErasureResidual(pred.Operation)) == 0 }) {
		n2 := applyFileHits(t, f.v.engines[2], votersCanary)
		t.Errorf("FALSE CLEAN: one voter forged another's acknowledgement; voter 1's receipt is clean, voter 2's apply.db holds %d canary copies", n2)
	}
	// The honest acknowledgement by voter 2 itself still works.
	f.voterErase(2, pred)
	f.ackErasure(2)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
}
