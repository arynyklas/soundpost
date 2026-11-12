// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// withdrawFixture is canaryVoters(6) that keeps what is needed to append more batches outside
// the deleted range (ObservedAt >= 2000) so a lagging voter can be pushed past a snapshot.
type withdrawFixture struct {
	*maintenanceFixture
	store      *control.Store
	service    *auth.Service
	credential auth.SourceCredential
}

func newWithdrawFixture(t *testing.T) *withdrawFixture {
	t.Helper()
	store, service, credential, descriptor := fixture(t)
	f := &maintenanceFixture{t: t, store: store, service: service, descriptor: descriptor, acks: &ackLog{}}
	f.v = openVotersWith(t, service, acceptBarriers{store})
	f.v.lead(t, func(int) uint64 { return 1 })
	var batches []model.NormalizedBatch
	for i := range 6 {
		scope, b := canaryBatch(t, store, service, credential, descriptor, i)
		f.scope = scope
		batches = append(batches, b)
	}
	f.ack(batches)
	f.v.converge(t, f.acks.perSlot())
	return &withdrawFixture{maintenanceFixture: f, store: store, service: service, credential: credential}
}

// deletedHits counts the canary in node's apply.db file and live keys. The kept batches the
// fixture appends later carry no canary, so any hit is the deleted data.
func (f *withdrawFixture) deletedHits(node uint64) int {
	return applyFileHits(f.t, f.v.engines[node], votersCanary) + len(rawHits(f.t, f.v.engines[node], votersCanary))
}

// lagAndInstall cuts node 3 off, moves the others past it with kept batches and compacts them,
// then reconnects it so it is repaired by a snapshot installed from a node that has not erased yet.
func (f *withdrawFixture) lagAndInstall() {
	f.t.Helper()
	f.v.lead(f.t, func(int) uint64 { return 1 })
	f.v.mesh.partition(3, true)
	var more []model.NormalizedBatch
	for i := 2100; i < 2130; i++ {
		_, b := distinctBatch(f.t, f.store, f.service, f.credential, f.descriptor, i)
		more = append(more, b)
	}
	f.ack(more)
	for _, n := range []uint64{1, 2} {
		if err := f.v.maintain(n); err != nil {
			f.t.Fatal(err)
		}
	}
	f.v.mesh.partition(3, false)
	f.v.converge(f.t, f.acks.perSlot())
}

// An acknowledgement states a fact about the voter's own stores, so it follows the fact: a voter
// that acknowledged and then installed a snapshot cut before the erasure holds the erased rows
// again, its marker goes with the install, its acknowledgement is withdrawn and every other
// voter's receipt names the data store again until it erased and acknowledged anew. The install
// is a real leader-sent one (the group's own snapshot path), not a replay by hand.
func TestAcknowledgementIsWithdrawnWhenTheVoterInstallsAPreErasureSnapshot(t *testing.T) {
	f := newWithdrawFixture(t)
	pred := f.fencedPredicate()
	f.voterErase(3, pred)
	f.ackErasure(3)
	if !f.hasAck(3, pred.Operation) {
		t.Fatal("fixture invalid: node 3 did not acknowledge")
	}
	f.lagAndInstall()
	e3 := f.v.engines[3]
	if len(e3.ResidualStores()) == 0 {
		t.Fatal("fixture invalid: the installed pre-erasure snapshot left node 3 clean")
	}
	t.Logf("after the install node 3 holds %d canary copies; residual stores %v", f.deletedHits(3), e3.ResidualStores())
	if e3.ErasedLocally(pred.Operation) {
		t.Fatal("node 3 installed the erased rows again and still says it erased the operation")
	}
	f.ackErasure(3)
	if f.hasAck(3, pred.Operation) || e3.ErasedLocally(pred.Operation) {
		t.Fatal("node 3 kept its acknowledgement or marker while its own stores are dirty again")
	}
	f.voterErase(1, pred)
	f.voterErase(2, pred)
	f.ackErasure(1)
	f.ackErasure(2)
	for _, node := range []uint64{1, 2, 3} {
		f.waitResidual(node, pred.Operation, true)
	}
	f.voterErase(3, pred)
	f.ackErasure(3)
	for _, node := range []uint64{1, 2, 3} {
		f.waitResidual(node, pred.Operation, false)
	}
	if n := f.deletedHits(3); n != 0 {
		t.Fatalf("node 3 holds %d copies of the deleted series after re-erasing", n)
	}
}

// A lost marker (or any dirt) with a standing acknowledgement withdraws it, the marker-less case
// without needing the dirt: the voter owes the erasure again and says so.
func TestAcknowledgementIsWithdrawnWhenTheLocalMarkerIsGone(t *testing.T) {
	f := newWithdrawFixture(t)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	e3 := f.v.engines[3]
	if err := e3.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_data")).Delete(erasedKey(pred.Operation))
	}); err != nil {
		t.Fatal(err)
	}
	f.ackErasure(3)
	f.waitResidual(1, pred.Operation, true)
	f.waitResidual(2, pred.Operation, true)
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
}

// Dirty stores alone (a retry table or scrub owed) withdraw too.
func TestAcknowledgementIsWithdrawnWhenTheStoresTurnDirty(t *testing.T) {
	f := newWithdrawFixture(t)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	e3 := f.v.engines[3]
	if err := e3.db.Update(e3.markScrubPendingTx); err != nil {
		t.Fatal(err)
	}
	f.ackErasure(3)
	f.waitResidual(1, pred.Operation, true)
	if e3.ErasedLocally(pred.Operation) {
		t.Fatal("marker kept while dirty")
	}
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
}

// Only members count, and only for themselves: an acknowledgement that names a node that is not a
// member (proposed by a member), and a withdrawal naming one, are refused at the proposal seam and
// change nothing for the members' receipts.
func TestNonMemberAcknowledgementAndWithdrawalAreRefusedAndHaveNoEffect(t *testing.T) {
	f := newWithdrawFixture(t)
	pred := f.fencedPredicate()
	f.voterErase(1, pred)
	f.voterErase(2, pred)
	f.ackErasure(1)
	f.ackErasure(2)
	e1 := f.v.engines[1]
	ctx := context.Background()
	f.v.lead(t, func(int) uint64 { return 1 })
	ack := e1.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: 99, Identity: "intruder", Operations: []model.ID{pred.Operation}, Cursor: cursor}}
	})
	if ack == nil {
		t.Fatal("an acknowledgement naming a node the proposer is not was accepted")
	}
	f.waitResidual(1, pred.Operation, true) // node 3 is still missing; 99 does not stand in for it
	unack := e1.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_unack", EraseUnack: &eraseUnack{Node: 99, Identity: "intruder", Epoch: 1, Cursor: cursor}}
	})
	if unack == nil {
		t.Fatal("a withdrawal naming a node the proposer is not was accepted")
	}
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
}
