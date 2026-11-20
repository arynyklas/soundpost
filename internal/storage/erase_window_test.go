// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The cross-voter receipt window (10.35#12): between a snapshot install that brings erased rows
// back on one voter and the commit of that voter's withdrawal, no receipt answered by another voter
// may read clean. The install is local and not in the log, so the only statement every voter can
// rely on is one committed BEFORE the install: the sender's notice (replica.SnapshotGate). Two
// shapes of acknowledgement escaped it and are closed here:
//
//   - an acknowledgement of the first protocol (no disk, no notice basis) is voided by no notice,
//     and a sender that does not know every member declared the protocol states nothing before it
//     sends; so a receipt never counts such an acknowledgement (every member must have declared
//     the protocol and every acknowledgement must carry the disk it was made on);
//   - a snapshot that arrives with no token (its sender's view said the protocol was not declared
//     yet) is refused by a voter that declared its disk, because the acknowledgements it made under
//     that declaration count on every voter and nothing was committed before the install.

// A receipt answered while the protocol is not declared by every member is never clean: the
// acknowledgements of the first protocol survive a snapshot install on their voter until its
// withdrawal commits, and nothing orders a statement before that install.
func TestAReceiptIsNotCleanOnAcknowledgementsOfAProtocolNoNoticeCanVoid(t *testing.T) {
	f := canaryVotersUndeclared(t, 6)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		for member := uint64(1); member <= 3; member++ {
			engine, id := f.v.engines[node], member
			if !eventually(30*time.Second, func() bool {
				return standsOn(t, engine, pred.Operation, id, "node-"+string(rune('0'+id)))
			}) {
				t.Fatalf("fixture invalid: node %d never applied the acknowledgement of node %d", node, member)
			}
		}
	}
	for node := uint64(1); node <= 3; node++ {
		if len(f.v.engines[node].ErasureResidual(pred.Operation)) == 0 {
			t.Fatalf("FALSE CLEAN: node %d answers a receipt with no residue on acknowledgements no notice can void (the protocol is not declared)", node)
		}
	}

	// Once every member declared the protocol and its disk, the same voters acknowledge under the
	// declaration (a notice now voids them) and the receipt reads clean.
	f.v.declareProtocol(t)
	for node := uint64(1); node <= 3; node++ {
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
}

// A gated sender whose own view says the protocol is not declared by every member (here: voters 1
// and 2 forget voter 2's declaration, as a view that lags it does) states nothing before it sends a
// snapshot, and the snapshot leaves with an empty token. Voter 3 declared its disk, so it refuses it:
// it stays behind, installs nothing and holds every acknowledgement it made, until the senders'
// view is whole again and the snapshot leaves with the notice that voids them.
func TestASnapshotWithNoNoticeNeverInstallsOnAVoterThatDeclaredItsDisk(t *testing.T) {
	tokenlessSnapshotNeverInstalls(t, false)
}

// The same view, but voter 3's disk was replaced after it acknowledged: its new incarnation is not
// declared yet, so its previous acknowledgement still stands on every voter and a receipt answered
// by voter 1 or 2 would read clean over rows an unannounced install put back. It refuses too.
func TestASnapshotWithNoNoticeNeverInstallsOnAVoterWhoseReplacedDiskIsNotDeclared(t *testing.T) {
	tokenlessSnapshotNeverInstalls(t, true)
}

func tokenlessSnapshotNeverInstalls(t *testing.T, replaced bool) {
	f := newWithdrawFixture(t)
	pred := f.fencedPredicate()
	f.voterErase(3, pred)
	f.ackErasure(3)
	forgotten := map[uint64][]byte{}
	f.v.lead(t, func(int) uint64 { return 1 })
	f.v.mesh.partition(3, true)
	if replaced {
		replaceDisk(f.v.engines[3])
	}
	var more []model.NormalizedBatch
	for i := 2100; i < 2130; i++ {
		_, b := distinctBatch(f.t, f.store, f.service, f.credential, f.descriptor, i)
		more = append(more, b)
	}
	f.ack(more)
	for _, n := range []uint64{1, 2} {
		if err := f.v.maintain(n); err != nil {
			t.Fatal(err)
		}
	}
	key := eraseAckKey(capabilityOp, 2, "node-2")
	for _, n := range []uint64{1, 2} {
		if err := f.v.engines[n].db.Update(func(tx *bolt.Tx) error {
			meta := tx.Bucket([]byte("replica_data"))
			forgotten[n] = append([]byte(nil), meta.Get(key)...)
			return meta.Delete(key)
		}); err != nil {
			t.Fatal(err)
		}
		if f.v.engines[n].protocolReady() {
			t.Fatalf("fixture invalid: voter %d still believes every member declared", n)
		}
	}
	epoch0, _, _ := erasureCounters(t, f.v.engines[3])
	behind := func() bool {
		indexes := func(n uint64) [64]uint64 {
			e := f.v.engines[n]
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.indexes
		}
		return indexes(3) != indexes(1)
	}
	f.v.mesh.partition(3, false)
	time.Sleep(3 * time.Second)
	if !behind() {
		t.Fatal("voter 3 caught up from a snapshot that no notice announced")
	}
	if epoch, _, _ := erasureCounters(t, f.v.engines[3]); epoch != epoch0 {
		t.Fatalf("voter 3 installed a snapshot that no notice announced (epoch %d, was %d)", epoch, epoch0)
	}
	if !f.hasAck(3, pred.Operation) {
		t.Fatal("voter 3 lost its acknowledgement without any statement ordered before an install")
	}

	// The senders' view is whole again: the snapshot leaves with a notice and is installed.
	for _, n := range []uint64{1, 2} {
		if err := f.v.engines[n].db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("replica_data")).Put(key, forgotten[n])
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.v.converge(t, f.acks.perSlot())
	if f.hasAck(3, pred.Operation) {
		t.Fatal("voter 3 installed the snapshot and its acknowledgement still stands")
	}
}

// A voter that declared its disk refuses a snapshot that carries no token; one that did not (a
// fresh or replaced disk holds no acknowledgement) admits it, and a token is judged as before.
func TestATokenlessSnapshotIsRefusedByAVoterThatDeclaredItsDisk(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	if release, err := e.admitSnapshot(nil); err != nil || release == nil {
		t.Fatalf("a voter that never declared its disk holds no acknowledgement a snapshot could outlive: %v", err)
	} else {
		release()
	}
	x.v1declare(t)
	if e.Incarnation() == "" {
		t.Fatal("fixture invalid: the engine has no incarnation")
	}
	if !e.diskDeclared() {
		t.Fatal("the voter declared its disk and the engine does not know it")
	}
	if _, err := e.admitSnapshot(nil); err == nil {
		t.Fatal("an unannounced snapshot was admitted by a voter whose acknowledgements stand on every other voter")
	}
	if _, err := e.admitSnapshot([]byte{1, 2, 3}); err == nil {
		t.Fatal("a token of the wrong length was admitted")
	}
	token := make([]byte, 8)
	token[7] = 9
	release, err := e.admitSnapshot(token)
	if err != nil {
		t.Fatalf("a snapshot announced by a notice was refused: %v", err)
	}
	release()
}

// The declared incarnation another member holds is not this voter's disk.
func TestADiskDeclaredByAnotherMemberIsNotThisDisk(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	if err := e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_data")).Put(eraseIncKey(7, "node-7"), []byte("0123456789abcdef0123456789abcdef"))
	}); err != nil {
		t.Fatal(err)
	}
	if e.diskDeclared() {
		t.Fatal("another member's declared disk counted as this voter's")
	}
}

// replaceDisk gives the engine a new data directory incarnation, as a disk replaced under the same
// node id and identity has: the replicated state still lists the old one.
func replaceDisk(e *Engine) {
	e.incMu.Lock()
	e.incarnation = "ffffffffffffffffffffffffffffffff"
	e.incMu.Unlock()
}

// A voter whose disk was replaced holds the acknowledgements of its predecessor until it declares
// the new one, so it refuses a tokenless snapshot too; a member the configuration does not name
// (a fresh learner) holds none and admits it.
func TestATokenlessSnapshotIsRefusedByAVoterWhoseReplacedDiskIsNotDeclared(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	x.v1declare(t)
	replaceDisk(e)
	if !e.diskDeclared() {
		t.Fatal("a replaced disk whose predecessor declared was treated as holding no acknowledgement")
	}
	if _, err := e.admitSnapshot(nil); err == nil {
		t.Fatal("an unannounced snapshot was admitted by a voter whose previous acknowledgement still stands")
	}
	e.self.Store(nil)
	if e.diskDeclared() {
		t.Fatal("a member the configuration does not name was held to a declaration it never made")
	}
	release, err := e.admitSnapshot(nil)
	if err != nil {
		t.Fatalf("a fresh learner could not be repaired: %v", err)
	}
	release()
}
