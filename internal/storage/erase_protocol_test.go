// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

func init() {
	// The suite declares the erase protocol where a test needs it (declareProtocol); a loop that
	// declared it by itself would switch protocols in the middle of the tests that exercise the
	// previous one.
	autoDeclare = false
}

// leadSlotZero makes node the leader of the slot that carries the acknowledgements.
func (v *voters) leadSlotZero(t *testing.T, node uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for v.groups[node][0].Status().Leader != node {
		if time.Now().After(deadline) {
			t.Fatalf("slot 0 never moved to node %d", node)
		}
		leader := v.groups[node][0].Status().Leader
		if leader == 0 {
			_ = v.groups[node][0].Campaign()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = v.groups[leader][0].TransferLeadership(ctx, node)
		cancel()
	}
}

// declareProtocol has every voter declare the protocol and then its disk incarnation, each from
// the slot-0 leader's seat (the test mesh cannot forward a proposal).
func (v *voters) declareProtocol(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for round := range 2 {
		for node := uint64(1); node <= 3; node++ {
			v.leadSlotZero(t, node)
			if round == 1 {
				e := v.engines[node]
				if !eventually(30*time.Second, e.protocolReady) {
					t.Fatalf("node %d never saw every member declare the protocol", node)
				}
			}
			if err := v.engines[node].declareErasure(ctx); err != nil {
				t.Fatalf("node %d declare (round %d): %v", node, round, err)
			}
		}
	}
	for node := uint64(1); node <= 3; node++ {
		e := v.engines[node]
		id, identity, _ := e.selfMember()
		if !eventually(30*time.Second, func() bool {
			var current string
			_ = e.db.View(func(tx *bolt.Tx) error {
				current = string(tx.Bucket([]byte("replica_data")).Get(eraseIncKey(id, identity)))
				return nil
			})
			return current == e.incarnation
		}) {
			t.Fatalf("node %d: its incarnation never reached its own replicated state", node)
		}
	}
}

// replicatedNotice is the notice counter node's replicated state holds for member.
func replicatedNotice(t *testing.T, e *Engine, member uint64) uint64 {
	t.Helper()
	var n uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		n = getUint(tx.Bucket([]byte("replica_data")), eraseNoticeKey(member, "node-"+string(rune('0'+member))))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// The window the previous change documented: between a snapshot install on voter X and the commit
// of X's own withdrawal, a receipt answered on ANOTHER voter read clean, because X's earlier
// acknowledgement still stood there. The sender now orders a notice naming X before the snapshot
// leaves, so the receipt is dirty on every voter from the notice on. Here the snapshot the leader
// cut BEFORE any voter erased is still in transit (held in the mesh) while voters 1 and 2 erase and
// acknowledge, so the only thing standing between the receipt and a false clean is X's voided
// acknowledgement.
func TestAReceiptReadOnAnotherVoterIsDirtyFromTheNoticeOfASnapshotToAnAcknowledgedVoter(t *testing.T) {
	f := newWithdrawFixture(t)
	f.v.declareProtocol(t)
	pred := f.fencedPredicate()
	f.voterErase(3, pred)
	f.ackErasure(3)
	if !f.hasAck(3, pred.Operation) {
		t.Fatal("fixture invalid: node 3 did not acknowledge")
	}
	release := f.v.mesh.holdSnapshots(3)
	defer release()

	// Node 3 falls behind and the leaders cut a snapshot that predates any erasure.
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
			t.Fatal(err)
		}
	}
	f.v.mesh.partition(3, false)
	// The leaders announce the snapshot to node 3 (and hold it in transit).
	if !eventually(60*time.Second, func() bool {
		return replicatedNotice(t, f.v.engines[2], 3) > 0 && replicatedNotice(t, f.v.engines[1], 3) > 0
	}) {
		t.Fatal("no notice naming node 3 was ever committed before the snapshot was sent")
	}
	if f.v.engines[3].Incarnation() == "" {
		t.Fatal("no incarnation")
	}
	// Voters 1 and 2 erase and acknowledge while node 3 has not installed anything yet.
	f.voterErase(1, pred)
	f.voterErase(2, pred)
	f.ackErasure(1)
	f.ackErasure(2)
	if f.hasAck(3, pred.Operation) {
		t.Fatal("node 3's acknowledgement still stands after a notice named it")
	}
	for _, node := range []uint64{1, 2} {
		if !eventually(30*time.Second, func() bool { return len(f.v.engines[node].ErasureResidual(pred.Operation)) > 0 }) {
			t.Fatalf("FALSE CLEAN: node %d answers clean while a pre-erasure snapshot is on its way to node 3 and node 3's acknowledgement predates the notice", node)
		}
		// And it stays dirty: nothing makes it clean before node 3 erased after its install.
		time.Sleep(200 * time.Millisecond)
		if len(f.v.engines[node].ErasureResidual(pred.Operation)) == 0 {
			t.Fatalf("FALSE CLEAN: node %d turned clean while node 3 had not installed or acknowledged again", node)
		}
	}
	// Node 3 does not re-acknowledge while the announced snapshot is still expected.
	// (Node 3 lags in the groups it needs to lead, so the call is made where it stands: held, it
	// proposes nothing.)
	if err := f.v.engines[3].AckErasure(context.Background()); err != nil {
		t.Fatalf("node 3 ack: %v", err)
	}
	if f.hasAck(3, pred.Operation) {
		t.Fatal("node 3 acknowledged while a notice naming it was unsettled")
	}

	release()
	// The snapshot arrives; node 3 erases again from what it installed and acknowledges anew.
	if !eventually(120*time.Second, func() bool {
		for node := uint64(1); node <= 3; node++ {
			for slot := range 64 {
				st := f.v.groups[node][slot].Status()
				if st.Applied < f.v.groups[1][slot].Status().Commit {
					return false
				}
			}
		}
		return true
	}) {
		t.Fatal("node 3 never caught up after the snapshot was released")
	}
	f.voterErase(3, pred)
	f.ackErasure(3)
	for _, node := range []uint64{1, 2, 3} {
		f.waitResidual(node, pred.Operation, false)
	}
	if n := f.deletedHits(3); n != 0 {
		t.Fatalf("node 3 holds %d copies of the deleted series after erasing again", n)
	}
}

// A voter that gave up waiting for the snapshot a notice announced (grace period) refuses it if it
// arrives later, so it can never install under an acknowledgement it made after giving up; a token
// that was never stepped and is above the settled counter is admitted.
func TestASnapshotAnnouncedByAnAbandonedNoticeIsRefused(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	x.v1declare(t)
	e.erasure.grace = 30 * time.Millisecond
	node, identity, _ := e.selfMember()
	noticeAt := func(index uint64) {
		t.Helper()
		if err := e.db.Update(func(tx *bolt.Tx) error {
			return putUint(tx.Bucket([]byte("replica_data")), eraseNoticeKey(node, identity), index)
		}); err != nil {
			t.Fatal(err)
		}
	}
	token := func(n uint64) []byte { out := make([]byte, 8); binary.BigEndian.PutUint64(out, n); return out }

	noticeAt(10)
	if _, held, err := e.noticeHeld(node, identity); err != nil || !held {
		t.Fatalf("a fresh notice must hold the voter's acknowledgements: held=%v err=%v", held, err)
	}
	time.Sleep(60 * time.Millisecond)
	basis, held, err := e.noticeHeld(node, identity)
	if err != nil || held || basis != 10 {
		t.Fatalf("after the grace period the voter gives the announcement up: basis=%d held=%v err=%v", basis, held, err)
	}
	if _, err := e.admitSnapshot(token(10)); err == nil {
		t.Fatal("a snapshot announced by a notice the voter gave up was admitted")
	}
	if _, err := e.admitSnapshot(token(7)); err == nil {
		t.Fatal("a snapshot announced below the settled counter was admitted")
	}
	release, err := e.admitSnapshot(token(11))
	if err != nil {
		t.Fatalf("a snapshot announced by a later notice was refused: %v", err)
	}
	noticeAt(11)
	if _, held, _ := e.noticeHeld(node, identity); !held {
		t.Fatal("a snapshot being stepped must hold the voter's acknowledgements")
	}
	release()
	if basis, held, _ := e.noticeHeld(node, identity); held || basis != 11 {
		t.Fatalf("a stepped snapshot settles its notice: basis=%d held=%v", basis, held)
	}
	// An acknowledgement stamped since refuses the earlier tokens: an install under it would be stale.
	if _, err := e.admitSnapshot(token(11)); err == nil {
		t.Fatal("a second snapshot under an already settled notice was admitted after the voter stamped an acknowledgement")
	}
	if release, err := e.admitSnapshot(nil); err != nil || release == nil {
		t.Fatalf("an unannounced snapshot (an older sender) must be admitted: %v", err)
	}
}

// v1declare has the single voter declare the protocol and its incarnation.
func (x *eraseEnv) v1declare(t *testing.T) {
	t.Helper()
	for range 2 {
		if err := x.e.declareErasure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !x.e.protocolReady() {
		t.Fatal("the single voter did not declare the protocol")
	}
}

// The wire shapes the two previous binaries wrote: commit 4fb0a92 (no epoch, no proposer), and
// be4070f/10.35 (epoch and proposer, erase_unack). Their DTOs are copied here, as an older binary
// holds them, strictly: a field it does not know is a decode error there.
type oldAck struct {
	Node       model.Uint64 `json:"node"`
	Identity   string       `json:"identity"`
	Operations []model.ID   `json:"operations"`
	Epoch      model.Uint64 `json:"epoch,omitempty"`
	Cursor     model.Cursor `json:"cursor"`
}
type oldUnack struct {
	Node     model.Uint64 `json:"node"`
	Identity string       `json:"identity"`
	Epoch    model.Uint64 `json:"epoch"`
	Cursor   model.Cursor `json:"cursor"`
}
type oldEntry struct {
	Type       string           `json:"type"`
	EraseAck   *oldAck          `json:"erase_ack,omitempty"`
	EraseUnack *oldUnack        `json:"erase_unack,omitempty"`
	Proposer   *replicaProposer `json:"proposer,omitempty"`
}
type replicaProposer struct {
	Node     model.Uint64 `json:"node"`
	Identity string       `json:"node_identity"`
}

// A new binary reads every entry shape an older one stored: it decodes, re-encodes to the same
// bytes (the apply path compares the stored bytes with the re-encoded command), and applies with
// the meaning it had. The shapes of the new binary, in turn, are not readable by the old DTOs,
// which is why nothing new is proposed before every member declared the protocol, and the
// declaration itself is in a shape the old DTOs do read.
func TestANewBinaryReadsEveryOlderEraseEntryShape(t *testing.T) {
	op := model.NewID()
	cursor := model.Cursor{Group: model.NewID(), Index: 9}
	by := &replicaProposer{Node: 1, Identity: "single"}
	old := map[string]oldEntry{
		"4fb0a92 ack (no epoch, no proposer)": {Type: "erase_ack", EraseAck: &oldAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Cursor: cursor}},
		"be4070f ack (epoch)":                 {Type: "erase_ack", EraseAck: &oldAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Epoch: 3, Cursor: cursor}},
		"be4070f ack with proposer":           {Type: "erase_ack", EraseAck: &oldAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Epoch: 3, Cursor: cursor}, Proposer: by},
		"be4070f unack with proposer":         {Type: "erase_unack", EraseUnack: &oldUnack{Node: 1, Identity: "single", Epoch: 4, Cursor: cursor}, Proposer: by},
	}
	for name, entry := range old {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeWAL(raw)
		if err != nil {
			t.Fatalf("%s: a new binary cannot read it: %v", name, err)
		}
		again, err := encodeWAL(decoded)
		if err != nil || string(again) != string(raw) {
			t.Fatalf("%s: re-encodes to other bytes:\n have %s\n want %s (%v)", name, again, raw, err)
		}
	}

	// Applied: an older acknowledgement stands exactly as it did (no notice, no declared disk), and
	// the one-byte value of the first shape never does.
	x := newCheckpointEnv(t)
	e := x.e
	applyAckEntry(t, e, walEntry{Type: "erase_ack", Proposer: proposer(1, "single"), EraseAck: &eraseAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Epoch: 3}})
	if !standsOn(t, e, op, 1, "single") {
		t.Fatal("an acknowledgement in the be4070f shape no longer stands under the new rule")
	}
	oneByte := model.NewID()
	if err := e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_data")).Put(eraseAckKey(oneByte, 1, "single"), []byte{1})
	}); err != nil {
		t.Fatal(err)
	}
	if standsOn(t, e, oneByte, 1, "single") {
		t.Fatal("a one-byte acknowledgement of the first shape stands")
	}

	// What the new binary proposes: every new shape is refused by the old DTOs (an old binary would
	// fail its apply), except the protocol declaration, which is an old-shape acknowledgement of a
	// reserved operation.
	newShapes := map[string]walEntry{
		"ack with a basis":       {Type: "erase_ack", EraseAck: &eraseAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Epoch: 1, Basis: 5, Incarnation: e.incarnation, Cursor: cursor}},
		"unack declaring a disk": {Type: "erase_unack", EraseUnack: &eraseUnack{Node: 1, Identity: "single", Epoch: 0, Incarnation: e.incarnation, Cursor: cursor}},
		"notice":                 {Type: "erase_notice", EraseNotice: &eraseNotice{Node: 1, Identity: "single", Cursor: cursor}},
	}
	for name, entry := range newShapes {
		raw, err := encodeWAL(entry)
		if err != nil {
			t.Fatal(err)
		}
		var legacy oldEntry
		if model.StrictJSON(raw, &legacy) == nil {
			t.Fatalf("%s decodes with the older DTOs: an older binary would apply it and the gate is not needed", name)
		}
		if _, err = decodeWAL(raw); err != nil {
			t.Fatalf("%s: the new binary cannot read its own entry: %v", name, err)
		}
	}
	capability, err := encodeWAL(walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: 1, Identity: "single", Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(eraseProtocol), Cursor: cursor}})
	if err != nil {
		t.Fatal(err)
	}
	var legacy oldEntry
	if err := model.StrictJSON(capability, &legacy); err != nil {
		t.Fatalf("the protocol declaration is not readable by the older DTOs: %v", err)
	}
}

// A disk replaced under the same node id and identity must not inherit the acknowledgements the
// previous disk made: an acknowledgement stands only for the incarnation its voter last declared,
// and a declaration of a new one voids every earlier acknowledgement and restarts the floor.
func TestAnAcknowledgementDoesNotOutliveTheDiskItWasMadeOn(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	op := model.NewID()
	by := proposer(1, "single")
	diskA, diskB := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ack := func(epoch uint64, inc string, basis uint64) {
		applyAckEntry(t, e, walEntry{Type: "erase_ack", Proposer: by, EraseAck: &eraseAck{Node: 1, Identity: "single", Operations: []model.ID{op}, Epoch: model.Uint64(epoch), Basis: model.Uint64(basis), Incarnation: inc}})
	}
	declare := func(epoch uint64, inc string) {
		applyAckEntry(t, e, walEntry{Type: "erase_unack", Proposer: by, EraseUnack: &eraseUnack{Node: 1, Identity: "single", Epoch: model.Uint64(epoch), Incarnation: inc}})
	}
	notice := func(index uint64) {
		if err := e.db.Update(func(tx *bolt.Tx) error {
			return applyEraseNoticeTx(tx, eraseAckSlot, index, walEntry{Type: "erase_notice", Proposer: proposer(2, "other"), EraseNotice: &eraseNotice{Node: 1, Identity: "single"}})
		}); err != nil {
			t.Fatal(err)
		}
	}

	declare(0, diskA)
	ack(0, diskA, 0)
	if !standsOn(t, e, op, 1, "single") {
		t.Fatal("an acknowledgement made on the declared disk does not stand")
	}
	// The disk is replaced: the new one declares itself (its epoch counter restarts at zero, below
	// the floor the old disk left behind).
	declare(5, diskA) // an old-disk withdrawal raises the floor
	declare(0, diskB)
	if standsOn(t, e, op, 1, "single") {
		t.Fatal("FALSE CLEAN: the replacement disk inherited the acknowledgement of the disk it replaced")
	}
	ack(0, diskA, 0) // one of the old disk still in flight
	if standsOn(t, e, op, 1, "single") {
		t.Fatal("an acknowledgement of the old disk, ordered after the declaration of the new one, stands")
	}
	ack(0, diskB, 0)
	if !standsOn(t, e, op, 1, "single") {
		t.Fatal("the replacement disk's own acknowledgement does not stand (the floor of the old disk was kept)")
	}
	// A notice voids it too; an acknowledgement measured after it (basis = the notice) stands.
	notice(40)
	if standsOn(t, e, op, 1, "single") {
		t.Fatal("an acknowledgement measured before a notice stands after it")
	}
	ack(0, diskB, 40)
	if !standsOn(t, e, op, 1, "single") {
		t.Fatal("an acknowledgement measured after the notice does not stand")
	}
	notice(30) // an older notice committed late never lowers the counter
	if !standsOn(t, e, op, 1, "single") {
		t.Fatal("a notice with a lower index changed the counter")
	}
}

// A data directory gets its random incarnation once, keeps it across opens, and a second
// directory (a replaced disk) gets another.
func TestEveryDataDirectoryHasItsOwnIncarnation(t *testing.T) {
	x := newCheckpointEnv(t)
	first := x.e.Incarnation()
	if !validIncarnation(first) {
		t.Fatalf("incarnation %q is not 32 hex digits", first)
	}
	if err := x.e.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(x.dir, x.a)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.Incarnation() != first {
		t.Fatalf("reopening the same directory changed its incarnation: %s -> %s", first, again.Incarnation())
	}
	other := newCheckpointEnv(t)
	if other.e.Incarnation() == first {
		t.Fatal("two data directories share an incarnation")
	}
}

// A voter that is cut off while the group commits covered records and the deletion's barriers
// erases (its worker sees the completed operation in the control state) before it applied any
// barrier, then catches up by LOG APPEND, not by an install: the covered records ordered before the
// barriers are applied live after its erase read the state. Its marker must not certify that erase
// (MarkErased refuses it), or a clean receipt would stand over copies this voter holds.
func TestAVoterThatErasedBeforeItAppliedTheTombstoneAndCaughtUpByLogAppendIsNotCertified(t *testing.T) {
	f := newWithdrawFixture(t)
	ctx := context.Background()
	f.v.lead(f.t, func(int) uint64 { return 1 })
	f.v.mesh.partition(3, true)
	var late []model.NormalizedBatch
	for i := 10; i < 16; i++ {
		_, b := canaryBatch(f.t, f.store, f.service, f.credential, f.descriptor, i)
		late = append(late, b)
	}
	f.ack(late)
	pred := f.deletionPredicate()
	for slot := range uint16(64) {
		if _, err := f.v.engines[1].RecordDeleteBarrier(ctx, slot, pred); err != nil {
			f.t.Fatalf("barrier slot %d: %v", slot, err)
		}
	}
	e3 := f.v.engines[3]
	epoch0, _, _ := erasureCounters(f.t, e3)
	if _, err := e3.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		f.t.Fatalf("node 3 erase: %v", err)
	}
	f.v.mesh.partition(3, false)
	f.v.converge(f.t, f.acks.perSlot())
	if epoch, _, _ := erasureCounters(f.t, e3); epoch != epoch0 {
		f.t.Fatalf("fixture invalid: node 3 caught up by an install (epoch %d, was %d)", epoch, epoch0)
	}
	if hits := len(rawHits(f.t, e3, votersCanary)); hits == 0 {
		f.t.Fatal("fixture invalid: node 3 holds no covered row after catching up by log append")
	} else {
		f.t.Logf("node 3 holds %d live canary keys after the catch-up", hits)
	}
	err := e3.MarkErased([]model.ID{pred.Operation})
	if err == nil || e3.ErasedLocally(pred.Operation) {
		f.t.Fatalf("FALSE CLEAN: node 3 certified an erase that ran before it applied the barriers while holding %d live canary keys (err=%v)", len(rawHits(f.t, e3, votersCanary)), err)
	}
	// The worker's next pass, after the barriers are applied everywhere, erases and certifies.
	for _, node := range []uint64{3, 1, 2} {
		f.voterErase(node, pred)
	}
	for _, node := range []uint64{3, 1, 2} {
		f.ackErasure(node)
	}
	for _, node := range []uint64{1, 2, 3} {
		f.waitResidual(node, pred.Operation, false)
	}
	if n := f.deletedHits(3); n != 0 {
		f.t.Fatalf("node 3 holds %d copies of the deleted series after the second erase", n)
	}
}

// Nothing in a shape an older binary cannot decode is proposed until every member of the committed
// configuration declared the protocol: until then a snapshot leaves with no notice and an
// acknowledgement is the previous shape (eight bytes); after it, the new shapes.
func TestNothingNewIsProposedUntilEveryMemberDeclaredTheProtocol(t *testing.T) {
	f := newWithdrawFixture(t)
	ctx := context.Background()
	e1 := f.v.engines[1]
	f.v.leadSlotZero(t, 1)
	if err := e1.declareErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if e1.protocolReady() {
		t.Fatal("the protocol is ready with one declaration of three")
	}
	token, err := e1.beforeSnapshotSend(ctx, 3)
	if err != nil || token != nil {
		t.Fatalf("a snapshot was announced before every member declared: token=%x err=%v", token, err)
	}
	if n := replicatedNotice(t, e1, 3); n != 0 {
		t.Fatalf("a notice was committed in the old protocol (counter %d)", n)
	}
	pred := f.fencedPredicate()
	f.voterErase(1, pred)
	f.ackErasure(1)
	ackLen := func(node uint64) int {
		var got int
		e := f.v.engines[node]
		id, identity, _ := e.selfMember()
		_ = e.db.View(func(tx *bolt.Tx) error {
			got = len(tx.Bucket([]byte("replica_data")).Get(eraseAckKey(pred.Operation, id, identity)))
			return nil
		})
		return got
	}
	if !eventually(30*time.Second, func() bool { return ackLen(1) != 0 }) {
		t.Fatal("node 1's acknowledgement never applied")
	}
	if got := ackLen(1); got != 8 {
		t.Fatalf("an acknowledgement before every member declared is %d bytes, want the previous shape (8)", got)
	}
	f.v.declareProtocol(t)
	f.voterErase(2, pred)
	f.voterErase(3, pred)
	f.ackErasure(1)
	f.ackErasure(2)
	f.ackErasure(3)
	if !eventually(30*time.Second, func() bool { return ackLen(3) != 0 && ackLen(1) == 32 }) {
		t.Fatalf("acknowledgements after the declaration are %d / %d bytes, want the new shape (32)", ackLen(1), ackLen(3))
	}
	for _, node := range []uint64{1, 2, 3} {
		f.waitResidual(node, pred.Operation, false)
	}
}
