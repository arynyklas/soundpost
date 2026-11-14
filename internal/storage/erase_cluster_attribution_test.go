// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// legacyEraseAck and legacyEraseEntry are the wire shape commit 1fd9bc1 wrote: no epoch, no
// proposer, no unack arm. A stored command in that form must still decode and re-encode to the
// same bytes (the apply path compares the stored bytes with the re-encoded command).
type legacyEraseAck struct {
	Node       model.Uint64 `json:"node"`
	Identity   string       `json:"identity"`
	Operations []model.ID   `json:"operations"`
	Cursor     model.Cursor `json:"cursor"`
}
type legacyEraseEntry struct {
	Type     string          `json:"type"`
	EraseAck *legacyEraseAck `json:"erase_ack,omitempty"`
}

func proposer(node uint64, identity string) *replica.Proposer {
	return &replica.Proposer{Node: node, Identity: identity}
}

// applyAckEntry applies an erase_ack or erase_unack entry through the machine's own apply
// function, as the committed log does.
func applyAckEntry(t *testing.T, e *Engine, entry walEntry) {
	t.Helper()
	if err := e.db.Update(func(tx *bolt.Tx) error {
		switch entry.Type {
		case "erase_ack":
			return applyEraseAckTx(tx, eraseAckSlot, entry)
		case "erase_unack":
			return applyEraseUnackTx(tx, eraseAckSlot, entry)
		}
		t.Fatalf("not an acknowledgement entry: %s", entry.Type)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func ackEntry(node uint64, identity string, epoch uint64, by *replica.Proposer, ops ...model.ID) walEntry {
	return walEntry{Type: "erase_ack", Proposer: by, EraseAck: &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: ops, Epoch: model.Uint64(epoch)}}
}

func unackEntry(node uint64, identity string, epoch uint64, by *replica.Proposer) walEntry {
	return walEntry{Type: "erase_unack", Proposer: by, EraseUnack: &eraseUnack{Node: model.Uint64(node), Identity: identity, Epoch: model.Uint64(epoch)}}
}

func standsOn(t *testing.T, e *Engine, op model.ID, node uint64, identity string) bool {
	t.Helper()
	var ok bool
	if err := e.db.View(func(tx *bolt.Tx) error {
		ok = ackStands(tx.Bucket([]byte("replica_data")), op, node, identity)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ok
}

// erasureCounters reads the install epoch, the epoch this voter still owes a withdrawal for, and
// the replicated floor of this voter's acknowledgements.
func erasureCounters(t *testing.T, e *Engine) (epoch, owed, floor uint64) {
	t.Helper()
	node, identity, ok := e.selfMember()
	if !ok {
		t.Fatal("no self member")
	}
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		epoch, owed, floor = getUint(meta, installEpochKey()), getUint(meta, unackOwedKey()), getUint(meta, eraseGenKey(node, identity))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// The routing check of an erase_ack or erase_unack binds the payload to the slot, the cursor and
// the PROPOSER: the leader records who proposed the command (replica.Entry.Proposer), and the
// statement counts only when it names that member. Everything the proposal seam must refuse is
// listed here next to what it accepts.
func TestEraseAckRoutingShapeIsClosed(t *testing.T) {
	x := newEraseEnv(t)
	e := x.e
	owner := e.group(eraseAckSlot)
	m0 := &slotMachine{engine: e, slot: eraseAckSlot}
	m1 := &slotMachine{engine: e, slot: 1}
	ops := []model.ID{model.NewID()}
	cursor := model.Cursor{Group: owner, Index: 9}
	self := proposer(1, "node-1")
	ack := func(mod func(*eraseAck)) walEntry {
		a := &eraseAck{Node: 1, Identity: "node-1", Operations: ops, Cursor: cursor}
		if mod != nil {
			mod(a)
		}
		return walEntry{Type: "erase_ack", EraseAck: a}
	}
	unack := func(mod func(*eraseUnack)) walEntry {
		u := &eraseUnack{Node: 1, Identity: "node-1", Epoch: 3, Cursor: cursor}
		if mod != nil {
			mod(u)
		}
		return walEntry{Type: "erase_unack", EraseUnack: u}
	}
	for _, tc := range []struct {
		name  string
		m     *slotMachine
		entry walEntry
		by    *replica.Proposer
		want  bool
	}{
		{"honest ack", m0, ack(nil), self, true},
		{"honest ack with an epoch", m0, ack(func(a *eraseAck) { a.Epoch = 4 }), self, true},
		{"ack naming another node", m0, ack(func(a *eraseAck) { a.Node, a.Identity = 2, "node-2" }), self, false},
		{"ack naming another node's identity under the proposer's id", m0, ack(func(a *eraseAck) { a.Identity = "node-2" }), self, false},
		{"ack naming the proposer's identity under another id", m0, ack(func(a *eraseAck) { a.Node = 2 }), self, false},
		{"ack with no recorded proposer (written before attribution)", m0, ack(nil), nil, false},
		{"ack whose payload carries its own proposer", m0, func() walEntry { w := ack(nil); w.Proposer = self; return w }(), self, false},
		{"the same ack in a data slot", m1, ack(func(a *eraseAck) { a.Cursor = model.Cursor{Group: e.group(1), Index: 9} }), self, false},
		{"stale cursor index", m0, ack(func(a *eraseAck) { a.Cursor.Index = 8 }), self, false},
		{"cursor of another group", m0, ack(func(a *eraseAck) { a.Cursor.Group = e.group(2) }), self, false},
		{"zero node", m0, ack(func(a *eraseAck) { a.Node = 0 }), proposer(0, "node-1"), false},
		{"empty identity", m0, ack(func(a *eraseAck) { a.Identity = "" }), proposer(1, ""), false},
		{"no operations", m0, ack(func(a *eraseAck) { a.Operations = nil }), self, false},
		{"65 operations", m0, ack(func(a *eraseAck) { a.Operations = make([]model.ID, 65) }), self, false},
		{"honest unack", m0, unack(nil), self, true},
		{"unack naming another node", m0, unack(func(u *eraseUnack) { u.Node, u.Identity = 2, "node-2" }), self, false},
		{"unack with no recorded proposer", m0, unack(nil), nil, false},
		{"unack with epoch zero", m0, unack(func(u *eraseUnack) { u.Epoch = 0 }), self, false},
		{"unack in a data slot", m1, unack(func(u *eraseUnack) { u.Cursor = model.Cursor{Group: e.group(1), Index: 9} }), self, false},
		{"unack with a stale cursor", m0, unack(func(u *eraseUnack) { u.Cursor.Index = 8 }), self, false},
	} {
		command := replica.Entry{Kind: replica.Barrier, ApplicationIndex: 9, Proposer: tc.by}
		if got := tc.m.validRouting(command, tc.entry); got != tc.want {
			t.Errorf("%s: validRouting=%v want %v", tc.name, got, tc.want)
		}
	}
}

// The proposal seam and the apply seam each refuse an acknowledgement that does not name its
// proposer: an entry that bypassed the first (a leader that did not validate it, a replayed
// history) still writes nothing on apply.
func TestEraseAckCountsOnlyWhenItNamesItsProposer(t *testing.T) {
	x := newEraseEnv(t)
	e := x.e
	op := model.NewID()

	applyAckEntry(t, e, ackEntry(2, "node-2", 0, proposer(1, "node-1"), op))
	if standsOn(t, e, op, 2, "node-2") {
		t.Fatal("voter 1's proposal that names voter 2 stood as voter 2's acknowledgement")
	}
	applyAckEntry(t, e, ackEntry(2, "node-2", 0, nil, op))
	if standsOn(t, e, op, 2, "node-2") {
		t.Fatal("an acknowledgement with no recorded proposer stood")
	}
	applyAckEntry(t, e, ackEntry(2, "node-2", 0, proposer(2, "other-identity"), op))
	if standsOn(t, e, op, 2, "node-2") {
		t.Fatal("an acknowledgement stood although its proposer's identity differs from the one it names")
	}
	applyAckEntry(t, e, ackEntry(2, "node-2", 0, proposer(2, "node-2"), op))
	if !standsOn(t, e, op, 2, "node-2") {
		t.Fatal("voter 2's own acknowledgement did not stand")
	}
	// A withdrawal is the voter's own statement too.
	applyAckEntry(t, e, unackEntry(2, "node-2", 5, proposer(1, "node-1")))
	if !standsOn(t, e, op, 2, "node-2") {
		t.Fatal("voter 1 withdrew voter 2's acknowledgement")
	}
	applyAckEntry(t, e, unackEntry(2, "node-2", 5, nil))
	if !standsOn(t, e, op, 2, "node-2") {
		t.Fatal("a withdrawal with no recorded proposer withdrew an acknowledgement")
	}
}

// A withdrawal raises the voter's floor: every acknowledgement it made under an earlier
// installation epoch stops counting, an acknowledgement made under a later (or the same) epoch
// counts, and neither order of arrival nor a repeated or lower withdrawal changes the result.
func TestWithdrawalVoidsOnlyAcknowledgementsOfEarlierEpochs(t *testing.T) {
	x := newEraseEnv(t)
	e := x.e
	a, b := model.NewID(), model.NewID()
	self := proposer(1, "node-1")

	applyAckEntry(t, e, ackEntry(1, "node-1", 0, self, a, b))
	if !standsOn(t, e, a, 1, "node-1") || !standsOn(t, e, b, 1, "node-1") {
		t.Fatal("acknowledgements under epoch 0 do not stand before any withdrawal")
	}
	applyAckEntry(t, e, unackEntry(1, "node-1", 2, self))
	if standsOn(t, e, a, 1, "node-1") || standsOn(t, e, b, 1, "node-1") {
		t.Fatal("a withdrawal for epoch 2 left an epoch 0 acknowledgement standing")
	}
	applyAckEntry(t, e, ackEntry(1, "node-1", 1, self, a))
	if standsOn(t, e, a, 1, "node-1") {
		t.Fatal("an acknowledgement committed AFTER the withdrawal but made under epoch 1 (before the install) stood")
	}
	applyAckEntry(t, e, ackEntry(1, "node-1", 2, self, a))
	if !standsOn(t, e, a, 1, "node-1") || standsOn(t, e, b, 1, "node-1") {
		t.Fatal("a fresh acknowledgement stands, the withdrawn one does not")
	}
	applyAckEntry(t, e, unackEntry(1, "node-1", 1, self)) // lower: never lowers the floor
	applyAckEntry(t, e, ackEntry(1, "node-1", 0, self, b))
	if standsOn(t, e, b, 1, "node-1") {
		t.Fatal("a lower withdrawal lowered the floor")
	}
	// An acknowledgement of an earlier epoch committed after a later one never replaces it.
	applyAckEntry(t, e, ackEntry(1, "node-1", 0, self, a))
	if !standsOn(t, e, a, 1, "node-1") {
		t.Fatal("a stale acknowledgement replaced a fresh one")
	}
	// Another voter's floor is its own.
	other := model.NewID()
	applyAckEntry(t, e, ackEntry(2, "node-2", 0, proposer(2, "node-2"), other))
	if !standsOn(t, e, other, 2, "node-2") {
		t.Fatal("voter 1's withdrawal voided voter 2's acknowledgement")
	}
}

// Commands written by 1fd9bc1 stay readable and are never counted as proven: their bytes decode
// and re-encode identically, applying one writes nothing, and a standing key of the old form (one
// byte) names the data store until the voter re-acknowledges.
func TestAnUnattributedEraseAckWrittenByThePreviousVersionDoesNotCount(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	ctx := context.Background()
	x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, e, pred)

	// Wire compatibility: the old command's exact bytes.
	cursor := model.Cursor{Group: e.group(eraseAckSlot), Index: 5}
	oldBytes, err := json.Marshal(legacyEraseEntry{Type: "erase_ack", EraseAck: &legacyEraseAck{Node: 1, Identity: "single", Operations: []model.ID{pred.Operation}, Cursor: cursor}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeWAL(oldBytes)
	if err != nil {
		t.Fatalf("a command the previous version wrote no longer decodes: %v", err)
	}
	if decoded.Proposer != nil || decoded.EraseAck == nil || decoded.EraseAck.Epoch != 0 {
		t.Fatalf("an old command decoded with attribution: %+v", decoded)
	}
	if again, err := encodeWAL(decoded); err != nil || !bytes.Equal(again, oldBytes) {
		t.Fatalf("an old command does not re-encode to its stored bytes:\n got  %s\n want %s (%v)", again, oldBytes, err)
	}
	// Applying it (a history replay, an install) counts for nobody.
	applyAckEntry(t, e, decoded)
	if standsOn(t, e, pred.Operation, 1, "single") {
		t.Fatal("an unattributed acknowledgement replayed from the previous version's log stood")
	}

	// A key of the old form already in the store (value of one byte, as 1fd9bc1 put it).
	if _, err = e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	x.maintain(pred)
	if err = e.MarkErased([]model.ID{pred.Operation}); err != nil {
		t.Fatal(err)
	}
	if err = e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_data")).Put(eraseAckKey(pred.Operation, 1, "single"), []byte{1})
	}); err != nil {
		t.Fatal(err)
	}
	if got := e.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("an acknowledgement of the previous version (no attribution) counts: the receipt is clean")
	}
	// The voter re-acknowledges once, with attribution, and only then is the receipt clean.
	if err = e.AckErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("after the re-acknowledgement the receipt still names %v", got)
	}
	var value []byte
	if err = e.db.View(func(tx *bolt.Tx) error {
		value = bytes.Clone(tx.Bucket([]byte("replica_data")).Get(eraseAckKey(pred.Operation, 1, "single")))
		return nil
	}); err != nil || len(value) != 8 {
		t.Fatalf("the re-acknowledgement did not replace the old key: %v %v", value, err)
	}
	// And a restart does not turn it back into proof of anything else.
	x.reopenDelete()
	if got := x.e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("after a restart the receipt names %v", got)
	}
}

// The new commands round-trip, and only an acknowledgement may carry a proposer.
func TestEraseAckWireRoundTripAndClosedProposerArm(t *testing.T) {
	op := model.NewID()
	cursor := model.Cursor{Group: model.NewID(), Index: 4}
	for _, entry := range []walEntry{
		{Type: "erase_ack", Proposer: proposer(2, "node-2"), EraseAck: &eraseAck{Node: 2, Identity: "node-2", Operations: []model.ID{op}, Epoch: 7, Cursor: cursor}},
		{Type: "erase_unack", Proposer: proposer(2, "node-2"), EraseUnack: &eraseUnack{Node: 2, Identity: "node-2", Epoch: 7, Cursor: cursor}},
		{Type: "erase_ack", EraseAck: &eraseAck{Node: 2, Identity: "node-2", Operations: []model.ID{op}, Cursor: cursor}},
	} {
		raw, err := encodeWAL(entry)
		if err != nil {
			t.Fatal(err)
		}
		back, err := decodeWAL(raw)
		if err != nil {
			t.Fatalf("%s does not decode: %v", raw, err)
		}
		if again, err := encodeWAL(back); err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("%s does not round-trip: %s %v", raw, again, err)
		}
		if (back.Proposer == nil) != (entry.Proposer == nil) || back.Proposer != nil && *back.Proposer != *entry.Proposer {
			t.Fatalf("proposer lost: %+v", back.Proposer)
		}
	}
	// A proposer on anything but an acknowledgement, and both acknowledgement arms at once, are corrupt.
	idOnly := model.NewID().String()
	if _, err := decodeWAL([]byte(`{"type":"rejected","rejection":"` + idOnly + `"}`)); err != nil {
		t.Fatalf("fixture invalid: a rejection without a proposer does not decode: %v", err)
	}
	if _, err := decodeWAL([]byte(`{"type":"rejected","rejection":"` + idOnly + `","proposer":{"node":"1","node_identity":"n"}}`)); err == nil {
		t.Fatal("a proposer on a rejection decoded")
	}
	both, err := json.Marshal(durableEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: 1, Identity: "n", Operations: []model.ID{op}, Cursor: cursor}, EraseUnack: &eraseUnack{Node: 1, Identity: "n", Epoch: 1, Cursor: cursor}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeWAL(both); err == nil {
		t.Fatal("an entry carrying both acknowledgement arms decoded")
	}
}

// eraseMarkAck is the worker's per-voter sequence for one operation on a single voter: erase from
// its own stores, cut its own snapshots and journal, mark, acknowledge.
func (x *eraseEnv) eraseMarkAck(pred model.DeletePredicate) {
	x.t.Helper()
	ctx := context.Background()
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		x.t.Fatalf("erase: %v", err)
	}
	x.maintain(pred)
	if err := x.e.MarkErased([]model.ID{pred.Operation}); err != nil {
		x.t.Fatalf("mark: %v", err)
	}
	if err := x.e.AckErasure(ctx); err != nil {
		x.t.Fatalf("ack: %v", err)
	}
}

// A snapshot install that replays erased rows back into the live buckets invalidates what the
// voter said about them: the marker goes, the installation epoch rises, the voter's withdrawal is
// proposed on its own (no worker pass), its earlier acknowledgement stops standing, and only an
// erase and an acknowledgement made after the install make the receipt clean again.
func TestAnInstallClearsTheMarkerAndWithdrawsTheAcknowledgement(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	ctx := context.Background()
	x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, e, pred)
	early := cutAllSlots(t, e)
	x.eraseMarkAck(pred)
	if got := e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("fixture invalid: the receipt names %v after the voter erased and acknowledged", got)
	}
	epoch0, _, floor0 := erasureCounters(t, e)
	if !standsOn(t, e, pred.Operation, 1, "single") {
		t.Fatal("fixture invalid: the acknowledgement does not stand")
	}

	installSlotCuts(t, e, withLaterHistory(t, e, early))

	if hits := rawHits(t, e, eraseCanary); len(hits) == 0 {
		t.Fatal("fixture invalid: the install did not bring the erased row back")
	}
	if e.ErasedLocally(pred.Operation) {
		t.Fatal("the install put the erased rows back but the marker still says the voter erased the operation")
	}
	if got := e.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("the receipt is clean right after an install that holds the erased rows")
	}
	if epoch, owed, _ := erasureCounters(t, e); epoch <= epoch0 || owed <= floor0 || owed > epoch {
		t.Fatalf("the install did not raise the installation epoch and owe its withdrawal: epoch %d (was %d), owed %d", epoch, epoch0, owed)
	}
	// The voter proposes the withdrawal by itself.
	if !eventually(15*time.Second, func() bool { _, owed, floor := erasureCounters(t, e); return owed > floor0 && floor >= owed }) {
		epoch, owed, floor := erasureCounters(t, e)
		t.Fatalf("the withdrawal was never proposed: epoch %d owed %d floor %d (was %d)", epoch, owed, floor, floor0)
	}
	if standsOn(t, e, pred.Operation, 1, "single") {
		t.Fatal("the acknowledgement made before the install still stands after its withdrawal")
	}
	// Nothing is acknowledged while the voter owes the erasure again.
	if err := e.AckErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("the receipt is clean before the voter erased again")
	}
	// The worker's next pass: erase, cut, mark, acknowledge.
	x.eraseMarkAck(pred)
	if got := e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("after erasing and acknowledging again the receipt still names %v", got)
	}
	x.requireNoCopy("after the second erase", eraseCanary)
}

// What an install owes survives a stop: the marker is gone for good, and a withdrawal the voter
// had not proposed yet when it stopped is proposed after the restart.
func TestAWithdrawalOwedAtShutdownIsProposedAfterARestart(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, e, pred)
	early := cutAllSlots(t, e)
	x.eraseMarkAck(pred)

	// The loop is stopped so that the install leaves its withdrawal owed, as a stop right after
	// an install does.
	e.erasure.cancelLoop()
	e.erasure.waitLoop()
	installSlotCuts(t, e, withLaterHistory(t, e, early))
	epoch, owed, floor := erasureCounters(t, e)
	if owed == 0 || owed <= floor {
		t.Fatalf("fixture invalid: no withdrawal owed after the install (epoch %d owed %d floor %d)", epoch, owed, floor)
	}

	x.reopenDelete()
	e = x.e
	if e.ErasedLocally(pred.Operation) {
		t.Fatal("the cleared marker came back after a restart")
	}
	if got := e.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("after a restart the receipt is clean while the install's rows are still in the store")
	}
	if !eventually(15*time.Second, func() bool { _, o, f := erasureCounters(t, e); return o > 0 && f >= o }) {
		epoch, owed, floor = erasureCounters(t, e)
		t.Fatalf("the withdrawal owed at shutdown was not proposed after the restart: epoch %d owed %d floor %d", epoch, owed, floor)
	}
	if standsOn(t, e, pred.Operation, 1, "single") {
		t.Fatal("the acknowledgement made before the install stands after the restart")
	}
	x.eraseMarkAck(pred)
	if got := e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("after erasing and acknowledging again the receipt still names %v", got)
	}
	var value []byte
	if err := e.db.View(func(tx *bolt.Tx) error {
		value = bytes.Clone(tx.Bucket([]byte("replica_data")).Get(eraseAckKey(pred.Operation, 1, "single")))
		return nil
	}); err != nil || len(value) != 8 || binary.BigEndian.Uint64(value) < owed {
		t.Fatalf("the new acknowledgement does not carry an epoch at or above the withdrawal: %v %v", value, err)
	}
}

// An acknowledgement follows the fact it states, not only the install that can break it: a
// standing acknowledgement whose marker is gone, or whose stores turn dirty (an owed scrub), is
// withdrawn by the voter's next pass, the operation is owed again, and only a new erase and
// acknowledgement make the receipt clean.
func TestAStandingAcknowledgementThatItsStoresNoLongerBackIsWithdrawn(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	ctx := context.Background()
	x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, e, pred)
	x.eraseMarkAck(pred)
	if !standsOn(t, e, pred.Operation, 1, "single") || len(e.ErasureResidual(pred.Operation)) != 0 {
		t.Fatal("fixture invalid: the acknowledgement does not stand")
	}

	// The marker is gone.
	if err := e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_data")).Delete(erasedKey(pred.Operation))
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.AckErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if standsOn(t, e, pred.Operation, 1, "single") {
		t.Fatal("an acknowledgement whose marker is gone survived the next pass")
	}
	if got := e.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("the receipt is clean while the voter owes the erasure")
	}
	x.eraseMarkAck(pred)
	if !standsOn(t, e, pred.Operation, 1, "single") || len(e.ErasureResidual(pred.Operation)) != 0 {
		t.Fatal("the voter did not acknowledge again after erasing again")
	}

	// The stores turn dirty.
	if err := e.db.Update(e.markScrubPendingTx); err != nil {
		t.Fatal(err)
	}
	if err := e.AckErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if standsOn(t, e, pred.Operation, 1, "single") || e.ErasedLocally(pred.Operation) {
		t.Fatal("an acknowledgement or a marker survived dirty stores")
	}
	x.eraseMarkAck(pred)
	if !standsOn(t, e, pred.Operation, 1, "single") || len(e.ErasureResidual(pred.Operation)) != 0 {
		t.Fatal("the voter did not acknowledge again once its stores were clean")
	}
}

// MarkErased certifies an erasure only when no install landed since the erase started: the
// install can put erased rows back after the erase read them.
func TestMarkErasedRefusesAnErasureAnInstallInterrupted(t *testing.T) {
	x := newCheckpointEnv(t)
	e := x.e
	ctx := context.Background()
	x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, e, pred)
	early := cutAllSlots(t, e)

	// A mark with no erase in this process is refused.
	if err := e.MarkErased([]model.ID{pred.Operation}); err == nil {
		t.Fatal("an operation this process never erased was marked")
	}
	if _, err := e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	x.maintain(pred)
	installSlotCuts(t, e, withLaterHistory(t, e, early)) // the install lands between the erase and the mark
	if hits := rawHits(t, e, eraseCanary); len(hits) == 0 {
		t.Fatal("fixture invalid: the install did not bring the erased row back")
	}
	if err := e.MarkErased([]model.ID{pred.Operation}); err == nil {
		t.Fatal("an erasure an install interrupted was marked")
	}
	if e.ErasedLocally(pred.Operation) {
		t.Fatal("the refused mark was recorded")
	}
	// The erase that started after the install is the one that counts.
	x.eraseMarkAck(pred)
	if !e.ErasedLocally(pred.Operation) {
		t.Fatal("an erase that started after the install was not marked")
	}
	if got := e.ErasureResidual(pred.Operation); len(got) != 0 {
		t.Fatalf("the receipt names %v after the second erase", got)
	}
}
