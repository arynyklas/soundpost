// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The bounded-state rules of control wait for every member of the committed configuration, like the
// erase entries do, but on their own declaration: a member that declared only the erase protocol (the
// release before the bounded-state rules) does not hold the erase entries back, and holds the control
// rules back until it declares the newer version too.
func TestControlBoundsWaitForEveryMemberToDeclareTheirProtocol(t *testing.T) {
	f := newWithdrawFixtureUndeclared(t)
	ctx := context.Background()
	declared := func(node uint64) uint64 {
		var got uint64
		e := f.v.engines[1]
		id, identity, _ := f.v.engines[node].selfMember()
		_ = e.db.View(func(tx *bolt.Tx) error {
			got = capabilityOf(tx.Bucket([]byte("replica_data")), id, identity)
			return nil
		})
		return got
	}
	for node := uint64(1); node <= 3; node++ {
		if f.v.engines[node].ControlBoundsReady() {
			t.Fatalf("node %d: bounds ready before anyone declared", node)
		}
	}
	// Nodes 1 and 2 are the new binary.
	for _, node := range []uint64{1, 2} {
		f.v.leadSlotZero(t, node)
		if err := f.v.engines[node].declareErasure(ctx); err != nil {
			t.Fatalf("node %d declare: %v", node, err)
		}
	}
	// Node 3 is the release before this one: it declares the erase protocol it speaks, in the shape
	// that binary proposes (the declaration of version 2).
	f.v.leadSlotZero(t, 3)
	e3 := f.v.engines[3]
	id, identity, _ := e3.selfMember()
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(eraseProtocol), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if !eventually(30*time.Second, e.protocolReady) {
			t.Fatalf("node %d: the erase protocol is held back by a member that declared version %d", node, declared(3))
		}
	}
	for node := uint64(1); node <= 3; node++ {
		if f.v.engines[node].ControlBoundsReady() {
			t.Fatalf("node %d: bounds ready while node 3 declared only version %d (nodes 1 and 2: %d, %d)", node, declared(3), declared(1), declared(2))
		}
	}
	if declared(1) != declaredProtocol || declared(2) != declaredProtocol || declared(3) != eraseProtocol {
		t.Fatalf("declarations %d, %d, %d", declared(1), declared(2), declared(3))
	}
	// Node 3 is upgraded and declares: the rules engage on every member.
	if err := e3.declareErasure(ctx); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if !eventually(30*time.Second, e.ControlBoundsReady) {
			t.Fatalf("node %d: bounds still not ready after every member declared (node 3: %d)", node, declared(3))
		}
	}
}

// Without replication there is no group to wait for: the gate stays closed until the engine's own
// replication is up (the application sets it before control can decide anything).
func TestControlBoundsAreClosedWithoutAGroup(t *testing.T) {
	e := &Engine{}
	if e.ControlBoundsReady() {
		t.Fatal("bounds ready on an engine with no replication")
	}
}
