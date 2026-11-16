// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The audit delta command of control (D49) waits for every member of the committed configuration on
// its own declaration, protocol 4: a member that declared only the bounded-state protocol (the
// release before this one) holds the delta back while it does not hold the bounded rules back.
func TestControlAuditDeltaWaitsForEveryMemberToDeclareProtocolFour(t *testing.T) {
	f := newWithdrawFixture(t)
	ctx := context.Background()
	for node := uint64(1); node <= 3; node++ {
		if f.v.engines[node].ControlAuditDeltaReady() {
			t.Fatalf("node %d: audit delta ready before anyone declared", node)
		}
	}
	for _, node := range []uint64{1, 2} { // the new binary
		f.v.leadSlotZero(t, node)
		if err := f.v.engines[node].declareErasure(ctx); err != nil {
			t.Fatalf("node %d declare: %v", node, err)
		}
	}
	// Node 3 is the release before this one: it declares the bounded-state protocol it speaks.
	f.v.leadSlotZero(t, 3)
	e3 := f.v.engines[3]
	id, identity, _ := e3.selfMember()
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(boundsProtocol), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		if !eventually(30*time.Second, f.v.engines[node].ControlBoundsReady) {
			t.Fatalf("node %d: the bounded rules are held back by a member that declared version %d", node, boundsProtocol)
		}
	}
	for node := uint64(1); node <= 3; node++ {
		if f.v.engines[node].ControlAuditDeltaReady() {
			t.Fatalf("node %d: audit delta ready while node 3 declared only version %d", node, boundsProtocol)
		}
	}
	if err := e3.declareErasure(ctx); err != nil { // node 3 is upgraded and declares
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		if !eventually(30*time.Second, f.v.engines[node].ControlAuditDeltaReady) {
			t.Fatalf("node %d: audit delta still not ready after every member declared", node)
		}
	}
}

// Without replication there is no group to wait for.
func TestControlAuditDeltaIsClosedWithoutAGroup(t *testing.T) {
	if (&Engine{}).ControlAuditDeltaReady() {
		t.Fatal("audit delta ready on an engine with no replication")
	}
}
