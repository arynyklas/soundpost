// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The state patch is a command of the control group, so the gate that lets control propose it reads
// the control group's own committed configuration. A membership change that reached the control
// group but not the slot-0 group (appcore/membership.go reports per-group failures) leaves a voter in
// the control configuration that the slot-0 configuration does not list: it never declared, and the
// gate stays closed for it, where a gate that read only the slot-0 configuration opened and let an
// old voter stop on a command it cannot decode.
func TestControlStatePatchGateReadsTheControlGroupsOwnMembers(t *testing.T) {
	f := newWithdrawFixtureUndeclared(t)
	ctx := context.Background()
	for node := uint64(1); node <= 3; node++ {
		f.v.leadSlotZero(t, node)
		if err := f.v.engines[node].declareErasure(ctx); err != nil {
			t.Fatalf("node %d declare: %v", node, err)
		}
	}
	slotZero := f.v.engines[1].repl.groups[eraseAckSlot].Status().Members.Nodes
	for node := uint64(1); node <= 3; node++ {
		if !eventually(30*time.Second, func() bool { return f.v.engines[node].ControlStatePatchReady(slotZero) }) {
			t.Fatalf("node %d: the gate is closed although every member declared", node)
		}
	}
	// The control group already has a fourth voter that the slot-0 group does not list.
	halfApplied := append(slices.Clone(slotZero), replica.Member{ID: 4, Address: "127.0.0.1:1", NodeIdentity: "voter-4"})
	for node := uint64(1); node <= 3; node++ {
		if f.v.engines[node].ControlStatePatchReady(halfApplied) {
			t.Fatalf("node %d: the gate is open for a control voter that never declared", node)
		}
		// The slot-0 view alone (the previous reading) would have said ready.
		if !f.v.engines[node].ControlStatePatchReady(slotZero) {
			t.Fatalf("node %d: the gate closed for the members that declared", node)
		}
	}
	// A control configuration that lists a known id under another identity (a replaced disk) is no
	// declaration either, and an unknown configuration is closed.
	replaced := slices.Clone(slotZero)
	replaced[0].NodeIdentity = "another-disk"
	if f.v.engines[1].ControlStatePatchReady(replaced) {
		t.Fatal("the gate is open for a member whose identity never declared")
	}
	if f.v.engines[1].ControlStatePatchReady(nil) {
		t.Fatal("the gate is open without a control configuration")
	}
	if (&Engine{}).ControlStatePatchReady(slotZero) {
		t.Fatal("the gate is open on an engine with no replication")
	}
}

// A state patch of the ledger layout names the digest of the committed state with the admission ledger
// folded in (control ledger.go): a voter of the previous release (protocol 5) computes another digest
// over its own bytes and could not apply it. The gate of that patch therefore waits for protocol 6 on
// every member, while the gate of the first protocol (5), which control uses only against an empty
// ledger, stays open for a group whose oldest member is the previous release, and the gates of the
// older protocols (audit delta 4, bounds 3) open as they did.
func TestControlStatePatchGateWaitsForTheLedgerProtocol(t *testing.T) {
	if statePatchProtocol != 9 || legacyStatePatchProtocol != 5 || compactAdmissionProtocol != 10 || declaredProtocol != 10 {
		t.Fatalf("state patch protocol %d, first protocol %d, compact admission protocol %d, declared %d: the ledger layout with the grouping issues and the command log as records and the scoped delta is protocol 9, the compact admission ops are 10, the previous release declares 5", statePatchProtocol, legacyStatePatchProtocol, compactAdmissionProtocol, declaredProtocol)
	}
	f := newWithdrawFixtureUndeclared(t) // the voters declare below (the declared fixture of 10.35#12 has every voter at the current protocol already)
	ctx := context.Background()
	for _, node := range []uint64{1, 2} {
		f.v.leadSlotZero(t, node)
		if err := f.v.engines[node].declareErasure(ctx); err != nil {
			t.Fatalf("node %d declare: %v", node, err)
		}
	}
	// Node 3 is the previous release: it declares the protocol it speaks, 5, in the shape it proposes.
	f.v.leadSlotZero(t, 3)
	e3 := f.v.engines[3]
	id, identity, _ := e3.selfMember()
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(5), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	slotZero := f.v.engines[1].repl.groups[eraseAckSlot].Status().Members.Nodes
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if !eventually(30*time.Second, e.ControlAuditDeltaReady) {
			t.Fatalf("node %d: the audit delta gate is held back by a member that declared protocol 5", node)
		}
		if e.ControlStatePatchReady(slotZero) {
			t.Fatalf("node %d: the state patch gate is open while node 3 declared only protocol 5", node)
		}
		if !e.ControlLegacyStatePatchReady(slotZero) {
			t.Fatalf("node %d: the gate of the first patch protocol is closed although every member declared 5 or more", node)
		}
	}
	// Node 3 is a build of the ledger layout that kept the job and issue books in the blob (protocol 6): the
	// digest a patch names covers a blob that holds them, so the gate stays closed for it.
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(6), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if e.ControlStatePatchReady(slotZero) || !e.ControlLegacyStatePatchReady(slotZero) {
			t.Fatalf("node %d: the gate of the books-in-the-ledger protocol is open while node 3 declared protocol 6", node)
		}
	}
	// Node 3 is the build before D85 (protocol 7): it holds the grouping issues and the command log in its blob
	// and has no record tables for them, so a patch that addresses those records stays held back.
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(7), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if e.ControlStatePatchReady(slotZero) || !e.ControlLegacyStatePatchReady(slotZero) {
			t.Fatalf("node %d: the gate of the records protocol is open while node 3 declared protocol 7", node)
		}
	}
	// Node 3 is the build before D102 (protocol 8): it does not decode the scoped delta (the login and the grant of
	// an instance scope that name the records they read), so the gate that proposes it stays closed.
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(8), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if e.ControlStatePatchReady(slotZero) || !e.ControlLegacyStatePatchReady(slotZero) {
			t.Fatalf("node %d: the gate of the scoped delta is open while node 3 declared protocol 8", node)
		}
	}
	// Node 3 is the build of the scoped delta (protocol 9): the patches flow, and the compact admission ops, which it does not
	// decode, stay held back (D104).
	if err := e3.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(id), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(9), Cursor: cursor}}
	}); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if !eventually(30*time.Second, func() bool { return e.ControlStatePatchReady(slotZero) && e.ControlLegacyStatePatchReady(slotZero) }) {
			t.Fatalf("node %d: a patch gate stays closed after every member declared protocol 9", node)
		}
		if e.ControlCompactAdmissionReady(slotZero) {
			t.Fatalf("node %d: the compact admission gate is open while node 3 declared only protocol 9", node)
		}
	}
	// Node 3 is upgraded and declares: the gate opens on every member.
	if err := e3.declareErasure(ctx); err != nil {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		e := f.v.engines[node]
		if !eventually(30*time.Second, func() bool { return e.ControlCompactAdmissionReady(slotZero) }) {
			t.Fatalf("node %d: the compact admission gate stays closed after every member declared protocol 10", node)
		}
	}
	if e1 := f.v.engines[1]; e1.ControlCompactAdmissionReady(nil) || (&Engine{}).ControlCompactAdmissionReady(slotZero) {
		t.Fatal("the compact admission gate is open without a control configuration or without replication")
	}
}
