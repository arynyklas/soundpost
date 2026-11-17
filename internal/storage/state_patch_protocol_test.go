// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/replica"
)

// The state patch is a command of the control group, so the gate that lets control propose it reads
// the control group's own committed configuration. A membership change that reached the control
// group but not the slot-0 group (appcore/membership.go reports per-group failures) leaves a voter in
// the control configuration that the slot-0 configuration does not list: it never declared, and the
// gate stays closed for it, where a gate that read only the slot-0 configuration opened and let an
// old voter stop on a command it cannot decode.
func TestControlStatePatchGateReadsTheControlGroupsOwnMembers(t *testing.T) {
	f := newWithdrawFixture(t)
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
