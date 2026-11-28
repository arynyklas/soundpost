// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"
)

// A receipt answered by a voter that has not applied the latest erase_notice must not read clean.
// The notice that names voter 3 voids 3's acknowledgement on every voter that APPLIES it; a voter
// that has not applied it yet (cut off, or slow to apply) still counts the old acknowledgement, so
// its local-only answer was clean while a pre-erasure snapshot was on its way to voter 3. The
// receipt now asks the slot-0 group for a read index first, so a voter that cannot confirm it has
// applied everything committed answers dirty.
func TestAReceiptOnAVoterThatHasNotAppliedTheLatestNoticeIsNotClean(t *testing.T) {
	f := newWithdrawFixture(t)
	f.v.declareProtocol(t)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false) // fixture: a healthy settled cluster reads clean everywhere
	}

	// Voter 2 is cut off; voters 1 and 3 still make a quorum and voter 1 announces a snapshot to 3.
	f.v.leadSlotZero(t, 1)
	f.v.mesh.partition(2, true)
	healed := false
	defer func() {
		if !healed {
			f.v.mesh.partition(2, false)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	token, err := f.v.engines[1].beforeSnapshotSend(ctx, 3)
	if err != nil || len(token) != 8 {
		t.Fatalf("fixture invalid: the notice naming voter 3 was not committed: token %x, %v", token, err)
	}
	if !eventually(30*time.Second, func() bool {
		return replicatedNotice(t, f.v.engines[1], 3) > 0 && replicatedNotice(t, f.v.engines[3], 3) > 0
	}) {
		t.Fatal("voters 1 and 3 never applied the notice")
	}
	e2 := f.v.engines[2]
	if replicatedNotice(t, e2, 3) != 0 || !standsOn(t, e2, pred.Operation, 3, "node-3") {
		t.Fatal("fixture invalid: the cut-off voter applied the notice, or no longer counts voter 3's acknowledgement")
	}
	if !eventually(30*time.Second, func() bool { return len(f.v.engines[1].ErasureResidual(pred.Operation)) > 0 }) {
		t.Fatal("voter 1 applied the notice and still reads clean")
	}
	// The cut-off voter's own state still counts all three acknowledgements; the answer it can give
	// from state alone is clean, which is the false clean.
	if got := e2.ErasureResidual(pred.Operation); len(got) == 0 {
		t.Fatal("FALSE CLEAN: a voter that has not applied the notice naming voter 3 answers a receipt with no residue while a snapshot that predates the erasure is on its way to voter 3")
	}

	// Healed, voter 2 applies the notice and then reads dirty for the same reason as everyone else.
	f.v.mesh.partition(2, false)
	healed = true
	if !eventually(60*time.Second, func() bool { return replicatedNotice(t, e2, 3) > 0 }) {
		t.Fatal("voter 2 never applied the notice after it was reconnected")
	}
	for node := uint64(1); node <= 3; node++ {
		if got := f.v.engines[node].ErasureResidual(pred.Operation); len(got) == 0 {
			t.Fatalf("FALSE CLEAN: voter %d reads clean after the notice, voter 3 has not erased again", node)
		}
	}
}
