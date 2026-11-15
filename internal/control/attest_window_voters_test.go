// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
)

// operationReceiptOn is the residual list the receipt of operation op carries when voter id answers
// it: the retention plane the application hands the service, asked per operation.
func (v *controlVoters) operationReceiptOn(id uint64, op model.ID) []string {
	v.t.Helper()
	return retention.NewResidualPlane(noData{}, v.stores[id]).OperationResidual(op)
}

// lastErasedOp is the operation the newest erasing audit of the control log names, read on voter id.
func (v *controlVoters) lastErasedOp(id uint64) model.ID {
	v.t.Helper()
	var op model.ID
	if err := v.stores[id].View(context.Background(), func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "delete.control_erased" && len(a.Targets) > 0 {
				op = a.Targets[len(a.Targets)-1]
			}
		}
		return nil
	}); err != nil {
		v.t.Fatal(err)
	}
	if op == (model.ID{}) {
		v.t.Fatal("fixture invalid: the control log holds no erasing audit")
	}
	return op
}

// appliedEverywhere waits until every running voter applied what the leader committed.
func (v *controlVoters) appliedEverywhere() {
	v.t.Helper()
	v.eventually("every voter applied what voter 1 committed", func() bool {
		top := v.stores[1].ReplicaGroup().Status().Applied
		for id, s := range v.stores {
			if !v.down[id] && s.ReplicaGroup().Status().Applied < top {
				return false
			}
		}
		return true
	})
}

// A stale control command is committed at one index on every node, and the group drops the redaction
// proof of every node on it. The attestation of another voter that predates that index vouches for a
// journal this event changed, but the voter withdraws it by a commit of its own that may not have
// happened when a receipt is answered. Voter 1's state machine is handed the stale command (see
// ApplyStaleCommandDirect) while voters 2 and 3 still hold their old records: voter 1's own proof is
// untouched, so what its receipt names can only come from the records of voters 2 and 3, which were
// written before the command and must not count. Voter 2, which did not apply it, still reads clean.
func TestAReceiptNeverTrustsAnAttestationOlderThanAStaleCommand(t *testing.T) {
	v := newControlVoters(t)
	w := v.watch(installTestBudget())
	const gone = "CANARYSTALEWINDOW5c0e17b9a2d4"
	w.at("fixture: erasure, every voter attests")
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	v.finish(3)
	v.converge()
	op := v.lastErasedOp(1)
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("fixture invalid: every voter attested and voter %d's receipt names %v", id, got)
		}
		if got := v.operationReceiptOn(id, op); len(got) != 0 {
			t.Fatalf("fixture invalid: every voter attested and voter %d's receipt for the operation names %v", id, got)
		}
	}
	w.at("voter 1 applies a stale command")
	if err := control.ApplyStaleCommandDirect(v.stores[1]); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("fixture invalid: the stale command was not rejected as stale: %v", err)
	}
	if got := v.stores[1].ResidualStores(); len(got) != 0 {
		t.Fatalf("fixture invalid: voter 1's own proof must be untouched by the machine-level stale command: %v", got)
	}
	for _, id := range []uint64{2, 3} {
		if j, s := v.facts(1, id); !j || !s {
			t.Fatalf("fixture invalid: voter %d's records are gone (journal=%v state=%v)", id, j, s)
		}
	}
	w.at("receipts")
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("voter 1 answered a receipt without the journal although the journal records of voters 2 and 3 predate the stale command it applied: %v", got)
	}
	if got := v.operationReceiptOn(1, op); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("voter 1's receipt for the operation lacks the journal although the records of voters 2 and 3 predate the stale command it applied: %v", got)
	}
	if got := v.operationReceiptOn(1, op); contains(got, control.ResidualControlState) {
		t.Fatalf("a stale command does not touch control.db: voter 1's receipt for the operation names it: %v", got)
	}
	if got := v.operationReceiptOn(2, op); len(got) != 0 {
		t.Fatalf("voter 2 did not apply the stale command and its receipt names %v", got)
	}
	w.stop()
}

// The receipt of one deletion names the control stores only for that deletion. Every voter proved the
// first erasure; a second deletion then erases (nobody cleaned it yet): the second receipt names the
// journal and control.db, the first must not, whichever voter answers it.
func TestAReceiptNamesControlStoresOnlyForTheOperationItAnswers(t *testing.T) {
	v := newControlVoters(t)
	w := v.watch(installTestBudget())
	const first, second = "CANARYOPFIRST4a8e2c71d09b", "CANARYOPSECOND93b1f60c5e7a"
	w.at("fixture: first erasure, every voter attests")
	v.erasedWithVoter3Idle(first)
	v.attest(1)
	v.attest(2)
	v.finish(3)
	op1 := v.lastErasedOp(1)
	for id := uint64(1); id <= 3; id++ {
		if got := v.operationReceiptOn(id, op1); len(got) != 0 {
			t.Fatalf("fixture invalid: every voter attested and voter %d's receipt for the first operation names %v", id, got)
		}
	}
	w.at("second erasure on the leader, nobody cleans it")
	v.leaderIs(1)
	leader := v.fx[1]
	leader.seedAll(leader.newSeed(leader.otherProject, second), 60)
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	v.leaderIs(1)
	op2 := leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.otherProject}})
	if op2 == op1 {
		t.Fatal("fixture invalid: the second deletion is the first operation")
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	if got := v.lastErasedOp(1); got != op2 {
		t.Fatalf("fixture invalid: the newest erasing audit names %v, not the second operation %v", got, op2)
	}
	w.at("every worker reconciles its record without cleaning the second erasure")
	for id := uint64(1); id <= 3; id++ {
		v.attest(id) // the older fact stays while the node can still prove it
	}
	w.at("receipts")
	for id := uint64(1); id <= 3; id++ {
		if got := v.operationReceiptOn(id, op1); len(got) != 0 {
			t.Fatalf("voter %d's receipt for the first operation names %v although every voter proved its erasure (only the second is unclean)", id, got)
		}
		got := v.operationReceiptOn(id, op2)
		if !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
			t.Fatalf("voter %d's receipt for the second operation, which nobody cleaned: %v", id, got)
		}
	}
	w.at("every voter cleans the second erasure")
	for id := uint64(1); id <= 3; id++ {
		v.finish(id)
	}
	v.converge()
	for id := uint64(1); id <= 3; id++ {
		for _, op := range []model.ID{op1, op2} {
			if got := v.operationReceiptOn(id, op); len(got) != 0 {
				t.Fatalf("every voter cleaned both erasures: voter %d's receipt for %v names %v", id, op, got)
			}
		}
	}
	w.stop()
}
