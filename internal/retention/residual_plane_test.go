// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

type fakeResiduals []string

func (r fakeResiduals) ResidualStores() []string { return r }

// The composite names what the storage engine measures AND what the control
// store still owes, each once, in a fixed order.
func TestResidualPlaneIsTheUnionOfEngineAndControl(t *testing.T) {
	f := newFx(t, options{})
	for _, c := range []struct {
		name         string
		engine, owed []string
		want         []string
	}{
		{"neither", nil, nil, nil},
		{"engine only", []string{"raft_journal"}, nil, []string{"raft_journal"}},
		{"control only", nil, []string{control.ResidualControlJournal, control.ResidualControlState}, []string{control.ResidualControlJournal, control.ResidualControlState}},
		{"both, deduplicated and ordered", []string{"snapshots", "raft_journal"}, []string{control.ResidualControlState, "raft_journal", control.ResidualControlJournal},
			[]string{control.ResidualControlJournal, control.ResidualControlState, "raft_journal", "snapshots"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f.plane.residual = func() []string { return c.engine }
			got := retention.NewResidualPlane(f.plane, fakeResiduals(c.owed)).ResidualStores()
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("residual stores %v, want %v", got, c.want)
			}
		})
	}
}

// seedIncident writes one incident whose state names a canary and an evidence
// time, in the shape the incident writer commits.
func (f *fx) seedIncident(project model.ID, canary string) {
	f.t.Helper()
	inc := model.NewID()
	state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","evidence":%q,"at":"5"}`, inc.String(), f.org.String(), project.String(), canary))
	raw, err := json.Marshal(control.IncidentRecord{Org: f.org, Project: project, ID: inc, Version: 1, Digest: model.Hash{7}, State: state})
	if err != nil {
		f.t.Fatal(err)
	}
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		if st.IncidentBooks == nil {
			st.IncidentBooks = map[string]json.RawMessage{}
		}
		st.IncidentBooks[f.org.String()+":"+project.String()+":"+inc.String()] = raw
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func hasResidual(list []string, name string) bool {
	for _, v := range list {
		if v == name {
			return true
		}
	}
	return false
}

// A receipt never reports "physical: done" with an empty residual list while the
// control store still owes a copy: the control Raft journal while a copy may remain
// (here a live backup pin the worker's pass cannot clear), and control.db while a
// scrub is owed. (01.08 review CD-2.) The journal is cleared by the worker's pass
// once nothing holds it: TestReceiptDropsTheControlJournalAfterThePass.
func TestDoneReceiptNeverHidesAControlResidual(t *testing.T) {
	f := newFx(t, options{controlResiduals: true})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ReplicaGroup().PinJournal(0); err != nil { // a backup in flight holds copies the pass cannot rewrite
		t.Fatal(err)
	}
	f.seedIncident(f.project, "CANARYRECEIPT7c41e90d2b86a")
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	done := f.poll(receipt.OperationID)
	if done.Physical != retention.PhysicalDone {
		t.Fatalf("setup: %+v", done)
	}
	if got := f.store.ResidualStores(); !hasResidual(got, control.ResidualControlJournal) {
		t.Fatalf("setup: the control store does not owe the journal copy: %v", got)
	}
	if !hasResidual(done.Residual, control.ResidualControlJournal) {
		t.Fatalf("a done receipt hides the control raft journal residue: %+v", done)
	}
	if hasResidual(done.Residual, control.ResidualControlState) {
		t.Fatalf("control.db was scrubbed by the physical step, the receipt still names it: %+v", done)
	}

	// Another deletion of the same organization failed after it erased control
	// payloads: its control.db scrub is owed, and the first operation's receipt
	// (still "done") names it until the worker has run it.
	f.seedIncident(f.other, "CANARYOWED7c41e90d2b86a0f")
	second, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.other} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.FailDeletion(f.ctx, second.OperationID, model.UnixNano(f.at().UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}
	owed := f.poll(receipt.OperationID)
	if owed.Physical != retention.PhysicalDone || !hasResidual(owed.Residual, control.ResidualControlState) || !hasResidual(owed.Residual, control.ResidualControlJournal) {
		t.Fatalf("a done receipt hides an owed control.db scrub: %+v", owed)
	}

	// The worker runs the scrub of a failed deletion (it is never recorded as
	// physically done), and the receipt stops naming control.db.
	f.run()
	cleared := f.poll(receipt.OperationID)
	if hasResidual(cleared.Residual, control.ResidualControlState) || !hasResidual(cleared.Residual, control.ResidualControlJournal) {
		t.Fatalf("after the worker's pass: %+v", cleared)
	}
	if op, _, _ := f.store.DeletionOperation(f.ctx, second.OperationID); op.PhysicalAt != 0 || op.Phase != model.DeletePhaseFailed {
		t.Fatalf("the worker recorded a physical step for a failed operation: %+v", op)
	}
}

// The control Raft journal is named from the first erasure on and stops being named once the
// worker's pass over this node's control group is proven: the receipt of the SAME operation
// drops it after the pass, keeps it before, and keeps it while the pass cannot complete.
func TestReceiptDropsTheControlJournalAfterThePass(t *testing.T) {
	f := newFx(t, options{controlResiduals: true})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	const gone = "CANARYPASSRECEIPT7c41e90d2b86a"
	f.seedIncident(f.project, gone)
	first, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	// Before the pass: the erasure committed at begin, nothing redacted yet.
	if !hasResidual(f.store.ResidualStores(), control.ResidualControlJournal) {
		t.Fatalf("an erasure committed and the control store does not owe its journal: %v", f.store.ResidualStores())
	}
	f.run()
	done := f.poll(first.OperationID)
	if done.Physical != retention.PhysicalDone {
		t.Fatalf("setup: %+v", done)
	}
	if hasResidual(done.Residual, control.ResidualControlJournal) || hasResidual(done.Residual, control.ResidualControlState) {
		t.Fatalf("the pass completed and the receipt still names the control stores: %+v", done)
	}

	// A second erasure owes a new pass: its receipt names the journal until the worker has run
	// it, and so does the first operation's (a receipt is about the node as it is now).
	f.seedIncident(f.other, "CANARYPASSRECEIPT2c41e90d2b86a")
	second, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.other} })
	if err != nil {
		t.Fatal(err)
	}
	if got := f.poll(first.OperationID); !hasResidual(got.Residual, control.ResidualControlJournal) {
		t.Fatalf("a newer erasure is owed and the done receipt hides it: %+v", got)
	}
	// A pass that cannot complete keeps naming it: a backup pin is live.
	pin, err := f.store.ReplicaGroup().PinJournal(0)
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	if got := f.poll(second.OperationID); got.Physical != retention.PhysicalDone || !hasResidual(got.Residual, control.ResidualControlJournal) {
		t.Fatalf("a pass held by a live pin must keep the journal named: %+v", got)
	}
	if err = pin.Release(); err != nil {
		t.Fatal(err)
	}
	f.run()
	for _, op := range []model.ID{first.OperationID, second.OperationID} {
		if got := f.poll(op); hasResidual(got.Residual, control.ResidualControlJournal) {
			t.Fatalf("the pass completed and the receipt of %s still names the journal: %+v", op, got)
		}
	}

	// A node whose control group cannot be measured keeps naming it.
	if err = f.store.ReplicaGroup().Close(); err != nil {
		t.Fatal(err)
	}
	if !hasResidual(f.store.ResidualStores(), control.ResidualControlJournal) {
		t.Fatalf("a group that cannot be measured must be named: %v", f.store.ResidualStores())
	}
}
