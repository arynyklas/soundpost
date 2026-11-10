// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
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
// control store still owes a copy: the control Raft journal always (it cannot yet
// be redacted), and control.db while a scrub is owed. (01.08 review CD-2.)
func TestDoneReceiptNeverHidesAControlResidual(t *testing.T) {
	f := newFx(t, options{controlResiduals: true})
	if _, _, err := f.append(5, "requests"); err != nil {
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
