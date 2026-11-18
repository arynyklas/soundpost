// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (n *workerNode) transact(kind control.CommandKind, payload any) {
	n.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		n.t.Fatal(err)
	}
	var revision model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	if _, err := n.app.Control.Transact(n.ctx, n.admin(), control.Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(kind), Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

// corruptState is a committed state whose closed header control accepts and
// whose body the owning package cannot read (the phase is a number).
func (n *workerNode) corruptState(idKey, id string, version int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{%q:%q,"org_id":%q,"project_id":%q,"version":"%d","phase":5,"status":5}`, idKey, id, n.org.String(), n.project.String(), version))
}

func (n *workerNode) assertSkippedNotCleanly(rep appcore.PassReport, what string) {
	n.t.Helper()
	found := false
	for _, e := range rep.Errors {
		if e.Stage == appcore.StageNotify && e.Project == n.project && e.Code == string(model.Corrupt) {
			found = true
		}
	}
	if !found {
		n.t.Fatalf("a %s with unreadable committed state was skipped without a report entry: %+v", what, rep)
	}
	for _, e := range rep.Errors {
		if strings.Contains(fmt.Sprint(e), "phase") {
			n.t.Fatalf("report carries state content: %+v", e)
		}
	}
}

func TestWorkersReportAConditionWhoseCommittedStateCannotBeRead(t *testing.T) {
	n := newWorkerNode(t)
	lease, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cond := model.NewID()
	state := n.corruptState("condition_id", cond.String(), 1)
	n.transact(control.KindApplyCondition, control.ConditionCommand{Project: n.project, Condition: cond, Lease: &lease, NewVersion: 1, At: workerNow, State: state, Digest: sha256.Sum256(state)})
	w, err := n.app.NewWorkers(n.conditionConfig(n.alertRule(), &countingSender{}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	n.assertSkippedNotCleanly(w.Tick(n.ctx), "condition")
}

func TestWorkersReportAnIncidentWhoseCommittedStateCannotBeRead(t *testing.T) {
	n := newWorkerNode(t)
	inc := model.NewID()
	state := n.corruptState("incident_id", inc.String(), 1)
	n.transact(control.KindIncidentAction, control.IncidentCommand{Project: n.project, Incident: inc, Action: "open", Origin: "human", Actor: n.admin().PrincipalID(), At: workerNow, NewVersion: 1, State: state, Digest: sha256.Sum256(state)})
	w, err := n.app.NewWorkers(n.conditionConfig(n.alertRule(), &countingSender{}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	n.assertSkippedNotCleanly(w.Tick(n.ctx), "incident")
}
