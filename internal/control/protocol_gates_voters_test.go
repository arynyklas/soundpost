// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The two control gates through a real three-voter group: each reads the lowest protocol any member
// declared (what storage.Engine answers on every member, see storage.TestControlGatesReadTheirOwnProtocolOfEveryMember).
// The gate numbers are the ones storage declares: 4 audit delta, 5 state patch.
const (
	gateAuditDelta = 4
	gateStatePatch = 5
)

// gateVoters is controlVoters whose three gates read the lowest declared protocol of the members.
type gateVoters struct {
	*controlVoters
	lowest atomic.Uint64
}

func newGateVoters(t *testing.T, lowest uint64) *gateVoters {
	t.Helper()
	d := &gateVoters{controlVoters: newControlVotersCadence(t, replica.Cadence{})}
	d.lowest.Store(lowest)
	for id := range d.stores {
		d.install(id)
	}
	return d
}

func (d *gateVoters) install(id uint64) {
	s := d.stores[id]
	s.SetAuditDeltaGate(func() bool { return d.lowest.Load() >= gateAuditDelta })
	s.SetStatePatchGate(func() bool { return d.lowest.Load() >= gateStatePatch })
}

// save commits one admin command through voter 1's service (the owner session lives there).
func (d *gateVoters) save(kind string, p auth.AdminPayload) {
	d.t.Helper()
	f := d.fx[1]
	p.Reason = "protocol gates"
	raw, _ := json.Marshal(p)
	var err error
	for range 20 {
		err = f.write(func() error {
			_, err := f.svc.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: f.org, Kind: kind, Payload: raw})
			return err
		})
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
			break
		}
	}
	if err != nil {
		d.t.Fatalf("%s: %v", kind, err)
	}
}

func (d *gateVoters) audit(n int) {
	d.t.Helper()
	for i := range n {
		row := model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: "export.chunk", Reason: "gate", Time: int64(1_000 + i), Org: model.ID{2}.String(), PolicyEpoch: 1, RequestID: model.ID{6}, Outcome: model.AuditAllowed}
		var err error
		for range 20 {
			err = d.fx[1].write(func() error {
				return d.stores[1].AppendAudit(context.Background(), func(model.ReadOnlyControl) error { return nil }, row)
			})
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
				break
			}
		}
		if err != nil {
			d.t.Fatalf("audit row: %v", err)
		}
	}
}

func (d *gateVoters) counts() (patches, deltas uint64) {
	for _, s := range d.stores {
		p, _ := s.StatePatchStatsForTest()
		c, _ := s.AuditDeltaStatsForTest()
		patches, deltas = patches+p, deltas+c
	}
	return
}

// orgs is the organization record of every voter as stored, after the voters converged and none failed.
func (d *gateVoters) orgs() map[uint64]string {
	d.t.Helper()
	d.converge()
	var want string
	out := map[uint64]string{}
	for id := uint64(1); id <= 3; id++ {
		if d.stores[id].ReplicaGroup().Status().Failed {
			d.t.Fatalf("voter %d: the group failed", id)
		}
		canonical := d.fx[id].canonicalState()
		if id == 1 {
			want = canonical
		} else if canonical != want {
			d.t.Fatalf("voter %d holds a control state that differs from voter 1's", id)
		}
		if err := d.stores[id].View(context.Background(), func(st control.State) error {
			raw, _ := json.Marshal(st.Orgs[d.fx[1].org.String()])
			out[id] = string(raw)
			return nil
		}); err != nil {
			d.t.Fatal(err)
		}
	}
	return out
}

func hasObjectRecords(org string) bool {
	return strings.Contains(org, model.ObjSeenKey) && strings.Contains(org, model.ObjEpochKeyPrefix)
}

func (d *gateVoters) trackedSaves() {
	d.t.Helper()
	project := model.NewID()
	d.save("create_project", auth.AdminPayload{ID: project, Name: "gated"})
	d.save("grant", auth.AdminPayload{UserID: d.fx[1].user, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}})
	d.save("membership", auth.AdminPayload{UserID: d.fx[1].user, Enabled: true})
}

// Three voters at every declared protocol: admin saves commit as patches (from 5) or whole states, audit rows
// as deltas (from 4), and the object records of the organization are on every voter, identical, after the
// saves and after a restart of a voter. The records need no protocol: they are Settings keys the previous
// release carries and ignores (D59).
func TestObjectRecordsAreWrittenAtEveryProtocolAndEveryVoterHoldsThem(t *testing.T) {
	d := newGateVoters(t, 5)
	p0, d0 := d.counts()
	d.trackedSaves()
	d.audit(3)
	orgs := d.orgs()
	for id, org := range orgs {
		if !hasObjectRecords(org) {
			t.Fatalf("voter %d: no object records after tracked saves: %s", id, org)
		}
		if org != orgs[1] {
			t.Fatalf("voter %d holds a different organization than voter 1:\n%s\n%s", id, org, orgs[1])
		}
	}
	if p, dl := d.counts(); p-p0 == 0 || dl-d0 != 3 {
		t.Fatalf("with every member at 5: %d patches and %d deltas proposed, want patches and 3 deltas", p-p0, dl-d0)
	}
	d.restart(2)
	d.install(2)
	d.trackedSaves()
	orgs = d.orgs()
	for id, org := range orgs {
		if !hasObjectRecords(org) || org != orgs[1] {
			t.Fatalf("voter %d after a restart: %s (voter 1: %s)", id, org, orgs[1])
		}
	}
}

// One member below 5 closes the patch gate (whole-state fallback on every voter) while the delta gate,
// which needs 4, stays open; one below 4 closes both. The object records are written either way (they are
// Settings keys, not a protocol).
func TestStatePatchAndAuditDeltaGatesFallBackBelowTheirOwnProtocol(t *testing.T) {
	d := newGateVoters(t, 4)
	p0, d0 := d.counts()
	d.trackedSaves()
	d.audit(2)
	p, dl := d.counts()
	if p-p0 != 0 || dl-d0 != 2 {
		t.Fatalf("a member at 4: %d patches and %d deltas, want no patch and 2 deltas", p-p0, dl-d0)
	}
	for id, org := range d.orgs() {
		if !hasObjectRecords(org) {
			t.Fatalf("voter %d: no object records at 4: %s", id, org)
		}
	}
	d.lowest.Store(3)
	p0, d0 = d.counts()
	d.trackedSaves()
	d.audit(2)
	if p, dl = d.counts(); p-p0 != 0 || dl-d0 != 0 {
		t.Fatalf("a member at 3: %d patches and %d deltas, want the whole-state path only", p-p0, dl-d0)
	}
	d.orgs()
}
