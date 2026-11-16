// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D49 through the real three-voter control group (three stores, three journals, one in-process
// network): an audit delta that the group committed has to survive what a replicated machine goes
// through in production, on every voter: a restart that replays the journal over a machine that
// applied it, a snapshot install on a voter that fell behind, and a restart of every voter. The
// machine-level tests (audit_delta_internal_test.go) drive Apply on one store; none of them proposes
// a command through a group.

// deltaVoters is controlVoters whose stores share one audit delta gate, which stands for what
// storage.Engine.ControlAuditDeltaReady answers on every member of a group: open only once every
// member declared protocol 4.
type deltaVoters struct {
	*controlVoters
	open atomic.Bool
	next atomic.Int64
	want []model.ID // the rows the test committed, in commit order
}

func newDeltaVoters(t *testing.T, cadence replica.Cadence, open bool) *deltaVoters {
	t.Helper()
	d := &deltaVoters{controlVoters: newControlVotersCadence(t, cadence)}
	d.open.Store(open)
	for _, s := range d.stores {
		s.SetAuditDeltaGate(d.open.Load)
	}
	return d
}

// restart is controlVoters.restart over a store that has the shared gate again.
func (d *deltaVoters) restart(id uint64) {
	d.t.Helper()
	d.controlVoters.restart(id)
	d.stores[id].SetAuditDeltaGate(d.open.Load)
}

func (d *deltaVoters) row() model.ControlAudit {
	n := d.next.Add(1)
	return model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: "export.chunk", Reason: fmt.Sprintf("elevated response released %d", n), Time: 1_000 + n,
		Org: model.ID{2}.String(), PolicyEpoch: 1, Targets: []model.ID{{3}, {4}}, RequestID: model.ID{6}, Outcome: model.AuditAllowed}
}

// append commits n audit rows through voter from's AppendAudit (a follower's proposal is forwarded to
// the leader). A commit that lost the race for its revision to another control write (a background
// writer) is stale: it is built again from the newer state, as the one user of AppendAudit does.
func (d *deltaVoters) append(from uint64, n int) {
	d.t.Helper()
	check := func(model.ReadOnlyControl) error { return nil }
	for range n {
		row := d.row()
		var err error
		for range 20 {
			err = d.fx[from].write(func() error { return d.stores[from].AppendAudit(context.Background(), check, row) })
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
				break
			}
		}
		if err != nil {
			d.t.Fatalf("voter %d: audit row %v: %v", from, row.ID, err)
		}
		d.want = append(d.want, row.ID)
	}
}

// deltas is the number of delta commands the voters proposed in all.
func (d *deltaVoters) deltas() (n uint64) {
	for _, s := range d.stores {
		c, _ := s.AuditDeltaStatsForTest()
		n += c
	}
	return n
}

// agree waits until every voter has the newest revision and then requires, on every voter: the same
// canonical control state (bytes and hash), no failed group, every row the test committed in the log
// in its order, and an AuthorityRevision that did not follow the revision through the audit rows.
func (d *deltaVoters) agree(baseRevision, baseAuthority model.Revision) {
	d.t.Helper()
	d.converge()
	var want string
	var wantHash [32]byte
	for id := uint64(1); id <= 3; id++ {
		if d.stores[id].ReplicaGroup().Status().Failed {
			d.t.Fatalf("voter %d: the group failed", id)
		}
		canonical := d.fx[id].canonicalState()
		hash := sha256.Sum256([]byte(canonical))
		if id == 1 {
			want, wantHash = canonical, hash
		} else if canonical != want || hash != wantHash {
			d.t.Fatalf("voter %d holds a control state that differs from voter 1's (hash %x vs %x)", id, hash, wantHash)
		}
		var rows []model.ID
		var revision, authority model.Revision
		if err := d.stores[id].View(context.Background(), func(st control.State) error {
			for _, a := range st.Audits {
				rows = append(rows, a.ID)
			}
			revision, authority = st.Revision, st.AuthorityRevision
			return nil
		}); err != nil {
			d.t.Fatalf("voter %d: %v", id, err)
		}
		next := 0
		for _, r := range rows {
			if next < len(d.want) && r == d.want[next] {
				next++
			}
		}
		if next != len(d.want) {
			d.t.Fatalf("voter %d holds %d of the %d committed audit rows in order", id, next, len(d.want))
		}
		if revision < baseRevision+model.Revision(len(d.want)) {
			d.t.Fatalf("voter %d: revision %d after %d audit commits from %d", id, revision, len(d.want), baseRevision)
		}
		if gained, grew := revision-baseRevision, authority-baseAuthority; gained < grew+model.Revision(len(d.want)) {
			d.t.Fatalf("voter %d: the revision moved by %d and the authority revision by %d over %d audit rows: the rows moved the authority revision", id, gained, grew, len(d.want))
		}
	}
}

func (d *deltaVoters) base() (revision, authority model.Revision) {
	d.t.Helper()
	if err := d.stores[1].View(context.Background(), func(st control.State) error {
		revision, authority = st.Revision, st.AuthorityRevision
		return nil
	}); err != nil {
		d.t.Fatal(err)
	}
	return revision, authority
}

// A delta the group committed is replayed by a voter that restarts: its journal holds the command
// and the machine, which applied it, verifies the replay against the committed state instead of
// applying it twice. The voter reaches the leader's state, its group stays up, and a delta proposed
// after the restart still commits against the restarted voter's revision.
func TestAuditDeltaSurvivesAFollowerJournalReplayAfterARestart(t *testing.T) {
	d := newDeltaVoters(t, replica.Cadence{}, true)
	rev, auth := d.base()
	d.append(1, 8)
	d.append(2, 4) // proposed by a follower, forwarded to the leader
	if n := d.deltas(); n != 12 {
		t.Fatalf("%d delta commands were proposed, want 12 (the gate is open)", n)
	}
	d.agree(rev, auth)
	d.restart(2)
	d.agree(rev, auth)
	d.restart(3)
	d.append(2, 3)
	d.append(3, 3)
	d.agree(rev, auth)
}

// A voter that is behind a cut of the leader's journal learns the deltas from the snapshot the leader
// installs: the snapshot holds the whole state, the rows are in it, and the voter then applies the
// deltas that follow.
func TestAuditDeltaSurvivesASnapshotInstallOnALaggingVoter(t *testing.T) {
	d := newDeltaVoters(t, replica.Cadence{Commands: 16}, true)
	rev, auth := d.base()
	d.mesh.cut(stormVoter, true)
	d.append(1, 60)
	leader := d.stores[1].ReplicaGroup()
	d.eventually("the leader cut its journal at least twice", func() bool { return leader.CadenceCuts() >= 2 })
	d.mesh.mu.Lock()
	installed := d.mesh.snaps[stormVoter]
	d.mesh.mu.Unlock()
	if installed != 0 {
		t.Fatalf("voter %d was handed %d snapshots while it was cut off", stormVoter, installed)
	}
	d.mesh.cut(stormVoter, false)
	d.await(stormVoter, d.mustRevision(1))
	d.mesh.mu.Lock()
	installed = d.mesh.snaps[stormVoter]
	d.mesh.mu.Unlock()
	if installed < 1 {
		t.Fatalf("voter %d caught up without installing a snapshot: the test does not exercise the install", stormVoter)
	}
	d.agree(rev, auth)
	d.append(stormVoter, 4) // the installed voter proposes against the installed revision
	d.append(1, 4)
	d.agree(rev, auth)
	if n := d.deltas(); n != 68 {
		t.Fatalf("%d delta commands were proposed, want 68", n)
	}
}

// Every voter restarts, one after the other, over journals that hold the deltas (a rolling restart
// of the cluster): each one reaches the group's state, and the group commits deltas again.
func TestAuditDeltaSurvivesTheRestartOfEveryVoter(t *testing.T) {
	d := newDeltaVoters(t, replica.Cadence{}, true)
	rev, auth := d.base()
	d.append(1, 10)
	d.agree(rev, auth)
	for _, id := range []uint64{3, 2, 1} {
		d.restart(id)
		d.agree(rev, auth)
	}
	d.settle()
	d.append(2, 5)
	d.agree(rev, auth)
	if n := d.deltas(); n < 5 {
		t.Fatalf("only %d delta commands were proposed after the restarts", n)
	}
}

// A control group in which one voter has not declared protocol 4 (the gate is closed on every voter,
// because it needs every member of the committed configuration) takes the whole-state fallback: no
// delta is proposed, whoever proposes, and the three voters converge on identical control state bytes.
// When that voter declares, deltas flow and they converge again.
func TestAuditDeltaMixedVersionGroupTakesTheWholeStateFallbackAndConverges(t *testing.T) {
	d := newDeltaVoters(t, replica.Cadence{}, false)
	rev, auth := d.base()
	d.append(1, 6)
	d.append(2, 3)
	d.append(3, 3)
	if n := d.deltas(); n != 0 {
		t.Fatalf("%d delta commands were proposed while one voter had not declared the protocol", n)
	}
	d.agree(rev, auth)
	d.open.Store(true) // the third voter declares
	d.append(1, 4)
	d.append(3, 4)
	if n := d.deltas(); n != 8 {
		t.Fatalf("%d delta commands were proposed after every voter declared, want 8", n)
	}
	d.agree(rev, auth)
}
