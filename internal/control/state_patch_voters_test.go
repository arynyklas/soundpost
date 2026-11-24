// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The state patch command (state_patch.go) through the real three-voter control group: a patch
// that the group committed has to survive what a replicated machine goes through in production, on
// every voter: a restart that replays the journal over a machine that applied it, a snapshot install
// on a voter that fell behind, a restart of every voter, a group in which one voter has not
// declared the protocol. The machine-level tests (state_patch_store_internal_test.go) drive Apply on
// one store.

// patchVoters is controlVoters whose stores share one state patch gate, which stands for what
// storage.Engine.ControlStatePatchReady answers on every member of a group: open only once every
// member declared protocol 5.
type patchVoters struct {
	*controlVoters
	open atomic.Bool
	next atomic.Int64
	want []string // the records the test committed, in commit order
}

func newPatchVoters(t *testing.T, cadence replica.Cadence, open bool) *patchVoters {
	t.Helper()
	d := &patchVoters{controlVoters: newControlVotersCadence(t, cadence)}
	d.open.Store(open)
	for _, s := range d.stores {
		s.SetStatePatchGate(d.open.Load)
	}
	return d
}

// restart is controlVoters.restart over a store that has the shared gate again.
func (d *patchVoters) restart(id uint64) {
	d.t.Helper()
	d.controlVoters.restart(id)
	d.stores[id].SetStatePatchGate(d.open.Load)
}

// write commits n transitions through voter from's Update (a follower's proposal is forwarded to the
// leader); each adds one opaque book record, so the command is a patch of one record. A commit that
// lost the race for its revision to another control write (a background writer) is stale: it is built
// again from the newer state, as every caller of Update does.
func (d *patchVoters) write(from uint64, n int) {
	d.t.Helper()
	for range n {
		k := d.next.Add(1)
		key := fmt.Sprintf("patch:voters:record-%d", k)
		value := json.RawMessage(fmt.Sprintf(`{"n":%d,"from":%d}`, k, from))
		var err error
		for range 20 {
			err = d.fx[from].write(func() error {
				return d.stores[from].Update(context.Background(), func(st *control.State) error {
					if st.IncidentBooks == nil {
						st.IncidentBooks = map[string]json.RawMessage{}
					}
					st.IncidentBooks[key] = value
					return nil
				})
			})
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
				break
			}
		}
		if err != nil {
			d.t.Fatalf("voter %d: record %s: %v", from, key, err)
		}
		d.want = append(d.want, key)
	}
}

// patches is the number of patch commands the voters proposed in all.
func (d *patchVoters) patches() (n uint64) {
	for _, s := range d.stores {
		c, _ := s.StatePatchStatsForTest()
		n += c
	}
	return n
}

// agree waits until every voter has the newest revision and then requires, on every voter: the same
// canonical control state (bytes and hash), no failed group, and every record the test committed.
func (d *patchVoters) agree() {
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
		var held int
		if err := d.stores[id].View(context.Background(), func(st control.State) error {
			for _, key := range d.want {
				if _, ok := st.IncidentBooks[key]; ok {
					held++
				}
			}
			return nil
		}); err != nil {
			d.t.Fatalf("voter %d: %v", id, err)
		}
		if held != len(d.want) {
			d.t.Fatalf("voter %d holds %d of the %d records the test committed", id, held, len(d.want))
		}
	}
}

// A patch the group committed is replayed by a voter that restarts: its journal holds the command
// and the machine, which applied it, verifies the replay against the committed state instead of
// applying it twice. The voter reaches the leader's state, its group stays up, and a patch proposed
// after the restart still commits against the restarted voter's revision.
func TestStatePatchSurvivesAFollowerJournalReplayAfterARestart(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{}, true)
	before := d.patches()
	d.write(1, 8)
	d.write(2, 4) // proposed by a follower, forwarded to the leader
	if n := d.patches() - before; n < 12 {
		t.Fatalf("%d patch commands were proposed for 12 commands (the gate is open)", n)
	}
	d.agree()
	d.restart(2)
	d.agree()
	d.restart(3)
	d.write(2, 3)
	d.write(3, 3)
	d.agree()
}

// A voter that is behind a cut of the leader's journal learns the patches from the snapshot the
// leader installs: the snapshot holds the whole state, the records are in it, and the voter then
// applies the patches that follow.
//
// The premise (the voter is behind the journal's head, so the only way to catch up is a snapshot) is
// made, not waited for: while the voter is cut off, the commits go in, and then the test itself cuts a
// snapshot and compacts the journal on the two reachable voters, whichever of them leads, until the
// head of each journal is past the first entry the lagging voter is missing. How many entries a
// journal keeps beyond the cut does not matter, nor does when the cadence loop gets to run.
func TestStatePatchSurvivesASnapshotInstallOnALaggingVoter(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{Commands: 16}, true)
	d.mesh.cut(stormVoter, true)
	patchesBefore := d.patches()
	d.write(1, 60)
	if n := d.patches() - patchesBefore; n < 60 {
		t.Fatalf("%d patch commands were proposed for 60 commands (the gate is open)", n)
	}
	for _, id := range []uint64{1, 2} {
		g := d.stores[id].ReplicaGroup()
		d.eventually(fmt.Sprintf("voter %d cut a snapshot and compacted its journal past voter %d", id, stormVoter), func() bool {
			// The cut voter takes nothing in, so its last index is read each time: the journal has to
			// be past the entry that follows it, or it would catch up from the log.
			_, behind := d.stores[stormVoter].ReplicaGroup().JournalRange()
			if first, _ := g.JournalRange(); first > behind+1 {
				return true
			}
			// A cadence cut that runs beside this one, or a machine that has not applied the cut yet,
			// answers with an error: the next attempt takes the newer state.
			if _, err := g.CreateSnapshot(context.Background(), g.Status().ApplicationCursor); err != nil {
				return false
			}
			if _, err := g.CompactJournal(context.Background()); err != nil {
				return false
			}
			first, _ := g.JournalRange()
			return first > behind+1
		})
	}
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
		t.Fatalf("voter %d caught up without installing a snapshot: the compacted journals left it no other way", stormVoter)
	}
	d.agree()
	d.write(stormVoter, 4) // the installed voter proposes against the installed revision
	d.write(1, 4)
	d.agree()
}

// Every voter restarts, one after the other, over journals that hold the patches (a rolling restart
// of the cluster): each one reaches the group's state, and the group commits patches again.
func TestStatePatchSurvivesTheRestartOfEveryVoter(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{}, true)
	d.write(1, 10)
	d.agree()
	for _, id := range []uint64{3, 2, 1} {
		d.restart(id)
		d.agree()
	}
	d.settle()
	before := d.patches()
	d.write(2, 5)
	d.agree()
	if n := d.patches() - before; n < 5 {
		t.Fatalf("only %d patch commands were proposed after the restarts", n)
	}
}

// A control group in which one voter has not declared protocol 5 (the gate is closed on every voter,
// because it needs every member of the committed configuration) takes the whole-state fallback: no
// patch is proposed, whoever proposes, and the three voters converge on identical control state
// bytes. When that voter declares, patches flow and they converge again.
func TestStatePatchMixedVersionGroupTakesTheWholeStateFallbackAndConverges(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{}, false)
	// The fixture's own commands (SOUNDPOST_FORCE_STATE_PATCH opens the gate while it is built) are
	// not the test's: only what the test proposes under the closed gate counts.
	base := d.patches()
	d.write(1, 6)
	d.write(2, 3)
	d.write(3, 3)
	if n := d.patches() - base; n != 0 {
		t.Fatalf("%d patch commands were proposed while one voter had not declared the protocol", n)
	}
	d.agree()
	d.open.Store(true) // the third voter declares
	d.write(1, 4)
	d.write(3, 4)
	if n := d.patches() - base; n < 8 {
		t.Fatalf("%d patch commands were proposed for the 8 commands after every voter declared", n)
	}
	d.agree()
}
