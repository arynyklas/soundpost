// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Commands are applied to the bytes of the committed state (state_raw.go) without decoding it. Every
// voter has to end up holding the same bytes, and those have to be the bytes the encoder writes for
// the state (a voter restored from a snapshot, or one that applied a replacement, holds the encoding
// of a State): a splice that left other bytes would pass the three voters' own comparison of the
// state they decode and fail the next base digest.

// rawWork commits a mixed workload through voter from: records of a book, users, an organization
// with settings that is edited and emptied, sessions, command results, audit rows (the delta
// command), and a log that is cut.
func (d *patchVoters) rawWork(from uint64, round int) {
	d.t.Helper()
	ctx := context.Background()
	update := func(fn func(st *control.State) error) {
		d.t.Helper()
		var err error
		for range 20 {
			err = d.fx[from].write(func() error { return d.stores[from].Update(ctx, fn) })
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
				break
			}
		}
		if err != nil {
			d.t.Fatalf("voter %d round %d: %v", from, round, err)
		}
	}
	org := fmt.Sprintf("org-%d", round%3)
	update(func(st *control.State) error {
		if st.Users == nil {
			st.Users = map[string]model.ControlUser{}
		}
		st.Users[fmt.Sprintf("user-%d", round%5)] = model.ControlUser{ID: model.ID{byte(round), 1}, Email: fmt.Sprintf("u%d@example.test", round)}
		return nil
	})
	update(func(st *control.State) error {
		if st.Orgs == nil {
			st.Orgs = map[string]model.ControlOrg{}
		}
		o := st.Orgs[org]
		o.ID = model.ID{byte(round % 3), 2}
		o.Epoch++
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		o.Settings[fmt.Sprintf("setting:%d", round%4)] = json.RawMessage(fmt.Sprintf(`{"round":%d,"html":"<a&b>"}`, round))
		st.Orgs[org] = o
		return nil
	})
	update(func(st *control.State) error {
		o := st.Orgs[org]
		if round%4 == 3 {
			clear(o.Settings) // emptied: a map that is {} afterwards
		}
		st.Orgs[org] = o
		if st.Sessions == nil {
			st.Sessions = map[string]model.ControlSession{}
		}
		st.Sessions[fmt.Sprintf("s-%d", round)] = model.ControlSession{User: model.ID{byte(round), 7}, CSRF: "c", Expires: 1 << 40}
		if round%3 == 2 {
			delete(st.Sessions, fmt.Sprintf("s-%d", round-1))
		}
		return nil
	})
	d.write(from, 2)
	check := func(model.ReadOnlyControl) error { return nil }
	for i := range 2 {
		row := model.ControlAudit{ID: model.ID{byte(round), byte(i), 9}, Principal: model.ID{1}, Action: "export.chunk", Reason: fmt.Sprintf("released %d/%d", round, i), Time: int64(1_000 + round), Outcome: model.AuditAllowed}
		var err error
		for range 20 {
			err = d.fx[from].write(func() error { return d.stores[from].AppendAudit(context.Background(), check, row) })
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Stale && fault.Code != model.Conflict {
				break
			}
		}
		if err != nil {
			d.t.Fatalf("voter %d round %d: audit: %v", from, round, err)
		}
	}
}

// sameBytes requires every voter to hold the same state bytes, and those to be the encoding of the
// state they decode to; it returns them.
func (d *patchVoters) sameBytes() []byte {
	d.t.Helper()
	d.converge()
	var first []byte
	for id := uint64(1); id <= 3; id++ {
		raw, err := d.stores[id].StateBytesForTest()
		if err != nil {
			d.t.Fatal(err)
		}
		var st control.State
		if err := json.Unmarshal(raw, &st); err != nil {
			d.t.Fatalf("voter %d: %v", id, err)
		}
		again, err := json.Marshal(st)
		if err != nil {
			d.t.Fatal(err)
		}
		if !bytes.Equal(raw, again) {
			d.t.Fatalf("voter %d holds a state that is not the encoding of the State it decodes to (%d bytes, re-encoded %d)", id, len(raw), len(again))
		}
		if first == nil {
			first = raw
		} else if !bytes.Equal(raw, first) {
			d.t.Fatalf("voter %d holds other state bytes than voter 1 (%d vs %d bytes)", id, len(raw), len(first))
		}
	}
	return first
}

func (d *patchVoters) applyStats() (spliced, decoded [4]uint64) {
	for id := uint64(1); id <= 3; id++ {
		spliced[id], decoded[id] = d.stores[id].ApplyPathStatsForTest()
	}
	return spliced, decoded
}

// Three voters, commands proposed by each of them (a follower's forwarded to the leader), and a
// restart in the middle: every command is applied to the bytes on every voter (none decodes the
// state), and the bytes are the same everywhere and are the encoding of a State.
func TestPatchedStateBytesAreIdenticalOnEveryVoter(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{}, true)
	for _, s := range d.stores {
		s.SetAuditDeltaGate(d.open.Load)
	}
	baseSpliced, baseDecoded := d.applyStats()
	for round := range 12 {
		d.rawWork(uint64(round%3)+1, round)
		d.sameBytes()
		if round == 5 {
			d.restart(2)
			for _, s := range d.stores {
				s.SetAuditDeltaGate(d.open.Load)
			}
		}
	}
	spliced, decoded := d.applyStats()
	for id := uint64(1); id <= 3; id++ {
		if id == 2 {
			continue // voter 2 restarted in the middle: its counters started again
		}
		if n := spliced[id] - baseSpliced[id]; n < 84 { // 7 commands in each of 12 rounds
			t.Fatalf("voter %d applied only %d commands to the bytes of its state", id, n)
		}
		if n := decoded[id] - baseDecoded[id]; n != 0 {
			t.Fatalf("voter %d decoded the whole state for %d commands of a workload that is all patches and deltas", id, n)
		}
	}
	d.agree()
}

// A voter that fell behind a cut of the journal installs a snapshot (the encoding of a State) and then
// applies patches to those bytes: it holds the bytes of the others afterwards.
func TestPatchedStateBytesAfterASnapshotInstallAreIdentical(t *testing.T) {
	d := newPatchVoters(t, replica.Cadence{Commands: 16}, true)
	for _, s := range d.stores {
		s.SetAuditDeltaGate(d.open.Load)
	}
	d.mesh.cut(stormVoter, true)
	for round := range 6 {
		d.rawWork(1, round)
	}
	leader := d.stores[1].ReplicaGroup()
	d.eventually("the leader cut its journal at least twice", func() bool { return leader.CadenceCuts() >= 2 })
	d.mesh.cut(stormVoter, false)
	d.await(stormVoter, d.mustRevision(1))
	d.mesh.mu.Lock()
	installed := d.mesh.snaps[stormVoter]
	d.mesh.mu.Unlock()
	if installed < 1 {
		t.Fatalf("voter %d caught up without installing a snapshot", stormVoter)
	}
	d.sameBytes()
	before, decodedBefore := d.stores[stormVoter].ApplyPathStatsForTest()
	for round := 6; round < 10; round++ {
		d.rawWork(stormVoter, round)
		d.rawWork(1, round)
	}
	d.sameBytes()
	if after, decoded := d.stores[stormVoter].ApplyPathStatsForTest(); after-before < 30 || decoded != decodedBefore {
		t.Fatalf("the installed voter applied %d commands to its bytes and decoded the state for %d", after-before, decoded-decodedBefore)
	}
	d.agree()
}
