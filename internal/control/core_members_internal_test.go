// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The decode of the state without the ledger (coreState) is kept per member of the blob. A commit
// that changed a few members costs the next reader the decode of those members and nothing else: the
// whole blob (1.8 MB at the single-host gate's estate) was decoded again after every rule commit and
// every outbox write, by every reader that came after them.

// newCoreFx is a replicated store of the ledger layout (layout 2: the blob holds the members, the
// revision is outside it) whose state holds a few books.
func newCoreFx(t *testing.T) *installFx {
	t.Helper()
	f := newInstallFxOf(t, 3)
	activateLedger(t, f.s)
	return f
}

// rewrite replaces the blob with the encoding of the state change makes of it, in a write transaction of its own
// that leaves the revision alone: a commit that changes exactly the members change touches.
func (f *installFx) rewrite(change func(*State)) {
	f.t.Helper()
	f.mutantWrite(func(ctrl *bolt.Bucket) error {
		var st State
		if err := readState(ctrl, &st); err != nil {
			return err
		}
		change(&st)
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return putState(ctrl, raw)
	})
}

// core is the state a shared reader is given (coreState) and, beside it, the state the whole decode of the
// same snapshot gives without the members a core reader does not see. The two must be the same
// state: the revision clock of the one may be older than the other's (a step moves the clock outside the
// blob), so it is left out of both.
func (f *installFx) core() State {
	f.t.Helper()
	var got, want State
	if err := f.s.db.View(func(tx *bolt.Tx) error {
		return f.s.coreStateAgainstWhole(tx, &got, &want)
	}); err != nil {
		f.t.Fatal(err)
	}
	f.sameState(got, want)
	return got
}

func (f *installFx) sameState(got, want State) {
	f.t.Helper()
	got.RevisionClock, want.RevisionClock = nil, nil
	if !reflect.DeepEqual(got, want) {
		var g, w map[string]json.RawMessage
		_ = json.Unmarshal(mustMarshal(f.t, got), &g)
		_ = json.Unmarshal(mustMarshal(f.t, want), &w)
		for name := range g {
			if string(g[name]) != string(w[name]) {
				f.t.Errorf("member %s: the shared decode holds %.120s, the whole decode %.120s", name, g[name], w[name])
			}
		}
		f.t.Fatal("the shared decode is not the whole decode")
	}
}

// coreStateAgainstWhole fills got with coreState(tx) and want with the whole decode of tx's blob.
func (s *Store) coreStateAgainstWhole(tx *bolt.Tx, got, want *State) error {
	st, err := s.coreState(tx)
	if err != nil {
		return err
	}
	*got = *st
	if err = readState(tx.Bucket([]byte("control")), want); err != nil {
		return err
	}
	want.JobBooks = nil // the job books are not part of what a core reader sees
	return nil
}

func (f *installFx) counters() (whole, members uint64) {
	return f.s.db.decodes.Load(), f.s.db.memberDecodes.Load()
}

// A write that changed k members makes the next shared read decode those k members, and no write that changed no member
// a core reader sees makes it decode anything. Every read is also compared with the whole decode of its snapshot.
func TestCoreStateRedecodesOnlyTheMembersAWriteChanged(t *testing.T) {
	f := newCoreFx(t)
	f.core() // the first read decodes the state
	for _, step := range []struct {
		name    string
		members int
		write   func(*State)
	}{
		{"a scalar", 1, func(st *State) { st.BootstrapHash = "changed" }},
		{"a book of the blob", 1, func(st *State) { st.IncidentBooks["extra"] = json.RawMessage(`{"n":1}`) }},
		{"a map of records", 1, func(st *State) {
			st.Users = map[string]model.ControlUser{"u": {ID: model.ID{9}, Email: "u@example.test"}}
		}},
		{"two members", 2, func(st *State) { st.BearerHashKey = "k"; st.PolicySigningKey = "p" }},
		{"a member that is emptied", 1, func(st *State) { st.IncidentBooks = nil }},
		{"the job books, which no core reader reads", 0, func(st *State) {
			st.JobBooks = map[string]json.RawMessage{"j": json.RawMessage(`{"version":"1"}`)}
		}},
		{"nothing at all", 0, func(*State) {}},
	} {
		f.rewrite(step.write)
		whole0, members0 := f.counters()
		got := f.core()
		for range 5 {
			f.core()
		}
		whole1, members1 := f.counters()
		if whole1 != whole0 {
			t.Errorf("%s: %d whole-state decodes after the write, want none", step.name, whole1-whole0)
		}
		if members1-members0 != uint64(step.members) {
			t.Errorf("%s: %d members decoded after the write, want %d", step.name, members1-members0, step.members)
		}
		if step.name == "a scalar" && got.BootstrapHash != "changed" {
			t.Errorf("%s: the read after the write holds %q", step.name, got.BootstrapHash)
		}
	}
}

// A reader whose snapshot is older than a commit sees the members of its own snapshot, whatever the readers of the newer
// snapshots decoded and published in the meantime, and the newer readers are not served the older members.
func TestCoreStateOlderSnapshotSeesItsOwnMembers(t *testing.T) {
	f := newCoreFx(t)
	f.core()
	older, err := f.s.db.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	defer older.Rollback()
	f.rewrite(func(st *State) { st.BootstrapHash = "newer"; st.IncidentBooks["x"] = json.RawMessage(`{}`) })
	if got := f.core(); got.BootstrapHash != "newer" {
		t.Fatalf("a reader after the write holds %q", got.BootstrapHash)
	}
	var got, want State
	if err = f.s.coreStateAgainstWhole(older, &got, &want); err != nil {
		t.Fatal(err)
	}
	f.sameState(got, want)
	if got.BootstrapHash == "newer" || len(got.IncidentBooks) != 3 {
		t.Fatalf("the reader of the older snapshot holds %q and %d incident books", got.BootstrapHash, len(got.IncidentBooks))
	}
	if got := f.core(); got.BootstrapHash != "newer" || len(got.IncidentBooks) != 4 {
		t.Fatalf("a reader after the older one holds %q and %d incident books", got.BootstrapHash, len(got.IncidentBooks))
	}
}

// Over random transitions, committed the two ways a group commits them (a replacement, a patch), and with
// readers on every kind of snapshot, the shared decode is the whole decode of the snapshot it was read in.
func TestCoreStateEqualsTheWholeDecodeOverRandomTransitions(t *testing.T) {
	f := newCoreFx(t)
	r := rand.New(rand.NewPCG(21, 4))
	f.core()
	for step := range 160 {
		patch := step%2 == 0
		f.s.SetStatePatchGate(func() bool { return patch })
		transition := func(st *State) error {
			tr := rand.New(rand.NewPCG(uint64(step), 9))
			for range 1 + tr.IntN(4) {
				mutateState(tr, st)
			}
			return nil
		}
		var older *bolt.Tx
		if r.IntN(3) == 0 {
			var err error
			if older, err = f.s.db.Begin(false); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.s.Update(f.ctx, transition); err != nil {
			t.Fatalf("transition %d: %v", step, err)
		}
		if r.IntN(4) != 0 {
			f.core()
		}
		if older != nil {
			var got, want State
			if err := f.s.coreStateAgainstWhole(older, &got, &want); err != nil {
				t.Fatal(err)
			}
			f.sameState(got, want)
			older.Rollback()
		}
		if step%7 == 0 {
			f.rewrite(func(st *State) {
				switch r.IntN(3) {
				case 0:
					st.BootstrapHash = fmt.Sprintf("h%d", r.IntN(9))
				case 1:
					if st.IncidentBooks == nil {
						st.IncidentBooks = map[string]json.RawMessage{}
					}
					st.IncidentBooks[fmt.Sprintf("b%d", r.IntN(4))] = json.RawMessage(fmt.Sprintf(`{"n":%d}`, r.IntN(99)))
				default:
					n := r.IntN(3)
					st.Holds = map[string]model.LegalHold{fmt.Sprintf("h%d", n): {ID: model.ID{0xb0, byte(n)}, Org: model.ID{0xb1}, PlacedBy: model.ID{0xb2}}}
				}
			})
		}
		f.core()
	}
}
