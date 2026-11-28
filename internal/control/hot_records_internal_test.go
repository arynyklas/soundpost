// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// D85: the grouping issues and the applied-command log (Commands, CommandOwners) are records of the ledger,
// like the job and issue books: the tests of the layer below the writers.

func TestHotMemberOpsAreLedgerOps(t *testing.T) {
	for _, member := range []string{"GroupingIssues", "Commands", "CommandOwners"} {
		if !ledgerRoot(member) || !bookRoot(member) {
			t.Errorf("%s is not a root of the ledger", member)
		}
		for _, op := range []string{opSet, opDelete} {
			if !validLedgerOp(patchOp{Op: op, Path: []string{member, "k"}}) {
				t.Errorf("%s of a record of %s is refused", op, member)
			}
			if validLedgerOp(patchOp{Op: op, Path: []string{member, "k", "deeper"}}) {
				t.Errorf("%s inside a record of %s is accepted", op, member)
			}
			if !wholeMemberOp(patchOp{Op: op, Path: []string{member}}) {
				t.Errorf("%s of the whole of %s is not the op of the blob layout", op, member)
			}
		}
		patch := &statePatch{Ops: []patchOp{revisionOp(2), {Op: opSet, Path: []string{member, "k"}, Value: json.RawMessage(`{}`)}}}
		if ledgerOnlyPatch(patch) {
			t.Errorf("a patch of %s is held for admission's sake like an admission command", member)
		}
	}
	for table, scope := range map[int]memberScope{tableGroupingIssues: scopeBooks, tableCommands: scopeCommands, tableCommandOwners: scopeCommands, tableJobBooks: scopeBooks, tableReservations: scopeAdmission} {
		if tableScope(table) != scope {
			t.Errorf("table %s is of scope %d, want %d", ledgerTables[table], tableScope(table), scope)
		}
	}
}

func hotIssue(r *rand.Rand, n int) model.GroupingIssue {
	return model.GroupingIssue{ID: model.ID{byte(n), 1}, Org: model.ID{1}, Project: model.ID{2}, Workflow: "open", Revision: model.Revision(1 + r.IntN(9))}
}

type hotCopy struct {
	issues map[string]model.GroupingIssue
	cmds   map[string]model.ControlResult
	owners map[string]string
}

// hotResult is the result a command of the log holds: a revision and the cursor of it.
func hotResult(revision int) model.ControlResult {
	return model.ControlResult{Revision: model.Revision(revision), Phase: "applied", AffectedIDs: []model.ID{{9, byte(revision)}}, Cursor: model.Cursor{Group: model.ID{1}, Index: model.Uint64(revision)}}
}

func (h hotCopy) members() ledgerMembers {
	m := ledgerMembers{GroupingIssues: map[string]model.GroupingIssue{}, Commands: map[string]model.ControlResult{}, CommandOwners: map[string]string{}}
	for k, v := range h.issues {
		m.GroupingIssues[k] = v
	}
	for k, v := range h.cmds {
		m.Commands[k] = v
	}
	for k, v := range h.owners {
		m.CommandOwners[k] = v
	}
	return m.normalized()
}

// Applying ops to the ledger leaves the records the ops name, the accumulator is the fold of them, the ops
// verify against what they wrote, and the ops that diffLedger finds between two assemblies give the same
// ledger on another file.
func TestHotRecordsFollowTheOps(t *testing.T) {
	for seed := range uint64(40) {
		r := rand.New(rand.NewPCG(seed, 85))
		a, b := newLedgerStore(t), newLedgerStore(t)
		cur := hotCopy{issues: map[string]model.GroupingIssue{}, cmds: map[string]model.ControlResult{}, owners: map[string]string{}}
		for round := range 12 {
			before := cur.members()
			var ops []patchOp
			for range 1 + r.IntN(6) {
				key := fmt.Sprintf("k%d", r.IntN(8))
				switch r.IntN(3) {
				case 0:
					if r.IntN(4) == 0 {
						ops = append(ops, patchOp{Op: opDelete, Path: []string{"GroupingIssues", key}})
						delete(cur.issues, key)
						continue
					}
					gi := hotIssue(r, r.IntN(200))
					raw, _ := json.Marshal(gi)
					ops = append(ops, patchOp{Op: opSet, Path: []string{"GroupingIssues", key}, Value: raw})
					cur.issues[key] = gi
				case 1:
					if r.IntN(4) == 0 {
						ops = append(ops, patchOp{Op: opDelete, Path: []string{"Commands", key}})
						delete(cur.cmds, key)
						continue
					}
					res := hotResult(r.IntN(1000))
					raw, _ := json.Marshal(res)
					ops = append(ops, patchOp{Op: opSet, Path: []string{"Commands", key}, Value: raw})
					cur.cmds[key] = res
				default:
					if r.IntN(4) == 0 {
						ops = append(ops, patchOp{Op: opDelete, Path: []string{"CommandOwners", key}})
						delete(cur.owners, key)
						continue
					}
					owner := fmt.Sprintf("p%d:o:Kind", r.IntN(50))
					raw, _ := json.Marshal(owner)
					ops = append(ops, patchOp{Op: opSet, Path: []string{"CommandOwners", key}, Value: raw})
					cur.owners[key] = owner
				}
			}
			ops = lastOpPerPath(ops)
			writeLedger(t, a, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
			checkLedger(t, a, cur.members(), fmt.Sprintf("seed %d round %d", seed, round))
			if err := a.db.View(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				return l.verifyLedgerOps(ops)
			}); err != nil {
				t.Fatalf("seed %d round %d: the ops do not verify against what they wrote: %v", seed, round, err)
			}
			found := diffLedger(before, cur.members())
			writeLedger(t, b, func(l *ledgerTx) error { return l.applyLedgerOps(found) })
			var accA, accB [32]byte
			read := func(s *Store, acc *[32]byte) {
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					*acc = l.acc
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			read(a, &accA)
			read(b, &accB)
			if accA != accB {
				t.Fatalf("seed %d round %d: the ops of the diff leave another accumulator than the ops they diff", seed, round)
			}
		}
		checkLedger(t, b, cur.members(), fmt.Sprintf("seed %d diff", seed))
	}
}

// A record of the grouping issues and of the command log is stored in the encoding of its value, whatever the
// spacing the command carried, and one that does not decode into its type is refused.
func TestHotRecordsAreStoredCanonical(t *testing.T) {
	s := newLedgerStore(t)
	compact, _ := json.Marshal(hotResult(7))
	var spaced bytes.Buffer
	if err := json.Indent(&spaced, compact, " ", "  "); err != nil {
		t.Fatal(err)
	}
	writeLedger(t, s, func(l *ledgerTx) error {
		return l.applyLedgerOps([]patchOp{
			{Op: opSet, Path: []string{"Commands", "c"}, Value: spaced.Bytes()},
			{Op: opSet, Path: []string{"CommandOwners", "c"}, Value: json.RawMessage(` "p:o:K" `)},
		})
	})
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		want, _ := json.Marshal(hotResult(7))
		if got := l.t[tableCommands].Get([]byte("c")); !bytes.Equal(got, want) {
			t.Errorf("the command is stored as %q, want %q", got, want)
		}
		if got := string(l.t[tableCommandOwners].Get([]byte("c"))); got != "p:o:K" {
			t.Errorf("the owner is stored as %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []patchOp{
		{Op: opSet, Path: []string{"Commands", "d"}, Value: json.RawMessage(`[1]`)},
		{Op: opSet, Path: []string{"CommandOwners", "d"}, Value: json.RawMessage(`{}`)},
		{Op: opSet, Path: []string{"GroupingIssues", "d"}, Value: json.RawMessage(`"x"`)},
	} {
		err := s.db.Update(func(tx *bolt.Tx) error {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			return l.applyLedgerOps([]patchOp{op})
		})
		if err == nil {
			t.Errorf("%v was stored", op.Path)
		}
	}
}

// membersOfKeyed reads the records of one command and no others of the log, and the other members whole.
func TestKeyedCommandScopeReadsOneRecord(t *testing.T) {
	s := newLedgerStore(t)
	r := rand.New(rand.NewPCG(3, 85))
	writeLedger(t, s, func(l *ledgerTx) error {
		m := ledgerMembers{GroupingIssues: map[string]model.GroupingIssue{"i1": hotIssue(r, 1), "i2": hotIssue(r, 2)}, Commands: map[string]model.ControlResult{}, CommandOwners: map[string]string{}}
		for i := range 50 {
			id := fmt.Sprintf("c%02d", i)
			m.Commands[id] = hotResult(i)
			m.CommandOwners[id] = "p:o:K"
		}
		return l.replace(m)
	})
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		m, err := l.membersOfKeyed(scopeBooks|scopeCommands, "c07")
		if err != nil {
			return err
		}
		if len(m.Commands) != 1 || m.Commands["c07"].Revision != 7 || len(m.CommandOwners) != 1 || len(m.GroupingIssues) != 2 {
			t.Errorf("keyed members: %d commands, %d owners, %d issues", len(m.Commands), len(m.CommandOwners), len(m.GroupingIssues))
		}
		if m, err = l.membersOfKeyed(scopeBooks|scopeCommands, "absent"); err != nil || len(m.Commands) != 0 || len(m.CommandOwners) != 0 {
			t.Errorf("a command that is not in the log reads %d records (%v)", len(m.Commands), err)
		}
		if m, err = l.membersOfKeyed(scopeBooks, "c07"); err != nil || m.Commands != nil || len(m.GroupingIssues) != 2 {
			t.Errorf("the log was read by a scope that does not name it")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A file of the build before D85 (format 3: the job and issue books are records, the grouping issues and the
// command log are in the blob) is moved at Open: the three members leave the blob for the ledger and the
// logical state, its revision and its digest stay what they were.
func TestOpenMovesTheHotMembersOfAnEarlierFormat(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	activateLedger(t, s)
	r := rand.New(rand.NewPCG(8, 85))
	issues := map[string]model.GroupingIssue{"o:p:i1": hotIssue(r, 1), "o:p:i2": hotIssue(r, 2)}
	commands := map[string]model.ControlResult{"c1": hotResult(3), "c2": hotResult(4)}
	owners := map[string]string{"c1": "p:o:A", "c2": "p:o:B"}
	jobs := map[string]json.RawMessage{"o:p:j1": bookRecord(r, "j1")}
	var want State
	if err = s.db.Update(func(tx *bolt.Tx) error {
		var st State
		if err := loadLogical(tx, &st); err != nil {
			return err
		}
		st.GroupingIssues, st.Commands, st.CommandOwners = issues, commands, owners
		st.JobBooks = jobs
		st.Revision = 41
		want = st
		ctrl := tx.Bucket([]byte("control"))
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = l.replace(ledgerMembers{JobBooks: jobs}); err != nil {
			return err
		}
		raw, err := json.Marshal(func() State {
			c := st
			detachScope(&c, scopeAdmission)
			c.JobBooks, c.IssueBooks = nil, nil // the job and issue books are records in the layout of the build before D85
			return c
		}())
		if err != nil {
			return err
		}
		if err = putStateLayout(ctrl, raw); err != nil {
			return err
		}
		return ctrl.Put(ledgerFormatKey, hotMembersInBlobFormat)
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if !ledgerLayout(ctrl) || !bytes.Equal(ctrl.Get(ledgerSealKey), ctrl.Get(stateSealKey)) {
			t.Errorf("the file is not of the current format after Open: %v", ctrl.Get(ledgerFormatKey))
		}
		members, err := decodeMembers(ctrl.Get(stateKey))
		if err != nil {
			return err
		}
		for _, name := range []string{"GroupingIssues", "Commands", "CommandOwners", "JobBooks", "IssueBooks", memberRevision} {
			if v, ok := members[name]; ok && string(v) != "null" {
				t.Errorf("the blob still holds %s: %.80s", name, v)
			}
		}
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		got, err := l.members()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got.GroupingIssues, issues) || !reflect.DeepEqual(got.Commands, commands) || !reflect.DeepEqual(got.CommandOwners, owners) || !reflect.DeepEqual(got.JobBooks, jobs) {
			t.Errorf("the ledger holds issues %v commands %v owners %v jobs %v", got.GroupingIssues, got.Commands, got.CommandOwners, got.JobBooks)
		}
		if recomputeAcc(l) != l.acc {
			t.Error("the accumulator is not the fold of the records after the move")
		}
		var logical State
		if err := loadLogical(tx, &logical); err != nil {
			return err
		}
		a, _ := json.Marshal(logical)
		b, _ := json.Marshal(want)
		if !bytes.Equal(a, b) {
			t.Errorf("the logical state changed by the move:\n%.300s\n%.300s", a, b)
		}
		snap, err := snapshotState(tx)
		if err != nil {
			return err
		}
		if !bytes.Equal(snap, a) {
			t.Error("the snapshot stream is not the encoding of the logical state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
