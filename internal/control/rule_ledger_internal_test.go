// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// D108: the rule books and the rule outbox are records of the ledger in a file that carries the mark
// (model.RuleLedgerKey): the tests of the layer below the rule writers.

func ruleOutputRecord(r *rand.Rand, org, project, rule model.ID, n int) json.RawMessage {
	raw, err := json.Marshal(RuleOutput{ID: model.ID{0xdd, byte(n >> 8), byte(n)}, Org: org, Project: project, Rule: rule, Version: 1, At: model.UnixNano(n), Kind: RuleOutputRecording,
		Signal: model.Metric, Mode: RuleModeLive, Phase: RulePhasePending, Payload: json.RawMessage(fmt.Sprintf(`{"v":%d}`, r.IntN(1000))), Inputs: []model.Cursor{}, Created: model.Revision(1 + r.IntN(9))})
	if err != nil {
		panic(err)
	}
	return raw
}

// Applying ops to a file that keeps the rule facts in the ledger leaves the records the ops name, the accumulator is
// the fold of them, the ops verify against what they wrote, and the ops that diffLedger finds between two assemblies
// give the same ledger on another file.
func TestRuleRecordsFollowTheOps(t *testing.T) {
	org, project := model.ID{1}, model.ID{2}
	for seed := range uint64(30) {
		r := rand.New(rand.NewPCG(seed, 108))
		a, b := newLedgerStore(t), newLedgerStore(t)
		for _, s := range []*Store{a, b} {
			writeLedger(t, s, func(l *ledgerTx) error { return l.setRules(true) })
		}
		books, outs := map[string]json.RawMessage{}, map[string]json.RawMessage{}
		current := func() ledgerMembers {
			m := ledgerMembers{Rules: true, RuleBooks: map[string]json.RawMessage{}, RuleOutputs: map[string]json.RawMessage{}}
			for k, v := range books {
				m.RuleBooks[k] = v
			}
			for k, v := range outs {
				m.RuleOutputs[k] = v
			}
			return m
		}
		for round := range 12 {
			before := current()
			var ops []patchOp
			for range 1 + r.IntN(6) {
				rule := model.ID{3, byte(r.IntN(5))}
				if r.IntN(2) == 0 {
					key := ruleKey(org, project, rule)
					if r.IntN(5) == 0 {
						ops = append(ops, patchOp{Op: opDelete, Path: []string{"RuleBooks", key}})
						delete(books, key)
						continue
					}
					raw := json.RawMessage(fmt.Sprintf(`{"org":"%s","project":"%s","rule":"%s","head":%d}`, org, project, rule, r.IntN(100)))
					ops = append(ops, patchOp{Op: opSet, Path: []string{"RuleBooks", key}, Value: raw})
					books[key] = raw
					continue
				}
				n := r.IntN(40)
				key := ruleOutputKey(org, project, rule, model.ID{0xdd, byte(n >> 8), byte(n)})
				if r.IntN(4) == 0 {
					ops = append(ops, patchOp{Op: opDelete, Path: []string{"RuleOutputs", key}})
					delete(outs, key)
					continue
				}
				raw := ruleOutputRecord(r, org, project, rule, n)
				ops = append(ops, patchOp{Op: opSet, Path: []string{"RuleOutputs", key}, Value: raw})
				outs[key] = raw
			}
			ops = lastOpPerPath(ops)
			writeLedger(t, a, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
			checkLedger(t, a, current(), fmt.Sprintf("seed %d round %d", seed, round))
			if err := a.db.View(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				return l.verifyLedgerOps(ops)
			}); err != nil {
				t.Fatalf("seed %d round %d: the ops do not verify against what they wrote: %v", seed, round, err)
			}
			found := diffLedger(before, current())
			writeLedger(t, b, func(l *ledgerTx) error { return l.applyLedgerOps(found) })
			var accA, accB [32]byte
			for s, acc := range map[*Store]*[32]byte{a: &accA, b: &accB} {
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					*acc = l.acc
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			if accA != accB {
				t.Fatalf("seed %d round %d: the ops of the diff leave another accumulator than the ops they diff", seed, round)
			}
		}
		checkLedger(t, b, current(), fmt.Sprintf("seed %d diff", seed))
	}
}

// The rule tables are the file's only when it carries the mark: ops that address RuleBooks and RuleOutputs are ops of
// the blob for every other file, and a whole member of them is never an op of the ledger.
func TestRuleOpsAddressTheLedgerOnlyOfAFileThatCarriesTheMark(t *testing.T) {
	ops := []patchOp{{Op: opSet, Path: []string{"RuleBooks", "k"}, Value: json.RawMessage(`{}`)}, {Op: opSet, Path: []string{"OIDC", "x"}, Value: json.RawMessage(`1`)}}
	if blob, ledger := splitLedgerOps(ops, false); len(blob) != 2 || len(ledger) != 0 {
		t.Fatalf("a file without the mark: blob %d ops, ledger %d, want 2 and 0", len(blob), len(ledger))
	}
	if blob, ledger := splitLedgerOps(ops, true); len(blob) != 1 || len(ledger) != 1 || ledger[0].Path[0] != "RuleBooks" {
		t.Fatalf("a file with the mark: blob %d ops, ledger %d", len(blob), len(ledger))
	}
	s := newLedgerStore(t)
	writeLedger(t, s, func(l *ledgerTx) error { return l.setRules(true) })
	if err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = l.applyLedgerOps([]patchOp{{Op: opSet, Path: []string{"RuleBooks"}, Value: json.RawMessage(`{}`)}}); err == nil {
			t.Error("a whole RuleBooks member was written into the ledger")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// markedFile puts the state of an installation that carries the mark into a contracted file, with the rule facts still in
// its blob (the state the command that writes the mark finds), and returns them.
func markedFile(t *testing.T, s *Store, rules, outputs int) (books, outs map[string]json.RawMessage) {
	t.Helper()
	r := rand.New(rand.NewPCG(7, 108))
	org, project := model.ID{1}, model.ID{2}
	books, outs = map[string]json.RawMessage{}, map[string]json.RawMessage{}
	for i := range rules {
		rule := model.ID{3, byte(i)}
		books[ruleKey(org, project, rule)] = json.RawMessage(fmt.Sprintf(`{"org":"%s","project":"%s","rule":"%s","head":%d,"versions":[]}`, org, project, rule, i))
		for j := range outputs {
			raw := ruleOutputRecord(r, org, project, rule, i*100+j)
			var o RuleOutput
			if err := json.Unmarshal(raw, &o); err != nil {
				t.Fatal(err)
			}
			outs[o.ID.String()] = raw // the blob keys an output by its ID
		}
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		raw, err := stateRaw(ctrl)
		if err != nil {
			return err
		}
		var st State
		if err = json.Unmarshal(raw, &st); err != nil {
			return err
		}
		st.RuleBooks, st.RuleOutputs = books, outs
		st.MarkRulesInLedger(st.Revision + 1)
		whole, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return putState(ctrl, whole)
	}); err != nil {
		t.Fatal(err)
	}
	return books, outs
}

// The command that writes the mark moves the two members out of the blob: the records are in the tables under the keys of
// the ledger, the blob holds null, the logical state is what it was (the same records, the outputs keyed by their rule),
// the snapshot that streams it is the state encoded as a whole, the seals agree, and a second move changes nothing.
func TestMigrateRulesMovesTheMembersAndKeepsTheLogicalState(t *testing.T) {
	s := newLedgerStore(t)
	books, outs := markedFile(t, s, 5, 7)
	var before State
	if err := s.db.View(func(tx *bolt.Tx) error { return loadLogical(tx, &before) }); err != nil {
		t.Fatal(err)
	}
	if len(before.RuleBooks) != 5 || len(before.RuleOutputs) != 35 {
		t.Fatalf("the file holds %d rule books and %d outputs in its blob, want 5 and 35", len(before.RuleBooks), len(before.RuleOutputs))
	}
	for range 2 { // the second is a no-op
		if err := s.db.Update(migrateRules); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if !l.rules {
			t.Error("the file does not keep the rule facts in the ledger after the move")
		}
		if string(ctrl.Get(ledgerSealKey)) != string(ctrl.Get(stateSealKey)) {
			t.Error("the ledger seal and the state seal differ after the move")
		}
		members, err := decodeMembers(ctrl.Get(stateKey))
		if err != nil {
			return err
		}
		for _, name := range []string{"RuleBooks", "RuleOutputs"} {
			if string(members[name]) != "null" {
				t.Errorf("the blob holds %s: %.80s", name, members[name])
			}
		}
		var after State
		if err = loadLogical(tx, &after); err != nil {
			return err
		}
		if len(after.RuleBooks) != len(books) {
			t.Errorf("the ledger holds %d rule books, want %d", len(after.RuleBooks), len(books))
		}
		for k, v := range books {
			if !bytes.Equal(after.RuleBooks[k], v) {
				t.Errorf("rule book %s changed in the move", k)
			}
		}
		if len(after.RuleOutputs) != len(outs) {
			t.Errorf("the ledger holds %d outputs, want %d", len(after.RuleOutputs), len(outs))
		}
		for _, v := range after.RuleOutputs {
			var o RuleOutput
			if err := json.Unmarshal(v, &o); err != nil {
				return err
			}
			if want := outs[o.ID.String()]; !bytes.Equal(want, v) {
				t.Errorf("output %s changed in the move", o.ID)
			}
		}
		for key := range after.RuleOutputs {
			var o RuleOutput
			if err := json.Unmarshal(after.RuleOutputs[key], &o); err != nil {
				return err
			}
			if key != ruleOutputKey(o.Org, o.Project, o.Rule, o.ID) {
				t.Errorf("an output is keyed %q, want %q", key, ruleOutputKey(o.Org, o.Project, o.Rule, o.ID))
			}
		}
		fast, err := snapshotState(tx)
		if err != nil {
			return err
		}
		slow, err := slowSnapshotState(tx)
		if err != nil {
			return err
		}
		if !bytes.Equal(fast, slow) {
			t.Error("the streamed snapshot is not the encoding of the logical state")
		}
		if l.acc != recomputeAcc(l) {
			t.Error("the accumulator is not the fold of the records after the move")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
