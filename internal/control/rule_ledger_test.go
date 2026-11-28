// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D108, equivalence: a rule command has the same outcome, and leaves the same rule facts, whether the file keeps them in the
// blob (today's form, kept until every member declared protocol 10) or in the ledger.

func (s *ruleFx) describe(res control.Result, err error) string {
	if err != nil {
		return fmt.Sprintf("error %s %s", code(err), faultDetail(err))
	}
	// The first affected ID is the rule, which differs between two fixtures; the revision is not part of an outcome either.
	rest := ""
	if len(res.AffectedIDs) > 1 {
		rest = fmt.Sprint(res.AffectedIDs[1:])
	}
	return fmt.Sprintf("%s affected=%d %s", res.Phase, len(res.AffectedIDs), rest)
}

// ruleScript runs every arm a plan writes, and the failures each answers, against f, and describes each outcome.
func ruleScript(f *ruleFx, lease replica.FenceToken) (steps []string) {
	step := func(res control.Result, err error) { steps = append(steps, f.describe(res, err)) }
	first := f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1), conditionIntent(2, true))
	id := model.NewID()
	step(f.applyAs(id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: first}))
	// The same command again, the same evaluation under a new command, another payload for the identity, one computed from an
	// older state, one out of order, a backfill that notifies, and the one that does not.
	step(f.applyAs(id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: first}))
	step(f.eval(lease, first))
	step(f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":2}`, recordingIntent(9))))
	step(f.eval(lease, f.evaluation(1, 120, 0, control.RuleModeLive, `{"n":3}`)))
	step(f.eval(lease, f.evaluation(1, 120, 1, control.RuleModeLive, `{"n":3}`, recordingIntent(3), recordingIntent(4))))
	step(f.eval(lease, f.evaluation(1, 30, 2, control.RuleModeLive, `{"n":0}`)))
	step(f.eval(lease, f.evaluation(1, 180, 2, control.RuleModeBackfill, `{"n":4}`, conditionIntent(5, true))))
	step(f.eval(lease, f.evaluation(1, 180, 2, control.RuleModeBackfill, `{"n":4}`, conditionIntent(5, false))))
	cursor, hash := model.Cursor{Group: model.ID{9}, Index: 5}, model.Hash{1}
	output := func(out model.ID, to string, receipt *model.Cursor, h *model.Hash, reason string) (control.Result, error) {
		return f.apply(control.RuleCommand{Operation: control.RuleOpOutput, Lease: &lease, Output: &control.RuleOutputApply{Project: f.project, Rule: f.rule, Output: out, To: to, Receipt: receipt, Hash: h, Reason: reason}})
	}
	step(output(model.ID{1}, control.RulePhaseAdmitted, &cursor, &hash, ""))
	step(output(model.ID{1}, control.RulePhaseAdmitted, &cursor, &hash, ""))
	step(output(model.ID{1}, control.RulePhaseFinalized, &cursor, &hash, ""))
	step(output(model.ID{2}, control.RulePhaseFinalized, nil, nil, ""))
	step(output(model.ID{3}, control.RulePhaseSuppress, nil, nil, "obsolete"))
	// A recording admitted without its receipt is invalid, and an output that does not exist is not found.
	step(output(model.ID{4}, control.RulePhaseAdmitted, nil, nil, ""))
	step(output(model.ID{0x77}, control.RulePhaseFinalized, &cursor, &hash, ""))
	step(f.apply(control.RuleCommand{Operation: control.RuleOpMissed, Lease: &lease, Missed: &control.RuleMissedApply{Project: f.project, Rule: f.rule, Version: 1, From: 200, To: 260, Count: 2, At: 300}}))
	// A newer leader commits and the older one is fenced out of the rule, every arm included.
	newer := lease
	newer.Term++
	step(f.eval(newer, f.evaluation(1, 240, 3, control.RuleModeLive, `{"n":5}`, recordingIntent(6))))
	step(f.eval(lease, f.evaluation(1, 300, 4, control.RuleModeLive, `{"n":6}`)))
	step(output(model.ID{6}, control.RulePhaseSuppress, nil, nil, "late"))
	// An evaluation with more outputs than one command carries: staged first, promoted by the evaluation.
	var surplus []control.RuleOutputIntent
	for i := range 270 {
		surplus = append(surplus, control.RuleOutputIntent{ID: model.ID{0x40 + byte(i>>8), byte(i)}, Kind: control.RuleOutputRecording, Payload: json.RawMessage(fmt.Sprintf(`{"batch":%d}`, i)), Inputs: []model.Cursor{}})
	}
	big := f.evaluation(1, 360, 4, control.RuleModeLive, `{"n":7}`, surplus[:14]...)
	big.Staged = 256
	step(f.apply(control.RuleCommand{Operation: control.RuleOpStage, Lease: &newer, Stage: &control.RuleStageApply{Project: f.project, Rule: f.rule, Version: 1, At: 360, Mode: control.RuleModeLive, Digest: big.Digest, Outputs: surplus[14:]}}))
	step(f.apply(control.RuleCommand{Operation: control.RuleOpStage, Lease: &newer, Stage: &control.RuleStageApply{Project: f.project, Rule: f.rule, Version: 1, At: 360, Mode: control.RuleModeLive, Digest: big.Digest, Outputs: surplus[14:]}})) // idempotent
	step(f.eval(newer, big))
	// More evaluations than the book retains and the outbox keeps settled.
	for i := range 20 {
		at := uint64(400 + 60*i)
		step(f.eval(newer, f.evaluation(1, at, uint64(5+i), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, 10+i))))
	}
	return steps
}

// facts is the rule book and the outbox of f as a reader sees them, without what differs between two fixtures (the identities
// of the organization, project and rule, the revision numbers the commands committed at) and what a reader never sees.
func (f *ruleFx) facts() string {
	book := f.book()
	type eval struct {
		At             model.UnixNano
		Digest         model.Hash
		Mode, Health   string
		Cursors        []model.Cursor
		Payload        string
		HasRevisionSet bool
	}
	type version struct {
		Version       model.Revision
		StateRevision model.Revision
		Last          *eval
		Recent        []eval
	}
	of := func(r control.RuleEvaluationRecord) eval {
		return eval{At: r.At, Digest: r.Digest, Mode: r.Mode, Health: r.Health, Cursors: r.Cursors, Payload: string(compactOr(r.Payload)), HasRevisionSet: r.Revision != 0}
	}
	var versions []version
	for _, v := range book.Versions {
		out := version{Version: v.Version, StateRevision: v.StateRevision}
		if v.Last != nil {
			e := of(*v.Last)
			out.Last = &e
		}
		for _, r := range v.Recent {
			out.Recent = append(out.Recent, of(r))
		}
		versions = append(versions, out)
	}
	type output struct {
		ID                    model.ID
		Version               model.Revision
		At                    model.UnixNano
		Kind, Mode, Phase     string
		Signal                model.Kind
		Notify                bool
		Digest, Stage         model.Hash
		Payload               string
		Inputs                []model.Cursor
		Receipt               *model.Cursor
		Hash                  *model.Hash
		Reason                string
		Obsolete, HasCreation bool
	}
	var outputs []output
	for _, phase := range []string{"", control.RulePhaseStaged} {
		for _, o := range f.outputs(phase) {
			outputs = append(outputs, output{o.ID, o.Version, o.At, o.Kind, o.Mode, o.Phase, o.Signal, o.Notify, o.Digest, o.Stage, string(compactOr(o.Payload)), o.Inputs, o.Receipt, o.Hash, o.Reason, o.Obsolete, o.Created != 0})
		}
	}
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].At < outputs[j].At || outputs[i].At == outputs[j].At && outputs[i].ID.String() < outputs[j].ID.String()
	})
	raw, err := json.Marshal(struct {
		Head     model.Revision
		Versions []version
		Missed   []control.RuleMissedRecord
		Outputs  []output
	}{book.Head, versions, book.Missed, outputs})
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func compactOr(raw json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, _ := json.Marshal(v)
	return out
}

// newRuleFxBlob is a rule fixture of the blob layout whatever SOUNDPOST_TEST_RULE_LEDGER says: that switch (fence_test.go)
// turns every fixture into a group of protocol 10, and a comparison of the two layouts needs the one it calls the blob to stay
// one. The compact gate is closed, so the rule facts never move.
func newRuleFxBlob(t *testing.T) *ruleFx {
	t.Helper()
	f := newRuleFx(t)
	f.store.SetStatePatchGate(func() bool { return true })
	f.store.SetCompactAdmissionGate(func() bool { return false })
	return f
}

// The rule books and the outbox of a group that declared protocol 10 are records of the ledger, and every command of every
// arm has the outcome, and leaves the facts, that it has on the blob.
func TestRuleCommandsHaveTheSameOutcomesWhereverTheFileKeepsTheRuleFacts(t *testing.T) {
	blob := newRuleFxBlob(t)
	ledger := newRuleFxProtocol10(t)
	want := ruleScript(blob, blob.lease())
	got := ruleScript(ledger, ledger.lease())
	if len(want) != len(got) {
		t.Fatalf("%d steps on the blob, %d on the ledger", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("step %d: the blob answers %q, the ledger %q", i, want[i], got[i])
		}
	}
	if a, b := blob.facts(), ledger.facts(); a != b {
		t.Errorf("the facts differ:\nblob   %.2000s\nledger %.2000s", a, b)
	}
	if blob.store.LedgerCountForTest("rule_books") != 0 || blob.store.BlobMemberForTest("RuleBooks") == "null" {
		t.Error("the blob fixture moved its rule facts")
	}
	if n := ledger.store.LedgerCountForTest("rule_books"); n != 1 {
		t.Errorf("the ledger holds %d rule books, want 1", n)
	}
	if got := ledger.store.BlobMemberForTest("RuleBooks"); got != "null" {
		t.Errorf("the blob of the ledger fixture holds RuleBooks: %.80s", got)
	}
	if got := ledger.store.BlobMemberForTest("RuleOutputs"); got != "null" {
		t.Errorf("the blob of the ledger fixture holds RuleOutputs: %.80s", got)
	}
	if n := ledger.store.LedgerCountForTest("rule_outputs"); n < 256 {
		t.Errorf("the ledger holds %d outbox records", n)
	}
	if ledger.store.SparseCommitsForTest() < 20 {
		t.Errorf("only %d commands of the ledger fixture were committed as records", ledger.store.SparseCommitsForTest())
	}
}

// Until every member declared protocol 10 the rule facts are members of the blob and every command is the whole-state
// transition it always was; the first command after the gate opens moves them, and the facts are the same after it.
func TestRuleFactsStayInTheBlobUntilTheGateOpensAndThenMoveOnce(t *testing.T) {
	f := newRuleFx(t)
	f.store.SetStatePatchGate(func() bool { return true })
	var gate atomic.Bool
	f.store.SetCompactAdmissionGate(gate.Load)
	lease := f.lease()
	for i := range 4 {
		if _, err := f.eval(lease, f.evaluation(1, uint64(60*(i+1)), uint64(i), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, i), recordingIntent(byte(i+1)))); err != nil {
			t.Fatal(err)
		}
	}
	if f.store.RuleLedgerForTest() || f.store.LedgerCountForTest("rule_books") != 0 || f.store.BlobMemberForTest("RuleBooks") == "null" || f.store.SparseCommitsForTest() != 0 {
		t.Fatal("the rule facts left the blob while a member had not declared protocol 10")
	}
	before := f.facts()
	gate.Store(true)
	if _, err := f.eval(lease, f.evaluation(1, 300, 4, control.RuleModeLive, `{"n":4}`, recordingIntent(5))); err != nil {
		t.Fatal(err)
	}
	if !f.store.RuleLedgerForTest() || f.store.LedgerCountForTest("rule_books") != 1 || f.store.BlobMemberForTest("RuleBooks") != "null" {
		t.Fatal("the rule facts did not move into the ledger when the group declared protocol 10")
	}
	if n := f.store.LedgerCountForTest("rule_outputs"); n != 5 {
		t.Errorf("the ledger holds %d outbox records, want 5", n)
	}
	var withFifth string
	withFifth = f.facts()
	if withFifth == before {
		t.Error("the fifth evaluation is not in the facts")
	}
	// The gate closing again (a member joined at protocol 9) changes nothing about a file that moved: the records stay where they are and
	// a command is still answered.
	gate.Store(false)
	if _, err := f.eval(lease, f.evaluation(1, 360, 5, control.RuleModeLive, `{"n":5}`)); err != nil {
		t.Fatal(err)
	}
	if !f.store.RuleLedgerForTest() || f.store.BlobMemberForTest("RuleBooks") != "null" {
		t.Error("a closed gate moved the rule facts back into the blob")
	}
}

// Three voters: a group with a member at protocol 9 keeps the rule facts in every voter's blob (a command of any voter is the
// whole-state transition), and when the member declares protocol 10 the facts move on every voter at the same command: from then on
// every voter holds the same state, a command of any voter is committed as records, and a restarted voter holds the same.
func TestRuleFactsMoveOnEveryVoterAtTheSameCommandWhenTheGroupDeclaresProtocolTen(t *testing.T) {
	v := newControlVoters(t)
	var gate atomic.Bool // false: a member of the group declared only protocol 9
	for _, s := range v.stores {
		s.SetStatePatchGate(func() bool { return true }) // every member declared protocol 9
		s.SetCompactAdmissionGate(gate.Load)
	}
	rule := model.NewID()
	lease := func() replica.FenceToken {
		token, err := v.stores[1].ReplicaGroup().Fence(v.fx[1].ctx)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}()
	at, expected := uint64(0), uint64(0)
	// The administrator's scope is voter 1's session; the command is submitted through the store of voter id, which validates the
	// scope against the state it holds and proposes through the group like the commands of any voter.
	commit := func(phase string, id uint64, n int) {
		f := &ruleFx{fenceFx: v.fx[1].fenceFx, rule: rule}
		for range n {
			at++
			if err := f.write(func() error {
				scope, err := f.scopeNow()
				if err != nil {
					return err
				}
				cmd, err := f.cmdNow(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: f.evaluation(1, at, expected, control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, at), recordingIntent(byte(at)))})
				if err != nil {
					return err
				}
				_, err = v.stores[id].Transact(f.ctx, scope, cmd)
				return err
			}); err != nil {
				t.Fatalf("%s: voter %d: %v", phase, id, err)
			}
			expected++
		}
		v.converge()
	}
	identical := func(phase string) {
		want := v.fx[1].canonicalState()
		for _, id := range []uint64{2, 3} {
			if got := v.fx[id].canonicalState(); got != want {
				t.Fatalf("%s: voter %d holds another state than voter 1", phase, id)
			}
		}
	}
	for id := uint64(1); id <= 3; id++ {
		commit("nine", id, 2)
	}
	identical("nine")
	for id := uint64(1); id <= 3; id++ {
		if v.stores[id].RuleLedgerForTest() || v.stores[id].LedgerCountForTest("rule_books") != 0 || v.stores[id].BlobMemberForTest("RuleBooks") == "null" {
			t.Fatalf("voter %d moved the rule facts while a member was at protocol 9", id)
		}
	}
	gate.Store(true) // the member was replaced by a build at protocol 10 and declared it
	commit("ten", 2, 1)
	for id := uint64(1); id <= 3; id++ {
		if !v.stores[id].RuleLedgerForTest() || v.stores[id].LedgerCountForTest("rule_books") != 1 || v.stores[id].BlobMemberForTest("RuleBooks") != "null" {
			t.Fatalf("voter %d did not move the rule facts at the command that marked the installation: ruleLedger=%v layout=%v rule_books=%d blob RuleBooks=%.30q sparse=%d", id, v.stores[id].RuleLedgerForTest(), v.stores[id].LedgerLayoutForTest(), v.stores[id].LedgerCountForTest("rule_books"), v.stores[id].BlobMemberForTest("RuleBooks"), v.stores[id].SparseCommitsForTest())
		}
	}
	identical("ten")
	for id := uint64(3); id >= 1; id-- {
		commit("ten", id, 3)
	}
	identical("ten, later")
	var sparse uint64
	for id := uint64(1); id <= 3; id++ {
		sparse += v.stores[id].SparseCommitsForTest()
	}
	if sparse < 9 {
		t.Errorf("%d of the rule commands of the voters were committed as records", sparse)
	}
	v.restart(2)
	v.stores[2].SetStatePatchGate(func() bool { return true }) // the restarted store has no gates until its owner installs them
	v.stores[2].SetCompactAdmissionGate(gate.Load)
	if !v.stores[2].RuleLedgerForTest() || v.stores[2].LedgerCountForTest("rule_books") != 1 {
		t.Fatal("a restarted voter lost the layout of its rule facts")
	}
	commit("restarted", 2, 2)
	identical("restarted")
}
