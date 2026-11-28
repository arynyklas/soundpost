// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// D108: a rec op takes the record a voter holds to the record the proposer's plans left, byte for byte, or the proposer writes the
// record whole.

func jobRecordBytes(t *testing.T, rec JobRecord) []byte {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonicalBook(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func commandEntry(n int) JobCommandEntry {
	return JobCommandEntry{ID: model.ID{0xc0, byte(n >> 8), byte(n)}, Principal: model.ID{0xaa}, Kind: "attempt", Digest: model.Hash{byte(n)}, Version: model.Revision(n), Origin: &model.Cursor{Group: model.ID{0xe1}, Index: model.Uint64(n)}}
}

// wireOf is the op as a voter decodes it from the command.
func wireOf(t *testing.T, op patchOp) recordDelta {
	t.Helper()
	raw, err := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: model.ID{1}, Ops: []patchOp{op}}})
	if err != nil {
		t.Fatal(err)
	}
	var back statePatchCommand
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	var d recordDelta
	if err := decodeValue(back.StatePatch.Ops[0].Value, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRecordDeltaIsTheRecordTheProposerLeftOrIsNotUsed(t *testing.T) {
	rng := rand.New(rand.NewPCG(108, 1))
	used, whole := 0, 0
	for round := range 40 {
		rec := JobRecord{Org: model.ID{1}, Project: model.ID{2}, Job: model.ID{3}, Version: 1, State: json.RawMessage(`{"a":1}`)}
		for i := range 30 + rng.IntN(40) {
			rec.Commands = append(rec.Commands, commandEntry(i))
		}
		before := jobRecordBytes(t, rec)
		for step := range 25 {
			next := rec
			next.Commands = append([]JobCommandEntry(nil), rec.Commands...)
			next.Version++
			switch rng.IntN(6) {
			case 0: // an update: one command appended
				next.Commands = append(next.Commands, commandEntry(1000*round+step))
			case 1: // the log is full: its oldest row goes
				if len(next.Commands) > 0 {
					next.Commands = next.Commands[1:]
				}
				next.Commands = append(next.Commands, commandEntry(1000*round+step))
			case 2: // several rows leave and several come
				k := min(rng.IntN(5), len(next.Commands))
				next.Commands = append(next.Commands[k:], commandEntry(1000*round+step), commandEntry(1000*round+step+500))
			case 3: // the state is replaced, with characters a RawMessage is escaped for on the wire
				next.State = json.RawMessage(fmt.Sprintf(`{"a":%d,"text":"<b>&</b>\u2028"}`, step))
			case 4: // the log is emptied
				next.Commands = nil
			case 5: // a member that was absent appears (omitempty)
				if len(next.Commands) == 0 {
					next.Commands = []JobCommandEntry{commandEntry(step)}
				}
			}
			after := jobRecordBytes(t, next)
			op, ok := recordDeltaOp([]string{"JobBooks", "k"}, before, after)
			if ok {
				used++
				got, err := applyRecordDelta(before, wireOf(t, op))
				if err != nil || !bytes.Equal(got, after) {
					t.Fatalf("round %d step %d: the delta leaves\n%s\nnot\n%s\n(%v)", round, step, got, after, err)
				}
				if len(op.Value)*2 > len(after) {
					t.Fatalf("round %d step %d: a delta of %d bytes for a record of %d", round, step, len(op.Value), len(after))
				}
			} else {
				whole++
			}
			rec, before = next, after
		}
	}
	if used < 100 || whole == 0 {
		t.Fatalf("%d deltas and %d whole records: the sequences did not exercise both forms", used, whole)
	}
}

func TestRecordDeltaOfAGroupingIssueAppendsEvidence(t *testing.T) {
	issue := model.GroupingIssue{ID: model.ID{9}, Org: model.ID{1}, Project: model.ID{2}, GroupingVersion: 1, Workflow: "open", Revision: 1}
	ev := func(n int) model.GroupingEvidence {
		return model.GroupingEvidence{OccurrenceID: model.ID{0xd0, byte(n)}, RecordID: model.ID{0xd1, byte(n)}, Origin: model.Cursor{Group: model.ID{0xe1}, Index: model.Uint64(n)}, GroupingVersion: 1, Ancestry: "known", Ordinal: model.Uint64(n), Freshness: "fresh"}
	}
	for i := range 40 {
		issue.Occurrences = append(issue.Occurrences, ev(i))
	}
	before, _ := json.Marshal(issue)
	issue.Revision++
	issue.Occurrences = append(issue.Occurrences, ev(40))
	after, _ := json.Marshal(issue)
	op, ok := recordDeltaOp([]string{"GroupingIssues", "k"}, before, after)
	if !ok {
		t.Fatalf("an append of one occurrence to %d bytes of issue is not a delta", len(before))
	}
	if len(op.Value) > 700 {
		t.Errorf("the delta of one occurrence is %d bytes", len(op.Value))
	}
	got, err := applyRecordDelta(before, wireOf(t, op))
	if err != nil || !bytes.Equal(got, after) {
		t.Fatalf("the delta leaves %s (%v)", got, err)
	}
	// the bytes of a delta do not follow the ledger: a ledger ten times as long costs the same
	for i := 40; i < 400; i++ {
		issue.Occurrences = append(issue.Occurrences, ev(i))
	}
	before, _ = json.Marshal(issue)
	issue.Revision++
	issue.Occurrences = append(issue.Occurrences, ev(400))
	after, _ = json.Marshal(issue)
	big, ok := recordDeltaOp([]string{"GroupingIssues", "k"}, before, after)
	if !ok || len(big.Value) > len(op.Value)+10 {
		t.Fatalf("on a ledger of %d bytes the delta is %d bytes (%v), on one of ~10 KB %d", len(before), len(big.Value), ok, len(op.Value))
	}
}

func TestRecordDeltaIsRefusedByAVoterThatHoldsOtherBytes(t *testing.T) {
	rec := JobRecord{Org: model.ID{1}, Project: model.ID{2}, Job: model.ID{3}, Version: 1, State: json.RawMessage(`{"a":1}`)}
	for i := range 60 {
		rec.Commands = append(rec.Commands, commandEntry(i))
	}
	before := jobRecordBytes(t, rec)
	next := rec
	next.Version = 2
	next.Commands = append(append([]JobCommandEntry(nil), rec.Commands...), commandEntry(60))
	after := jobRecordBytes(t, next)
	op, ok := recordDeltaOp([]string{"JobBooks", "k"}, before, after)
	if !ok {
		t.Fatal("not a delta")
	}
	d := wireOf(t, op)
	// a voter whose record lacks a row (it replayed a log an erasure rewrote, or diverged)
	other := rec
	other.Commands = rec.Commands[1:]
	if _, err := applyRecordDelta(jobRecordBytes(t, other), d); err == nil {
		t.Fatal("the delta was applied to a record other than the one it was computed from")
	}
	var fault *model.Fault
	if _, err := applyRecordDelta(before, recordDelta{Sum: strings.Repeat("0", 64), Arr: d.Arr, Set: d.Set}); !errors.As(err, &fault) || fault.Code != model.Corrupt {
		t.Fatalf("a wrong digest is %v, want Corrupt", err)
	}
	cut := d
	cut.Arr = map[string]recordRows{"commands": {Cut: 999, Rows: nil}}
	if _, err := applyRecordDelta(before, cut); err == nil {
		t.Fatal("a cut beyond the rows was applied")
	}
	if _, err := applyRecordDelta([]byte(`[1]`), d); err == nil {
		t.Fatal("a delta was applied to something that is not an object")
	}
	if _, err := applyRecordDelta(before, recordDelta{Sum: d.Sum, Set: map[string]json.RawMessage{"version": json.RawMessage(` 2`)}}); err == nil {
		t.Fatal("a member that is not compact JSON was applied")
	}
}

// The ledger applies a rec op to the record it holds, verifies a replay by its digest, and refuses a record it does not hold.
func TestLedgerAppliesAndVerifiesARecordDelta(t *testing.T) {
	s := newLedgerStore(t)
	rec := JobRecord{Org: model.ID{1}, Project: model.ID{2}, Job: model.ID{3}, Version: 1, State: json.RawMessage(`{"a":1}`)}
	for i := range 60 {
		rec.Commands = append(rec.Commands, commandEntry(i))
	}
	before := jobRecordBytes(t, rec)
	next := rec
	next.Version = 2
	next.Commands = append(append([]JobCommandEntry(nil), rec.Commands...), commandEntry(60))
	after := jobRecordBytes(t, next)
	op, ok := recordDeltaOp([]string{"JobBooks", "o:p:j"}, before, after)
	if !ok {
		t.Fatal("not a delta")
	}
	if !validLedgerOp(op) || validLedgerOp(patchOp{Op: opRecord, Path: []string{"Quotas", "k"}, Value: op.Value}) {
		t.Fatal("a rec op is valid for the job books and the grouping issues only")
	}
	if err := validatePatch(statePatch{Installation: model.ID{1}, Expected: 1, Base: strings.Repeat("0", 64), Keys: map[string][]byte{}, Ops: []patchOp{op}}); err != nil {
		t.Fatalf("a patch with a rec op is refused: %v", err)
	}
	writeLedger(t, s, func(l *ledgerTx) error {
		if err := l.applyLedgerOps([]patchOp{op}); err == nil {
			t.Error("a delta was applied to a record the ledger does not hold")
		}
		return l.putBook(tableJobBooks, "o:p:j", before)
	})
	writeLedger(t, s, func(l *ledgerTx) error {
		if err := l.verifyLedgerOps([]patchOp{op}); err == nil {
			t.Error("the ledger holds the record before the delta and verifies as the record after it")
		}
		if err := l.applyLedgerOps([]patchOp{op}); err != nil {
			return err
		}
		return l.verifyLedgerOps([]patchOp{op})
	})
	viewRound(t, s, func(l *ledgerTx) {
		if got := l.t[tableJobBooks].Get([]byte("o:p:j")); !bytes.Equal(got, after) {
			t.Errorf("the ledger holds\n%s\nwant\n%s", got, after)
		}
	})
	// the ledger a plain set leaves is the ledger the delta leaves (same accumulator)
	plain := newLedgerStore(t)
	writeLedger(t, plain, func(l *ledgerTx) error {
		if err := l.putBook(tableJobBooks, "o:p:j", before); err != nil {
			return err
		}
		return l.applyLedgerOps([]patchOp{{Op: opSet, Path: []string{"JobBooks", "o:p:j"}, Value: after}})
	})
	var a, b [32]byte
	viewRound(t, s, func(l *ledgerTx) { a = l.acc })
	viewRound(t, plain, func(l *ledgerTx) { b = l.acc })
	if a != b {
		t.Error("the delta and the plain set leave other ledger accumulators")
	}
}

// The sparse round writes a rec op for a big record that its plans changed a little, when the group applies them, and the plain
// set when it does not or when the record is small.
func TestSparseRoundWritesRecordDeltasOnlyWhenTheGroupAppliesThem(t *testing.T) {
	s := newLedgerStore(t)
	rows := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"version":1,"commands":[`)
		for i := range n {
			if i != 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"%032d","kind":"attempt"}`, i)
		}
		b.WriteString(`]}`)
		return b.String()
	}
	big, small := rows(100), rows(3)
	writeLedger(t, s, func(l *ledgerTx) error {
		if err := l.putBook(tableJobBooks, "o:p:big", json.RawMessage(big)); err != nil {
			return err
		}
		return l.putBook(tableJobBooks, "o:p:small", json.RawMessage(small))
	})
	grow := func(key, before string) sparsePlan {
		return func(*State, *ledgerTx) ([]patchOp, error) {
			after := strings.Replace(before, `"version":1`, `"version":2`, 1)
			after = strings.TrimSuffix(after, `]}`) + `,{"id":"new","kind":"attempt"}]}`
			return []patchOp{setJob(key, after)}, nil
		}
	}
	for _, compact := range []bool{false, true} {
		viewRound(t, s, func(l *ledgerTx) {
			var r sparseRound
			r.compact = compact
			for key, before := range map[string]string{"o:p:big": big, "o:p:small": small} {
				if _, wait, err := r.admit(grow(key, before), &State{}, l); err != nil || wait {
					t.Fatalf("admit %s: wait %v, %v", key, wait, err)
				}
			}
			ops := r.ops()
			if len(ops) != 2 {
				t.Fatalf("%d ops, want one for each record", len(ops))
			}
			for _, op := range ops {
				want := opSet
				if compact && op.Path[1] == "o:p:big" {
					want = opRecord
				}
				if op.Op != want {
					t.Errorf("compact %v: %s is written by %s, want %s", compact, op.Path[1], op.Op, want)
				}
				if op.Op == opRecord && len(op.Value) > 400 {
					t.Errorf("the delta of one row is %d bytes", len(op.Value))
				}
			}
		})
	}
}

// An erasure pass rewrites the retained rec ops of a project a deletion covers as the plain record the committed state holds, and
// leaves the ones of other projects alone.
func TestExpandRecordsWritesThePlainRecordOfACoveredProject(t *testing.T) {
	ops := []patchOp{
		{Op: opRecord, Path: []string{"JobBooks", "covered"}, Value: json.RawMessage(`{"sum":"x"}`)},
		{Op: opRecord, Path: []string{"GroupingIssues", "gone"}, Value: json.RawMessage(`{"sum":"x"}`)},
		{Op: opRecord, Path: []string{"JobBooks", "other"}, Value: json.RawMessage(`{"sum":"x"}`)},
		{Op: opSet, Path: []string{"Commands", "c"}, Value: json.RawMessage(`{}`)},
	}
	covers := func(key string) bool { return key != "other" }
	committed := func(member, key string) (json.RawMessage, bool, error) {
		if key == "gone" {
			return nil, false, nil
		}
		return json.RawMessage(`{"committed":true}`), true, nil
	}
	got, expanded, err := expandRecords(ops, covers, committed)
	if err != nil || !expanded {
		t.Fatalf("expanded %v, %v", expanded, err)
	}
	if got[0].Op != opSet || string(got[0].Value) != `{"committed":true}` || got[1].Op != opDelete || got[2].Op != opRecord || got[3].Op != opSet {
		t.Fatalf("expanded to %+v", got)
	}
	if ops[0].Op != opRecord {
		t.Fatal("the ops of the command were changed in place")
	}
	if _, expanded, _ := expandRecords(ops[2:], covers, committed); expanded {
		t.Fatal("ops of an uncovered project were expanded")
	}
	rules := State{Deletions: map[string]model.DeletionOperation{
		"d": {Phase: model.DeletePhaseComplete, Predicate: model.DeletePredicate{Mode: model.DeleteRetireProject, Org: model.ID{1}, Projects: []model.ID{{2}}}},
		"h": {Phase: model.DeletePhaseHeld, Predicate: model.DeletePredicate{Mode: model.DeleteRetireProject, Org: model.ID{1}, Projects: []model.ID{{7}}}},
	}}
	key := func(org, project byte) string {
		return model.ID{org}.String() + ":" + model.ID{project}.String() + ":" + model.ID{3}.String()
	}
	if !keyCoveredByDeletion(rules, key(1, 2)) || keyCoveredByDeletion(rules, key(1, 7)) || keyCoveredByDeletion(rules, key(1, 5)) || !keyCoveredByDeletion(rules, "not-a-key") {
		t.Fatal("the projects a deletion covers are not the ones its predicate names (a held deletion covers none, a key that does not parse is covered)")
	}
}

// A retained command that carries a rec op for a project a deletion covers is retained as the plain record the committed state holds
// (no row of a delta outlives the erasure); a command of another project is retained as it is.
func TestRedactPatchRetainsTheCommittedRecordInPlaceOfADeltaOfACoveredProject(t *testing.T) {
	rec := JobRecord{Org: model.ID{1}, Project: model.ID{2}, Job: model.ID{3}, Version: 1, State: json.RawMessage(`{"a":1}`)}
	for i := range 60 {
		rec.Commands = append(rec.Commands, commandEntry(i))
	}
	older := jobRecordBytes(t, rec)
	rec.Version = 2
	rec.Commands = append(rec.Commands, commandEntry(60))
	committed := jobRecordBytes(t, rec)
	key := func(project byte) string {
		return model.ID{1}.String() + ":" + model.ID{project}.String() + ":" + model.ID{3}.String()
	}
	op, ok := recordDeltaOp([]string{"JobBooks", key(2)}, older, committed)
	if !ok {
		t.Fatal("not a delta")
	}
	other := op
	other.Path = []string{"JobBooks", key(5)}
	payload, err := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: model.ID{9}, Expected: 4, Base: strings.Repeat("0", 64), Keys: map[string][]byte{}, Ops: []patchOp{op, other}}})
	if err != nil {
		t.Fatal(err)
	}
	state := State{Installation: model.ID{9}, Revision: 5, JobBooks: map[string]json.RawMessage{key(2): committed},
		Deletions: map[string]model.DeletionOperation{"d": {Phase: model.DeletePhaseComplete, Principal: model.ID{7}, Predicate: model.DeletePredicate{Operation: model.ID{8}, Mode: model.DeleteRetireProject, Org: model.ID{1}, Projects: []model.ID{{2}}}}}}
	if _, err := json.Marshal(state); err != nil {
		t.Fatalf("the state does not encode: %v", err)
	}
	out, changed, err := redactControlPayload(state, payload)
	if err != nil || !changed {
		t.Fatalf("changed %v, %v", changed, err)
	}
	cmd, err := decodeControlCommand(out)
	if err != nil || cmd.patch == nil || len(cmd.patch.Ops) != 2 {
		t.Fatalf("the retained command is %+v (%v)", cmd, err)
	}
	got := cmd.patch.Ops
	if got[0].Op != opSet || !bytes.Equal(got[0].Value, committed) || got[1].Op != opRecord || cmd.patch.Base != "" {
		t.Fatalf("retained ops %s %d bytes, %s, base %q: want the committed record of the covered project, the delta of the other, no base", got[0].Op, len(got[0].Value), got[1].Op, cmd.patch.Base)
	}
	state.Deletions = nil
	if out, changed, err := redactControlPayload(state, payload); err != nil || changed || !bytes.Equal(out, payload) {
		t.Fatalf("with no deletion the command was rewritten (changed %v, %v)", changed, err)
	}
}
