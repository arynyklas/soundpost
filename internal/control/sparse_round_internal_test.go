// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// D86: the sparse plans of one round are judged one after the other, each against the records as the plans
// before it left them, and what the round writes is one op for each record.

func setJob(key, record string) patchOp {
	return patchOp{Op: opSet, Path: []string{"JobBooks", key}, Value: json.RawMessage(record)}
}

func viewRound(t *testing.T, s *Store, fn func(l *ledgerTx)) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		fn(l)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSparseRoundJudgesEachPlanAgainstTheOnesBeforeIt(t *testing.T) {
	s := newLedgerStore(t)
	writeLedger(t, s, func(l *ledgerTx) error {
		if err := l.putBook(tableJobBooks, "o:p:j1", json.RawMessage(`{"v":1}`)); err != nil {
			return err
		}
		return l.putBook(tableJobBooks, "q:p:j9", json.RawMessage(`{"v":9}`))
	})
	// count is a plan that reads the project's records by prefix, as the quota of a job update does.
	count := func(prefix string, got *int) sparsePlan {
		return func(_ *State, l *ledgerTx) ([]patchOp, error) {
			*got = len(l.bookRecords(tableJobBooks, prefix))
			return nil, nil
		}
	}
	// bump reads the record under key and writes the next version of it (a record without one is version 1).
	bump := func(key string, saw *int) sparsePlan {
		return func(_ *State, l *ledgerTx) ([]patchOp, error) {
			var rec struct{ V int }
			if raw := l.t[tableJobBooks].Get([]byte(key)); raw != nil {
				if err := json.Unmarshal(raw, &rec); err != nil {
					return nil, err
				}
			}
			*saw = rec.V
			return []patchOp{setJob(key, `{ "v": `+string(rune('0'+rec.V+1))+` }`)}, nil
		}
	}
	viewRound(t, s, func(l *ledgerTx) {
		var r sparseRound
		core := &State{}
		var first, second, fresh, n1, n2, n3 int
		for i, step := range []struct {
			plan sparsePlan
			want []patchOp
		}{
			{bump("o:p:j1", &first), []patchOp{setJob("o:p:j1", `{ "v": 2 }`)}},
			{bump("o:p:j1", &second), []patchOp{setJob("o:p:j1", `{ "v": 3 }`)}},
			{count("o:p:", &n1), nil},
			{bump("o:p:j2", &fresh), []patchOp{setJob("o:p:j2", `{ "v": 1 }`)}},
			{count("o:p:", &n2), nil},
			{func(*State, *ledgerTx) ([]patchOp, error) {
				return []patchOp{{Op: opDelete, Path: []string{"JobBooks", "o:p:j2"}}}, nil
			}, []patchOp{{Op: opDelete, Path: []string{"JobBooks", "o:p:j2"}}}},
			{count("o:p:", &n3), nil},
		} {
			written, wait, err := r.admit(step.plan, core, l)
			if err != nil || wait {
				t.Fatalf("plan %d: wait %v, %v", i, wait, err)
			}
			if len(written) != len(step.want) {
				t.Fatalf("plan %d wrote %d ops, want %d", i, len(written), len(step.want))
			}
		}
		if first != 1 || second != 2 || fresh != 0 {
			t.Errorf("the plans saw versions %d, %d and %d, want 1, 2 and 0 (a plan sees the write of the one before it)", first, second, fresh)
		}
		if n1 != 1 || n2 != 2 || n3 != 1 {
			t.Errorf("a scan of the project saw %d, %d and %d records, want 1, 2 and 1 (the writes and the delete of the plans before it)", n1, n2, n3)
		}
		// the foreign project is never in the scan, and the records the plans wrote read back canonical
		if got := string(r.tbl[tableJobBooks].Get([]byte("o:p:j1"))); got != `{"v":3}` {
			t.Errorf("the record reads back as %q", got)
		}
		ops := r.ops()
		if len(ops) != 2 {
			t.Fatalf("the round wrote %d ops, want one for each record (j1 and the deleted j2): %+v", len(ops), ops)
		}
		for _, op := range ops {
			switch op.Path[1] {
			case "o:p:j1":
				if op.Op != opSet || string(op.Value) != `{ "v": 3 }` {
					t.Errorf("j1 is written by %s %s, want the last plan's", op.Op, op.Value)
				}
			case "o:p:j2":
				if op.Op != opDelete {
					t.Errorf("j2 is written by %s, want its delete", op.Op)
				}
			default:
				t.Errorf("unexpected op %+v", op)
			}
		}
	})
}

func TestSparseRoundAnswersAFailureWithoutWritingAndRefusesWhatIsNotARecord(t *testing.T) {
	s := newLedgerStore(t)
	viewRound(t, s, func(l *ledgerTx) {
		var r sparseRound
		boom := errors.New("boom")
		if _, _, err := r.admit(func(*State, *ledgerTx) ([]patchOp, error) { return []patchOp{setJob("k", `{}`)}, boom }, &State{}, l); !errors.Is(err, boom) {
			t.Errorf("a plan's error is %v", err)
		}
		if _, _, err := r.admit(func(*State, *ledgerTx) ([]patchOp, error) { return nil, errSparseFallback }, &State{}, l); !errors.Is(err, errSparseFallback) {
			t.Errorf("the fallback of a plan is %v", err)
		}
		for _, op := range []patchOp{
			{Op: opSet, Path: []string{"Reservations", "r"}, Value: json.RawMessage(`{}`)},
			{Op: opSet, Path: []string{"JobBooks", "k", "deeper"}, Value: json.RawMessage(`{}`)},
			{Op: opArray, Path: []string{"JobBooks", "k"}, Value: json.RawMessage(`[]`)},
		} {
			_, _, err := r.admit(func(*State, *ledgerTx) ([]patchOp, error) { return []patchOp{op}, nil }, &State{}, l)
			var f *model.Fault
			if !errors.As(err, &f) || f.Code != model.Invalid {
				t.Errorf("%v is judged %v, want Invalid", op.Path, err)
			}
		}
		if len(r.ops()) != 0 {
			t.Errorf("failed plans left %d ops in the round", len(r.ops()))
		}
	})
}

func TestSparseRoundHoldsBackWhatWouldMakeAPatchTooLarge(t *testing.T) {
	s := newLedgerStore(t)
	viewRound(t, s, func(l *ledgerTx) {
		var r sparseRound
		big := func(key string) sparsePlan {
			return func(*State, *ledgerTx) ([]patchOp, error) {
				return []patchOp{setJob(key, `{"pad":"`+strings.Repeat("x", sparseRoundBytes*3/4)+`"}`)}, nil
			}
		}
		if _, wait, err := r.admit(big("a"), &State{}, l); wait || err != nil {
			t.Fatalf("the first plan of a round: wait %v, %v", wait, err)
		}
		if _, wait, err := r.admit(big("b"), &State{}, l); !wait || err != nil {
			t.Fatalf("a second plan that does not fit: wait %v, %v", wait, err)
		}
		if got := r.tbl[tableJobBooks].Get([]byte("b")); got != nil {
			t.Error("a plan that waits left its record in the round")
		}
		small := func(*State, *ledgerTx) ([]patchOp, error) { return []patchOp{setJob("c", `{}`)}, nil }
		if _, wait, err := r.admit(small, &State{}, l); wait || err != nil || !bytes.Equal(r.tbl[tableJobBooks].Get([]byte("c")), []byte(`{}`)) {
			t.Errorf("a plan that fits is held back: wait %v, %v", wait, err)
		}
		if len(r.ops()) != 2 {
			t.Errorf("the round holds %d ops, want 2", len(r.ops()))
		}
	})
}

// An issue action appends the audit rows of its transition: the plan writes them as an op on the append-only Audits array,
// and the rows of the plans of a round are one op in the order the plans ran (set when the log has no rows yet, append when it
// has: every plan of a round judges that against the same state). A plan that cuts the log, or one that sets while another
// appends, is not judged by a round.
func TestSparseRoundTakesTheAuditRowsOfItsPlansInOrder(t *testing.T) {
	s := newLedgerStore(t)
	audit := func(op, rows string) sparsePlan {
		return func(*State, *ledgerTx) ([]patchOp, error) {
			return []patchOp{setJob("k", `{}`), {Op: op, Path: []string{"Audits"}, Value: json.RawMessage(rows)}}, nil
		}
	}
	for _, op := range []string{opSet, opArray} {
		viewRound(t, s, func(l *ledgerTx) {
			var r sparseRound
			for i, rows := range []string{`[{"a":1}]`, `[ {"a":2}, {"a":3} ]`} {
				if _, wait, err := r.admit(audit(op, rows), &State{}, l); wait || err != nil {
					t.Fatalf("%s plan %d: wait %v, %v", op, i, wait, err)
				}
			}
			var got []patchOp
			for _, o := range r.ops() {
				if len(o.Path) == 1 && o.Path[0] == "Audits" {
					got = append(got, o)
				}
			}
			if len(got) != 1 || got[0].Op != op || string(got[0].Value) != `[{"a":1},{"a":2},{"a":3}]` {
				t.Fatalf("%s: the round writes the audit ops %+v, want one with the rows of both plans in order", op, got)
			}
		})
	}
	viewRound(t, s, func(l *ledgerTx) {
		var r sparseRound
		if _, _, err := r.admit(audit(opSet, `[{"a":1}]`), &State{}, l); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.admit(audit(opArray, `[{"a":2}]`), &State{}, l); !errors.Is(err, errSparseFallback) {
			t.Errorf("a plan that appends beside one that sets is judged %v, want the fallback", err)
		}
		cut := func(*State, *ledgerTx) ([]patchOp, error) {
			return []patchOp{{Op: opArray, Path: []string{"Audits"}, Value: json.RawMessage(`[{"a":4}]`), Cut: 1}}, nil
		}
		_, _, err := r.admit(cut, &State{}, l)
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Invalid {
			t.Errorf("a plan that cuts the audit log is judged %v, want Invalid", err)
		}
		if got := len(r.ops()); got != 2 {
			t.Errorf("the failed plans left ops: %d, want the record and the one audit op", got)
		}
	})
}
