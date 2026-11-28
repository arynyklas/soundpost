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

// The job and issue books are records of the ledger (D84): the tests of the layer below the writers.

func bookRecord(r *rand.Rand, tag string) json.RawMessage {
	raw, err := json.Marshal(map[string]any{"tag": tag, "n": r.IntN(1000), "pad": fmt.Sprintf("%0*d", 1+r.IntN(40), r.IntN(100))})
	if err != nil {
		panic(err)
	}
	return raw
}

func TestBookOpsAreLedgerOps(t *testing.T) {
	for _, member := range []string{"JobBooks", "IssueBooks"} {
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
		if validLedgerOp(patchOp{Op: opArray, Path: []string{member, "k"}}) {
			t.Errorf("an array op addresses a record of %s", member)
		}
	}
	// Admission's fairness is for the admission books: a writer of the job or issue books is a writer.
	book := &statePatch{Ops: []patchOp{revisionOp(2), {Op: opSet, Path: []string{"JobBooks", "k"}, Value: json.RawMessage(`{}`)}}}
	if ledgerOnlyPatch(book) {
		t.Error("a patch of the job books is held for admission's sake like an admission command")
	}
	adm := &statePatch{Ops: []patchOp{revisionOp(2), {Op: opSet, Path: []string{"AdmissionKeys", "k"}, Value: json.RawMessage(`"x"`)}}}
	if !ledgerOnlyPatch(adm) {
		t.Error("an admission patch is not an admission command")
	}
}

// Applying ops to the ledger leaves the records the ops name, the accumulator is the fold of them, the
// ops verify against what they wrote, and the ops that diffLedger finds between two assemblies give the
// same ledger on another file.
func TestBookRecordsFollowTheOps(t *testing.T) {
	for seed := range uint64(60) {
		r := rand.New(rand.NewPCG(seed, 9))
		a, b := newLedgerStore(t), newLedgerStore(t)
		books := ledgerMembers{}
		for round := range 12 {
			var ops []patchOp
			before := cloneBooks(books)
			for range 1 + r.IntN(5) {
				member, table := "JobBooks", &books.JobBooks
				if r.IntN(2) == 0 {
					member, table = "IssueBooks", &books.IssueBooks
				}
				key := fmt.Sprintf("o:p:%d", r.IntN(8))
				if r.IntN(4) == 0 {
					ops = append(ops, patchOp{Op: opDelete, Path: []string{member, key}})
					delete(*table, key)
					continue
				}
				raw := bookRecord(r, key)
				ops = append(ops, patchOp{Op: opSet, Path: []string{member, key}, Value: raw})
				if *table == nil {
					*table = map[string]json.RawMessage{}
				}
				(*table)[key] = raw
			}
			// One op per path, as a patch is.
			ops = lastOpPerPath(ops)
			writeLedger(t, a, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
			checkLedger(t, a, ledgerMembers{JobBooks: books.JobBooks, IssueBooks: books.IssueBooks}, fmt.Sprintf("seed %d round %d", seed, round))
			if err := a.db.View(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				return l.verifyLedgerOps(ops)
			}); err != nil {
				t.Fatalf("seed %d round %d: the ops do not verify against what they wrote: %v", seed, round, err)
			}
			found := diffLedger(before.normalized(), cloneBooks(books).normalized())
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
		checkLedger(t, b, ledgerMembers{JobBooks: books.JobBooks, IssueBooks: books.IssueBooks}, fmt.Sprintf("seed %d diff", seed))
	}
}

func cloneBooks(m ledgerMembers) ledgerMembers {
	out := ledgerMembers{}
	if m.JobBooks != nil {
		out.JobBooks = map[string]json.RawMessage{}
		for k, v := range m.JobBooks {
			out.JobBooks[k] = v
		}
	}
	if m.IssueBooks != nil {
		out.IssueBooks = map[string]json.RawMessage{}
		for k, v := range m.IssueBooks {
			out.IssueBooks[k] = v
		}
	}
	return out
}

func lastOpPerPath(ops []patchOp) []patchOp {
	last := map[string]int{}
	for i, op := range ops {
		last[op.Path[0]+"/"+op.Path[1]] = i
	}
	var out []patchOp
	for i, op := range ops {
		if last[op.Path[0]+"/"+op.Path[1]] == i {
			out = append(out, op)
		}
	}
	return out
}

// A record is stored in its compact form, whatever spacing the command carried, and a record that is not
// an object is refused.
func TestBookRecordsAreStoredCompact(t *testing.T) {
	s := newLedgerStore(t)
	writeLedger(t, s, func(l *ledgerTx) error {
		return l.applyLedgerOps([]patchOp{{Op: opSet, Path: []string{"JobBooks", "k"}, Value: json.RawMessage("{ \"a\" : 1,\n \"b\":[ 1, 2 ] }")}})
	})
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if got := string(l.t[tableJobBooks].Get([]byte("k"))); got != `{"a":1,"b":[1,2]}` {
			t.Errorf("the record is stored as %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		return l.applyLedgerOps([]patchOp{{Op: opSet, Path: []string{"IssueBooks", "k"}, Value: json.RawMessage(`[1]`)}})
	})
	if err == nil {
		t.Error("a record that is not an object was stored")
	}
}

// A file of the build that kept the job and issue books in the blob (format 2, or the first layout's
// format 1) is moved at Open: the books leave the blob for the ledger and the logical state, its revision
// and its digest stay what they were.
func TestOpenMovesTheJobAndIssueBooksOfAnEarlierFormat(t *testing.T) {
	for _, format := range [][]byte{booksInBlobFormat, legacyLedgerFormat} {
		t.Run(fmt.Sprintf("format %d", format[0]), func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			activateLedger(t, s)
			r := rand.New(rand.NewPCG(5, uint64(format[0])))
			jobs := map[string]json.RawMessage{"o:p:j1": bookRecord(r, "j1"), "o:p:j2": bookRecord(r, "j2")}
			issues := map[string]json.RawMessage{"o:p": bookRecord(r, "i1")}
			reservation := model.AdmissionReservation{ID: model.ID{7}, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: model.ID{5}, Bytes: 10, State: "reserved"}
			var want []byte
			// Rewrite the file the way an earlier build left it: admission books in the ledger, the job and issue
			// books in the blob, the format key of that build.
			if err = s.db.Update(func(tx *bolt.Tx) error {
				var st State
				if err := loadLogical(tx, &st); err != nil {
					return err
				}
				st.JobBooks, st.IssueBooks = jobs, issues
				st.Reservations = map[string]model.AdmissionReservation{reservation.ID.String(): reservation}
				st.Revision = 41
				whole, err := json.Marshal(st)
				if err != nil {
					return err
				}
				want = whole
				ctrl := tx.Bucket([]byte("control"))
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				if err = l.replace(ledgerMembers{Reservations: st.Reservations}); err != nil {
					return err
				}
				if format[0] == legacyLedgerFormat[0] {
					// The first build kept the revision in the blob.
					if err = dropLayoutKeys(ctrl); err != nil {
						return err
					}
					raw, err := json.Marshal(func() State { c := st; detachScope(&c, scopeAdmission); return c }())
					if err != nil {
						return err
					}
					if err = putStateKeep(ctrl, raw); err != nil {
						return err
					}
				} else {
					raw, err := json.Marshal(func() State { c := st; detachScope(&c, scopeAdmission); return c }())
					if err != nil {
						return err
					}
					if err = putStateLayout(ctrl, raw); err != nil {
						return err
					}
				}
				return ctrl.Put(ledgerFormatKey, format)
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
				if !ledgerLayout(ctrl) {
					t.Errorf("the file is not of the current format after Open: %v", ctrl.Get(ledgerFormatKey))
				}
				if !bytes.Equal(ctrl.Get(ledgerSealKey), ctrl.Get(stateSealKey)) {
					t.Error("the seals differ")
				}
				members, err := decodeMembers(ctrl.Get(stateKey))
				if err != nil {
					return err
				}
				for _, name := range []string{"JobBooks", "IssueBooks", memberRevision} {
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
				if !reflect.DeepEqual(got.JobBooks, jobs) || !reflect.DeepEqual(got.IssueBooks, issues) {
					t.Errorf("the ledger holds jobs %v issues %v", got.JobBooks, got.IssueBooks)
				}
				if recomputeAcc(l) != l.acc {
					t.Error("the accumulator is not the fold of the records after the move")
				}
				var logical State
				if err := loadLogical(tx, &logical); err != nil {
					return err
				}
				if logical.Revision != 41 {
					t.Errorf("the revision is %d after the move", logical.Revision)
				}
				raw, err := json.Marshal(logical)
				if err != nil {
					return err
				}
				if !sameState(logicalOf(t, want), logicalOf(t, raw)) {
					t.Errorf("the logical state changed by the move")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func logicalOf(t *testing.T, raw []byte) State {
	t.Helper()
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	normalizeLedger(&st)
	return st
}
