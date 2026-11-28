// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// D104: the compact admission ops (compact_admission.go). A round that proposes them leaves every voter with the ledger the plain
// ops leave: the same records, the same accumulator, and an erasure pass that reads the plain ops of a reservation gets them.

// admissionStep is one transition of a round, as the books see it.
type admissionStep struct {
	kind   string // reserve, finalize, cancel
	row    model.AdmissionReservation
	id     model.ID
	cursor model.Cursor
}

func (s admissionStep) run(books admissionBooks) error {
	switch s.kind {
	case "reserve":
		for _, tier := range quotaKeys(s.row) {
			h, err := books.head(tier)
			if err != nil {
				return err
			}
			h.MaxBytes, h.MaxSeries = 1<<30, 1000
			h.Bytes += s.row.Bytes
			for _, id := range s.row.Series {
				books.setSeries(tier, id, books.series(tier, id)+1)
			}
			books.putHead(tier, h)
		}
		books.putReservation(s.row)
		books.putKey(reservationKey(s.row), s.row.ID.String())
		return nil
	case "finalize":
		old, ok, err := books.reservation(s.id.String())
		if err != nil || !ok || old.State == "cancelled" || old.Cursor != nil {
			return model.Fail(model.Conflict)
		}
		old.State = "consumed"
		cursor := s.cursor
		old.Cursor = &cursor
		books.putReservation(old)
		return nil
	}
	old, ok, err := books.reservation(s.id.String())
	if err != nil || !ok || old.State != "reserved" {
		return model.Fail(model.Conflict)
	}
	for _, tier := range quotaKeys(old) {
		h, err := books.head(tier)
		if err != nil {
			return err
		}
		h.Bytes -= old.Bytes
		for _, id := range old.Series {
			if n := books.series(tier, id); n <= 1 {
				books.setSeries(tier, id, 0)
			} else {
				books.setSeries(tier, id, n-1)
			}
		}
		books.putHead(tier, h)
	}
	old.State = "cancelled"
	books.putReservation(old)
	return nil
}

// admissionRounds draws rounds of transitions on reservations of one source whose batches share a small pool of series, so that
// transitions of one round meet on a series, finalize or cancel a row that the round itself reserved, and a row is settled by
// the next round.
type admissionRounds struct {
	r     *rand.Rand
	known []model.ID
}

func (g *admissionRounds) next() []admissionStep {
	var steps []admissionStep
	for range 1 + g.r.IntN(8) {
		switch d := g.r.IntN(20); {
		case d < 12 || len(g.known) == 0:
			var id, batch model.ID
			for i := range id {
				id[i], batch[i] = byte(1+g.r.IntN(255)), byte(1+g.r.IntN(255))
			}
			row := model.AdmissionReservation{ID: id, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: batch, Slot: uint16(g.r.IntN(64)), Bytes: model.Uint64(100 + g.r.IntN(900)), State: "reserved"}
			seen := map[string]bool{}
			for range g.r.IntN(7) {
				series := fmt.Sprintf("p:%02d", g.r.IntN(10))
				if !seen[series] {
					seen[series] = true
					row.Series = append(row.Series, series)
				}
			}
			slices.Sort(row.Series)
			g.known = append(g.known, id)
			steps = append(steps, admissionStep{kind: "reserve", row: row})
		case d < 17:
			steps = append(steps, admissionStep{kind: "finalize", id: g.known[g.r.IntN(len(g.known))], cursor: model.Cursor{Group: model.ID{9}, Index: model.Uint64(1 + g.r.IntN(1000))}})
		default:
			steps = append(steps, admissionStep{kind: "cancel", id: g.known[g.r.IntN(len(g.known))]})
		}
	}
	return steps
}

// roundOps is the ops of the steps run as one round of the group commit over the ledger of s (a child of the round for each
// transition, merged when it succeeds), written compact or plain.
func roundOps(t *testing.T, s *Store, steps []admissionStep, compact bool) []patchOp {
	t.Helper()
	var ops []patchOp
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		round := newLedgerBooks(l)
		round.compact = compact
		for _, step := range steps {
			c := round.child()
			if step.run(c) == nil {
				round.merge(c)
			}
		}
		ops = round.ops()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ops
}

func ledgerAcc(t *testing.T, s *Store) (acc [32]byte) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		acc = l.acc
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return acc
}

// TestCompactAdmissionOpsLeaveTheLedgerThePlainOpsLeave pins that the compact ops are an encoding of what the transitions wrote:
// the rounds of random reserve, finalize and cancel transitions leave the ledger of a voter that applies the compact ops, one
// that applies the plain ops and one that applies the compact ops as an erasure pass reads them (expandCompact) with the same
// records, the same series counts and heads and the same accumulator; the ops are in the grammar, survive the codec and are
// verified by a voter that already applied them.
func TestCompactAdmissionOpsLeaveTheLedgerThePlainOpsLeave(t *testing.T) {
	var rsv, fin, plainRows int
	for seed := range uint64(80) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			g := &admissionRounds{r: rand.New(rand.NewPCG(seed, 111))}
			compact, plain, expanded := newLedgerStore(t), newLedgerStore(t), newLedgerStore(t)
			var st State
			for round := range 40 {
				steps := g.next()
				for _, step := range steps {
					_ = step.run(stateBooks{&st})
				}
				ops := roundOps(t, compact, steps, true)
				plainOps := roundOps(t, plain, steps, false)
				for _, op := range ops {
					if !validLedgerOp(op) {
						t.Fatalf("round %d: an op the grammar refuses: %+v", round, op)
					}
					switch op.Op {
					case opReserve:
						rsv++
					case opFinalize:
						fin++
					}
				}
				plainRows += len(plainOps)
				if len(ops) != 0 {
					raw, err := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: model.ID{7}, Expected: 1, Keys: map[string][]byte{}, Ops: ops}})
					if err != nil {
						t.Fatal(err)
					}
					cmd, err := decodeControlCommand(raw)
					if err != nil || cmd.patch == nil || validatePatch(*cmd.patch) != nil {
						t.Fatalf("round %d: the codec or the structural check refuses the patch: %v", round, err)
					}
				}
				writeLedger(t, compact, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
				writeLedger(t, plain, func(l *ledgerTx) error { return l.applyLedgerOps(plainOps) })
				expandedOps, err := expandCompact(ops)
				if err != nil {
					t.Fatal(err)
				}
				for _, op := range expandedOps {
					if op.Op == opReserve {
						t.Fatalf("round %d: expandCompact left an rsv op", round)
					}
				}
				writeLedger(t, expanded, func(l *ledgerTx) error { return l.applyLedgerOps(expandedOps) })
				want := ledgerMembers{Reservations: st.Reservations, AdmissionKeys: st.AdmissionKeys, Quotas: st.Quotas, Settlement: st.Settlement}
				checkLedger(t, compact, want, fmt.Sprintf("compact, round %d", round))
				checkLedger(t, plain, want, fmt.Sprintf("plain, round %d", round))
				if a, b, c := ledgerAcc(t, compact), ledgerAcc(t, plain), ledgerAcc(t, expanded); a != b || a != c {
					t.Fatalf("round %d: the accumulators differ: compact %x plain %x expanded %x", round, a, b, c)
				}
				if err := compact.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					return l.verifyLedgerOps(ops)
				}); err != nil {
					t.Fatalf("round %d: the ledger does not verify the compact ops it applied: %v", round, err)
				}
			}
		})
	}
	if rsv == 0 || fin == 0 {
		t.Fatalf("the rounds drew %d rsv and %d fin ops: the test does not reach the compact ops", rsv, fin)
	}
	t.Logf("%d rsv and %d fin ops over %d plain ops", rsv, fin, plainRows)
}

// A round writes the plain ops where the compact ones would say something else than the transitions wrote: the reservation is
// cancelled again in its own round (its series are released, the counts the rsv op carries are not the round's), or its key
// names another row.
func TestCompactAdmissionFallsBackWhereTheOpWouldSaySomethingElse(t *testing.T) {
	s := newLedgerStore(t)
	row := model.AdmissionReservation{ID: model.ID{1}, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: model.ID{5}, Bytes: 10, Series: []string{"p:00", "p:01"}, State: "reserved"}
	reserve := admissionStep{kind: "reserve", row: row}
	cancel := admissionStep{kind: "cancel", id: row.ID}
	for _, op := range roundOps(t, s, []admissionStep{reserve, cancel}, true) {
		if op.Op == opReserve || op.Op == opFinalize {
			t.Fatalf("a reservation cancelled in its own round was written as %s: %+v", op.Op, op)
		}
	}
	ops := roundOps(t, s, []admissionStep{reserve}, true)
	if len(ops) == 0 || !hasOp(ops, opReserve) {
		t.Fatalf("a reservation of its own round was not written as an rsv op: %+v", ops)
	}
	for _, op := range ops {
		if len(op.Path) == 4 && op.Path[2] == "series" || len(op.Path) == 2 && op.Path[0] == "AdmissionKeys" {
			t.Fatalf("the rsv op was written beside the plain op of a record it carries: %+v", op)
		}
	}
	writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
	fin := roundOps(t, s, []admissionStep{{kind: "finalize", id: row.ID, cursor: model.Cursor{Group: model.ID{9}, Index: 3}}}, true)
	if len(fin) != 1 || fin[0].Op != opFinalize {
		t.Fatalf("the settling of a reservation of an earlier round was not one fin op: %+v", fin)
	}
	if len(fin[0].Value) > 120 {
		t.Fatalf("the fin op carries %d bytes: %s", len(fin[0].Value), fin[0].Value)
	}
	// A voter that replays a command an erasure pass rewrote reaches the fin op without the row: nothing to settle.
	other := newLedgerStore(t)
	writeLedger(t, other, func(l *ledgerTx) error { return l.applyLedgerOps(fin) })
	checkLedger(t, other, ledgerMembers{}, "a fin op for a reservation the voter does not hold")
}

func hasOp(ops []patchOp, name string) bool {
	for _, op := range ops {
		if op.Op == name {
			return true
		}
	}
	return false
}

// The structure of a compact op is checked before it is applied: an op whose row is not the one its path names, or whose counts
// do not cover the series of the row, is no command a proposer writes.
func TestCompactAdmissionOpsAreCheckedBeforeTheyAreApplied(t *testing.T) {
	s := newLedgerStore(t)
	row := model.AdmissionReservation{ID: model.ID{1}, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: model.ID{5}, Bytes: 10, Series: []string{"p:00"}, State: "reserved"}
	good := reserveOp{Row: row, Counts: [3][]uint64{{1}, {1}, {1}}}
	for name, q := range map[string]reserveOp{
		"short counts": {Row: row, Counts: [3][]uint64{{1}, {1}, {}}},
		"zero count":   {Row: row, Counts: [3][]uint64{{1}, {0}, {1}}},
	} {
		raw, _ := json.Marshal(q)
		err := s.db.Update(func(tx *bolt.Tx) error {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			return l.applyLedgerOps([]patchOp{{Op: opReserve, Path: []string{"Reservations", row.ID.String()}, Value: raw}})
		})
		if err == nil {
			t.Fatalf("%s: applied", name)
		}
	}
	raw, _ := json.Marshal(good)
	err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		return l.applyLedgerOps([]patchOp{{Op: opReserve, Path: []string{"Reservations", model.ID{2}.String()}, Value: raw}})
	})
	if err == nil {
		t.Fatal("an rsv op under another reservation's path was applied")
	}
	if validLedgerOp(patchOp{Op: opReserve, Path: []string{"Quotas", "x"}, Value: raw}) || validLedgerOp(patchOp{Op: opFinalize, Path: []string{"Reservations"}, Value: raw}) {
		t.Fatal("the grammar accepts a compact op anywhere but [Reservations, id]")
	}
}
