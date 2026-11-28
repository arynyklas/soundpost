// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The derived settlement op (compact_settle.go). A command that carries the rows it drops and the parts it adds leaves every voter the
// ledger the plain ops of the settlement leave, and a statement the rows do not prove is refused before anything is written.

const (
	settleSpan = 100
	settlePart = 25
)

var settleGroup = model.ID{9}

// settleRoundOps is the ops of one settlement command over the ledger of s: planned and applied on a child of a round, the way
// SettleAdmissions builds it, written as the stl op (compact) or as the plain ops.
func settleRoundOps(t *testing.T, s *Store, candidates []model.SettleCandidate, compact bool) (ops []patchOp, rep SettleReport) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		round := newLedgerBooks(l)
		round.compact = compact
		c := round.child()
		var scanned atomic.Uint64
		plan, _, err := planSettlement(c, candidates, nil, &scanned)
		if err != nil || len(plan) == 0 {
			return err
		}
		if held, err := settleRowsHeld(c, plan); err != nil || !held {
			return errors.Join(err, errors.New("the rows moved"))
		}
		rep = applySettlement(c, plan)
		round.merge(c)
		ops = round.ops()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ops, rep
}

func partsOf(rows []model.AdmissionReservation) (parts []model.SettlePart) {
	byPart := map[uint32][]model.AdmissionReservation{}
	for _, row := range rows {
		j := model.PartOf(uint64(row.Cursor.Index), settleSpan, settlePart)
		byPart[j] = append(byPart[j], row)
	}
	for j := range uint32(settleSpan / settlePart) {
		if in := byPart[j]; len(in) != 0 {
			parts = append(parts, model.SettlePart{J: j, Batches: uint64(len(in)), Charge: model.ChargeDigest(chargeItems(in))})
		}
	}
	return parts
}

// settleCandidates is what the data states about the consumed rows of history: the windows of settleSpan commands, the even ones cut
// into parts of settlePart (offered open, some of the parts, or sealed with all of them), the odd ones whole; now and then a
// statement that is false (a digest that is not the rows').
func settleCandidates(r *rand.Rand, history []model.AdmissionReservation) []model.SettleCandidate {
	byWindow := map[uint64][]model.AdmissionReservation{}
	for _, row := range history {
		n := (uint64(row.Cursor.Index) - 1) / settleSpan
		byWindow[n] = append(byWindow[n], row)
	}
	var windows []uint64
	for n := range byWindow {
		windows = append(windows, n)
	}
	slices.Sort(windows)
	var out []model.SettleCandidate
	for _, n := range windows {
		if r.IntN(3) == 0 {
			continue
		}
		rows := byWindow[n]
		sort.Slice(rows, func(i, j int) bool { return rows[i].Cursor.Index < rows[j].Cursor.Index })
		c := model.SettleCandidate{Group: settleGroup, N: n, Span: settleSpan}
		sealed := func() {
			c.Batches, c.Charge = uint64(len(rows)), model.ChargeDigest(chargeItems(rows))
		}
		if n%2 == 1 {
			sealed()
		} else {
			c.Part = settlePart
			all := partsOf(rows)
			if r.IntN(2) == 0 {
				c.Open = true
				for _, p := range all {
					if r.IntN(2) == 0 {
						c.Parts = append(c.Parts, p)
					}
				}
			} else {
				sealed()
				c.Parts = all
			}
			if len(c.Parts) == 0 {
				continue
			}
		}
		if r.IntN(7) == 0 { // a statement the rows do not prove
			if len(c.Parts) != 0 {
				c.Parts[r.IntN(len(c.Parts))].Charge[0] ^= 1
			} else {
				c.Charge[0] ^= 1
			}
		}
		out = append(out, c)
	}
	return out
}

func TestSettleOpLeavesTheLedgerThePlainOpsLeave(t *testing.T) {
	var stls, completed, partsAdded, unsettled, rowsSettled int
	for seed := range uint64(60) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			g := &admissionRounds{r: rand.New(rand.NewPCG(seed, 222))}
			r := rand.New(rand.NewPCG(seed, 333))
			compact, plain := newLedgerStore(t), newLedgerStore(t)
			var st State
			var history []model.AdmissionReservation
			counted := map[string]bool{}
			used := map[uint64]bool{}
			for round := range 50 {
				steps := g.next()
				for i := range steps {
					if steps[i].kind != "finalize" {
						continue
					}
					idx := uint64(1 + r.IntN(400))
					for used[idx] {
						idx = idx%400 + 1
					}
					used[idx] = true
					steps[i].cursor = model.Cursor{Group: settleGroup, Index: model.Uint64(idx)}
				}
				for _, step := range steps {
					_ = step.run(stateBooks{&st})
				}
				ops, plainOps := roundOps(t, compact, steps, true), roundOps(t, plain, steps, false)
				writeLedger(t, compact, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
				writeLedger(t, plain, func(l *ledgerTx) error { return l.applyLedgerOps(plainOps) })
				var ids []string
				for id, row := range st.Reservations {
					if row.State == "consumed" && !counted[id] {
						ids = append(ids, id)
					}
				}
				slices.Sort(ids)
				for _, id := range ids {
					counted[id] = true
					history = append(history, st.Reservations[id])
				}
				if round%3 != 2 {
					continue
				}
				candidates := settleCandidates(r, history)
				sops, rep := settleRoundOps(t, compact, candidates, true)
				pops, prep := settleRoundOps(t, plain, candidates, false)
				var refRep SettleReport
				var scanned atomic.Uint64
				if plan, _, err := planSettlement(stateBooks{&st}, candidates, nil, &scanned); err != nil {
					t.Fatal(err)
				} else if len(plan) != 0 {
					refRep = applySettlement(stateBooks{&st}, plan)
				}
				if rep != prep || rep != refRep {
					t.Fatalf("round %d: the settlements differ: stl %+v plain %+v model %+v", round, rep, prep, refRep)
				}
				if len(sops) == 0 {
					if len(candidates) != 0 {
						unsettled++
					}
					continue
				}
				stls++
				completed += rep.Windows
				partsAdded += rep.Parts
				rowsSettled += rep.Reservations
				for _, op := range sops {
					if !validLedgerOp(op) {
						t.Fatalf("round %d: an op the grammar refuses: %+v", round, op)
					}
				}
				raw, err := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: model.ID{7}, Expected: 1, Keys: map[string][]byte{}, Ops: sops}})
				if err != nil {
					t.Fatal(err)
				}
				if cmd, err := decodeControlCommand(raw); err != nil || cmd.patch == nil || validatePatch(*cmd.patch) != nil {
					t.Fatalf("round %d: the codec or the structural check refuses the patch: %v", round, err)
				}
				if len(sops) != 1 || sops[0].Op != opSettle {
					t.Fatalf("round %d: the settlement is not one stl op: %+v", round, sops)
				}
				writeLedger(t, compact, func(l *ledgerTx) error { return l.applyLedgerOps(sops) })
				writeLedger(t, plain, func(l *ledgerTx) error { return l.applyLedgerOps(pops) })
				want := ledgerMembers{Reservations: st.Reservations, AdmissionKeys: st.AdmissionKeys, Quotas: st.Quotas, Settlement: st.Settlement}
				checkLedger(t, compact, want, fmt.Sprintf("stl, round %d", round))
				checkLedger(t, plain, want, fmt.Sprintf("plain, round %d", round))
				if a, b := ledgerAcc(t, compact), ledgerAcc(t, plain); a != b {
					t.Fatalf("round %d: the accumulators differ: stl %x plain %x", round, a, b)
				}
				if err := compact.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					return l.verifyLedgerOps(sops)
				}); err != nil {
					t.Fatalf("round %d: the ledger does not verify the stl op it applied: %v", round, err)
				}
			}
		})
	}
	if stls == 0 || completed == 0 || partsAdded == 0 || unsettled == 0 {
		t.Fatalf("the rounds drew %d stl ops, %d completed windows, %d parts added and %d refused offers: the test does not reach the op", stls, completed, partsAdded, unsettled)
	}
	t.Logf("%d stl ops: %d rows settled, %d windows completed, %d parts added, %d rounds whose offers were refused", stls, rowsSettled, completed, partsAdded, unsettled)
}

// settleLedger is a ledger holding n consumed reservations, the cursor of the i-th at i+1, and the rows as the data states them.
func settleLedger(t *testing.T, n int) (*Store, []model.AdmissionReservation) {
	t.Helper()
	s := newLedgerStore(t)
	var steps []admissionStep
	var rows []model.AdmissionReservation
	for i := range n {
		row := model.AdmissionReservation{ID: model.ID{byte(i + 1)}, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: model.ID{byte(10 + i)}, Slot: uint16(i), Bytes: model.Uint64(100 * (i + 1)), State: "reserved", Series: []string{"p:00", fmt.Sprintf("p:%02d", 1+i%3)}}
		cursor := model.Cursor{Group: settleGroup, Index: model.Uint64(i + 1)}
		steps = append(steps, admissionStep{kind: "reserve", row: row}, admissionStep{kind: "finalize", id: row.ID, cursor: cursor})
		row.State, row.Cursor = "consumed", &cursor
		rows = append(rows, row)
	}
	ops := roundOps(t, s, steps, false)
	writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
	return s, rows
}

func tryOp(s *Store, op patchOp) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = l.applyLedgerOps([]patchOp{op}); err != nil {
			return err
		}
		return l.flush()
	})
}

func settleOpOf(t *testing.T, ops []patchOp) (op patchOp, q settleOp) {
	t.Helper()
	i := slices.IndexFunc(ops, func(op patchOp) bool { return op.Op == opSettle })
	if i < 0 {
		t.Fatal("the settlement wrote no stl op")
	}
	if err := json.Unmarshal(ops[i].Value, &q); err != nil {
		t.Fatal(err)
	}
	return ops[i], q
}

func isCorrupt(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.Corrupt
}

// opWith is op with its first window changed by mutate (on copies of the window's slices).
func opWith(op patchOp, q settleOp, mutate func(*settleWindow)) patchOp {
	c := settleOp{Windows: slices.Clone(q.Windows)}
	c.Windows[0].Parts = slices.Clone(q.Windows[0].Parts)
	c.Windows[0].Rows = slices.Clone(q.Windows[0].Rows)
	mutate(&c.Windows[0])
	op.Value = mustJSON(c)
	return op
}

// A statement the rows do not prove is refused whole, whoever made it: a window digest that is not the rows', a count that is not the
// rows' (a row lost or invented), a row twice, a row of another window, a part settled again, a part whose digest or count is not the
// rows'. Nothing is written by an op that is refused, and the same op is not applied twice (a double count).
func TestSettleOpIsRefusedWhenTheRowsDoNotProveIt(t *testing.T) {
	const n = 8
	_, rows := settleLedger(t, n)
	whole := model.SettleCandidate{Group: settleGroup, N: 0, Span: n, Batches: n, Charge: model.ChargeDigest(chargeItems(rows))}
	parts := model.SettleCandidate{Group: settleGroup, N: 0, Span: n, Part: n / 2, Open: true, Parts: []model.SettlePart{{J: 0, Batches: n / 2, Charge: model.ChargeDigest(chargeItems(rows[:n/2]))}}}

	build := func(t *testing.T, c model.SettleCandidate) (*Store, patchOp, settleOp) {
		t.Helper()
		s, _ := settleLedger(t, n)
		ops, rep := settleRoundOps(t, s, []model.SettleCandidate{c}, true)
		if rep.Reservations == 0 {
			t.Fatal("the honest candidate settled nothing")
		}
		op, q := settleOpOf(t, ops)
		return s, op, q
	}
	refused := func(t *testing.T, s *Store, op patchOp, why string) {
		t.Helper()
		before := ledgerAcc(t, s)
		if err := tryOp(s, op); !isCorrupt(err) {
			t.Fatalf("%s: applied or refused another way: %v", why, err)
		}
		if ledgerAcc(t, s) != before {
			t.Fatalf("%s: the refused op wrote", why)
		}
	}

	t.Run("honest", func(t *testing.T) {
		s, op, q := build(t, whole)
		if len(q.Windows) != 1 || len(q.Windows[0].Rows) != n || q.Windows[0].Charge == nil {
			t.Fatalf("the op says %+v", q)
		}
		if err := tryOp(s, op); err != nil {
			t.Fatal(err)
		}
		refused(t, s, op, "the op applied twice") // the rows are gone: the charge is not folded again
	})
	t.Run("whole window", func(t *testing.T) {
		s, op, q := build(t, whole)
		refused(t, s, opWith(op, q, func(w *settleWindow) {
			charge := *w.Charge
			charge[0] ^= 1
			w.Charge = &charge
		}), "a window digest that is not the rows'")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Rows = w.Rows[1:] }), "a row lost from the window")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Rows = append(w.Rows, model.ID{0x77}.String()) }), "a row the window does not hold")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Rows = append(w.Rows, w.Rows[0]) }), "a row named twice")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.N = 1 }), "rows of another window")
		if err := tryOp(s, op); err != nil {
			t.Fatalf("the honest op after the refused ones: %v", err)
		}
	})
	t.Run("parts", func(t *testing.T) {
		s, op, q := build(t, parts)
		w := q.Windows[0]
		if w.Part != n/2 || len(w.Parts) != 1 || w.Charge != nil {
			t.Fatalf("the op says %+v", w)
		}
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Parts[0].Charge[0] ^= 1 }), "a part whose digest is not the rows'")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Parts[0].Count++ }), "a part whose count is not the rows'")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Parts[0].J = 1 }), "a part the rows are not in")
		refused(t, s, opWith(op, q, func(w *settleWindow) { w.Rows = append(w.Rows, model.ID{byte(n/2 + 1)}.String()) }), "a row outside the parts the op adds")
		if err := tryOp(s, op); err != nil {
			t.Fatal(err)
		}
		refused(t, s, op, "the same part twice")
	})
	t.Run("structure", func(t *testing.T) {
		_, op, q := build(t, whole)
		for _, c := range []struct {
			name   string
			mutate func(*settleWindow)
		}{
			{"no rows", func(w *settleWindow) { w.Rows = nil }},
			{"a whole window without its digest", func(w *settleWindow) { w.Charge = nil }},
			{"parts of a whole window", func(w *settleWindow) { w.Parts = []model.SettledPart{{J: 0, Count: 1}} }},
			{"a zero span", func(w *settleWindow) { w.Span = 0 }},
			{"a part larger than the window", func(w *settleWindow) { w.Part = w.Span }},
		} {
			var got settleOp
			if err := json.Unmarshal(opWith(op, q, c.mutate).Value, &got); err != nil {
				t.Fatal(err)
			}
			if err := got.check(op.Path); !isCorrupt(err) {
				t.Errorf("%s: the structural check answers %v", c.name, err)
			}
		}
		if err := (settleOp{}).check(op.Path); !isCorrupt(err) {
			t.Errorf("an stl op without a window: %v", err)
		}
		if err := q.check([]string{"settlement", "chs"}); !isCorrupt(err) {
			t.Errorf("an stl op at another path: %v", err)
		}
		if validLedgerOp(patchOp{Op: opSettle, Path: []string{"settlement", "windows", "x"}}) {
			t.Error("the grammar takes an stl op at the path of a window")
		}
	})
}
