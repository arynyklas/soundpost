// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// recomputeAcc is the accumulator of every record of the ledger, folded from scratch.
func recomputeAcc(l *ledgerTx) (acc [32]byte) {
	for table := range ledgerTableCount {
		c := l.t[table].Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			sum := recordHash(table, k, v)
			for i := range sum {
				acc[i] ^= sum[i]
			}
		}
	}
	return acc
}

// activateLedger contracts the installation of s (the mark in the stored state) and moves its books into
// the ledger, the way the command that contracts it does on every voter.
func activateLedger(t *testing.T, s *Store) {
	t.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		var st State
		if json.Unmarshal(ctrl.Get([]byte("state")), &st) != nil {
			t.Fatal("state")
		}
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC[model.IndexesContractedKey] = json.RawMessage(`true`)
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err = putState(ctrl, raw); err != nil {
			return err
		}
		return migrateLedger(tx)
	}); err != nil {
		t.Fatal(err)
	}
	s.noteLayout()
}

func newLedgerStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	activateLedger(t, s)
	return s
}

// writeLedger runs fn in a write transaction of the store's ledger.
func writeLedger(t *testing.T, s *Store, fn func(l *ledgerTx) error) {
	t.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = fn(l); err != nil {
			return err
		}
		return l.flush()
	}); err != nil {
		t.Fatal(err)
	}
}

// checkLedger compares the members the ledger assembles with want and its accumulator with a fresh
// fold of its records.
func checkLedger(t *testing.T, s *Store, want ledgerMembers, label string) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		got, err := l.members()
		if err != nil {
			return err
		}
		want = want.normalized()
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("%s: the ledger holds\n%s\nwant\n%s", label, g, w)
		}
		if acc := recomputeAcc(l); acc != l.acc {
			t.Fatalf("%s: the accumulator %x is not the fold of the records %x", label, l.acc, acc)
		}
		for tier, q := range got.Quotas {
			h, _, err := l.head(tier)
			if err != nil || h.Series != uint64(len(q.Series)) {
				t.Fatalf("%s: quota %s counts %d series records, holds %d (%v)", label, tier, h.Series, len(q.Series), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

var (
	tiers     = []string{"org:o", "project:o:p", "source:o:p:s"}
	seriesIDs = func() []string {
		var out []string
		for i := range 12 {
			out = append(out, fmt.Sprintf("series%02d", i))
		}
		return out
	}()
	groups = []model.ID{{1}, {2}}
)

// randomRound is one command's worth of writes to the books, the way the admission transitions make
// them: a reservation with its key, a charge on quota keys (head and series always together), and the
// settlement's rows.
func randomRound(r *rand.Rand, books admissionBooks) {
	for range 1 + r.IntN(6) {
		switch r.IntN(8) {
		case 0, 1:
			id := model.ID{byte(1 + r.IntN(20))}
			res := model.AdmissionReservation{ID: id, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Producer: model.ID{4}, Batch: model.ID{byte(1 + r.IntN(200))}, Slot: uint16(r.IntN(64)), Bytes: model.Uint64(1 + r.IntN(900)), State: []string{"reserved", "consumed", "cancelled"}[r.IntN(3)]}
			for range r.IntN(4) {
				res.Series = append(res.Series, seriesIDs[r.IntN(len(seriesIDs))])
			}
			if res.State == "consumed" {
				res.Cursor = &model.Cursor{Group: groups[r.IntN(2)], Index: model.Uint64(1 + r.IntN(50))}
			}
			books.putReservation(res)
			books.putKey(reservationKey(res), id.String())
		case 2:
			id := model.ID{byte(1 + r.IntN(20))}
			books.delReservation(id.String())
			books.delKey(fmt.Sprintf("k%d", id[0]))
		case 3, 4:
			tier := tiers[r.IntN(len(tiers))]
			h, err := books.head(tier)
			if err != nil {
				panic(err)
			}
			h.Bytes += model.Uint64(r.IntN(1000))
			h.MaxBytes = model.Uint64(1 << 20)
			h.MaxSeries = model.Uint64(1 + r.IntN(100))
			h.Configured = r.IntN(4) == 0
			for range r.IntN(5) {
				books.setSeries(tier, seriesIDs[r.IntN(len(seriesIDs))], uint64(r.IntN(4)))
			}
			books.putHead(tier, h)
		case 5:
			g := groups[r.IntN(2)]
			books.setSpan(g.String(), 4)
			n := uint64(r.IntN(10))
			books.putWindow(model.SettledKey(g, n), model.SettledWindow{Group: g, N: n, Span: 4, Count: uint64(1 + r.IntN(4))})
		case 6, 7:
			tier := tiers[r.IntN(len(tiers))]
			books.setCharge(tier, books.charge(tier)+uint64(r.IntN(500)))
			for range r.IntN(4) {
				id := seriesIDs[r.IntN(len(seriesIDs))]
				books.setChargeSeries(tier, id, uint64(r.IntN(3)))
			}
		}
	}
}

// TestLedgerBooksEqualStateBooks pins that the two implementations of the books decide alike: the same
// writes through a State (stateBooks) and through the ledger (ledgerBooks, applied as the patch ops it
// collected) leave the same members, and the ledger keeps its accumulator and its series counts.
func TestLedgerBooksEqualStateBooks(t *testing.T) {
	for seed := range uint64(200) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 7))
			s := newLedgerStore(t)
			var st State
			for round := range 60 {
				// The same round, drawn twice from the same stream: once for each implementation.
				state := r.Uint64()
				randomRound(rand.New(rand.NewPCG(state, 1)), stateBooks{&st})
				var ops []patchOp
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					books := newLedgerBooks(l)
					randomRound(rand.New(rand.NewPCG(state, 1)), books)
					ops = books.ops()
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, op := range ops {
					if !validLedgerOp(op) {
						t.Fatalf("round %d: the books wrote an op the grammar refuses: %+v", round, op)
					}
				}
				writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
				checkLedger(t, s, ledgerMembers{Reservations: st.Reservations, AdmissionKeys: st.AdmissionKeys, Quotas: st.Quotas, Settlement: st.Settlement}, fmt.Sprintf("round %d", round))
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					return l.verifyLedgerOps(ops)
				}); err != nil {
					t.Fatalf("round %d: the ledger does not verify the ops it applied: %v", round, err)
				}
			}
		})
	}
}

// TestLedgerDiffAppliesToTheLedger pins diffLedger: the ops it makes take the ledger from one set of
// members to another, whichever the two are.
func TestLedgerDiffAppliesToTheLedger(t *testing.T) {
	for seed := range uint64(8) {
		r := rand.New(rand.NewPCG(seed, 11))
		var a, b State
		for range 30 {
			randomRound(r, stateBooks{&a})
		}
		for range 30 {
			randomRound(r, stateBooks{&b})
		}
		s := newLedgerStore(t)
		before, after := detachLedger(&a).normalized(), detachLedger(&b).normalized()
		writeLedger(t, s, func(l *ledgerTx) error { return l.replace(before) })
		checkLedger(t, s, before, "replace")
		ops := diffLedger(before, after)
		for _, op := range ops {
			if !validLedgerOp(op) {
				t.Fatalf("seed %d: diffLedger wrote an op the grammar refuses: %+v", seed, op)
			}
		}
		writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
		checkLedger(t, s, after, fmt.Sprintf("seed %d diff", seed))
	}
}

// TestLedgerReplacementEqualsOps pins that installing a state (replace) and reaching it by ops leave the
// same ledger bytes: the accumulator two voters compare is a function of the content.
func TestLedgerReplacementEqualsOps(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 5))
	var st State
	for range 40 {
		randomRound(r, stateBooks{&st})
	}
	members := detachLedger(&st).normalized()
	one, two := newLedgerStore(t), newLedgerStore(t)
	writeLedger(t, one, func(l *ledgerTx) error { return l.replace(members) })
	writeLedger(t, two, func(l *ledgerTx) error { return l.applyLedgerOps(diffLedger(ledgerMembers{}, members)) })
	var a, b [32]byte
	for i, s := range []*Store{one, two} {
		if err := s.db.View(func(tx *bolt.Tx) error {
			l, err := openLedger(tx)
			if i == 0 {
				a = l.acc
			} else {
				b = l.acc
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if a != b || a == ([32]byte{}) {
		t.Fatalf("the accumulator of a replaced ledger %x and of one built by ops %x differ", a, b)
	}
}

// TestOpenMovesTheBooksOfAnOlderFileIntoTheLedger pins the migration: a file whose blob still holds
// the books (written by a build without the ledger) is opened, its members are moved in that
// transaction, the blob keeps none of them and the state a reader assembles is the one it held.
func TestOpenMovesTheBooksOfAnOlderFileIntoTheLedger(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(9, 9))
	var legacy State
	for range 25 {
		randomRound(r, stateBooks{&legacy})
	}
	want := detachLedger(&legacy).normalized()
	// What an earlier build left: the books in the blob, no ledger buckets, no marker.
	if err = s.db.DB.Update(func(tx *bolt.Tx) error {
		var st State
		ctrl := tx.Bucket([]byte("control"))
		if json.Unmarshal(ctrl.Get([]byte("state")), &st) != nil {
			t.Fatal("state")
		}
		attachLedger(&st, want)
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC[model.IndexesContractedKey] = json.RawMessage(`true`)
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err = ctrl.Put([]byte("state"), raw); err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if err = ctrl.Put(stateSealKey, sum[:]); err != nil {
			return err
		}
		if err = ctrl.Delete(ledgerFormatKey); err != nil {
			return err
		}
		if err = ctrl.Delete(ledgerAccKey); err != nil {
			return err
		}
		for _, name := range ledgerTables {
			if err = tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkLedger(t, s, want, "after migration")
	if err = s.db.View(func(tx *bolt.Tx) error {
		var blob State
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &blob) != nil {
			t.Fatal("blob")
		}
		if blob.Reservations != nil || blob.AdmissionKeys != nil || blob.Quotas != nil || blob.Settlement != nil {
			t.Fatal("the blob still holds ledger members")
		}
		var logical State
		if err := loadLogical(tx, &logical); err != nil {
			return err
		}
		if !reflect.DeepEqual(detachLedger(&logical), want) {
			t.Fatal("the assembled state is not the one the file held")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A second open leaves it as it is.
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	checkLedger(t, s, want, "after the second open")
	defer s.Close()
}

// TestOpenTakesTheBooksFromABlobTheLedgerIsOlderThan pins the rollback of one voter to a build without
// the ledger (the previous release): it commits the whole logical state into the blob and moves the
// state seal, but knows nothing of the ledger and its seal. The next Open of this build must take the
// books from the blob, not trust the ledger that was left behind, whatever the books of the two were.
func TestOpenTakesTheBooksFromABlobTheLedgerIsOlderThan(t *testing.T) {
	for name, empty := range map[string]bool{"the earlier build wrote books": false, "the earlier build wrote none": true} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err == nil {
				activateLedger(t, s)
			}
			if err != nil {
				t.Fatal(err)
			}
			r := rand.New(rand.NewPCG(3, 4))
			var before, after State
			for range 25 {
				randomRound(r, stateBooks{&before})
			}
			if !empty {
				for range 25 {
					randomRound(r, stateBooks{&after})
				}
			}
			was, want := detachLedger(&before).normalized(), detachLedger(&after).normalized()
			writeLedger(t, s, func(l *ledgerTx) error { return l.replace(was) })
			// What the earlier build leaves: the books of its own in the blob and a seal of that blob.
			if err = s.db.DB.Update(func(tx *bolt.Tx) error {
				var st State
				ctrl := tx.Bucket([]byte("control"))
				if json.Unmarshal(ctrl.Get([]byte("state")), &st) != nil {
					t.Fatal("state")
				}
				attachLedger(&st, want)
				st.Revision++
				raw, err := json.Marshal(st)
				if err != nil {
					return err
				}
				if err = ctrl.Put([]byte("state"), raw); err != nil {
					return err
				}
				sum := sha256.Sum256(raw)
				return ctrl.Put(stateSealKey, sum[:])
			}); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			checkLedger(t, s, want, "after the rollback and the open")
			if err = s.db.View(func(tx *bolt.Tx) error {
				var blob State
				if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &blob) != nil {
					t.Fatal("blob")
				}
				if blob.Reservations != nil || blob.AdmissionKeys != nil || blob.Quotas != nil || blob.Settlement != nil {
					t.Fatal("the blob still holds ledger members")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBaseMatchesTheDigestsOfBothLayouts pins what a voter accepts as the base of a patch: the digest of
// this release (blob and ledger accumulator) and the one a release without the ledger computed over its
// whole logical state (the previous release proposes patches to this one in a mixed group), and nothing
// else, whether the ledger is empty or holds books.
func TestBaseMatchesTheDigestsOfBothLayouts(t *testing.T) {
	for _, books := range []bool{false, true} {
		s := newLedgerStore(t)
		if books {
			var st State
			r := rand.New(rand.NewPCG(5, 5))
			for range 30 {
				randomRound(r, stateBooks{&st})
			}
			writeLedger(t, s, func(l *ledgerTx) error { return l.replace(detachLedger(&st).normalized()) })
		}
		if err := s.db.View(func(tx *bolt.Tx) error {
			raw, err := stateRaw(tx.Bucket([]byte("control")))
			if err != nil {
				return err
			}
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			blob, err := patchBase(raw)
			if err != nil {
				return err
			}
			this, err := committedBase(raw, l.acc)
			if err != nil {
				return err
			}
			other, err := committedBase(raw, [32]byte{1})
			if err != nil {
				return err
			}
			for name, tc := range map[string]struct {
				base string
				want bool
			}{
				"this release":                  {this, true},
				"the first build of the ledger": {ledgerBase1(blob, l.acc), true},
				"another accumulator":           {other, false},
				"the first build, another one":  {ledgerBase1(blob, [32]byte{1}), false},
				"the digest of a lie":           {ledgerBase("00", nil, nil, l.acc), false},
			} {
				got, err := baseMatches(tx, tc.base)
				if err != nil || got != tc.want {
					t.Errorf("books=%v %s: baseMatches = %v, %v, want %v", books, name, got, err, tc.want)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestValidLedgerOpGrammar pins what the grammar accepts: the shapes the books write, and nothing else.
func TestValidLedgerOpGrammar(t *testing.T) {
	set := func(p ...string) patchOp { return patchOp{Op: opSet, Path: p, Value: json.RawMessage("1")} }
	del := func(p ...string) patchOp { return patchOp{Op: opDelete, Path: p} }
	for _, op := range []patchOp{
		set("Reservations", "id"), del("Reservations", "id"), set("AdmissionKeys", "k"), del("AdmissionKeys", "k"),
		set("Quotas", "t"), del("Quotas", "t"), set("Quotas", "t", "bytes"), set("Quotas", "t", "configured"),
		set("Quotas", "t", "series"), del("Quotas", "t", "series"), set("Quotas", "t", "series", "id"), del("Quotas", "t", "series", "id"),
		set("settlement"), del("settlement"), set("settlement", "spans", "g"), del("settlement", "windows", "w"),
		set("settlement", "charges", "t"), set("settlement", "charges", "t", "bytes"), set("settlement", "charges", "t", "series", "id"), del("settlement", "charges", "t", "series", "id"),
	} {
		if !validLedgerOp(op) {
			t.Errorf("%s %v is refused", op.Op, op.Path)
		}
	}
	for _, op := range []patchOp{
		set("Reservations"), set("Reservations", "id", "x"), set("AdmissionKeys"), del("Quotas", "t", "bytes"), set("Quotas", "t", "nope"),
		set("Quotas", "t", "bytes", "x"), set("Quotas", "t", "series", "id", "x"), set("settlement", "windows"), set("settlement", "nope", "x"),
		del("settlement", "charges", "t", "bytes"), set("settlement", "charges", "t", "nope", "x"), {Op: opArray, Path: []string{"Reservations", "x"}},
	} {
		if validLedgerOp(op) {
			t.Errorf("%s %v is accepted", op.Op, op.Path)
		}
	}
}
