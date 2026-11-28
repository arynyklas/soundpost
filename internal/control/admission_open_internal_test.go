// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// resv is a reservation row the ledger can store: every member the encoding needs is set.
func resv(id model.ID, state string) model.AdmissionReservation {
	return model.AdmissionReservation{ID: id, Org: model.NewID(), Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), Batch: model.NewID(), Hash: model.HashCanonical([]byte("reservation")), State: state}
}

func withCursor(r model.AdmissionReservation, c model.Cursor) model.AdmissionReservation {
	r.Cursor = &c
	return r
}

// openIndexMatches compares the index of open reservations of l with the reservation rows that are still
// reserved.
func openIndexMatches(l *ledgerTx) error {
	if l.open == nil {
		return fmt.Errorf("the file has no index of open reservations")
	}
	var want, got []string
	c := l.t[tableReservations].Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if reservationOpen(v) {
			want = append(want, string(k))
		}
	}
	oc := l.open.Cursor()
	for k, _ := oc.First(); k != nil; k, _ = oc.Next() {
		got = append(got, string(k))
	}
	sort.Strings(want)
	sort.Strings(got)
	if fmt.Sprint(want) != fmt.Sprint(got) {
		return fmt.Errorf("the index holds %d reservations %v, the rows that are reserved are %d %v", len(got), got, len(want), want)
	}
	return nil
}

// TestOpenIndexFollowsTheReservationRows drives random writes (a reservation reserved, finalized, cancelled,
// rewritten, deleted) and replacements of the whole ledger through the ledger's own write path and checks, after
// every transaction, that the index of open reservations is exactly the set of rows that are still reserved and
// that it belongs to the accumulator it sits beside.
func TestOpenIndexFollowsTheReservationRows(t *testing.T) {
	for seed := range uint64(40) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 29))
			s := newLedgerStore(t)
			var ids []model.ID
			for step := range 60 {
				writeLedger(t, s, func(l *ledgerTx) error {
					for range 1 + r.IntN(6) {
						switch op := r.IntN(10); {
						case op < 4 || len(ids) == 0: // a new reservation
							id := model.NewID()
							ids = append(ids, id)
							if err := l.putReservation(resv(id, "reserved")); err != nil {
								return err
							}
						case op < 7: // finalized
							id := ids[r.IntN(len(ids))]
							cursor := model.Cursor{Group: model.NewID(), Index: 1}
							if err := l.putReservation(withCursor(resv(id, "consumed"), cursor)); err != nil {
								return err
							}
						case op < 8: // cancelled
							id := ids[r.IntN(len(ids))]
							if err := l.putReservation(resv(id, "cancelled")); err != nil {
								return err
							}
						case op < 9: // reserved again (a rewrite of a row)
							id := ids[r.IntN(len(ids))]
							if err := l.putReservation(resv(id, "reserved")); err != nil {
								return err
							}
						default: // settled away
							i := r.IntN(len(ids))
							if _, err := l.del(tableReservations, []byte(ids[i].String())); err != nil {
								return err
							}
						}
					}
					return nil
				})
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					if !openIndexCurrent(l.ctrl) {
						return fmt.Errorf("the index does not belong to the ledger's accumulator")
					}
					return openIndexMatches(l)
				}); err != nil {
					t.Fatalf("step %d: %v", step, err)
				}
			}
			// A replacement of the ledger (a snapshot install) rebuilds the index with the rows.
			held := ledgerMembers{Reservations: map[string]model.AdmissionReservation{}}
			for i := range 25 {
				id := model.NewID()
				state := "consumed"
				if i%3 == 0 {
					state = "reserved"
				}
				held.Reservations[id.String()] = resv(id, state)
			}
			writeLedger(t, s, func(l *ledgerTx) error { return l.replace(held) })
			if err := s.db.View(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				return openIndexMatches(l)
			}); err != nil {
				t.Fatalf("after a replacement: %v", err)
			}
		})
	}
}

// TestOpenIndexIsRebuiltWhenItDoesNotBelongToTheLedger: a file that has no index, or whose ledger a build
// without the index changed, finds its index stale and rebuilds it from the table in one pass.
func TestOpenIndexIsRebuiltWhenItDoesNotBelongToTheLedger(t *testing.T) {
	s := newLedgerStore(t)
	writeLedger(t, s, func(l *ledgerTx) error {
		for i := range 30 {
			id := model.NewID()
			state := "consumed"
			if i%4 == 0 {
				state = "reserved"
			}
			if err := l.putReservation(resv(id, state)); err != nil {
				return err
			}
		}
		return nil
	})
	damage := map[string]func(tx *bolt.Tx) error{
		"the bucket is gone": func(tx *bolt.Tx) error { return tx.DeleteBucket(openIndexBucket) },
		"the mark is gone":   func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(ledgerOpenKey) },
		"a row changed without the index": func(tx *bolt.Tx) error {
			// what a build that does not know the index does: a row written and the accumulator moved
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			l.open = nil
			if err = l.putReservation(resv(model.NewID(), "reserved")); err != nil {
				return err
			}
			l.dirty = false
			return l.ctrl.Put(ledgerAccKey, l.acc[:])
		},
	}
	for name, hurt := range damage {
		t.Run(name, func(t *testing.T) {
			if err := s.db.Update(hurt); err != nil {
				t.Fatal(err)
			}
			if err := s.db.View(func(tx *bolt.Tx) error {
				if b := tx.Bucket(openIndexBucket); b != nil && openIndexCurrent(tx.Bucket([]byte("control"))) {
					return fmt.Errorf("the damage left the index current")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Update(ensureOpenIndex); err != nil {
				t.Fatal(err)
			}
			if err := s.db.View(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				if !openIndexCurrent(l.ctrl) {
					return fmt.Errorf("the rebuilt index does not belong to the ledger")
				}
				return openIndexMatches(l)
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Update(func(tx *bolt.Tx) error { // a current index is left alone
				before := bytes.Clone(tx.Bucket([]byte("control")).Get(ledgerOpenKey))
				if err := ensureOpenIndex(tx); err != nil {
					return err
				}
				if !bytes.Equal(before, tx.Bucket([]byte("control")).Get(ledgerOpenKey)) {
					return fmt.Errorf("a current index was rebuilt")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
