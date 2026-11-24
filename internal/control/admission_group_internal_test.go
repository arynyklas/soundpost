// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"math/rand/v2"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestGroupedBooksEqualTheTransitionsOneByOne pins the group commit of admission (admission_group.go): the
// transitions of one round, each over its own child of the round's books, the ones that fail left out,
// write exactly what the transitions that succeeded leave when they run one after the other on a State:
// a read inside the round sees what the transitions before it wrote, a refused transition leaves nothing,
// and the ops of the round apply to the ledger the way the ops of one transition do.
func TestGroupedBooksEqualTheTransitionsOneByOne(t *testing.T) {
	for seed := range uint64(120) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 13))
			s := newLedgerStore(t)
			var st State
			for command := range 30 {
				n := 1 + r.IntN(7)
				draws, refused := make([]uint64, n), make([]bool, n)
				for i := range n {
					draws[i], refused[i] = r.Uint64(), r.IntN(3) == 0
				}
				for i := range n {
					if !refused[i] {
						randomRound(rand.New(rand.NewPCG(draws[i], 1)), stateBooks{&st})
					}
				}
				var ops []patchOp
				if err := s.db.View(func(tx *bolt.Tx) error {
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					round := newLedgerBooks(l)
					for i := range n {
						child := round.child()
						randomRound(rand.New(rand.NewPCG(draws[i], 1)), child)
						if !refused[i] {
							round.merge(child)
						}
					}
					ops = round.ops()
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, op := range ops {
					if !validLedgerOp(op) {
						t.Fatalf("command %d: the round wrote an op the grammar refuses: %+v", command, op)
					}
				}
				writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
				checkLedger(t, s, ledgerMembers{Reservations: st.Reservations, AdmissionKeys: st.AdmissionKeys, Quotas: st.Quotas, Settlement: st.Settlement}, fmt.Sprintf("command %d of %d transitions", command, n))
			}
		})
	}
}
