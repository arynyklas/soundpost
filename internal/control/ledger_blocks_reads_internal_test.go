// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// seriesBlockFile is a store whose series tables hold their records in the blocks of the bolt file (not only in the overlay's
// generations): enough series were written, with a small overlay, for the generations to have been folded.
func seriesBlockFile(t *testing.T, n int) *Store {
	t.Helper()
	withSmallOverlay(t, 1<<10, 1, 200)
	s := newLedgerStore(t)
	for round := range n / 50 {
		writeLedger(t, s, func(l *ledgerTx) error {
			for i := range 50 {
				id := fmt.Sprintf("series-%06d", round*50+i)
				for _, tier := range tiers {
					if err := l.put(tableSeries, seriesKey(tier, id), u64(uint64(1+i))); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	return s
}

// baseReads runs fn on a read transaction and answers how many reads of the bolt file the two series tables made for it: reads of
// the dictionary of quota keys, and of the blocks.
func baseReads(t *testing.T, s *Store, fn func(l *ledgerTx)) (ords, blocks int) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		fn(l)
		for _, st := range l.ov.store {
			if st != nil {
				ords += st.ordReads
				blocks += st.blockReads
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// A batch counts each of its six series under three quota keys, and the three records of a series lie in one block: what the
// reads of a transaction cost in the bolt file is a function of the series and the quota keys it names, not of how many
// records it reads. The three quota keys are three dictionary entries; the six series are six blocks at most. Eighteen reads
// of the records made 18 reads of the dictionary and 18 of the blocks (the same entry, the same block, read again each time).
func TestSeriesReadsOfOneTransactionReadEachBlockAndEachDictionaryEntryOnce(t *testing.T) {
	s := seriesBlockFile(t, 1000)
	var ids []string
	for i := range 6 {
		ids = append(ids, fmt.Sprintf("series-%06d", 7+i*11))
	}
	ords, blocks := baseReads(t, s, func(l *ledgerTx) {
		for _, id := range ids {
			for _, tier := range tiers {
				if n := l.series(tier, id); n == 0 {
					t.Errorf("series %s under %s is not counted", id, tier)
				}
			}
		}
		for _, id := range ids { // read again: nothing more to read from the file
			for _, tier := range tiers {
				l.series(tier, id)
			}
		}
	})
	if ords > len(tiers) {
		t.Errorf("36 reads of series records read the dictionary of quota keys %d times, want %d (one per quota key)", ords, len(tiers))
	}
	if blocks > len(ids) {
		t.Errorf("36 reads of series records read the blocks %d times, want %d (one per series)", blocks, len(ids))
	}
}
