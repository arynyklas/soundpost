// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestARoundReadsEachSeriesRecordOfTheLedgerOnce is the red test of the reads the control lane makes for a series (round 2 of the
// control lane): a transition read the count of a series (series), read it again to see whether the write changed the number of
// series under the quota key (setSeries), and the round read it a third time to write the op only when it differs from the
// ledger's (ops). The ledger the round reads is one read transaction, so the record is the same each time: what the round needs
// is one lookup of it, and a lookup is the rows of a block of the base file. A settlement command reads 2,300 of these records.
func TestARoundReadsEachSeriesRecordOfTheLedgerOnce(t *testing.T) {
	s := seriesBlockFile(t, 1000)
	var ids []string
	for i := range 6 {
		ids = append(ids, fmt.Sprintf("series-%06d", 7+i*11))
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		round := newLedgerBooks(l)
		for pass := range 2 { // two transitions of the round that charge the same series
			c := round.child()
			for _, id := range ids {
				for _, tier := range tiers {
					c.setSeries(tier, id, c.series(tier, id)+1)
					c.setChargeSeries(tier, id, c.chargeSeries(tier, id)+uint64(pass)+1)
				}
			}
			round.merge(c)
		}
		if ops := round.ops(); len(ops) == 0 {
			t.Error("the round wrote nothing")
		}
		gets := 0
		for _, st := range l.ov.store {
			if st != nil {
				gets += st.gets
			}
		}
		// the counts of the series and the settled charges are two tables of blocks: one lookup in each for every (series, quota key)
		if want := 2 * len(ids) * len(tiers); gets > want {
			t.Errorf("%d lookups of the base file for %d series records, want at most one each", gets, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
