// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A start decodes the log of the overlay before the first read of the ledger: the active and the frozen generation, each as
// full as it gets (300,000 series records in all, 40 MB of keys and values). That is a few percent of the 20 s the start has,
// and does not grow with the history: the log is never longer than two generations.
func TestOverlayRebuildsTwoFullGenerationsWithinTheStartupBudget(t *testing.T) {
	dir := t.TempDir()
	s := openOverlayStore(t, dir)
	activateLedger(t, s)
	const blobs, perBlob = 100, 1500
	if err := s.db.Update(func(tx *bolt.Tx) error {
		log, ctrl := tx.Bucket(ovLogBucket), tx.Bucket([]byte("control"))
		for gen := uint64(1); gen <= 2; gen++ {
			for n := range uint64(blobs) {
				pend := newOvMaps()
				for i := range perBlob {
					id := fmt.Sprintf("%032x:%064x", gen*1000+n, i/3)
					pend[1][string(seriesKey(tiers[i%3], id))] = u64(1 + uint64(i%9))
				}
				if err := putBlob(log, gen, n, encodeBlob(&pend)); err != nil {
					return err
				}
			}
		}
		return ctrl.Put(ovMetaKey, ovMeta{seq: 7, active: 2, frozen: 1, blobN: blobs}.encode())
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openOverlayStore(t, dir)
	defer s.Close()
	began := time.Now()
	var got uint64
	if err := s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		got = readU64(l.t[tableSeries].Get(seriesKey(tiers[0], fmt.Sprintf("%032x:%064x", 2*1000+99, 0))))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	t.Logf("the log of two full generations (%d records) was decoded by the first read in %v", 2*blobs*perBlob, took)
	if got != 1 {
		t.Errorf("the first read found %d, want 1", got)
	}
	if took > startupBudget/10 {
		t.Errorf("rebuilding the overlay took %v, more than a tenth of the %v startup budget", took, startupBudget)
	}
}
