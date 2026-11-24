// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// D85: an admission charges a series under each of the three quota tiers it belongs to. The series table is
// keyed by the series first, so the three records of one series are on one page: a round that charges
// thousands of series writes a page per series, not a page per (tier, series).

func seriesID(i int) string { return fmt.Sprintf("%032x", uint64(i)*0x9e3779b97f4a7c15) }

func TestASeriesChargedUnderThreeTiersIsOnePageOfWrites(t *testing.T) {
	const series, tiers, rounds, items = 20000, 3, 12, 100
	tierNames := []string{"org:" + model.ID{1}.String(), "project:" + model.ID{2}.String(), "source:" + model.ID{3}.String()}
	s := newLedgerStore(t)
	writeLedger(t, s, func(l *ledgerTx) error {
		m := ledgerMembers{Quotas: map[string]model.QuotaState{}}
		for _, tier := range tierNames {
			q := model.QuotaState{Configured: true, MaxSeries: 1 << 40, MaxBytes: 1 << 40, Series: map[string]uint64{}}
			for i := range series {
				q.Series[seriesID(i)] = 1
			}
			m.Quotas[tier] = q
		}
		return l.replace(m)
	})
	r := rand.New(rand.NewPCG(5, 85))
	counts := map[string]uint64{}
	var writes, puts int64
	for range rounds {
		var ops []patchOp
		seen := map[string]bool{}
		for range items {
			for range 4 {
				id := seriesID(r.IntN(series))
				if seen[id] {
					continue
				}
				seen[id] = true
				counts[id]++
				for _, tier := range tierNames {
					ops = append(ops, patchOp{Op: opSet, Path: []string{"Quotas", tier, "series", id}, Value: mustJSON(1 + counts[id])})
					puts++
				}
			}
		}
		w0 := s.BoltWriteStatsForTest().Writes
		writeLedger(t, s, func(l *ledgerTx) error { return l.applyLedgerOps(ops) })
		writes += s.BoltWriteStatsForTest().Writes - w0
	}
	t.Logf("%d series records written in %d pages (%.2f pages per record)", puts, writes, float64(writes)/float64(puts))
	if float64(writes) > 0.45*float64(puts) {
		t.Errorf("%d records of series charged under %d tiers were written in %d pages: the records of one series are not together", puts, tiers, writes)
	}
}

// The records of a series are keyed series first, and the keys parse back.
func TestSeriesKeysAreSeriesMajor(t *testing.T) {
	a, b := seriesKey("tier-b", "aa"), seriesKey("tier-a", "ab")
	if bytes.Compare(a, b) >= 0 {
		t.Error("the records of series aa are not before those of series ab")
	}
	if bytes.Compare(seriesKey("tier-a", "aa"), seriesKey("tier-b", "aa")) >= 0 || !bytes.HasPrefix(seriesKey("tier-a", "aa"), []byte("aa\x00")) {
		t.Error("the records of one series are not together")
	}
	if tier, id := splitSeriesKey(string(seriesKey("tier-a", "aa"))); tier != "tier-a" || id != "aa" {
		t.Errorf("the key parses to %q %q", tier, id)
	}
	if tier, id := splitSeriesKeyBytes(seriesKey("tier-a", "aa")); string(tier) != "tier-a" || string(id) != "aa" {
		t.Errorf("the key parses to %q %q", tier, id)
	}
}

// A file of an earlier layout (the quota key first) is moved at Open; the books, the accumulator and the
// logical state are what they were.
func TestOpenRekeysTheSeriesOfAnEarlierLayout(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	activateLedger(t, s)
	want := ledgerMembers{
		Quotas:     map[string]model.QuotaState{"q1": {Configured: true, MaxSeries: 9, Series: map[string]uint64{"s1": 2, "s2": 1}}, "q2": {Configured: true, MaxSeries: 9, Series: map[string]uint64{"s1": 1}}},
		Settlement: &model.Settlement{Charges: map[string]model.SettledCharge{"q1": {Bytes: 5, Series: map[string]uint64{"s1": 1, "s3": 4}}}},
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = l.replace(want); err != nil {
			return err
		}
		// Put the series records where the earlier layout kept them: plain rows, the quota key first.
		var all [ovSlots][][2][]byte
		for slot := range ovSlots {
			c := l.t[ovTableOf[slot]].Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				all[slot] = append(all[slot], [2][]byte{bytes.Clone(k), bytes.Clone(v)})
			}
		}
		if err = l.ov.wipe(); err != nil {
			return err
		}
		for slot := range ovSlots {
			for _, e := range all[slot] {
				key := e[0]
				if table := ovTableOf[slot]; slot == ovSeriesSlots[0] || slot == ovSeriesSlots[1] {
					tier, id := splitSeriesKeyBytes(e[0])
					key = append(append(append([]byte{}, tier...), 0), id...)
					l.xor(recordHash(table, e[0], e[1]))
					l.xor(recordHash(table, key, e[1]))
				}
				if err = l.ov.tbl[slot].Put(key, e[1]); err != nil {
					return err
				}
			}
		}
		if err = l.flush(); err != nil {
			return err
		}
		return l.ctrl.Put(ledgerFormatKey, hotMembersInBlobFormat)
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
	checkLedger(t, s, want, "after the move")
}
