// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// withSmallOverlay makes the generations of the overlay a few kilobytes, so that a short test freezes, folds and
// drops many of them.
func withSmallOverlay(t *testing.T, freeze uint64, fold, bulk int) {
	t.Helper()
	lo, hi, o, b := ovFreezeMin, ovFreezeMax, ovFoldMin, ovBulkEntries
	ovFreezeMin, ovFreezeMax, ovFoldMin, ovBulkEntries = freeze, freeze, fold, bulk
	t.Cleanup(func() { ovFreezeMin, ovFreezeMax, ovFoldMin, ovBulkEntries = lo, hi, o, b })
}

// ovModel is what the three overlaid tables hold, by slot.
type ovModel [ovSlots]map[string]string

func newOvModel() *ovModel {
	var m ovModel
	for i := range m {
		m[i] = map[string]string{}
	}
	return &m
}

func (m *ovModel) clone() *ovModel {
	c := newOvModel()
	for i := range m {
		for k, v := range m[i] {
			c[i][k] = v
		}
	}
	return c
}

// checkOverlay compares every table of tx with the model: the scan in order, a read of every key, a read of keys that
// are not there, a seek, and the accumulator against a fold of the records.
func checkOverlay(t *testing.T, tx *bolt.Tx, m *ovModel, label string) {
	t.Helper()
	l, err := openLedger(tx)
	if err != nil {
		t.Fatal(err)
	}
	for slot, table := range ovTableOf {
		want := make([]string, 0, len(m[slot]))
		for k := range m[slot] {
			want = append(want, k)
		}
		sort.Strings(want)
		var got []string
		c := l.t[table].Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			got = append(got, string(k))
			if string(v) != m[slot][string(k)] {
				t.Fatalf("%s: slot %d scan: %q holds %q, want %q", label, slot, k, v, m[slot][string(k)])
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: slot %d scan holds %d records, want %d", label, slot, len(got), len(want))
		}
		for k, v := range m[slot] {
			if g := l.t[table].Get([]byte(k)); string(g) != v {
				t.Fatalf("%s: slot %d get %q = %q, want %q", label, slot, k, g, v)
			}
		}
		for _, k := range want {
			if g := l.t[table].Get([]byte(k + "x")); g != nil && m[slot][k+"x"] == "" {
				t.Fatalf("%s: slot %d get %q is %q, want none", label, slot, k+"x", g)
			}
		}
		for i := 0; i < len(want); i += 1 + len(want)/7 {
			p := []byte(want[i][:len(want[i])-len(want[i])/3])
			wantSeek := ""
			if j := sort.SearchStrings(want, string(p)); j < len(want) {
				wantSeek = want[j]
			}
			k, _ := l.t[table].Cursor().Seek(p)
			if string(k) != wantSeek {
				t.Fatalf("%s: slot %d seek %q = %q, want %q", label, slot, p, k, wantSeek)
			}
		}
	}
	if acc := recomputeAcc(l); acc != l.acc {
		t.Fatalf("%s: the accumulator %x is not the fold of the records %x", label, l.acc, acc)
	}
}

func checkOverlayStore(t *testing.T, s *Store, m *ovModel, label string) {
	t.Helper()
	if err := s.db.View(func(tx *bolt.Tx) error { checkOverlay(t, tx, m, label); return nil }); err != nil {
		t.Fatal(err)
	}
}

// ovRecord is a random record of slot: the keys of a table of reservation keys, or the series of three quota keys.
func ovRecord(r *rand.Rand, slot int) (key, value []byte) {
	switch slot {
	case 0:
		return []byte(fmt.Sprintf("o1:p%02d:s1:pr:%d:batch%04d", r.IntN(5), r.IntN(3), r.IntN(120))), []byte(fmt.Sprintf("res%06d", r.IntN(1000000)))
	case 3, 4:
		return []byte(fmt.Sprintf("row%03d-%d", r.IntN(90), slot)), []byte(fmt.Sprintf("value %d", r.IntN(1000000)))
	}
	tier := tiers[r.IntN(len(tiers))]
	if r.IntN(10) == 0 {
		tier = fmt.Sprintf("source:o:p%d:s%d", r.IntN(4), r.IntN(4))
	}
	return seriesKey(tier, fmt.Sprintf("series-%03d", r.IntN(150))), u64(1 + uint64(r.IntN(9)))
}

func openOverlayStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The overlay holds what a plain table holds, whatever its generations are doing: random puts and deletes in many
// commits (a generation is 40 records: it freezes, folds and drops all the time), a restart in the middle, a replacement
// of the ledger in the middle.
func TestOverlayHoldsWhatAPlainTableHolds(t *testing.T) {
	withSmallOverlay(t, 2500, 8, 1000)
	dir := t.TempDir()
	s := openOverlayStore(t, dir)
	defer func() { s.Close() }()
	activateLedger(t, s)
	r := rand.New(rand.NewPCG(7, 11))
	m := newOvModel()
	frozen, dropped := 0, 0
	for round := range 600 {
		writeLedger(t, s, func(l *ledgerTx) error {
			for range 1 + r.IntN(30) {
				slot := r.IntN(ovSlots)
				table := ovTableOf[slot]
				key, value := ovRecord(r, slot)
				if _, has := m[slot][string(key)]; has && r.IntN(3) == 0 {
					if _, err := l.del(table, key); err != nil {
						return err
					}
					delete(m[slot], string(key))
				} else {
					if err := l.put(table, key, value); err != nil {
						return err
					}
					m[slot][string(key)] = string(value)
				}
			}
			return nil
		})
		_ = s.db.View(func(tx *bolt.Tx) error {
			meta := readOvMeta(tx.Bucket([]byte("control")))
			if meta.frozen != 0 {
				frozen++
			} else if frozen > 0 {
				dropped++
				frozen = 0
			}
			return nil
		})
		switch {
		case round%50 == 49:
			checkOverlayStore(t, s, m, fmt.Sprintf("round %d", round))
		case round == 300:
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = openOverlayStore(t, dir)
			checkOverlayStore(t, s, m, "after a restart")
		}
	}
	if dropped < 5 {
		t.Errorf("only %d generations were folded and dropped: the test did not exercise the fold", dropped)
	}
	// A replacement of the ledger empties it and fills it again.
	held := ledgerMembers{Quotas: map[string]model.QuotaState{"q": {Configured: true, MaxSeries: 9, Series: map[string]uint64{"a": 1, "b": 2}}}, AdmissionKeys: map[string]string{"k": "id"}}
	writeLedger(t, s, func(l *ledgerTx) error { return l.replace(held) })
	checkLedger(t, s, held, "after a replacement")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openOverlayStore(t, dir)
	checkLedger(t, s, held, "after a replacement and a restart")
}

// A transaction reads the version of its own snapshot: a reader that began before commits (some of which freeze and
// drop generations) keeps reading what it began with, and a reader that began after reads what they wrote.
func TestOverlayReadersSeeTheirOwnSnapshot(t *testing.T) {
	withSmallOverlay(t, 1800, 6, 1000)
	s := newLedgerStore(t)
	r := rand.New(rand.NewPCG(3, 5))
	m := newOvModel()
	step := func(rounds int) {
		for range rounds {
			writeLedger(t, s, func(l *ledgerTx) error {
				for range 1 + r.IntN(12) {
					slot := r.IntN(ovSlots)
					key, value := ovRecord(r, slot)
					if err := l.put(ovTableOf[slot], key, value); err != nil {
						return err
					}
					m[slot][string(key)] = string(value)
				}
				return nil
			})
		}
	}
	step(20)
	type reader struct {
		tx   *bolt.Tx
		want *ovModel
	}
	var readers []reader
	for range 6 {
		tx, err := s.db.Begin(false)
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader{tx: tx, want: m.clone()})
		step(9)
	}
	for i, rd := range readers {
		checkOverlay(t, rd.tx, rd.want, fmt.Sprintf("reader %d (older than %d commits)", i, 9*(len(readers)-i)))
		_ = rd.tx.Rollback()
	}
	checkOverlayStore(t, s, m, "the newest")
}

// Readers and a writer at once: every read is of one version.
func TestOverlayConcurrentReadersAndWriter(t *testing.T) {
	withSmallOverlay(t, 3000, 8, 1000)
	s := newLedgerStore(t)
	var mu sync.Mutex
	versions := map[uint64]*ovModel{}
	m := newOvModel()
	record := func() {
		_ = s.db.View(func(tx *bolt.Tx) error {
			mu.Lock()
			versions[readOvMeta(tx.Bucket([]byte("control"))).seq] = m.clone()
			mu.Unlock()
			return nil
		})
	}
	record()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	fails := make(chan string, 8)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.db.View(func(tx *bolt.Tx) error {
					seq := readOvMeta(tx.Bucket([]byte("control"))).seq
					mu.Lock()
					want := versions[seq]
					mu.Unlock()
					if want == nil {
						return nil // a version the writer has not recorded yet
					}
					l, err := openLedger(tx)
					if err != nil {
						return err
					}
					for slot, table := range ovTableOf {
						n := 0
						c := l.t[table].Cursor()
						for k, v := c.First(); k != nil; k, v = c.Next() {
							n++
							if want[slot][string(k)] != string(v) {
								select {
								case fails <- fmt.Sprintf("version %d slot %d: %q holds %q, want %q", seq, slot, k, v, want[slot][string(k)]):
								default:
								}
								return nil
							}
						}
						if n != len(want[slot]) {
							select {
							case fails <- fmt.Sprintf("version %d slot %d: %d records, want %d", seq, slot, n, len(want[slot])):
							default:
							}
						}
					}
					return nil
				})
			}
		}()
	}
	r := rand.New(rand.NewPCG(9, 9))
	for range 300 {
		mu.Lock()
		next := m.clone()
		mu.Unlock()
		writeLedger(t, s, func(l *ledgerTx) error {
			for range 1 + r.IntN(10) {
				slot := r.IntN(ovSlots)
				key, value := ovRecord(r, slot)
				if err := l.put(ovTableOf[slot], key, value); err != nil {
					return err
				}
				next[slot][string(key)] = string(value)
			}
			return nil
		})
		mu.Lock()
		m = next
		mu.Unlock()
		record()
	}
	close(stop)
	wg.Wait()
	close(fails)
	for f := range fails {
		t.Error(f)
	}
	checkOverlayStore(t, s, m, "after the readers")
}

// A transaction that failed after it wrote leaves nothing in the overlay: not in the file, not in the copy the readers share.
func TestOverlayRolledBackWritesLeaveNothing(t *testing.T) {
	withSmallOverlay(t, 1800, 6, 1000)
	s := newLedgerStore(t)
	r := rand.New(rand.NewPCG(4, 4))
	m := newOvModel()
	boom := errors.New("boom")
	for round := range 120 {
		writeLedger(t, s, func(l *ledgerTx) error {
			for range 1 + r.IntN(10) {
				slot := r.IntN(ovSlots)
				key, value := ovRecord(r, slot)
				if err := l.put(ovTableOf[slot], key, value); err != nil {
					return err
				}
				m[slot][string(key)] = string(value)
			}
			return nil
		})
		if round%3 == 0 {
			err := s.db.Update(func(tx *bolt.Tx) error {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				for range 1 + r.IntN(40) {
					slot := r.IntN(ovSlots)
					key, value := ovRecord(r, slot)
					if err := l.put(ovTableOf[slot], key, value); err != nil {
						return err
					}
				}
				if err = l.flush(); err != nil {
					return err
				}
				return boom
			})
			if !errors.Is(err, boom) {
				t.Fatal(err)
			}
		}
		if round%10 == 9 {
			checkOverlayStore(t, s, m, fmt.Sprintf("round %d", round))
		}
	}
}

// A commit of very many records goes to the base tables whole (the overlay is folded first), and the ledger is what it
// would have been.
func TestOverlayBulkCommitFoldsTheOverlay(t *testing.T) {
	withSmallOverlay(t, 1<<20, 6, 200)
	s := newLedgerStore(t)
	r := rand.New(rand.NewPCG(5, 5))
	m := newOvModel()
	for round := range 40 {
		n := 1 + r.IntN(30)
		if round%10 == 5 {
			n = 500
		}
		writeLedger(t, s, func(l *ledgerTx) error {
			for range n {
				slot := r.IntN(ovSlots)
				key, value := ovRecord(r, slot)
				if _, has := m[slot][string(key)]; has && r.IntN(4) == 0 {
					if _, err := l.del(ovTableOf[slot], key); err != nil {
						return err
					}
					delete(m[slot], string(key))
					continue
				}
				if err := l.put(ovTableOf[slot], key, value); err != nil {
					return err
				}
				m[slot][string(key)] = string(value)
			}
			return nil
		})
		checkOverlayStore(t, s, m, fmt.Sprintf("round %d", round))
	}
}

// A file of the layout before the overlay (plain series tables) is moved to blocks at Open, with its records and its
// accumulator.
func TestOpenMovesPlainSeriesTablesToBlocks(t *testing.T) {
	dir := t.TempDir()
	s := openOverlayStore(t, dir)
	activateLedger(t, s)
	want := ledgerMembers{
		Quotas:        map[string]model.QuotaState{"q1": {Configured: true, MaxSeries: 9, Series: map[string]uint64{"s1": 2, "s2": 1}}, "q2": {Configured: true, MaxSeries: 9, Series: map[string]uint64{"s1": 1}}},
		Settlement:    &model.Settlement{Charges: map[string]model.SettledCharge{"q1": {Bytes: 5, Series: map[string]uint64{"s1": 1, "s3": 4}}}},
		AdmissionKeys: map[string]string{"k1": "r1"},
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		if err = l.replace(want); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Put the series records where the previous layout kept them: plain rows, the series first.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		var rows [ovSlots][][2][]byte
		for slot := range ovSlots {
			c := l.t[ovTableOf[slot]].Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				rows[slot] = append(rows[slot], [2][]byte{bytes.Clone(k), bytes.Clone(v)})
			}
		}
		if err = l.ov.wipe(); err != nil { // the overlay and the blocks go, the records come back as plain rows
			return err
		}
		for slot := range ovSlots {
			for _, row := range rows[slot] {
				if err := l.ov.tbl[slot].Put(row[0], row[1]); err != nil {
					return err
				}
			}
		}
		if err = l.flush(); err != nil {
			return err
		}
		return l.ctrl.Put(ledgerFormatKey, previousLedgerFormat)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openOverlayStore(t, dir)
	defer s.Close()
	checkLedger(t, s, want, "after the move")
	if err := s.db.View(func(tx *bolt.Tx) error {
		if !ledgerLayout(tx.Bucket([]byte("control"))) {
			t.Error("the file did not get the layout of this build")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
