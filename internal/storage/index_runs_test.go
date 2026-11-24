// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

const irIndex = "scan_time"

func irOpenAt(t testing.TB, path string, mmap int) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{NoSync: true, InitialMmapSize: mmap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// irOpen opens a fresh database; mmap > 0 maps that much up front, which a test needs when it holds a read
// transaction open across write transactions (bolt cannot remap while a reader lives).
func irOpen(t testing.TB, mmap int) *bolt.DB {
	t.Helper()
	return irOpenAt(t, filepath.Join(t.TempDir(), "idx.db"), mmap)
}

func irCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func irSetHook(t *testing.T, fn func()) {
	t.Helper()
	indexRunsChunkHook = fn
	t.Cleanup(func() { indexRunsChunkHook = nil })
}

// irModel is the logical index: what one bolt bucket holding the union would hold.
type irModel struct{ kv map[string][]byte }

func (m *irModel) keys() []string {
	out := make([]string, 0, len(m.kv))
	for k := range m.kv {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var irAlphabet = []byte{0x00, 'a', 'b', 'c', 0xff}

func irRandBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if r.Intn(5) == 0 {
			b[i] = byte(r.Intn(256))
		} else {
			b[i] = irAlphabet[r.Intn(len(irAlphabet))]
		}
	}
	return b
}

// irRandModel returns n distinct keys of length 1..80 (many share long prefixes, some are prefixes of others)
// with values of 0..30 bytes.
func irRandModel(r *rand.Rand, n int) *irModel {
	prefixes := make([][]byte, 8)
	for i := range prefixes {
		prefixes[i] = irRandBytes(r, 1+r.Intn(30))
		if i > 0 && r.Intn(2) == 0 {
			prefixes[i] = append(bytes.Clone(prefixes[i-1]), prefixes[i]...)
		}
	}
	m := &irModel{kv: map[string][]byte{}}
	for len(m.kv) < n {
		m.kv[string(irRandKey(r, prefixes))] = irRandBytes(r, r.Intn(31))
	}
	return m
}

func irRandKey(r *rand.Rand, prefixes [][]byte) []byte {
	n := 1 + r.Intn(80)
	var key []byte
	if r.Intn(10) < 7 {
		p := prefixes[r.Intn(len(prefixes))]
		if len(p) > n {
			p = p[:n]
		}
		key = append(key, p...)
	}
	for len(key) < n {
		key = append(key, irRandBytes(r, 1)...)
	}
	return key
}

// irNewKeys returns n keys that md does not hold (and that are distinct); they are not added to md.
func irNewKeys(r *rand.Rand, md *irModel, n int) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for len(out) < n {
		k := irRandBytes(r, 1+r.Intn(80))
		if _, ok := md.kv[string(k)]; ok || seen[string(k)] {
			continue
		}
		seen[string(k)] = true
		out = append(out, k)
	}
	return out
}

// irLayout writes md as the logical index name: a base bucket with baseShare percent of the keys and nruns
// runs (written in random order, one to three per transaction, from scrambled-after-use buffers) holding the
// rest. It returns the number of non-empty runs and the number of keys in the base.
func irLayout(t testing.TB, db *bolt.DB, r *rand.Rand, name string, md *irModel, nruns, baseShare int) (written, baseKeys int) {
	t.Helper()
	groups := make([][]string, nruns+1)
	for _, k := range md.keys() {
		g := 0
		if nruns > 0 && r.Intn(100) >= baseShare {
			g = 1 + r.Intn(nruns)
		}
		groups[g] = append(groups[g], k)
	}
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return err
		}
		for _, k := range groups[0] {
			if err := b.Put([]byte(k), md.kv[k]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	order := r.Perm(nruns)
	for i := 0; i < len(order); {
		end := min(i+1+r.Intn(3), len(order))
		batch := order[i:end]
		i = end
		err := db.Update(func(tx *bolt.Tx) error {
			for _, g := range batch {
				keys := groups[g+1]
				pairs := make([]indexPair, 0, len(keys))
				for _, k := range keys {
					pairs = append(pairs, indexPair{Key: []byte(k), Value: bytes.Clone(md.kv[k])})
				}
				r.Shuffle(len(pairs), func(a, b int) { pairs[a], pairs[b] = pairs[b], pairs[a] })
				if err := writeIndexRun(tx, name, pairs); err != nil {
					return err
				}
				// The caller may reuse its buffers once writeIndexRun returns, before the commit.
				for _, p := range pairs {
					for j := range p.Key {
						p.Key[j] = 0xAA
					}
					for j := range p.Value {
						p.Value[j] = 0xBB
					}
				}
				if len(keys) > 0 {
					written++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return written, len(groups[0])
}

func irProbe(r *rand.Rand, keys []string) []byte {
	if len(keys) == 0 {
		return irRandBytes(r, r.Intn(10))
	}
	k := []byte(keys[r.Intn(len(keys))])
	switch r.Intn(7) {
	case 0:
		return irRandBytes(r, 1+r.Intn(80))
	case 1:
		return k
	case 2:
		k[len(k)-1]--
		return k
	case 3:
		k[len(k)-1]++
		return k
	case 4:
		return k[:r.Intn(len(k)+1)]
	case 5:
		return append(k, 0)
	}
	return []byte{}
}

// irVerify checks the set against the model: First/Next iteration, Seek (then Next) of random probes on one
// reused cursor, Seek past the end, Get of every key and of absent probes, ForEach.
func irVerify(t *testing.T, s *indexSet, md *irModel, r *rand.Rand, probes int) {
	t.Helper()
	keys := md.keys()
	c := s.Cursor()
	i := 0
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if i >= len(keys) {
			t.Fatalf("cursor yields the extra key %x", k)
		}
		if string(k) != keys[i] {
			t.Fatalf("key %d: got %x want %x", i, k, keys[i])
		}
		if !bytes.Equal(v, md.kv[keys[i]]) {
			t.Fatalf("value of key %x: got %x want %x", k, v, md.kv[keys[i]])
		}
		i++
	}
	if i != len(keys) {
		t.Fatalf("cursor yielded %d keys, want %d", i, len(keys))
	}
	if k, v := c.Next(); k != nil || v != nil {
		t.Fatalf("Next after the end returned %x", k)
	}
	for range probes {
		probe := irProbe(r, keys)
		want := sort.SearchStrings(keys, string(probe))
		k, v := c.Seek(probe)
		for step := range 4 {
			idx := want + step
			if idx >= len(keys) {
				if k != nil {
					t.Fatalf("Seek(%x)+%d: got %x past the end", probe, step, k)
				}
				break
			}
			if k == nil || string(k) != keys[idx] || !bytes.Equal(v, md.kv[keys[idx]]) {
				t.Fatalf("Seek(%x)+%d: got %x want %x", probe, step, k, keys[idx])
			}
			k, v = c.Next()
		}
	}
	if k, _ := c.Seek(bytes.Repeat([]byte{0xff}, 100)); k != nil {
		t.Fatalf("Seek past the end returned %x", k)
	}
	for _, k := range keys {
		if got := s.Get([]byte(k)); got == nil || !bytes.Equal(got, md.kv[k]) {
			t.Fatalf("Get(%x) = %x want %x", k, got, md.kv[k])
		}
	}
	for range probes {
		probe := irProbe(r, keys)
		if _, ok := md.kv[string(probe)]; !ok && s.Get(probe) != nil {
			t.Fatalf("Get(%x) found an absent key", probe)
		}
	}
	i = 0
	if err := s.ForEach(func(k, v []byte) error {
		if i >= len(keys) || string(k) != keys[i] || !bytes.Equal(v, md.kv[keys[i]]) {
			t.Fatalf("ForEach entry %d: got %x", i, k)
		}
		i++
		return nil
	}); err != nil || i != len(keys) {
		t.Fatalf("ForEach: %d of %d keys, err %v", i, len(keys), err)
	}
	stop := errors.New("stop")
	n := 0
	err := s.ForEach(func(k, v []byte) error {
		if n++; n == 3 {
			return stop
		}
		return nil
	})
	if len(keys) >= 3 && (err != stop || n != 3) {
		t.Fatalf("ForEach did not stop at the callback error: n=%d err=%v", n, err)
	}
}

// irCheckDB verifies the committed state of the index name in a fresh read transaction.
func irCheckDB(t *testing.T, db *bolt.DB, name string, md *irModel, r *rand.Rand) {
	t.Helper()
	if err := db.View(func(tx *bolt.Tx) error {
		s, err := openIndexSet(tx, name)
		if err != nil {
			return err
		}
		irVerify(t, s, md, r, 30)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func irRegistry(t testing.TB, db *bolt.DB, name string) (ready, building []indexRunEntry) {
	t.Helper()
	err := db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if reg == nil {
			return nil
		}
		runs, err := listIndexRuns(reg, name)
		for _, e := range runs {
			if e.meta.State == indexRunReady {
				ready = append(ready, e)
			} else {
				building = append(building, e)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ready, building
}

func irBucketNames(t testing.TB, db *bolt.DB) []string {
	t.Helper()
	var names []string
	if err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(n []byte, _ *bolt.Bucket) error {
			names = append(names, string(n))
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	return names
}

func TestIndexRunsProperty(t *testing.T) {
	iters := 24
	if raceEnabled {
		iters = 8
	}
	for it := range iters {
		seed := int64(7001 + it)
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			db := irOpen(t, 0)
			md := irRandModel(r, 200+r.Intn(4801))
			nruns := r.Intn(10)
			baseShare := []int{0, 20, 50, 100}[r.Intn(4)]
			if nruns == 0 {
				baseShare = 100
			}
			written, _ := irLayout(t, db, r, irIndex, md, nruns, baseShare)
			if err := db.View(func(tx *bolt.Tx) error {
				s, err := openIndexSet(tx, irIndex)
				if err != nil {
					return err
				}
				if s.RunCount() != written {
					t.Fatalf("RunCount %d, want %d", s.RunCount(), written)
				}
				irVerify(t, s, md, r, 150)
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			// Delete a random subset, verifying in the same transaction and after the commit.
			share := []int{5, 30, 70, 100}[r.Intn(4)]
			var gone []string
			for _, k := range md.keys() {
				if r.Intn(100) < share {
					gone = append(gone, k)
				}
			}
			r.Shuffle(len(gone), func(a, b int) { gone[a], gone[b] = gone[b], gone[a] })
			if err := db.Update(func(tx *bolt.Tx) error {
				s, err := openIndexSet(tx, irIndex)
				if err != nil {
					return err
				}
				for _, k := range gone {
					found, err := s.Delete([]byte(k))
					if err != nil {
						return err
					}
					if !found {
						t.Fatalf("Delete(%x) did not find the key", k)
					}
					delete(md.kv, k)
				}
				if len(gone) > 0 {
					if found, err := s.Delete([]byte(gone[0])); err != nil || found {
						t.Fatalf("second Delete: found=%v err=%v", found, err)
					}
				}
				for _, k := range irNewKeys(r, md, 5) {
					if found, err := s.Delete(k); err != nil || found {
						t.Fatalf("Delete of an absent key: found=%v err=%v", found, err)
					}
				}
				irVerify(t, s, md, r, 60)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			irCheckDB(t, db, irIndex, md, r)

			// The rare path: Put into the base, never over a key any source holds.
			if err := db.Update(func(tx *bolt.Tx) error {
				s, err := openIndexSet(tx, irIndex)
				if err != nil {
					return err
				}
				for _, k := range irNewKeys(r, md, 40) {
					v := irRandBytes(r, r.Intn(20))
					if err := s.Put(k, v); err != nil {
						return err
					}
					md.kv[string(k)] = v
				}
				for k := range md.kv {
					if err := s.Put([]byte(k), []byte("x")); irCode(err) != model.Corrupt {
						t.Fatalf("Put over an existing key: %v", err)
					}
					break
				}
				irVerify(t, s, md, r, 60)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			irCheckDB(t, db, irIndex, md, r)
		})
	}
}

func TestIndexRunsErrorsAndEdges(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	db := irOpen(t, 0)

	// No base bucket: corrupt. No registry: no runs. Empty index: everything is nil.
	if err := db.View(func(tx *bolt.Tx) error {
		if _, err := openIndexSet(tx, irIndex); irCode(err) != model.Corrupt {
			t.Fatalf("openIndexSet without a base: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte(irIndex)); err != nil {
			return err
		}
		if err := writeIndexRun(tx, irIndex, nil); err != nil {
			return err
		}
		if tx.Bucket([]byte(runsRegistry)) != nil {
			t.Fatal("an empty run created the registry")
		}
		s, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		c := s.Cursor()
		if k, v := c.First(); k != nil || v != nil {
			t.Fatalf("First of an empty index: %x", k)
		}
		if k, _ := c.Seek([]byte("a")); k != nil {
			t.Fatalf("Seek of an empty index: %x", k)
		}
		if s.RunCount() != 0 || s.Get([]byte("a")) != nil {
			t.Fatal("empty index is not empty")
		}
		if found, err := s.Delete([]byte("a")); found || err != nil {
			t.Fatalf("Delete in an empty index: %v %v", found, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Invalid input is rejected before the transaction is touched.
	bad := [][]indexPair{
		{{Key: []byte("b"), Value: []byte("1")}, {Key: []byte("a"), Value: nil}, {Key: []byte("b"), Value: []byte("2")}},
		{{Key: []byte("a")}, {Key: nil}},
	}
	wantCode := []model.Code{model.Corrupt, model.Invalid}
	for i, pairs := range bad {
		err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, pairs) })
		if irCode(err) != wantCode[i] {
			t.Fatalf("case %d: %v, want %s", i, err, wantCode[i])
		}
	}
	if ready, building := irRegistry(t, db, irIndex); len(ready)+len(building) != 0 {
		t.Fatal("a failed writeIndexRun left a run")
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if err := writeIndexRun(tx, irIndex, []indexPair{{Key: []byte("a")}}); !errors.Is(err, bolt.ErrTxNotWritable) {
			t.Fatalf("writeIndexRun in a read transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A nil value is stored as an empty value, a present key.
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := writeIndexRun(tx, irIndex, []indexPair{{Key: []byte("k1")}, {Key: []byte("k0"), Value: []byte("v")}}); err != nil {
			return err
		}
		s, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		if v := s.Get([]byte("k1")); v == nil || len(v) != 0 {
			t.Fatalf("Get of a key with an empty value: %#v", v)
		}
		if err := s.Put([]byte("k1"), nil); irCode(err) != model.Corrupt {
			t.Fatalf("Put of a key a run holds: %v", err)
		}
		if err := s.Put([]byte("k2"), nil); err != nil {
			return err
		}
		if v := s.Get([]byte("k2")); v == nil || len(v) != 0 {
			t.Fatalf("Get of a Put key with an empty value: %#v", v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A read-only transaction opens the set and can read it; deleting there fails.
	if err := db.View(func(tx *bolt.Tx) error {
		s, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		md := &irModel{kv: map[string][]byte{"k0": []byte("v"), "k1": {}, "k2": {}}}
		irVerify(t, s, md, r, 20)
		if _, err := s.Delete([]byte("k0")); err == nil {
			t.Fatal("Delete in a read-only transaction succeeded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIndexRunsRegistryAndNames(t *testing.T) {
	db := irOpen(t, 0)
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte(irIndex)); err != nil {
			return err
		}
		if _, err := tx.CreateBucket([]byte("scan_postings")); err != nil {
			return err
		}
		for i := range 3 {
			pairs := []indexPair{{Key: []byte{byte(i), 1}, Value: []byte("vv")}, {Key: []byte{byte(i), 0}, Value: []byte("w")}}
			if err := writeIndexRun(tx, irIndex, pairs); err != nil {
				return err
			}
		}
		return writeIndexRun(tx, "scan_postings", []indexPair{{Key: []byte("p"), Value: []byte("q")}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		for id := uint64(1); id <= 3; id++ {
			key := binary.BigEndian.AppendUint64([]byte(irIndex+"/"), id)
			raw := reg.Get(key)
			if raw == nil {
				t.Fatalf("registry has no entry for run %d", id)
			}
			var m struct {
				State string `json:"state"`
				Level int    `json:"level"`
				Count int    `json:"count"`
				Bytes int    `json:"bytes"`
			}
			if err := json.Unmarshal(raw, &m); err != nil || m.State != "ready" || m.Level != 0 || m.Count != 2 || m.Bytes != 7 {
				t.Fatalf("registry value %s: %+v %v", raw, m, err)
			}
			if tx.Bucket([]byte(fmt.Sprintf("%s.r%016x", irIndex, id))) == nil {
				t.Fatalf("no bucket for run %d", id)
			}
		}
		// Ids are per index: the other index starts at 1.
		if reg.Get(binary.BigEndian.AppendUint64([]byte("scan_postings/"), 1)) == nil {
			t.Fatal("scan_postings run 1 missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A well-formed entry in any JSON spelling is read; a ready entry without its bucket, or garbage, is corrupt.
	if err := db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		old := binary.BigEndian.AppendUint64([]byte(irIndex+"/"), 2)
		return reg.Put(old, []byte(` { "bytes": 6, "count": 2, "state": "ready", "level": 3 } `))
	}); err != nil {
		t.Fatal(err)
	}
	ready, _ := irRegistry(t, db, irIndex)
	if len(ready) != 3 || ready[1].meta.Level != 3 || ready[1].id != 2 {
		t.Fatalf("ready runs %+v", ready)
	}
	for name, value := range map[string]string{
		"garbage":  `not json`,
		"state":    `{"state":"weird","level":0,"count":0,"bytes":0}`,
		"negative": `{"state":"ready","level":-1,"count":0,"bytes":0}`,
	} {
		err := db.Update(func(tx *bolt.Tx) error {
			reg := tx.Bucket([]byte(runsRegistry))
			if err := reg.Put(binary.BigEndian.AppendUint64([]byte(irIndex+"/"), 9), []byte(value)); err != nil {
				return err
			}
			_, err := openIndexSet(tx, irIndex)
			if irCode(err) != model.Corrupt {
				t.Fatalf("%s: openIndexSet: %v", name, err)
			}
			return errors.New("rollback")
		})
		if err == nil || err.Error() != "rollback" {
			t.Fatal(err)
		}
	}
	err := db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if err := reg.Put(binary.BigEndian.AppendUint64([]byte(irIndex+"/"), 9), indexRunMetaJSON(indexRunMeta{State: indexRunReady})); err != nil {
			return err
		}
		_, err := openIndexSet(tx, irIndex)
		return err
	})
	if irCode(err) != model.Corrupt {
		t.Fatalf("a ready run without a bucket: %v", err)
	}
}

func TestIndexRunsMetaEncoding(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := range 200 {
		m := indexRunMeta{State: indexRunReady, Level: r.Intn(12), Count: r.Int63n(1 << 40), Bytes: r.Int63n(1 << 50)}
		if i%2 == 1 {
			m.State = indexRunBuilding
		}
		enc := indexRunMetaJSON(m)
		std, err := json.Marshal(m)
		if err != nil || !bytes.Equal(enc, std) {
			t.Fatalf("encoding %s differs from encoding/json %s (%v)", enc, std, err)
		}
		got, ok := parseIndexRunMetaFast(enc)
		if !ok || got != m {
			t.Fatalf("fast parse of %s: %+v %v", enc, got, ok)
		}
		if got, err := parseIndexRunMeta(enc); err != nil || got != m {
			t.Fatalf("parse of %s: %+v %v", enc, got, err)
		}
	}
	for _, bad := range []string{
		``, `{`, `{"state":"ready","level":0,"count":0,"bytes":0`, `{"state":"ready","level":0,"count":0,"bytes":0}x`,
		`{"state":"ready","level":,"count":0,"bytes":0}`, `{"state":"ready","level":0,"count":99999999999999999999,"bytes":0}`,
		`{"state":"done","level":0,"count":0,"bytes":0}`,
	} {
		if _, err := parseIndexRunMeta([]byte(bad)); irCode(err) != model.Corrupt {
			t.Fatalf("parse of %q: %v", bad, err)
		}
	}
}

func TestIndexRunsDuplicateKeyInTwoSources(t *testing.T) {
	db := irOpen(t, 0)
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(irIndex))
		if err != nil {
			return err
		}
		if err := b.Put([]byte("k1"), []byte("base1")); err != nil {
			return err
		}
		if err := b.Put([]byte("k2"), []byte("base2")); err != nil {
			return err
		}
		if err := writeIndexRun(tx, irIndex, []indexPair{{Key: []byte("k1"), Value: []byte("runA1")}, {Key: []byte("k3"), Value: []byte("runA3")}}); err != nil {
			return err
		}
		return writeIndexRun(tx, irIndex, []indexPair{{Key: []byte("k1"), Value: []byte("runB1")}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		s, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		if got := s.Get([]byte("k1")); string(got) != "runB1" {
			t.Fatalf("Get of a duplicated key = %q, the newest run must win", got)
		}
		var seen []string
		if err := s.ForEach(func(k, v []byte) error { seen = append(seen, string(k)+"="+string(v)); return nil }); err != nil {
			return err
		}
		if fmt.Sprint(seen) != "[k1=runB1 k2=base2 k3=runA3]" {
			t.Fatalf("merged cursor over a duplicated key: %v", seen)
		}
		if found, err := s.Delete([]byte("k1")); err != nil || !found {
			t.Fatalf("Delete of a duplicated key: %v %v", found, err)
		}
		for _, b := range s.sources() {
			if b.Get([]byte("k1")) != nil {
				t.Fatal("a copy of the duplicated key survived Delete")
			}
		}
		if err := s.Put([]byte("k3"), []byte("x")); irCode(err) != model.Corrupt {
			t.Fatalf("Put of a key a run holds: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIndexRunsNextNoAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	r := rand.New(rand.NewSource(11))
	db := irOpen(t, 0)
	md := irRandModel(r, 4000)
	irLayout(t, db, r, irIndex, md, 8, 10)
	if err := db.View(func(tx *bolt.Tx) error {
		s, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		c := s.Cursor()
		allocs := testing.AllocsPerRun(20, func() {
			k, _ := c.First()
			for i := 0; i < 500 && k != nil; i++ {
				k, _ = c.Next()
			}
		})
		if allocs != 0 {
			t.Fatalf("First + 500 Next allocated %v times", allocs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type irSimRun struct {
	id    uint64
	level int
}

func irSimRuns(entries []indexRunEntry) []irSimRun {
	out := make([]irSimRun, len(entries))
	for i, e := range entries {
		out[i] = irSimRun{e.id, e.meta.Level}
	}
	return out
}

// irSimulate is the compaction policy written down independently: while some level holds fanout runs, the
// oldest fanout of the lowest such level become one run of the next level with the next id.
func irSimulate(runs []irSimRun, fanout int) (out []irSimRun, merges int) {
	return irSimulateAt(runs, func(int) int { return fanout })
}

// irSimulateAt is irSimulate with a fanout per level (the default policy: 64 runs of level 0 and of level 1, 8 above).
func irSimulateAt(runs []irSimRun, fanoutAt func(level int) int) (out []irSimRun, merges int) {
	for {
		byLevel := map[int][]irSimRun{}
		var maxID uint64
		for _, r := range runs {
			byLevel[r.level] = append(byLevel[r.level], r)
			maxID = max(maxID, r.id)
		}
		best := -1
		for level, rs := range byLevel {
			if len(rs) >= fanoutAt(level) && (best < 0 || level < best) {
				best = level
			}
		}
		if best < 0 {
			return runs, merges
		}
		drop := map[uint64]bool{}
		for _, r := range byLevel[best][:fanoutAt(best)] {
			drop[r.id] = true
		}
		var next []irSimRun
		for _, r := range runs {
			if !drop[r.id] {
				next = append(next, r)
			}
		}
		runs = append(next, irSimRun{maxID + 1, best + 1})
		merges++
	}
}

func TestIndexRunsCompact(t *testing.T) {
	r := rand.New(rand.NewSource(91))
	db := irOpen(t, 0)
	md := irRandModel(r, 3000)
	_, baseKeys := irLayout(t, db, r, irIndex, md, 37, 15)
	md2 := irRandModel(r, 500)
	irLayout(t, db, r, "scan_postings", md2, 10, 10)

	before, _ := irRegistry(t, db, irIndex)
	otherBefore, _ := irRegistry(t, db, "scan_postings")
	const fanout = 4
	wantRuns, wantMerges := irSimulate(irSimRuns(before), fanout)

	chunks := 0
	irSetHook(t, func() {
		chunks++
		ready, building := irRegistry(t, db, irIndex)
		if len(building) != 1 || len(ready) < len(wantRuns) {
			t.Fatalf("between chunks: %d ready, %d building runs", len(ready), len(building))
		}
		irCheckDB(t, db, irIndex, md, r)
		irCheckDB(t, db, "scan_postings", md2, r)
		if err := db.View(func(tx *bolt.Tx) error {
			s, err := openIndexSet(tx, irIndex)
			if err != nil {
				return err
			}
			if s.RunCount() != len(ready) {
				t.Fatalf("a reader sees %d runs, %d are ready", s.RunCount(), len(ready))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: fanout, MaxChunkBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
		if _, building := irRegistry(t, db, irIndex); len(building) != 0 {
			t.Fatal("a finished merge left a building run")
		}
		irCheckDB(t, db, irIndex, md, r)
	}
	if merges != wantMerges {
		t.Fatalf("%d merges, want %d", merges, wantMerges)
	}
	if chunks <= merges {
		t.Fatalf("%d chunk transactions for %d merges: 4 KiB chunks must split a merge", chunks, merges)
	}
	after, _ := irRegistry(t, db, irIndex)
	if len(after) >= len(before) {
		t.Fatalf("ready runs %d -> %d", len(before), len(after))
	}
	if got := irSimRuns(after); fmt.Sprint(got) != fmt.Sprint(wantRuns) {
		t.Fatalf("runs after compaction %v, want %v", got, wantRuns)
	}
	var total int64
	for _, e := range after {
		total += e.meta.Count
	}
	if total != int64(len(md.kv)-baseKeys) {
		t.Fatalf("run counts sum to %d, want %d", total, len(md.kv)-baseKeys)
	}
	if otherAfter, _ := irRegistry(t, db, "scan_postings"); fmt.Sprint(otherAfter) != fmt.Sprint(otherBefore) {
		t.Fatal("compacting one index changed the other")
	}
	// Exactly the base buckets, the registry and the buckets of the surviving runs remain: the inputs are gone.
	want := []string{irIndex, "scan_postings", runsRegistry}
	for _, name := range []string{irIndex, "scan_postings"} {
		runs, _ := irRegistry(t, db, name)
		for _, e := range runs {
			want = append(want, string(indexRunBucketName(name, e.id)))
		}
	}
	sort.Strings(want)
	if got := irBucketNames(t, db); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("buckets %v, want %v", got, want)
	}
	irCheckDB(t, db, irIndex, md, r)
	irCheckDB(t, db, "scan_postings", md2, r)

	// Ids keep increasing after a merge: a new run gets an id above every surviving run.
	if err := db.Update(func(tx *bolt.Tx) error {
		return writeIndexRun(tx, irIndex, []indexPair{{Key: []byte("zz-new"), Value: []byte("1")}})
	}); err != nil {
		t.Fatal(err)
	}
	md.kv["zz-new"] = []byte("1")
	last, _ := irRegistry(t, db, irIndex)
	if e := last[len(last)-1]; e.meta.Level != 0 || e.id <= wantRuns[len(wantRuns)-1].id {
		t.Fatalf("new run %+v after the merges %v", e, wantRuns)
	}
	irCheckDB(t, db, irIndex, md, r)
}

// The default policy (indexRunFanouts, D83): 64 runs of level 0 and of level 1 make one run of the next level, 8 runs of a higher
// level do. 140 runs of level 0 are two merges at the default (a fanout of 8 makes nineteen); the policy is written down here
// literally, not read from the code.
func TestIndexRunsCompactDefaults(t *testing.T) {
	r := rand.New(rand.NewSource(92))
	db := irOpen(t, 0)
	md := irRandModel(r, 3000)
	irLayout(t, db, r, irIndex, md, 140, 5)
	before, _ := irRegistry(t, db, irIndex)
	policy := func(level int) int { return [...]int{64, 64, 8}[min(level, 2)] }
	wantRuns, wantMerges := irSimulateAt(irSimRuns(before), policy)
	if wantMerges != 2 {
		t.Fatalf("the literal policy makes %d merges of %d runs, want 2", wantMerges, len(before))
	}
	irSetHook(t, func() { t.Fatal("a small merge needed more than one 2 MiB chunk transaction") })
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
	}
	after, _ := irRegistry(t, db, irIndex)
	if merges != wantMerges || fmt.Sprint(irSimRuns(after)) != fmt.Sprint(wantRuns) {
		t.Fatalf("%d merges, runs %v; want %d, %v", merges, irSimRuns(after), wantMerges, wantRuns)
	}
	irCheckDB(t, db, irIndex, md, r)

	// Nothing to do: no registry, then a bad fanout.
	other := irOpen(t, 0)
	if did, err := compactIndexRuns(other, irIndex, compactOptions{}); did || err != nil {
		t.Fatalf("compaction without a registry: %v %v", did, err)
	}
	if _, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 1}); irCode(err) != model.Invalid {
		t.Fatalf("Fanout 1: %v", err)
	}
}

// irCompactFixture is a database with 8 level-0 runs of a 2000-key index.
func irCompactFixture(t *testing.T, path string, mmap int, seed int64) (*bolt.DB, *irModel, *rand.Rand) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	db := irOpenAt(t, path, mmap)
	md := irRandModel(r, 2000)
	irLayout(t, db, r, irIndex, md, 8, 10)
	return db, md, r
}

func TestIndexRunsCompactCrashBetweenChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crash.db")
	db, md, r := irCompactFixture(t, path, 0, 93)
	before, _ := irRegistry(t, db, irIndex)

	chunks := 0
	irSetHook(t, func() {
		if chunks++; chunks == 2 {
			_ = db.Close() // the process dies between two chunk transactions
		}
	})
	did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096})
	if did || !errors.Is(err, bolt.ErrDatabaseNotOpen) {
		t.Fatalf("compaction on a closed database: %v %v", did, err)
	}
	indexRunsChunkHook = nil

	db = irOpenAt(t, path, 0)
	ready, building := irRegistry(t, db, irIndex)
	if len(building) != 1 || fmt.Sprint(irSimRuns(ready)) != fmt.Sprint(irSimRuns(before)) {
		t.Fatalf("after the crash: ready %v building %v", ready, building)
	}
	irCheckDB(t, db, irIndex, md, r) // the building run is invisible
	if err := db.Update(func(tx *bolt.Tx) error {
		if n, err := removeBuildingRuns(tx, irIndex); err != nil || n != 1 {
			t.Fatalf("removeBuildingRuns: %d %v", n, err)
		}
		if n, err := removeBuildingRuns(tx, irIndex); err != nil || n != 0 {
			t.Fatalf("second removeBuildingRuns: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, building := irRegistry(t, db, irIndex); len(building) != 0 {
		t.Fatal("building run still registered")
	}
	for _, name := range irBucketNames(t, db) {
		if name != irIndex && name != runsRegistry {
			found := false
			for _, e := range before {
				found = found || name == string(indexRunBucketName(irIndex, e.id))
			}
			if !found {
				t.Fatalf("unexpected bucket %s after removeBuildingRuns", name)
			}
		}
	}
	irCheckDB(t, db, irIndex, md, r)

	// A leftover building run that is not removed first is dropped by the next compaction.
	chunks = 0
	irSetHook(t, func() {
		if chunks++; chunks == 1 {
			_ = db.Close()
		}
	})
	if _, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096}); err == nil {
		t.Fatal("expected an error from the closed database")
	}
	indexRunsChunkHook = nil
	db = irOpenAt(t, path, 0)
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
	}
	if _, wantMerges := irSimulate(irSimRuns(before), 4); merges != wantMerges {
		t.Fatalf("%d merges after recovery, want %d", merges, wantMerges)
	}
	if _, building := irRegistry(t, db, irIndex); len(building) != 0 {
		t.Fatal("building run left after recovery")
	}
	irCheckDB(t, db, irIndex, md, r)
}

func TestIndexRunsCompactCancel(t *testing.T) {
	db, md, r := irCompactFixture(t, filepath.Join(t.TempDir(), "cancel.db"), 0, 94)
	before, _ := irRegistry(t, db, irIndex)

	// Cancelled before it starts: nothing happens.
	closed := make(chan struct{})
	close(closed)
	if did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, Cancel: closed}); did || err != nil {
		t.Fatalf("cancelled compaction: %v %v", did, err)
	}
	if ready, building := irRegistry(t, db, irIndex); len(building) != 0 || len(ready) != len(before) {
		t.Fatal("a cancelled compaction changed the registry")
	}

	// Cancelled after two chunk transactions: stops without an error, the building run stays invisible.
	cancel := make(chan struct{})
	chunks := 0
	irSetHook(t, func() {
		if chunks++; chunks == 2 {
			close(cancel)
		}
	})
	did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096, Cancel: cancel})
	if did || err != nil || chunks != 2 {
		t.Fatalf("cancel after two chunks: did=%v err=%v chunks=%d", did, err, chunks)
	}
	indexRunsChunkHook = nil
	ready, building := irRegistry(t, db, irIndex)
	if len(building) != 1 || fmt.Sprint(irSimRuns(ready)) != fmt.Sprint(irSimRuns(before)) {
		t.Fatalf("after cancel: ready %v building %v", ready, building)
	}
	irCheckDB(t, db, irIndex, md, r)
	if err := db.Update(func(tx *bolt.Tx) error {
		if n, err := removeBuildingRuns(tx, irIndex); err != nil || n != 1 {
			t.Fatalf("removeBuildingRuns: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := len(irBucketNames(t, db)), len(before)+2; got != want {
		t.Fatalf("%d buckets after removeBuildingRuns, want %d", got, want)
	}
	irCheckDB(t, db, irIndex, md, r)

	// Not cancelled any more: the merge runs to the end.
	did, err = compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096})
	if !did || err != nil {
		t.Fatalf("compaction after cancel: %v %v", did, err)
	}
	irCheckDB(t, db, irIndex, md, r)
}

func TestIndexRunsCompactSnapshotReader(t *testing.T) {
	// The mapping is large enough that no write transaction needs a remap, which waits for every reader.
	db, md, r := irCompactFixture(t, filepath.Join(t.TempDir(), "snap.db"), 64<<20, 95)
	before, _ := irRegistry(t, db, irIndex)
	rtx, err := db.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rtx.Rollback() }()
	old, err := openIndexSet(rtx, irIndex)
	if err != nil {
		t.Fatal(err)
	}

	chunks := 0
	irSetHook(t, func() {
		chunks++
		irVerify(t, old, md, r, 10) // the held snapshot, between chunk transactions
	})
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 2, MaxChunkBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
	}
	if merges == 0 || chunks == 0 {
		t.Fatalf("%d merges, %d chunks", merges, chunks)
	}
	if old.RunCount() != len(before) {
		t.Fatalf("the snapshot lost runs: %d of %d", old.RunCount(), len(before))
	}
	irVerify(t, old, md, r, 100) // the old snapshot after the whole compaction
	for _, e := range before {
		if rtx.Bucket(indexRunBucketName(irIndex, e.id)) == nil {
			t.Fatalf("snapshot lost the bucket of run %d", e.id)
		}
	}
	irCheckDB(t, db, irIndex, md, r)
	if after, _ := irRegistry(t, db, irIndex); len(after) != 1 {
		t.Fatalf("Fanout 2 left %d runs", len(after))
	}
}

func TestIndexRunsCompactWithConcurrentDeletes(t *testing.T) {
	r := rand.New(rand.NewSource(96))
	db := irOpen(t, 0)
	md := irRandModel(r, 3000)
	irLayout(t, db, r, irIndex, md, 12, 10)

	hooks := 0
	copiedDeleted := 0
	irSetHook(t, func() {
		hooks++
		err := db.Update(func(tx *bolt.Tx) error {
			s, err := openIndexSet(tx, irIndex)
			if err != nil {
				return err
			}
			if len(s.building) != 1 {
				return fmt.Errorf("%d building runs visible to Delete", len(s.building))
			}
			// A key already copied into the building run must leave it too.
			first, _ := s.building[0].Cursor().First()
			if first == nil {
				return errors.New("the building run is empty after a chunk")
			}
			key := bytes.Clone(first)
			if found, err := s.Delete(key); err != nil || !found {
				return fmt.Errorf("Delete of a copied key: %v %v", found, err)
			}
			if s.building[0].Get(key) != nil {
				return errors.New("Delete left the key in the building run")
			}
			delete(md.kv, string(key))
			copiedDeleted++
			keys := md.keys()
			for range 15 {
				k := keys[r.Intn(len(keys))]
				if _, ok := md.kv[k]; !ok {
					continue
				}
				if found, err := s.Delete([]byte(k)); err != nil || !found {
					return fmt.Errorf("Delete of %x: %v %v", k, found, err)
				}
				delete(md.kv, k)
			}
			if hooks == 2 { // new data arrives as a new run while the merge is in flight
				var pairs []indexPair
				for _, k := range irNewKeys(r, md, 30) {
					v := irRandBytes(r, 8)
					pairs = append(pairs, indexPair{Key: k, Value: v})
					md.kv[string(k)] = v
				}
				if err := writeIndexRun(tx, irIndex, pairs); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		irCheckDB(t, db, irIndex, md, r)
	})
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 4, MaxChunkBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		irCheckDB(t, db, irIndex, md, r)
	}
	if copiedDeleted < 3 {
		t.Fatalf("only %d hook rounds ran", copiedDeleted)
	}
	irCheckDB(t, db, irIndex, md, r)
	if _, building := irRegistry(t, db, irIndex); len(building) != 0 {
		t.Fatal("building run left")
	}
}

func TestIndexRunsCompactConcurrentReaders(t *testing.T) {
	r := rand.New(rand.NewSource(97))
	db := irOpen(t, 0)
	md := irRandModel(r, 5000)
	irLayout(t, db, r, irIndex, md, 24, 10)
	keys := md.keys()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failure string
	fail := func(format string, args ...any) {
		mu.Lock()
		if failure == "" {
			failure = fmt.Sprintf(format, args...)
		}
		mu.Unlock()
	}
	views := 0
	firstView := make(chan struct{}, 4)
	for g := range 4 {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rr := rand.New(rand.NewSource(seed))
			signalled := false
			for {
				select {
				case <-stop:
					return
				default:
				}
				err := db.View(func(tx *bolt.Tx) error {
					s, err := openIndexSet(tx, irIndex)
					if err != nil {
						return err
					}
					i := 0
					c := s.Cursor()
					for k, v := c.First(); k != nil; k, v = c.Next() {
						if i >= len(keys) || string(k) != keys[i] || !bytes.Equal(v, md.kv[keys[i]]) {
							return fmt.Errorf("iteration diverges at %d", i)
						}
						i++
					}
					if i != len(keys) {
						return fmt.Errorf("iteration yields %d of %d keys", i, len(keys))
					}
					for range 50 {
						k := keys[rr.Intn(len(keys))]
						if v := s.Get([]byte(k)); v == nil || !bytes.Equal(v, md.kv[k]) {
							return fmt.Errorf("Get(%x) wrong", k)
						}
					}
					return nil
				})
				if !signalled {
					signalled = true
					firstView <- struct{}{}
				}
				mu.Lock()
				views++
				mu.Unlock()
				if err != nil {
					fail("%v", err)
					return
				}
			}
		}(int64(100 + g))
	}
	for range 4 {
		<-firstView // every reader has completed a transaction before the compaction starts
	}
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 3, MaxChunkBytes: 2048})
		if err != nil {
			fail("compaction: %v", err)
			break
		}
		if !did {
			break
		}
		merges++
	}
	close(stop)
	wg.Wait()
	if failure != "" {
		t.Fatal(failure)
	}
	if views < 4 || merges == 0 {
		t.Fatalf("%d reader transactions, %d merges", views, merges)
	}
	irCheckDB(t, db, irIndex, md, r)
}

func irPageKeys(r *rand.Rand, prefixes [][]byte, n int) []indexPair {
	pairs := make([]indexPair, n)
	for i := range pairs {
		key := make([]byte, 100)
		copy(key, prefixes[r.Intn(len(prefixes))])
		r.Read(key[40:])
		val := make([]byte, 22)
		r.Read(val)
		pairs[i] = indexPair{Key: key, Value: val}
	}
	return pairs
}

// The point of the module: one commit of 600 index keys writes a few dozen pages as a run, hundreds as
// random inserts into a big sorted bucket.
func TestIndexRunsPageCount(t *testing.T) {
	r := rand.New(rand.NewSource(98))
	// The freelist page is rewritten by every commit and is as large as the free list is long, which says
	// nothing about the index layout: leave it out of the count.
	db, err := bolt.Open(filepath.Join(t.TempDir(), "pages.db"), 0o600,
		&bolt.Options{NoSync: true, NoFreelistSync: true, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prefixes := make([][]byte, 10)
	for i := range prefixes {
		prefixes[i] = make([]byte, 40)
		r.Read(prefixes[i])
	}

	const prefill, perTx = 200_000, 25_000
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte("pc_base")); err != nil {
			return err
		}
		_, err := tx.CreateBucket([]byte(irIndex))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for done := 0; done < prefill; done += perTx {
		pairs := irPageKeys(r, prefixes, perTx)
		if err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("pc_base"))
			for _, p := range pairs {
				if err := b.Put(p.Key, p.Value); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	written := func(fn func(tx *bolt.Tx) error) int {
		t.Helper()
		before := db.Stats().TxStats
		if err := db.Update(fn); err != nil {
			t.Fatal(err)
		}
		after := db.Stats().TxStats
		delta := after.Sub(&before)
		return int(delta.GetWrite())
	}
	runPairs := irPageKeys(r, prefixes, 600)
	runPages := written(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, runPairs) })
	basePairs := irPageKeys(r, prefixes, 600)
	basePages := written(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("pc_base"))
		for _, p := range basePairs {
			if err := b.Put(p.Key, p.Value); err != nil {
				return err
			}
		}
		return nil
	})
	t.Logf("600 keys: %d pages as a run, %d pages as random inserts into %d keys", runPages, basePages, prefill)
	if runPages > 40 {
		t.Fatalf("a run of 600 keys wrote %d pages, want at most 40", runPages)
	}
	if basePages <= 300 {
		t.Fatalf("random inserts wrote only %d pages, want more than 300", basePages)
	}
	if runPages*5 > basePages {
		t.Fatalf("runs wrote %d pages, base inserts %d: want at least 5x fewer", runPages, basePages)
	}
}
