// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// ibEncode encodes sorted, distinct pairs as one block.
func ibEncode(pairs []indexPair) []byte {
	var bb blockBuilder
	bb.start(0)
	for _, p := range pairs {
		bb.add(p.Key, p.Value)
	}
	return bb.finish()
}

// ibDecode reads every pair of a block (copies) and checks that the records tile the block exactly.
func ibDecode(t testing.TB, raw []byte) []indexPair {
	t.Helper()
	blk, ok := parseIndexBlock(raw)
	if !ok {
		t.Fatal("block header does not parse")
	}
	var rd blockReader
	var out []indexPair
	for rd.reset(blk, 0); rd.next(); {
		out = append(out, indexPair{Key: bytes.Clone(rd.key), Value: bytes.Clone(rd.val)})
	}
	if rd.bad || len(out) != blk.n || rd.pos != blk.recEnd {
		t.Fatalf("block does not decode to its %d pairs (bad=%v, %d decoded, ends at %d of %d)", blk.n, rd.bad, len(out), rd.pos, blk.recEnd)
	}
	return out
}

// ibKeys returns n sorted distinct keys built like index keys: a few namespaces, a body, and a tail that many
// keys share, and values of 0..30 bytes.
func ibPairs(r *rand.Rand, n int) []indexPair {
	heads := [][]byte{[]byte("alpha/"), []byte("alpha/beta/"), []byte("omega"), {0x00, 0xff}}
	tails := [][]byte{[]byte("/t1"), []byte("/t1/t2"), {0xff, 0xff}, nil}
	seen := map[string]bool{}
	var pairs []indexPair
	for len(pairs) < n {
		k := append([]byte(nil), heads[r.Intn(len(heads))]...)
		k = append(k, irRandBytes(r, r.Intn(6))...)
		k = append(k, tails[r.Intn(len(tails))]...)
		if len(k) == 0 || seen[string(k)] {
			continue
		}
		seen[string(k)] = true
		pairs = append(pairs, indexPair{Key: k, Value: irRandBytes(r, r.Intn(31))})
	}
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].Key, pairs[j].Key) < 0 })
	return pairs
}

func TestIndexBlockRoundTripAndSeek(t *testing.T) {
	r := rand.New(rand.NewSource(31))
	for _, n := range []int{1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 100, 1000} {
		pairs := ibPairs(r, n)
		raw := ibEncode(pairs)
		got := ibDecode(t, raw)
		for i := range pairs {
			if !bytes.Equal(got[i].Key, pairs[i].Key) || !bytes.Equal(got[i].Value, pairs[i].Value) {
				t.Fatalf("n=%d: pair %d decodes to %x=%x, want %x=%x", n, i, got[i].Key, got[i].Value, pairs[i].Key, pairs[i].Value)
			}
		}
		blk, _ := parseIndexBlock(raw)
		if blk.nr != (n+15)/16 {
			t.Fatalf("n=%d: %d restart points", n, blk.nr)
		}
		var rd blockReader
		probes := [][]byte{{}, {0x00}, bytes.Repeat([]byte{0xff}, 40), []byte("alpha/"), []byte("zzz")}
		for _, p := range pairs {
			probes = append(probes, p.Key, append(bytes.Clone(p.Key), 0), p.Key[:len(p.Key)-1])
			dec := bytes.Clone(p.Key)
			dec[len(dec)-1]--
			probes = append(probes, dec)
		}
		for range 200 {
			probes = append(probes, irRandBytes(r, 1+r.Intn(12)))
		}
		for _, probe := range probes {
			want := sort.Search(len(pairs), func(i int) bool { return bytes.Compare(pairs[i].Key, probe) >= 0 })
			found := rd.seek(blk, probe)
			if found != (want < n) {
				t.Fatalf("n=%d: seek(%x) found=%v, want index %d of %d", n, probe, found, want, n)
			}
			if !found {
				continue
			}
			if rd.idx-1 != want || !bytes.Equal(rd.key, pairs[want].Key) || !bytes.Equal(rd.val, pairs[want].Value) {
				t.Fatalf("n=%d: seek(%x) stands on %d (%x), want %d (%x)", n, probe, rd.idx-1, rd.key, want, pairs[want].Key)
			}
			// next() continues in order from where seek stopped.
			for j := want + 1; j < min(n, want+20); j++ {
				if !rd.next() || !bytes.Equal(rd.key, pairs[j].Key) || !bytes.Equal(rd.val, pairs[j].Value) {
					t.Fatalf("n=%d: next after seek(%x) wrong at %d", n, probe, j)
				}
			}
		}
	}
}

// ibPostingPairs returns the pairs the records of some appends put in an index. A key is the namespace of the
// pages (org, project, kind: 34 bytes), for postings the 4-byte length and the term, then time (8), record
// id (16), commit group (16), commit index (8) and the position in the batch (2); the value is the page id,
// the position and a CRC (22). Ten records make an append (one commit group, one index). A record has seven
// terms: its id (unique) and six that the records of a service share.
func ibPostingPairs(r *rand.Rand, records int, postings bool) []indexPair {
	ns := make([]byte, 34)
	r.Read(ns)
	hexID := func() string {
		var b [16]byte
		r.Read(b[:])
		return hex.EncodeToString(b[:])
	}
	shared := []string{"service_id=" + hexID(), "environment_id=" + hexID(), "build_id=" + hexID(),
		"name=http_requests_total", "label:route=/api/v1/items", "label:method=GET"}
	groups := make([][16]byte, 4)
	for i := range groups {
		r.Read(groups[i][:])
	}
	pages := make([][16]byte, records/10+1) // the page id every row of an append carries in its value
	for i := range pages {
		r.Read(pages[i][:])
	}
	now := uint64(1_700_000_000_000_000_000)
	var pairs []indexPair
	for i := range records {
		now += uint64(1_000_000 + r.Intn(2_000_000))
		var suffix [50]byte
		binary.BigEndian.PutUint64(suffix[:8], now^1<<63)
		r.Read(suffix[8:24])
		copy(suffix[24:40], groups[(i/10)%4][:])
		binary.BigEndian.PutUint64(suffix[40:48], uint64(i/10))
		binary.BigEndian.PutUint16(suffix[48:], uint16(i%10))
		value := make([]byte, 22)
		copy(value[:16], pages[i/10][:])
		copy(value[16:18], suffix[48:])
		r.Read(value[18:])
		if !postings {
			pairs = append(pairs, indexPair{Key: append(bytes.Clone(ns), suffix[:]...), Value: value})
			continue
		}
		for _, term := range append([]string{"id=" + hexID()}, shared...) {
			key := append(bytes.Clone(ns), binary.BigEndian.AppendUint32(nil, uint32(len(term)))...)
			key = append(append(key, term...), suffix[:]...)
			pairs = append(pairs, indexPair{Key: key, Value: value})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].Key, pairs[j].Key) < 0 })
	return pairs
}

// A block is a third to a half of the plain pairs for index keys: their neighbours share the namespace and
// the term in front and the commit cursor behind, which the live database is disk-bound on.
func TestIndexBlockIsSmallerThanThePairs(t *testing.T) {
	r := rand.New(rand.NewSource(33))
	for _, postings := range []bool{true, false} {
		pairs := ibPostingPairs(r, 600, postings)
		plain := 0
		for _, p := range pairs {
			plain += len(p.Key) + len(p.Value)
		}
		raw := ibEncode(pairs)
		ratio := float64(len(raw)) / float64(plain)
		t.Logf("postings=%v: %d pairs, %d plain bytes, %d encoded (%.1f%%)", postings, len(pairs), plain, len(raw), 100*ratio)
		if ratio > 0.5 {
			t.Fatalf("postings=%v: the block is %.1f%% of the plain pairs, want at most 50%%", postings, 100*ratio)
		}
		if got := ibDecode(t, raw); len(got) != len(pairs) {
			t.Fatalf("decoded %d of %d pairs", len(got), len(pairs))
		}
	}
}

// ibRun writes pairs as a run (blocks of about blockBytes) of the index irIndex of a fresh database and returns
// the database and the bucket name of the run.
func ibRun(t *testing.T, pairs []indexPair, blockBytes int) (*bolt.DB, []byte) {
	t.Helper()
	old := indexRunBlockBytes
	indexRunBlockBytes = blockBytes
	t.Cleanup(func() { indexRunBlockBytes = old })
	db := irOpen(t, 0)
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte(irIndex)); err != nil {
			return err
		}
		return writeIndexRun(tx, irIndex, ibClone(pairs))
	}); err != nil {
		t.Fatal(err)
	}
	ready, _ := irRegistry(t, db, irIndex)
	return db, indexRunBucketName(irIndex, ready[0].id)
}

func ibClone(in []indexPair) []indexPair {
	out := make([]indexPair, len(in))
	for i, p := range in {
		out[i] = indexPair{Key: bytes.Clone(p.Key), Value: bytes.Clone(p.Value)}
	}
	return out
}

// ibCheckRuns checks the structure of every run bucket of the index: each bolt key is the last key of the
// block it names, keys strictly increase inside and across blocks.
func ibCheckRuns(t testing.TB, db *bolt.DB, name string) {
	t.Helper()
	if err := db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if reg == nil {
			return nil
		}
		runs, err := listIndexRuns(reg, name)
		if err != nil {
			return err
		}
		for _, e := range runs {
			var prev []byte
			c := tx.Bucket(indexRunBucketName(name, e.id)).Cursor()
			for bk, raw := c.First(); bk != nil; bk, raw = c.Next() {
				pairs := ibDecode(t, raw)
				if !bytes.Equal(pairs[len(pairs)-1].Key, bk) {
					t.Fatalf("run %d: a block is filed under %x, its last key is %x", e.id, bk, pairs[len(pairs)-1].Key)
				}
				for _, p := range pairs {
					if prev != nil && bytes.Compare(prev, p.Key) >= 0 {
						t.Fatalf("run %d: keys do not increase: %x then %x", e.id, prev, p.Key)
					}
					prev = p.Key
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Delete rewrites the block of a key: the first, a middle, the last pair of a block and a block's only pair.
func TestIndexBlockDelete(t *testing.T) {
	r := rand.New(rand.NewSource(35))
	pairs := ibPairs(r, 300)
	db, bucket := ibRun(t, pairs, 120) // blocks of a handful of pairs: many blocks, some of one pair
	md := &irModel{kv: map[string][]byte{}}
	for _, p := range pairs {
		md.kv[string(p.Key)] = p.Value
	}
	blocks := func() int {
		n := 0
		if err := db.View(func(tx *bolt.Tx) error {
			n = tx.Bucket(bucket).Stats().KeyN
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	start := blocks()
	if start < 20 {
		t.Fatalf("only %d blocks, the test needs many", start)
	}
	order := r.Perm(len(pairs))
	for step, i := range order {
		key := pairs[i].Key
		if err := db.Update(func(tx *bolt.Tx) error {
			s, err := openIndexSet(tx, irIndex)
			if err != nil {
				return err
			}
			found, err := s.Delete(key)
			if err != nil || !found {
				t.Fatalf("Delete(%x): found=%v err=%v", key, found, err)
			}
			if s.Get(key) != nil {
				t.Fatalf("Get(%x) after Delete", key)
			}
			if found, err := s.Delete(key); err != nil || found {
				t.Fatalf("second Delete(%x): found=%v err=%v", key, found, err)
			}
			delete(md.kv, string(key))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if step%7 == 0 || step > len(order)-5 {
			irCheckDB(t, db, irIndex, md, r)
			ibCheckRuns(t, db, irIndex)
		}
	}
	if n := blocks(); n != 0 {
		t.Fatalf("%d blocks left after deleting every key (started with %d)", n, start)
	}
}

// A damaged block is model.Corrupt, never a wrong answer: the cursor ends the damaged source with one entry no
// index value can be, and says so (Err); a Get answers right or with that entry, never absent, never wrong.
func TestIndexBlockDamageIsCorrupt(t *testing.T) {
	r := rand.New(rand.NewSource(37))
	var pairs []indexPair
	for _, p := range ibPairs(r, 60) {
		p.Value = append([]byte{1}, p.Value...) // never empty: an empty value is how a damaged block answers
		pairs = append(pairs, p)
	}
	type mutation struct {
		name string
		fn   func(raw []byte, boltKey []byte) (newRaw, newKey []byte)
	}
	be := binary.BigEndian
	mutations := []mutation{
		{"magic", func(raw, k []byte) ([]byte, []byte) { raw[0] ^= 0xff; return raw, k }},
		{"count up", func(raw, k []byte) ([]byte, []byte) { be.PutUint32(raw[1:], be.Uint32(raw[1:])+1); return raw, k }},
		{"count down", func(raw, k []byte) ([]byte, []byte) { be.PutUint32(raw[1:], be.Uint32(raw[1:])-1); return raw, k }},
		{"restart count", func(raw, k []byte) ([]byte, []byte) {
			be.PutUint32(raw[len(raw)-4:], be.Uint32(raw[len(raw)-4:])+1)
			return raw, k
		}},
		{"truncated", func(raw, k []byte) ([]byte, []byte) { return raw[:len(raw)-7], k }},
		{"cut to the header", func(raw, k []byte) ([]byte, []byte) { return raw[:6], k }},
		{"second restart offset", func(raw, k []byte) ([]byte, []byte) {
			blk, _ := parseIndexBlock(raw)
			be.PutUint32(raw[blk.recEnd+4:], be.Uint32(raw[blk.recEnd+4:])+1)
			return raw, k
		}},
		{"first restart offset", func(raw, k []byte) ([]byte, []byte) {
			blk, _ := parseIndexBlock(raw)
			be.PutUint32(raw[blk.recEnd:], be.Uint32(raw[blk.recEnd:])+1)
			return raw, k
		}},
		{"record length", func(raw, k []byte) ([]byte, []byte) { raw[indexBlockHeader] = 0xff; return raw, k }},
		{"filed under another key", func(raw, k []byte) ([]byte, []byte) { return raw, append(bytes.Clone(k), 0) }},
		{"filed under a lower key", func(raw, k []byte) ([]byte, []byte) {
			k = bytes.Clone(k)
			k[len(k)-1]--
			return raw, k
		}},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			db, bucket := ibRun(t, pairs, 1<<20) // one block of 60 pairs: four restart groups
			if err := db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucket)
				bk, raw := b.Cursor().First()
				k, raw := bytes.Clone(bk), bytes.Clone(raw)
				if err := b.Delete(k); err != nil {
					return err
				}
				raw, k = m.fn(raw, k)
				return b.Put(k, raw)
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.View(func(tx *bolt.Tx) error {
				s, err := openIndexSet(tx, irIndex)
				if err != nil {
					return err
				}
				c := s.Cursor()
				for k, _ := c.First(); k != nil; k, _ = c.Next() {
				}
				if irCode(c.Err()) != model.Corrupt {
					t.Fatalf("a full scan over the damaged block: Err = %v", c.Err())
				}
				if err := s.ForEach(func(_, _ []byte) error { return nil }); irCode(err) != model.Corrupt {
					t.Fatalf("ForEach over the damaged block: %v", err)
				}
				for _, p := range pairs {
					got := s.Get(p.Key)
					if got == nil && m.name == "filed under a lower key" {
						continue // a Get cannot know that the last key of a block is filed under a lower one: only a scan can
					}
					if got == nil || !bytes.Equal(got, p.Value) && len(got) != 0 {
						t.Fatalf("Get(%x) = %x on a damaged block, want its value or the damage entry", p.Key, got)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The damage entry is what no consumer of the merged cursor accepts: not nil (the key is there) and not an
// index value.
func TestIndexBlockDamageIsNotAnIndexValue(t *testing.T) {
	if validIndexValue([]byte("k"), damagedIndexValue) {
		t.Fatal("the damage entry is a valid index value")
	}
	if damagedIndexValue == nil {
		t.Fatal("the damage entry is nil: Get would report the key absent")
	}
}
