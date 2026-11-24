// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// livePageIDs is every page the live tree of the file holds (each node's own pages), read from the file the way WarmBoltTree reads it.
func livePageIDs(t *testing.T, path string) map[uint64]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, pageSize, ok := newestBoltRoot(f)
	if !ok {
		t.Fatal("the file names a freelist or no root")
	}
	w := &boltWalk{f: f, pageSize: int64(pageSize), maxPage: uint64(info.Size()) / uint64(pageSize)}
	live := map[uint64]bool{}
	queue := []uint64{root}
	for len(queue) > 0 {
		pgid := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if live[pgid] {
			continue
		}
		hdr := make([]byte, boltPageHeader)
		if _, err := f.ReadAt(hdr, int64(pgid)*int64(pageSize)); err != nil {
			t.Fatal(err)
		}
		overflow := uint64(binary.LittleEndian.Uint32(hdr[12:]))
		for i := range 1 + overflow {
			live[pgid+i] = true
		}
		children, _ := w.visit(pgid)
		queue = append(queue, children...)
	}
	return live
}

// freePageIDs are the pages below the high-water mark that the live tree and the two metas do not hold, ascending.
func freePageIDs(t *testing.T, path string) []uint64 {
	t.Helper()
	live := livePageIDs(t, path)
	var free []uint64
	for id, high := uint64(2), metaHighWater(t, path); id < high; id++ {
		if !live[id] {
			free = append(free, id)
		}
	}
	return free
}

// TestBoltOptionsWriteTheLowestFreePagesFirst: the commits of a file that holds many free pages in many spans take the lowest ones. The
// hashmap freelist of bbolt allocates the span a Go map iteration yields first, a random one, so the single-host gate's apply.db (5 GB,
// 1.15 million free pages) wrote every commit's pages scattered over its whole length: every dirty page a seek, the cache a working set
// of the whole file (L2w20Admission28). The
// file here is 600 values of 100 KB in 600 buckets, every other one deleted (300 spans of ~26 free pages, the front of the file to its
// end); 400 commits of one small key then leave the tree they grew within the lowest free pages, not spread over the 300 spans.
func TestBoltOptionsWriteTheLowestFreePagesFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	db, err := bolt.Open(path, 0600, BoltOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	value := make([]byte, 100_000)
	if err = db.Update(func(tx *bolt.Tx) error {
		for i := range 600 {
			b, err := tx.CreateBucket(fmt.Appendf(nil, "junk%04d", i))
			if err != nil {
				return err
			}
			if err = b.Put([]byte("v"), value); err != nil {
				return err
			}
		}
		_, err := tx.CreateBucket([]byte("probe"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 600; i += 2 {
		if err = db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(fmt.Appendf(nil, "junk%04d", i)) }); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 { // the deletes are pending until the commits after them release them
		if err = db.Update(func(*bolt.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	freeBefore := freePageIDs(t, path)
	liveBefore := livePageIDs(t, path)
	if len(freeBefore) < 7000 {
		t.Fatalf("the file holds %d free pages, want the spans of 300 deleted values", len(freeBefore))
	}
	rng := rand.New(rand.NewPCG(1, 2))
	row := make([]byte, 100)
	for range 400 {
		if err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("probe")).Put(binary.BigEndian.AppendUint64(nil, rng.Uint64()), row)
		}); err != nil {
			t.Fatal(err)
		}
	}
	var grown []uint64
	for id := range livePageIDs(t, path) {
		if !liveBefore[id] {
			grown = append(grown, id)
		}
	}
	slices.Sort(grown)
	if len(grown) == 0 {
		t.Fatal("the commits left no new page")
	}
	// The tree of the probe is a few dozen pages and the commits' own copy-on-write churn a few more: the lowest ~400 free pages hold them
	// all when the lowest ones are taken first; spread over the spans they reach the last ones.
	bound := freeBefore[min(400, len(freeBefore)-1)]
	if top := grown[len(grown)-1]; top > bound {
		t.Fatalf("%d new pages up to page %d: the commits did not take the lowest free pages (the 400th free page was %d of %d free, the highest %d)",
			len(grown), top, bound, len(freeBefore), freeBefore[len(freeBefore)-1])
	}
}
