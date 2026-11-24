// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// storedBytes is what apply.db holds, by the logical table: the bytes of the keys and values, per table of the row store, per
// ordered index and per ordinary bucket (the run buckets of the row store and of the indexes are not counted twice: they are the
// physical form of the logical table).
func storedBytes(t *testing.T, e *Engine) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := e.db.View(func(tx *bolt.Tx) error {
		for _, tbl := range rowTables {
			var n int64
			if err := tableForEach(tx, tbl, func(k, v []byte) error { n += int64(len(k) + len(v)); return nil }); err != nil {
				return err
			}
			out["rows:"+tbl.bucket] = n
		}
		for _, name := range []string{"scan_time", "scan_postings"} {
			set, err := openIndexSet(tx, name)
			if err != nil {
				return err
			}
			var n int64
			if err = set.ForEach(func(k, v []byte) error { n += int64(len(k) + len(v)); return nil }); err != nil {
				return err
			}
			out["index:"+name] = n
		}
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			s := string(name)
			if strings.HasPrefix(s, "scan_time") || strings.HasPrefix(s, "scan_postings") || strings.HasPrefix(s, "scan_rows") || s == "scan_runs" {
				return nil
			}
			switch s {
			case "batches", "receipts", "metrics", "scan_pages", "scan_commits":
				return nil // legacy buckets: counted through the row store above
			}
			var n int64
			var walk func(b *bolt.Bucket)
			walk = func(b *bolt.Bucket) {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if v == nil {
						if sub := b.Bucket(k); sub != nil {
							walk(sub)
						}
						continue
					}
					n += int64(len(k) + len(v))
				}
			}
			walk(b)
			if n != 0 {
				out["bucket:"+s] = n
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestStoredBytesPerBatch measures what one acknowledged batch leaves in apply.db after the background merges: bytes by table and the
// size of the file. It is the measurement of the D89 work (apply.db was 30 GB after one hour at 2,000 records/s: about 18 KB per
// batch of ~4 records).
func TestStoredBytesPerBatch(t *testing.T) {
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	const total = 400
	batches := make([]preparedAppend, total)
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
	}
	pageNodesPerAck(t, e, batches, 1)
	sizes := storedBytes(t, e)
	names := make([]string, 0, len(sizes))
	var sum int64
	for n, v := range sizes {
		names = append(names, n)
		sum += v
	}
	sort.Strings(names)
	for _, n := range names {
		t.Logf("%-28s %8.1f bytes per batch", n, float64(sizes[n])/total)
	}
	var file int64
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(p) == "apply.db" {
			if fi, e := d.Info(); e == nil {
				file = fi.Size()
			}
		}
		return nil
	})
	t.Logf("logical bytes per batch %.0f; apply.db file %.0f bytes per batch (%d batches)", float64(sum)/total, float64(file)/total, total)
}
