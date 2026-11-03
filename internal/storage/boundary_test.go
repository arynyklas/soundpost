// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
)

func TestCursorOverflowNeverAcknowledges(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := Open(t.TempDir(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	engine.indexes[b.RouteSlot] = ^uint64(0)
	if receipt, e := engine.Append(context.Background(), scope, b); e == nil || receipt.Cursor.Index != 0 {
		t.Fatal("wrapped cursor acknowledged without apply")
	}
}
func TestMissingIdentityAndAcknowledgedWALDenyOpen(t *testing.T) {
	for _, part := range []string{"identity", "wal"} {
		t.Run(part, func(t *testing.T) {
			store, a, c, d := fixture(t)
			scope, b := normalized(t, store, a, c, d)
			dir := t.TempDir()
			engine, e := Open(dir, a)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = engine.Append(context.Background(), scope, b); e != nil {
				t.Fatal(e)
			}
			if part == "identity" {
				if e = engine.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("meta")).Delete([]byte("identity")) }); e != nil {
					t.Fatal(e)
				}
			}
			engine.Close()
			if part == "wal" {
				if e = os.Remove(filepath.Join(dir, walName(b.RouteSlot))); e != nil {
					t.Fatal(e)
				}
			}
			if engine, e = Open(dir, a); e == nil {
				engine.Close()
				t.Fatal("missing durable authority silently recreated")
			}
		})
	}
}
