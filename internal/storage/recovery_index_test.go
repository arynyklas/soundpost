// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyAppliedWALRebuildsExactPolicyRevision(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := e.Append(context.Background(), write, b)
	if err != nil {
		t.Fatal(err)
	}
	// First obtain a real Raft ACK, then export the exact applied command into
	// the predecessor's image. This is not a legacy proposer or ACK adapter.
	var applied walEntry
	err = e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("replica_commands")).Get(commandKey(b.RouteSlot, uint64(receipt.Cursor.Index)))
		if raw == nil {
			return model.Fail(model.Corrupt)
		}
		return json.Unmarshal(raw, &applied)
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Batch == nil || applied.Receipt == nil || applied.Batch.PolicyRevision != b.PolicyRevision || applied.Receipt.Cursor != receipt.Cursor {
		t.Fatal("actual committed command lost original metadata")
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writeLegacyTestEntry(dir, b.RouteSlot, uint64(receipt.Cursor.Index), applied); err != nil {
		t.Fatal(err)
	}
	predecessor, err := bolt.Open(filepath.Join(dir, "apply.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = predecessor.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"replica_data", "replica_commands", "scan_pages", "scan_time", "scan_postings", "scan_commits", "scan_integrity"} {
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		meta := tx.Bucket([]byte("meta"))
		if err := meta.Delete([]byte("replica_format")); err != nil {
			return err
		}
		return meta.Delete([]byte("scan_index_version"))
	})
	closeErr := predecessor.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	// A predecessor has no later-format Ready state or Raft snapshot. Never
	// remove this authority in a runtime path, only this deliberate test image.
	if err = os.RemoveAll(filepath.Join(dir, "raft")); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2, Fence: ReadFence{Min: []model.Cursor{receipt.Cursor}}})
	if len(got) != 1 || got[0].ID != b.Records[0].ID {
		t.Fatal("legacy typed row lost or duplicated")
	}
	err = e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("scan_pages")).ForEach(func(_, raw []byte) error {
			ref, err := parsePageRef(raw)
			if err != nil {
				return err
			}
			if ref.PolicyRevision != b.PolicyRevision {
				t.Fatal("historical capture revision replaced")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := e.LookupReceipt(context.Background(), write, model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: b.Hash})
	if err != nil || original.Cursor != receipt.Cursor || original.RetainUntil != receipt.RetainUntil {
		t.Fatal("legacy receipt changed", err)
	}
}
func TestMissingIndexEntryFailsStartupInsteadOfEmptyResult(t *testing.T) {
	for _, name := range []string{"scan_time", "scan_postings"} {
		t.Run(name, func(t *testing.T) {
			store, a, c, d := fixture(t)
			write, b := normalized(t, store, a, c, d)
			dir := t.TempDir()
			e, err := openTestEngine(t, dir, a, store)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Append(context.Background(), write, b); err != nil {
				t.Fatal(err)
			}
			if err = e.db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte(name))
				key, _ := bucket.Cursor().First()
				if key == nil {
					t.Fatal("missing fixture entry")
				}
				return bucket.Delete(key)
			}); err != nil {
				t.Fatal(err)
			}
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openTestEngine(t, dir, a, store)
			if err == nil {
				reopened.Close()
				t.Fatal("missing retained index entry became an empty result")
			}
		})
	}
}
