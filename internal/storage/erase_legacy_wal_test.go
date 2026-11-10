// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// treeHits lists every regular file of the node (the apply database, the segments, the legacy
// per-slot WAL, the whole Raft tree, temp files left by a crash) that holds the canary in any
// nesting of encodings.
func (x *eraseEnv) treeHits(canary string) []string {
	x.t.Helper()
	var hits []string
	err := filepath.WalkDir(x.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if deepContains(raw, []byte(canary), 5) {
			rel, _ := filepath.Rel(x.dir, p)
			hits = append(hits, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		x.t.Fatal(err)
	}
	sort.Strings(hits)
	return hits
}

// legacyImage turns x into the image the pre-replication layout leaves behind, from a real Raft
// ACK: the applied command is exported into data/slot-NN.wal, the later-format buckets and
// markers are deleted and raft/ is removed, exactly as TestLegacyAppliedWALRebuildsExactPolicyRevision
// builds it. The engine is then reopened, which imports the legacy prefix into replica_commands
// and leaves the WAL in place.
func (x *eraseEnv) legacyImage(hit erased) (slot uint16, index uint64) {
	x.t.Helper()
	slot, index = x.closedLegacyImage(hit)
	x.e = openDeleteEngineRestored(x.t, x.dir, x.a, x.store)
	return slot, index
}

// closedLegacyImage leaves the node closed, in the predecessor's layout.
func (x *eraseEnv) closedLegacyImage(hit erased) (slot uint16, index uint64) {
	x.t.Helper()
	slot, index = hit.batch.RouteSlot, uint64(hit.receipt.Cursor.Index)
	var applied walEntry
	if err := x.e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("replica_commands")).Get(commandKey(slot, index))
		if raw == nil {
			return model.Fail(model.Corrupt)
		}
		return json.Unmarshal(raw, &applied)
	}); err != nil {
		x.t.Fatal(err)
	}
	if err := x.e.Close(); err != nil {
		x.t.Fatal(err)
	}
	if err := writeLegacyTestEntry(x.dir, slot, index, applied); err != nil {
		x.t.Fatal(err)
	}
	predecessor, err := bolt.Open(filepath.Join(x.dir, "apply.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		x.t.Fatal(err)
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
		x.t.Fatal(err)
	}
	if closeErr != nil {
		x.t.Fatal(closeErr)
	}
	if err = os.RemoveAll(filepath.Join(x.dir, "raft")); err != nil {
		x.t.Fatal(err)
	}
	return slot, index
}

// legacyWALEntry reads the payload the legacy WAL holds at index.
func legacyWALEntry(t *testing.T, dir string, slot uint16, index uint64) walEntry {
	t.Helper()
	entries, err := legacyHistory(dir, slot, index)
	if err != nil {
		t.Fatalf("the legacy WAL no longer reads: %v", err)
	}
	var entry walEntry
	if err = json.Unmarshal(entries[index-1], &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// A node upgraded from the pre-replication layout keeps data/slot-NN.wal after the import into
// replica_commands. The erasure must not leave the erased record's bytes in it, and the receipt's
// residual measurement must not be empty while any file of the node still holds them.
func TestErasedBytesAreNotLeftInTheLegacyWALOfAnUpgradedNode(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	slot, index := x.legacyImage(hit)
	if hits := x.treeHits(eraseCanary); !inHits(hits, walName(slot)) {
		t.Fatalf("fixture invalid: the upgrade image's WAL does not hold the canary: %v", hits)
	}
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records != 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	x.maintain(pred)
	hits, residual := x.treeHits(eraseCanary), x.e.ResidualStores()
	if len(hits) != 0 {
		t.Fatalf("erased bytes survive in %v after the whole physical sequence (ResidualStores %v)", hits, residual)
	}
	if len(residual) != 0 {
		t.Fatalf("residual stores after the whole physical sequence: %v", residual)
	}
	// The legacy WAL stays, structurally intact, and now carries the stored redacted command.
	entry := legacyWALEntry(t, x.dir, slot, index)
	if entry.Type != "batch_redacted" || entry.Redaction == nil || entry.Redaction.Erased != 1 || entry.Receipt == nil || entry.Receipt.Cursor != hit.receipt.Cursor || len(entry.Batch.Records) != 2 {
		t.Fatalf("legacy WAL entry after the erasure: %+v", entry)
	}
	if raws, err := legacyHistory(x.dir, slot, index); err != nil || !bytes.Equal(raws[index-1], x.command(hit.batch, hit.receipt)) {
		t.Fatalf("the legacy WAL entry is not the stored redacted command (%v)", err)
	}
	x.requireReceipt("after the erasure of a legacy command", hit)
	walPath := filepath.Join(x.dir, walName(slot))
	rewritten, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	x.reopenDelete()
	if again, rerr := os.Stat(walPath); rerr != nil || !os.SameFile(rewritten, again) {
		t.Fatalf("a clean legacy WAL was replaced again on open (%v)", rerr)
	}
	if hits = x.treeHits(eraseCanary); len(hits) != 0 {
		t.Fatalf("erased bytes survive in %v after a restart", hits)
	}
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows after a restart %v want %v", got, want)
	}
	x.requireReceipt("after a restart", hit)
}

// Until the legacy WAL has been rewritten it is a store that holds erased bytes and is named as
// such; the owed rewrite also keeps the physical cleanup from completing (the erasure pass fails).
func TestLegacyWALIsNamedAsAResidualStoreUntilItIsRewritten(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	slot, _ := x.legacyImage(hit)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	// A receipt rendered before the erasure measures the legacy WAL clean; the measurement must
	// not be remembered past the erasure that changes it.
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores before any erasure: %v", got)
	}
	fired := false
	x.e.fault = func(at string) error {
		if at == HookLegacyWALBegin && !fired {
			fired = true
			return errors.New("interrupted at " + at)
		}
		return nil
	}
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err == nil || !fired {
		t.Fatalf("the erasure pass was not interrupted before the legacy WAL was rewritten: %v", err)
	}
	if !inHits(x.treeHits(eraseCanary), walName(slot)) {
		t.Fatal("fixture invalid: the WAL no longer holds the canary")
	}
	if got := x.e.ResidualStores(); !contains(got, ResidualLegacyWAL) {
		t.Fatalf("a legacy WAL holding erased bytes is not named as a residual store: %v", got)
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatalf("the next pass: %+v %v", report, err)
	}
	if got := x.e.ResidualStores(); contains(got, ResidualLegacyWAL) {
		t.Fatalf("the legacy WAL is still named after it was rewritten: %v", got)
	}
	if hits := x.treeHits(eraseCanary); inHits(hits, walName(slot)) {
		t.Fatalf("the legacy WAL still holds the canary: %v", hits)
	}
}

// Kill the process at every step of the legacy WAL rewrite. The stored redacted command is the
// authority; the old or the new WAL is in force, never a mix, and the next open converges.
func TestLegacyWALRedactionCrashPointsConverge(t *testing.T) {
	for _, hook := range []string{HookLegacyWALBegin, HookLegacyWALWrite, HookLegacyWALSync, HookLegacyWALSwitch, HookLegacyWALRenamed} {
		t.Run(hook, func(t *testing.T) {
			x := newCheckpointEnv(t)
			ctx := context.Background()
			hit := x.appendMixed(eraseCanary, bothDeadlines)
			slot, index := x.legacyImage(hit)
			pred := x.rangePredicate(0, 10, model.Metric)
			barrierAll(t, x.e, pred)
			fired := false
			x.e.fault = func(at string) error {
				if at == hook && !fired {
					fired = true
					return errors.New("crash at " + at)
				}
				return nil
			}
			if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err == nil || !fired {
				t.Fatalf("hook %s never interrupted the erasure (%v)", hook, err)
			}
			// Whatever the crash left, the WAL in force is complete and readable.
			legacyWALEntry(t, x.dir, slot, index)
			x.reopenDelete()
			legacyWALEntry(t, x.dir, slot, index)
			if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
				t.Fatalf("the worker's next pass after a crash at %s: %v", hook, err)
			}
			x.maintain(pred)
			if hits := x.treeHits(eraseCanary); len(hits) != 0 {
				t.Fatalf("erased bytes survive a crash at %s in %v", hook, hits)
			}
			if got := x.e.ResidualStores(); len(got) != 0 {
				t.Fatalf("residual stores after a crash at %s and a full pass: %v", hook, got)
			}
			if leftover, _ := filepath.Glob(filepath.Join(x.dir, "slot-*.wal.*")); len(leftover) != 0 {
				t.Fatalf("temp files left behind after a crash at %s: %v", hook, leftover)
			}
			x.requireReceipt("after a crash at "+hook, hit)
			if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
				t.Fatalf("rows %v want %v", got, want)
			}
			x.integrity()
		})
	}
}

// A node that never replicates still reads its own WAL, byte for byte, and the erasure machinery
// never touches it (there is nothing to erase in that layout: no stored command exists).
func TestNonReplicatedEngineStillReadsAndKeepsItsWAL(t *testing.T) {
	x := newCheckpointEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	slot, index := x.closedLegacyImage(hit)
	path := filepath.Join(x.dir, walName(slot))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Open(x.dir, x.a)
	if err != nil {
		t.Fatalf("a never-replicated node no longer reads its WAL: %v", err)
	}
	defer e.Close()
	if e.indexes[slot] != index {
		t.Fatalf("applied index %d want %d", e.indexes[slot], index)
	}
	if got := e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores of a node that cannot be erased from: %v", got)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the non-replicated reader changed its WAL (%v)", err)
	}
}
