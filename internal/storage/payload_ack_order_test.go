// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// payloadSize is the bytes of every file of the payload log (what a crash that loses every unsynced byte would leave, at most).
func payloadNewestFile(t *testing.T, dir string) (string, int64) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, payloadDirName))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no payload log: %v", err)
	}
	last := entries[len(entries)-1].Name()
	fi, err := os.Stat(filepath.Join(dir, payloadDirName, last))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, payloadDirName, last), fi.Size()
}

// everyReferenceReads reads every payload reference the file holds (commands, rows, the blocks of the runs, the pages) and fails on one
// that names bytes that are not there: a reference that reached disk names bytes that reached disk.
func everyReferenceReads(t *testing.T, e *Engine) (refs int) {
	t.Helper()
	read := func(where string, v []byte) {
		if isPayloadRef(v) {
			refs++
			if _, err := e.payload.read(v); err != nil {
				t.Errorf("%s: a reference names bytes that are not in the log: %v", where, err)
			}
		}
	}
	if err := e.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if string(name) == payloadScrubBucket { // the references of records that are dead
				return nil
			}
			return b.ForEach(func(k, v []byte) error {
				if v == nil {
					return nil
				}
				read(string(name), v)
				if p, err := parsePageRef(v); err == nil {
					read(string(name)+" (page)", p.Log)
				}
				return nil
			})
		})
	}); err != nil {
		t.Fatal(err)
	}
	return refs
}

// TestPayloadLogIsSyncedBeforeAnyReferenceToItCommits is the ACK-ordering test of D89: an append is acknowledged after the payload log
// holds its bytes durably AND bolt holds the references, in that order. A crash between the two (the bytes written and not synced, the
// bytes synced and no reference committed, the reference committed in a transaction that did not complete) never loses an
// acknowledged record, never leaves a reference to bytes that are not there, and the append is retried to a single receipt.
func TestPayloadLogIsSyncedBeforeAnyReferenceToItCommits(t *testing.T) {
	withoutPayloadToggle(t)
	// The order itself: when the transaction that carries the references starts, the log is synced to its end.
	t.Run("the log is synced when the commit starts", func(t *testing.T) {
		store, service, cred, desc := fixture(t)
		e := openPayloadEngine(t, t.TempDir(), store, service)
		defer e.Close()
		if err := store.BindAdmissionOwner(e); err != nil {
			t.Fatal(err)
		}
		e.stopIndexMerger()
		var unsynced int
		var commits int
		e.setFault(func(at string) error {
			if at == "receipt_write" { // inside the transaction that carries the references
				commits++
				l := e.payload
				l.mu.Lock()
				if l.synced < l.size || len(l.pending) != 0 {
					unsynced++
				}
				l.mu.Unlock()
			}
			return nil
		})
		for i := range 8 {
			scope, b := settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("order_%d", i))
			if _, err := e.Append(context.Background(), scope, b); err != nil {
				t.Fatal(err)
			}
		}
		if commits == 0 || unsynced != 0 {
			t.Fatalf("%d of %d commits started with payload bytes that were not synced", unsynced, commits)
		}
	})

	for _, c := range []struct {
		name, hook string
		torn       bool // the bytes written after the last sync did not reach the disk (some of them, torn in the middle of a record)
	}{
		{"records written, not synced (the bytes are lost)", "payload_sync", true},
		{"records synced, no reference committed", "payload_synced", false},
		{"references in a transaction that did not complete", "receipt_write", false},
		{"references in the last step of the transaction", "applied_cursor", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, service, cred, desc := fixture(t)
			fx := layoutFixture{store, service, cred, desc}
			dir := t.TempDir()
			e := openPayloadEngine(t, dir, store, service)
			if err := store.BindAdmissionOwner(e); err != nil {
				t.Fatal(err)
			}
			e.stopIndexMerger()
			acked := appendKept(t, e, fx, 5)
			want := readState(t, e, fx, acked)
			path, durable := payloadNewestFile(t, dir)

			scope, victim := settleBatch(t, store, service, cred, desc, model.NewID(), 1, "victim")
			e.setFault(func(at string) error {
				if at == c.hook {
					return errors.New("crash at " + at)
				}
				return nil
			})
			if _, err := e.Append(context.Background(), scope, victim); err == nil {
				t.Fatalf("the append was acknowledged although the engine crashed at %s", c.hook)
			}
			e.setFault(nil)
			_ = e.Close()
			if c.torn { // what the unsynced bytes become: the file ends in the middle of the record, as a power cut leaves it
				_, size := payloadNewestFile(t, dir)
				if size <= durable {
					t.Fatalf("the crashed append wrote nothing after the last sync (%d bytes)", size)
				}
				if err := os.Truncate(path, durable+payloadHeaderLen/2); err != nil {
					t.Fatal(err)
				}
			}

			e2, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatalf("reopen after the crash at %s: %v", c.hook, err)
			}
			defer e2.Close()
			if !e2.payloadOn.Load() {
				t.Fatal("the layout was lost")
			}
			if got := readState(t, e2, fx, acked); !got.equal(want) {
				t.Fatalf("an acknowledged record was lost or changed by the crash at %s: %s", c.hook, storedStateWhy)
			}
			if refs := everyReferenceReads(t, e2); refs == 0 {
				t.Fatal("the file holds no payload reference")
			}
			// The committed entry of the append that crashed may be applied again by the replay of the journal, or not: either way the
			// client, which never saw an ACK, retries it, and it ends as one receipt, after the dead tail of the log.
			r1, err := e2.Append(context.Background(), scope, victim)
			if err != nil {
				t.Fatalf("retry of the unacknowledged append: %v", err)
			}
			r2, err := e2.Append(context.Background(), scope, victim)
			if err != nil || !bytes.Equal(mustJSON(t, r1), mustJSON(t, r2)) {
				t.Fatalf("the second retry changed the receipt: %v", err)
			}
			if _, err = e2.Append(context.Background(), scope, victim); err != nil {
				t.Fatal(err)
			}
			all := append(append([]keptAppend{}, acked...), keptAppend{scope, victim, r1})
			if got := readState(t, e2, fx, all); got.rows != len(all) {
				t.Fatalf("a query returns %d rows, want %d", got.rows, len(all))
			}
			everyReferenceReads(t, e2)
			// A restart of the repaired file reads the same.
			if err = e2.Close(); err != nil {
				t.Fatal(err)
			}
			e3, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			defer e3.Close()
			if got := readState(t, e3, fx, all); got.rows != len(all) {
				t.Fatalf("after the restart a query returns %d rows, want %d", got.rows, len(all))
			}
			everyReferenceReads(t, e3)
		})
	}
}
