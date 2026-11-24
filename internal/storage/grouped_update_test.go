// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openGroupedDB(t *testing.T) *trackedDB {
	t.Helper()
	raw, err := bolt.Open(filepath.Join(t.TempDir(), "g.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if err = raw.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte("k")); return err }); err != nil {
		t.Fatal(err)
	}
	return &trackedDB{DB: raw}
}

// Callers that arrive while a commit is in progress share the next one, a failing caller gets its
// own error and leaves no write behind, and every other caller's write is stored when its call
// returns.
func TestGroupedUpdatesFoldCommitsAndIsolateAFailure(t *testing.T) {
	db := openGroupedDB(t)
	errBad := errors.New("bad caller")
	const callers = 96
	put := func(i int) func(*bolt.Tx) error {
		return func(tx *bolt.Tx) error {
			if err := tx.Bucket([]byte("k")).Put([]byte(fmt.Sprintf("key%03d", i)), []byte{1}); err != nil {
				return err
			}
			if i%7 == 3 {
				return errBad
			}
			return nil
		}
	}
	errs := make([]error, callers)
	var wg sync.WaitGroup
	// Caller 0 commits first and is held inside its function: the others queue behind it.
	inside, release := make(chan struct{}), make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs[0] = db.updateGrouped(func(tx *bolt.Tx) error {
			close(inside)
			<-release
			return put(0)(tx)
		})
	}()
	<-inside
	stats := db.Stats()
	before := stats.TxStats.GetWrite()
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = db.updateGrouped(put(i))
			if errs[i] == nil {
				if err := db.View(func(tx *bolt.Tx) error {
					if tx.Bucket([]byte("k")).Get([]byte(fmt.Sprintf("key%03d", i))) == nil {
						return errors.New("acknowledged write missing")
					}
					return nil
				}); err != nil {
					errs[i] = err
				}
			}
		}()
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		db.grouped.mu.Lock()
		queued := len(db.grouped.pending)
		db.grouped.mu.Unlock()
		if queued == callers-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d callers queued", queued, callers-1)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	stats = db.Stats()
	writes := stats.TxStats.GetWrite() - before
	for i, err := range errs {
		switch {
		case i%7 == 3 && !errors.Is(err, errBad):
			t.Fatalf("caller %d: %v, want its own error", i, err)
		case i%7 != 3 && err != nil:
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if err := db.View(func(tx *bolt.Tx) error {
		for i := range callers {
			if got := tx.Bucket([]byte("k")).Get([]byte(fmt.Sprintf("key%03d", i))) != nil; got != (i%7 != 3) {
				t.Fatalf("caller %d: stored=%v, failed=%v", i, got, i%7 == 3)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// One transaction per caller would write at least a leaf and a meta page each; 95 queued
	// callers, a dozen of them failing alone, cost a handful of transactions.
	t.Logf("%d callers, %d page writes after the first commit", callers, writes)
	if writes >= callers {
		t.Fatalf("%d page writes for %d queued callers: their commits were not folded", writes, callers-1)
	}
}

// A lone caller is never made to wait for company.
func TestGroupedUpdateOfALoneCallerReturnsAtOnce(t *testing.T) {
	db := openGroupedDB(t)
	start := time.Now()
	for i := range 20 {
		if err := db.updateGrouped(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("k")).Put([]byte{byte(i)}, []byte{1})
		}); err != nil {
			t.Fatal(err)
		}
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("20 lone updates took %s", took)
	}
}
