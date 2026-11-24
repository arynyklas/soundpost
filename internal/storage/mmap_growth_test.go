// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/durablefs"
	bolt "go.etcd.io/bbolt"
)

// TestGrowthOfApplyDBDoesNotWaitForAReader: bolt maps the file once and maps it again, under the lock every read transaction holds
// shared, when a commit grows the file past the mapping. The commit then waits for every open reader and every reader that starts
// after it waits for the commit: one reader that lives a second stops the engine for a second. On the single-host gate apply.db grew
// from 1.6 GB to 2.1 GB in the minute the p95 of the requests was 10 s and 1,146 of them were shed (L2w20Admission26). The file is
// therefore mapped ahead of its growth (durablefs.BoltInitialMmapSize), and a commit that grows it, 64 MB here, while a reader is open
// does not wait for it.
func TestGrowthOfApplyDBDoesNotWaitForAReader(t *testing.T) {
	if durablefs.BoltInitialMmapSize == 0 {
		t.Skip("the bolt files are not mapped ahead of their growth on this platform")
	}
	store, service, _, _ := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	held, release, readerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		readerDone <- e.db.View(func(*bolt.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	grown := make(chan error, 1)
	go func() {
		chunk := make([]byte, 1<<20)
		grown <- e.db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(freelistProbeBucket)
			if err != nil {
				return err
			}
			for i := range 64 {
				chunk[0] = byte(i)
				if err = b.Put([]byte{byte(i)}, chunk); err != nil {
					return err
				}
			}
			return nil
		})
	}()
	select {
	case err = <-grown:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Errorf("a commit that grew apply.db by 64 MB waited 10 s for a reader that was still open: the file is not mapped ahead of its growth")
	}
	close(release)
	if err = <-readerDone; err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
}
