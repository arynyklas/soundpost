// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

var errProbeRollback = errors.New("probe: roll back")

// probeDB runs fn in a write transaction that is always rolled back (nothing is committed, the file
// does not change). bbolt's freelist is shared and not synchronised: Tx.Page and Tx.Check read it, and
// Tx.Check is documented as safe only on a writable transaction, because in a READ transaction they
// race with the commit of any writer (a voter applying a replicated entry, the intake of the test
// itself): measured in l1w14-evidence (zz_bolt_hammer: data races and "panic: mergepgids bad len"
// within a minute). The writer lock is what makes a page probe safe; Info() reads the mapping and is
// read inside the transaction for the same reason.
func (s *Store) probeDB(fn func(tx *bolt.Tx, pageSize uint64) error) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := fn(tx, uint64(tx.DB().Info().PageSize)); err != nil {
			return err
		}
		return errProbeRollback
	})
	if errors.Is(err, errProbeRollback) {
		return nil
	}
	return err
}

// pageSize is bbolt's page size of this file, read under the writer lock (see probeDB).
func (f *installFx) pageSize() uint64 {
	f.t.Helper()
	var size uint64
	if err := f.s.probeDB(func(_ *bolt.Tx, pageSize uint64) error { size = pageSize; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return size
}

// PlantInFreePagesForTest builds, on this store's own control.db, the precondition of an erased
// payload sitting in free pages: it commits a filler value of fillerPages pages and deletes it (the
// pages come free at the end of the file, and any later commit allocates its pages lowest-first, so
// the highest ones outlive a handful of commits), then writes canary into the highest free page
// with a plain file write (a free page is garbage by definition). It returns the page id. When
// live is set the canary goes into the highest LIVE page instead (the mutant of the precondition:
// a copy that is in the file but not in a free page). Test only.
func (s *Store) PlantInFreePagesForTest(canary string, fillerPages int, live bool) (uint64, error) {
	var pageSize uint64
	if err := s.probeDB(func(_ *bolt.Tx, size uint64) error { pageSize = size; return nil }); err != nil {
		return 0, err
	}
	key := []byte("w14_filler")
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("control")).Put(key, make([]byte, fillerPages*int(pageSize)))
	}); err != nil {
		return 0, err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(key) }); err != nil {
		return 0, err
	}
	var target uint64
	if err := s.probeDB(func(tx *bolt.Tx, _ uint64) error {
		for id := uint64(tx.Size())/pageSize - 1; id >= 2; id-- {
			info, err := tx.Page(int(id))
			if err != nil {
				return err
			}
			if info != nil && (info.Type == "free") != live {
				target = id
				return nil
			}
		}
		return fmt.Errorf("no page to plant in")
	}); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.db.Path(), os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	if _, err = f.WriteAt([]byte(canary), int64(target*pageSize)+64); err != nil {
		f.Close()
		return 0, err
	}
	return target, f.Close()
}

// FreePagesHoldingForTest lists the pages bbolt reports free (type "free", pending ones included)
// whose bytes in the file hold canary. Test only.
func (s *Store) FreePagesHoldingForTest(canary string) ([]uint64, error) {
	var out []uint64
	err := s.probeDB(func(tx *bolt.Tx, pageSize uint64) error {
		raw, err := os.ReadFile(s.db.Path()) // under the writer lock: no commit moves the pages meanwhile
		if err != nil {
			return err
		}
		for id := uint64(2); id < uint64(tx.Size())/pageSize && (id+1)*pageSize <= uint64(len(raw)); id++ {
			info, err := tx.Page(int(id))
			if err != nil {
				return err
			}
			if info != nil && info.Type == "free" && bytes.Contains(raw[id*pageSize:(id+1)*pageSize], []byte(canary)) {
				out = append(out, id)
			}
		}
		return nil
	})
	return out, err
}
