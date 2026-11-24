// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// layout1File puts the control.db that the first build of the ledger layout wrote (testdata/layout1-control.db.gz:
// the revision in the blob, format 1) into dir and returns the encoding of its logical state.
func layout1File(t *testing.T, dir string) []byte {
	t.Helper()
	in, err := os.Open(filepath.Join("testdata", "layout1-control.db.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(out, zr); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "layout1-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return want
}

// TestOpenMovesAFileOfTheFirstLedgerLayout is the migration test of layout 2 (state_layout.go): a control.db
// written by the build that kept the revision in the blob (a real file, taken from that build with a
// reservation lifecycle in it) opens, loses the revision and the clock from its blob into keys of their
// own, keeps every record of its ledger and its logical state byte for byte, gives the same snapshot, and a
// second open leaves it as it is.
func TestOpenMovesAFileOfTheFirstLedgerLayout(t *testing.T) {
	dir := t.TempDir()
	want := layout1File(t, dir)
	// The file is what it claims to be.
	func() {
		db, err := bolt.Open(filepath.Join(dir, "control.db"), 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err = db.View(func(tx *bolt.Tx) error {
			ctrl := tx.Bucket([]byte("control"))
			if !bytes.Equal(ctrl.Get(ledgerFormatKey), legacyLedgerFormat) {
				t.Fatalf("the golden file is not of the first ledger layout: format %v", ctrl.Get(ledgerFormatKey))
			}
			members, err := decodeMembers(ctrl.Get(stateKey))
			if err != nil {
				return err
			}
			if _, ok := members[memberRevision]; !ok {
				t.Fatal("the golden file's blob holds no revision")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}()

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var dump1 map[string]KeyDump
	check := func(s *Store) {
		t.Helper()
		if err := s.db.View(func(tx *bolt.Tx) error {
			ctrl := tx.Bucket([]byte("control"))
			if !ledgerLayout(ctrl) {
				t.Fatal("the file is not of layout 2 after Open")
			}
			members, err := decodeMembers(ctrl.Get(stateKey))
			if err != nil {
				return err
			}
			for _, name := range []string{memberRevision, memberClock} {
				if _, ok := members[name]; ok {
					t.Errorf("the blob still holds %s", name)
				}
			}
			for _, key := range [][]byte{stateRevKey, stateInstKey, stateDigestKey} {
				if ctrl.Get(key) == nil {
					t.Errorf("no key %s", key)
				}
			}
			if !bytes.Equal(ctrl.Get(ledgerSealKey), ctrl.Get(stateSealKey)) {
				t.Error("the seals differ")
			}
			var whole State
			if err := loadLogical(tx, &whole); err != nil {
				return err
			}
			got, err := json.Marshal(whole)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				t.Errorf("the logical state changed by the migration\n got %.300s\nwant %.300s", got, want)
			}
			snap, err := snapshotState(tx)
			if err != nil {
				return err
			}
			if !bytes.Equal(snap, want) {
				t.Errorf("the snapshot of the migrated file is not the state\n got %.300s\nwant %.300s", snap, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(s)
	if dump1, err = s.DumpForTest(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check(s)
	dump2, err := s.DumpForTest()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range dump1 {
		if dump2[k] != v {
			t.Errorf("a second Open changed %q", k)
		}
	}
	if len(dump2) != len(dump1) {
		t.Errorf("a second Open changed the number of keys: %d -> %d", len(dump1), len(dump2))
	}
}
