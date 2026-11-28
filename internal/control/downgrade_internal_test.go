// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// An earlier build commits state without knowing the state seal. This build then opening the
// file must refuse it (Unsupported) rather than trust a settled marker that build never kept,
// and must leave the file as it found it.
func TestOpenRefusesAControlDBAnEarlierBuildCommittedOn(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.local().owed {
		t.Fatal("fixture invalid: the scrub did not settle the marker")
	}
	f.reopen() // an ordinary restart of this build is accepted
	// The earlier build's commit: new state bytes, the seal untouched.
	st := f.state()
	st.Revision++
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Put([]byte("state"), raw) }); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(f.dir)
	var fault *model.Fault
	if err == nil || !errors.As(err, &fault) || fault.Code != model.Unsupported {
		if s != nil {
			s.Close()
		}
		t.Fatalf("Open accepted a control.db an earlier build committed on: %v", err)
	}
	if _, err = OpenSeed(f.dir, []byte(`{"state":{"installation":"`+st.Installation.String()+`"}}`)); err == nil {
		t.Fatal("OpenSeed accepted it too")
	}
}

// Every build-this write path keeps the seal: a restart after Apply and after an install is
// never mistaken for a downgrade.
func TestOpenAcceptsAFileThisBuildCommittedOn(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	// A file this build opened carries a seal; the writes below must keep it current.
	if err := f.s.db.Update(func(tx *bolt.Tx) error { return sealState(tx.Bucket([]byte("control"))) }); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Update(f.ctx, func(st *State) error { // the replicated write path
		st.Quotas = map[string]model.QuotaState{"after:seal": {MaxBytes: 1}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.install(f.leader(9, true, true)) // the install path
	f.reopen()
	f.reopen()
}

// seedOf is a seed of a fresh installation that carries keys and metadata.
func seedOf(t *testing.T, keys, metadata map[string][]byte) []byte {
	t.Helper()
	raw, err := json.Marshal(controlSnapshot{State: State{Installation: model.NewID()}, Keys: keys, Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// seedKeys is n envelope key files with distinct contents.
func seedKeys(n int) map[string][]byte {
	keys := map[string][]byte{}
	for i := range n {
		keys[fmt.Sprintf("envelope-k%02d.key", i)] = []byte{byte(i), 0x5a}
	}
	return keys
}

// A seed the group rejects must not leave anything of itself in the data directory: not the
// control.db OpenSeed created (with its settled key and state), and not the envelope keys the
// install wrote before it failed. Go randomizes map order, so a seed with many keys and one bad
// element reaches the bad element after a different number of writes each time; every case runs
// many times so that no order can hide a partial write.
func TestARejectedOpenSeedLeavesNoControlDB(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSeed(dir, seedOf(t, seedKeys(24), nil))
	if err != nil {
		t.Fatalf("fixture invalid: the seed without the bad element is refused: %v", err)
	}
	s.Close()
	if got, _ := os.ReadDir(dir); len(got) != 25 {
		t.Fatalf("fixture invalid: an accepted seed leaves %d entries, want control.db and its 24 keys", len(got))
	}
	withEscape := seedKeys(24)
	withEscape["../escape"] = []byte("x")
	withStranger := seedKeys(24)
	withStranger["notes.txt"] = []byte("x")
	withActive := seedKeys(24)
	withActive["envelope.active"] = []byte("new")
	for _, tc := range []struct {
		name     string
		keys     map[string][]byte
		metadata map[string][]byte
		before   map[string][]byte // files the directory already holds
		failure  func(error) bool
	}{
		{"a key name outside the directory", withEscape, nil, nil, func(err error) bool { return mutantCode(err) == model.Corrupt }},
		{"a file that is not a key", withStranger, nil, nil, func(err error) bool { return mutantCode(err) == model.Corrupt }},
		{"a key that differs from the file already there", seedKeys(24), nil, map[string][]byte{"envelope-k07.key": []byte("other")},
			func(err error) bool { return mutantCode(err) == model.Conflict }},
		// The database refuses the seed after every key landed (an empty metadata name).
		{"a state the database refuses after the keys were written", withActive, map[string][]byte{"": []byte("x")}, nil,
			func(err error) bool { return errors.Is(err, bolt.ErrKeyRequired) }},
		{"the same with an envelope.active already in place", withActive, map[string][]byte{"": []byte("x")}, map[string][]byte{"envelope.active": []byte("old")},
			func(err error) bool { return errors.Is(err, bolt.ErrKeyRequired) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 25 {
				dir := t.TempDir()
				for name, value := range tc.before {
					if err := os.WriteFile(filepath.Join(dir, name), value, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				s, err := OpenSeed(dir, seedOf(t, tc.keys, tc.metadata))
				if err == nil {
					s.Close()
					t.Fatal("fixture invalid: the seed was accepted")
				}
				if !tc.failure(err) {
					t.Fatalf("the seed was refused for another reason than the case names: %v", err)
				}
				if _, err = os.Stat(filepath.Join(dir, "control.db")); !os.IsNotExist(err) {
					t.Fatalf("a rejected seed left control.db behind: %v", err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				var left, want []string
				for _, entry := range entries {
					left = append(left, entry.Name())
					if value, ok := tc.before[entry.Name()]; ok {
						if raw, err := os.ReadFile(filepath.Join(dir, entry.Name())); err != nil || !bytes.Equal(raw, value) {
							t.Fatalf("a rejected seed changed %s: %q, %v", entry.Name(), raw, err)
						}
					}
				}
				for name := range tc.before {
					want = append(want, name)
				}
				slices.Sort(left)
				slices.Sort(want)
				if !slices.Equal(left, want) {
					t.Fatalf("a rejected seed left %v in the data directory, want %v", left, want)
				}
			}
		})
	}
}
