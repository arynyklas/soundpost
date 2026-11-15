// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// A seed the group rejects must not leave the control.db OpenSeed created (with its settled
// key and state) in the data directory.
func TestARejectedOpenSeedLeavesNoControlDB(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.Marshal(controlSnapshot{State: State{Installation: model.NewID()}, Keys: map[string][]byte{"../escape": []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := OpenSeed(dir, raw); err == nil {
		s.Close()
		t.Fatal("fixture invalid: the seed was accepted")
	}
	if _, err = os.Stat(filepath.Join(dir, "control.db")); !os.IsNotExist(err) {
		t.Fatalf("a rejected seed left control.db behind: %v", err)
	}
}
