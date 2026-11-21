// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The seed is a snapshot of the machine's whole history: it must be built when a journal is
// created and never when an existing journal is reopened (D15: startup cost does not depend on
// history).
func TestSeedFuncRunsOnlyForAFreshJournal(t *testing.T) {
	dir, id := t.TempDir(), model.NewID()
	machine := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(machine.dir, 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	open := func() *Group {
		transport := NewLoopback()
		g, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine, SeedFunc: func() ([]byte, error) {
			calls++
			return nil, nil
		}})
		if err != nil {
			transport.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { g.Close(); transport.Close() })
		return g
	}
	g := open()
	if calls != 1 {
		t.Fatalf("fresh journal: seed built %d times, want 1", calls)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	open()
	if calls != 1 {
		t.Fatalf("existing journal: seed built again (%d calls)", calls)
	}
}
