// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// A restart of a node whose admission ledger is large (the single-host gate holds tens of thousands of
// unsettled admission rows, hundreds of MB of control.db) must not read the ledger to become ready: the
// control journal exists, so no seed is built from the state; the checks the start makes (the revision,
// the installation, the artifact references, the attestation record) read members of the state outside
// the admission books. The tests below make the ledger much larger than anything the start may allocate
// and bound what the start allocates (counters, not wall time: the bound holds on any machine).

// startupLedgerRows are the reservation rows the start tests hold in the ledger; startupAllocBound is what
// each step of the start may allocate while it runs (the ledger is several times larger).
const (
	startupLedgerRows = 8000
	startupAllocBound = 2 << 20
)

// stubBlobOwner is the admission owner of a node whose artifact blobs all verify.
type stubBlobOwner struct{ AdmissionProofs }

func (stubBlobOwner) VerifyBlob(context.Context, model.BlobReceipt) error { return nil }

// bigLedgerStore builds a contracted installation with a replicated control journal whose ledger holds
// startupLedgerRows reservation rows (the way the settlement has not yet taken them away), cut onto a
// snapshot and compacted as the journal of a running node is, then closes it and opens the file again
// without its group. It returns the store, the directory of the journal and the bytes of the ledger.
func bigLedgerStore(t *testing.T) (*Store, string, uint64) {
	t.Helper()
	dir := t.TempDir()
	raft := filepath.Join(dir, "raft-control")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	activateLedger(t, s)
	s.SetStatePatchGate(func() bool { return true })                     // a command carries its rows, not the whole state
	enableSingleTimed(t, s, raft, replica.Cadence{Commands: ^uint64(0)}) // on, and the test cuts
	pad := strings.Repeat("series-label-of-a-realistic-length-", 3)
	const batch = 200
	for first := 0; first < startupLedgerRows; first += batch {
		if err = s.Update(context.Background(), func(st *State) error {
			if st.Reservations == nil {
				st.Reservations = map[string]model.AdmissionReservation{}
			}
			for i := first; i < first+batch; i++ {
				r := resv(model.NewID(), "consumed")
				for n := range 12 {
					r.Series = append(r.Series, fmt.Sprintf("%s%d-%d", pad, i, n))
				}
				st.Reservations[r.ID.String()] = r
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	g, ctx := s.ReplicaGroup(), context.Background()
	if _, err = g.CreateSnapshot(ctx, g.Status().ApplicationCursor); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Snapshots().DropSuperseded(); err != nil {
		t.Fatal(err)
	}
	if _, err = g.CompactJournal(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var bytes uint64
	if err = s.db.View(func(tx *bolt.Tx) error {
		l, err := openLedger(tx)
		if err != nil {
			return err
		}
		l.each(tableReservations, nil, func(_, v []byte) bool { bytes += uint64(len(v)); return true })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes < 5*startupAllocBound {
		t.Fatalf("the ledger of the test is %d bytes: too small to tell a read of it from the rest of the start", bytes)
	}
	return s, raft, bytes
}

// allocated is the bytes the process allocated while fn ran (other goroutines of the test included: the
// store's own workers are what the start must not wake up on the ledger either).
func allocated(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestStartOfAnExistingJournalDoesNotReadTheLedger(t *testing.T) {
	if raceBuild {
		t.Skip("the race detector multiplies allocations")
	}
	s, raft, ledger := bigLedgerStore(t)
	enable := allocated(func() { enableSingleTimed(t, s, raft, replica.Cadence{Commands: ^uint64(0)}) })
	t.Logf("ledger %d bytes; EnableReplication on the existing journal allocated %d", ledger, enable)
	if enable > startupAllocBound {
		t.Fatalf("EnableReplication of an existing journal allocated %d bytes (bound %d, ledger %d): it assembled the state it does not need", enable, startupAllocBound, ledger)
	}
	if s.repl == nil || s.repl.group == nil {
		t.Fatal("the group is not open")
	}
}

func TestStartupChecksDoNotReadTheLedger(t *testing.T) {
	if raceBuild {
		t.Skip("the race detector multiplies allocations")
	}
	s, raft, ledger := bigLedgerStore(t)
	enableSingleTimed(t, s, raft, replica.Cadence{Commands: ^uint64(0)})
	s.ownerProof = stubBlobOwner{}
	ctx := context.Background()
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"ValidateArtifactReferences", func() error { return s.ValidateArtifactReferences(ctx) }},
		{"Installation", func() error { _, err := s.Installation(); return err }},
		{"syncAttestation", func() error { return s.syncAttestation(ctx, true) }},
	} {
		var err error
		n := allocated(func() { err = step.run() })
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		t.Logf("%s allocated %d bytes (ledger %d)", step.name, n, ledger)
		if n > startupAllocBound {
			t.Errorf("%s allocated %d bytes (bound %d, ledger %d): it read the admission ledger", step.name, n, startupAllocBound, ledger)
		}
	}
}

// TestDataInitializedIsTheAnswerOfView: the application asks DataInitialized before it opens any group; it
// must be what View reads, in a file that has just been created, in one that moved its books to the ledger
// and after the engine is marked initialized.
func TestDataInitializedIsTheAnswerOfView(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	check := func(label string, want bool) {
		t.Helper()
		var viewed bool
		if err := s.View(context.Background(), func(st State) error { viewed = st.DataInitialized; return nil }); err != nil {
			t.Fatal(err)
		}
		got, err := s.DataInitialized()
		if err != nil {
			t.Fatal(err)
		}
		if got != viewed || got != want {
			t.Fatalf("%s: DataInitialized %v, View %v, want %v", label, got, viewed, want)
		}
	}
	check("fresh file", false)
	activateLedger(t, s)
	check("contracted, not initialized", false)
	enableSingleWith(t, s, filepath.Join(dir, "raft-control"), replica.Cadence{})
	if err := s.Update(context.Background(), func(st *State) error { st.DataInitialized = true; return nil }); err != nil {
		t.Fatal(err)
	}
	check("contracted, initialized", true)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	check("reopened, before the group", true)
}
