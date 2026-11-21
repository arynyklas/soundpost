// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// snapshotWith cuts a snapshot of a fresh history of one group: tombstones deletion-ledger entries
// (generation) and writes ordinary entries (index).
func snapshotWith(t *testing.T, id model.ID, tombstones, writes int) Snapshot {
	t.Helper()
	s := openSolo(t, t.TempDir(), id, nil)
	for i := range tombstones {
		s.propose(Barrier, fmt.Sprintf("tombstone-%d", i))
	}
	for i := range writes {
		s.propose(Data, fmt.Sprintf("ordinary-write-%d", i))
	}
	return s.snapshot()
}

// The generation clause of the installation fence is the only thing that refuses a snapshot that
// is newer by index but older by deletion generation, and no FENCE file exists on a store that the
// restore authority never touched. It is the cut of an old backup node that kept applying
// ordinary writes while the authority's ledger moved on. Deleting the clause must break this test.
func TestSnapshotHigherIndexLowerGenerationIsStaleWithoutAFenceFile(t *testing.T) {
	id := model.NewID()
	current := snapshotWith(t, id, 3, 3)
	stale := snapshotWith(t, id, 1, 40)
	if stale.Manifest.Index <= current.Manifest.Index || stale.Manifest.Generation >= current.Manifest.Generation {
		t.Fatalf("fixture invalid: stale index %d generation %d, current index %d generation %d",
			stale.Manifest.Index, stale.Manifest.Generation, current.Manifest.Index, current.Manifest.Generation)
	}
	dir := t.TempDir()
	store, err := OpenSnapshotStore(dir, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.InstallSnapshot(context.Background(), current.Manifest, bytes.NewReader(stream(t, current))); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "snapshots", fenceName)); !os.IsNotExist(err) {
		t.Fatalf("fixture invalid: the store has a FENCE file (%v)", err)
	}
	if err = store.InstallSnapshot(context.Background(), stale.Manifest, bytes.NewReader(stream(t, stale))); !errors.Is(err, ErrStale) {
		t.Fatalf("a snapshot with a higher index and an older deletion generation was installed: %v", err)
	}
	selected, ok := store.Current()
	if !ok || selected.Manifest.Checksum != current.Manifest.Checksum {
		t.Fatal("the stale snapshot displaced the authority's snapshot")
	}
	if _, err = store.Verify(); err != nil {
		t.Fatalf("the retained snapshot no longer verifies: %v", err)
	}
}

// The fence is part of the crash matrix: a crash at any hook of a legitimate installation leaves a
// store in which a candidate with a higher index and an older generation than every snapshot the
// crash could have left selected is still refused.
func TestSnapshotGenerationFenceHoldsAtEveryInstallCrashPoint(t *testing.T) {
	id := model.NewID()
	seed := snapshotWith(t, id, 1, 2)
	next := snapshotWith(t, id, 3, 3)
	candidate := snapshotWith(t, id, 0, 60)
	if seed.Manifest.Generation >= next.Manifest.Generation || candidate.Manifest.Generation >= seed.Manifest.Generation ||
		candidate.Manifest.Index <= next.Manifest.Index {
		t.Fatalf("fixture invalid: seed g%d i%d, next g%d i%d, candidate g%d i%d",
			seed.Manifest.Generation, seed.Manifest.Index, next.Manifest.Generation, next.Manifest.Index, candidate.Manifest.Generation, candidate.Manifest.Index)
	}
	hooks := []string{HookInstallBegin, HookInstallFileWrite, HookInstallFileSync, HookInstallManifestWrite, HookInstallDirSync, HookInstallSwitch, HookInstallRenamed, HookInstallCurrentWrite, HookInstallCurrentSwitch, HookInstallPublished}
	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			dir := t.TempDir()
			store, err := OpenSnapshotStore(dir, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.InstallSnapshot(context.Background(), seed.Manifest, bytes.NewReader(stream(t, seed))); err != nil {
				t.Fatal(err)
			}
			crashing, err := OpenSnapshotStore(dir, id, faultOnce(hook))
			if err != nil {
				t.Fatal(err)
			}
			if err = crashing.InstallSnapshot(context.Background(), next.Manifest, bytes.NewReader(stream(t, next))); err == nil {
				t.Fatalf("hook %s did not interrupt the installation", hook)
			}
			repaired, err := OpenSnapshotStore(dir, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			before, ok := repaired.Current()
			if !ok {
				t.Fatal("no snapshot selected after the crash")
			}
			if err = repaired.InstallSnapshot(context.Background(), candidate.Manifest, bytes.NewReader(stream(t, candidate))); !errors.Is(err, ErrStale) {
				t.Fatalf("after a crash at %s a snapshot older by generation was admitted: %v", hook, err)
			}
			after, ok := repaired.Current()
			if !ok || after.Manifest.Checksum != before.Manifest.Checksum {
				t.Fatalf("after a crash at %s the refused candidate changed the selection", hook)
			}
		})
	}
}

// laggingMachine reports less applied progress than the group delivered to it: a machine whose
// durable state is behind what the group believes it applied.
type laggingMachine struct {
	*ledgerMachine
	lagMu  sync.Mutex
	behind uint64
}

func (m *laggingMachine) setBehind(n uint64) { m.lagMu.Lock(); m.behind = n; m.lagMu.Unlock() }
func (m *laggingMachine) Applied() uint64 {
	m.lagMu.Lock()
	behind := m.behind
	m.lagMu.Unlock()
	applied := m.ledgerMachine.Applied()
	if applied < behind {
		return 0
	}
	return applied - behind
}

// CompactJournal re-anchors the journal on a snapshot and discards everything before it. It may do
// that only for a cut the machine has durably applied; the group's own applied index is not that
// proof. Removing the machine check must break this test.
func TestCompactJournalRefusesACutTheMachineHasNotDurablyApplied(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	base := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(base.dir, 0700); err != nil {
		t.Fatal(err)
	}
	machine := &laggingMachine{ledgerMachine: base}
	transport := NewLoopback()
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine})
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	if err = transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		group.Close()
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Close() })
	for i := range 6 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, perr := group.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("row-%d", i))})
		cancel()
		if perr != nil {
			t.Fatal(perr)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snap, err := group.CreateSnapshot(ctx, model.Cursor{Group: id, Index: group.Status().ApplicationCursor.Index})
	if err != nil {
		t.Fatal(err)
	}
	if group.Status().Applied < snap.Manifest.Index {
		t.Fatal("fixture invalid: the group has not applied its own cut")
	}
	first, _ := group.JournalRange()

	machine.setBehind(1) // the machine's durable progress is one entry short of the cut
	if _, err = group.CompactJournal(ctx); !errors.Is(err, ErrStale) {
		t.Fatalf("the journal was truncated onto a cut the machine has not durably applied: %v", err)
	}
	if again, _ := group.JournalRange(); again != first {
		t.Fatalf("a refused truncation moved the journal start from %d to %d", first, again)
	}

	machine.setBehind(0)
	res, err := group.CompactJournal(ctx)
	if err != nil {
		t.Fatalf("the truncation must proceed once the machine caught up: %v", err)
	}
	if res.FirstIndex != snap.Manifest.Index+1 {
		t.Fatalf("journal starts at %d, want %d", res.FirstIndex, snap.Manifest.Index+1)
	}
}

// failingMachine refuses to apply once failOn is set.
type failingMachine struct {
	*ledgerMachine
	failOn atomic.Bool
}

func (m *failingMachine) Apply(c CommittedEntry) error {
	if m.failOn.Load() && c.Entry.Kind != Noop {
		return errors.New("injected apply failure")
	}
	return m.ledgerMachine.Apply(c)
}

// A machine whose Apply fails takes the group down with it, and a group that failed refuses to
// truncate: the other half of the guard above, which keeps a lagging machine from ever being
// treated as caught up.
func TestCompactJournalRefusesAfterTheMachineFailedToApply(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	base := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(base.dir, 0700); err != nil {
		t.Fatal(err)
	}
	machine := &failingMachine{ledgerMachine: base}
	transport := NewLoopback()
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine})
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	if err = transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		group.Close()
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Close() })
	put := func(payload string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, perr := group.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(payload)})
		return perr
	}
	for i := range 4 {
		if err = put(fmt.Sprintf("row-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = group.CreateSnapshot(ctx, model.Cursor{Group: id, Index: group.Status().ApplicationCursor.Index}); err != nil {
		t.Fatal(err)
	}
	machine.failOn.Store(true)
	if err = put("the entry the machine cannot apply"); err == nil {
		t.Fatal("an entry the machine failed to apply was acknowledged")
	}
	if _, err = group.CompactJournal(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a group whose machine failed to apply truncated its journal: %v", err)
	}
}
