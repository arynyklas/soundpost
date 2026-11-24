// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The full snapshot of the control group (the form a peer is given, a backup cuts, and the seed of a journal
// is) was one buffer in one journal record, and a journal record is bounded (256 MiB). The state of the
// live 2,000 records/s run was 141 MB, which base64 turns into more than the bound twice over: the first
// compaction failed the bound and the group stopped (replica: fail-stop in rewrite journal: invalid
// replica command), and a node whose control.db was larger than the bound could not even start a journal
// on it. D86 condition 3: the snapshot is written and read as a chain of records, so the bound is on a
// record and not on the state.
//
// The bound is lowered (replica.SetRecordLimitForTest) to half of the state instead of building hundreds of
// megabytes of state. The installation is expanded (the previous release can read it), so the group cuts
// whole snapshots for itself, which is the case a compact snapshot does not cover.

func canonicalControl(t *testing.T, s *control.Store) string {
	t.Helper()
	var out string
	if err := s.View(t.Context(), func(st control.State) error {
		raw, err := model.CanonicalJSON(st)
		out = string(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAControlSnapshotLargerThanOneRecordIsCompactedSeededAndRestoredWhole(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(60)
	cursorGroup := model.NewID()
	for i := range 60 {
		if err := admitAndFinalize(f, fmt.Sprintf("parts_series_%03d", i), model.Cursor{Group: cursorGroup, Index: model.Uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.ExpandForTest(); err != nil {
		t.Fatal(err)
	}
	seed, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	limit := len(seed) / 2
	t.Logf("full snapshot %d B, record bound %d B", len(seed), limit)
	defer replica.SetRecordLimitForTest(limit)()

	// (b) the group compacts its journal onto a whole snapshot larger than a record, and does not stop.
	group := f.store.ReplicaGroup()
	cut, err := group.ReadIndex(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := group.CreateSnapshot(f.ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	in, err := snapshot.File("envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := io.ReadAll(in)
	in.Close()
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		State []byte `json:"state"`
	}
	if err = json.Unmarshal(envelopeRaw, &envelope); err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(envelope.State, []byte(`{"compact":`)) || len(envelope.State) < limit {
		t.Fatalf("the fixture cut a %d B snapshot (%.40s...), it must be a whole one larger than the bound %d", len(envelope.State), envelope.State, limit)
	}
	if _, err = group.CompactJournal(f.ctx); err != nil {
		t.Fatalf("compaction onto a whole snapshot of %d B, the bound being %d B: %v", len(envelope.State), limit, err)
	}
	if first, _ := group.JournalRange(); first <= 2 {
		t.Fatalf("control journal not truncated: first=%d", first)
	}
	f.admin("create_project", f.org, auth.AdminPayload{ID: model.NewID(), Name: "after-compaction", Reason: "the group still commits"})
	want := canonicalControl(t, f.store)
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}

	// The journal on a chain of parts restarts to the same state.
	reopen := func(dir string) *control.Store {
		t.Helper()
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		if err = store.EnableSingle(f.ctx, filepath.Join(dir, "raft-control")); err != nil {
			t.Fatal(err)
		}
		return store
	}
	again := reopen(f.dir)
	if got := canonicalControl(t, again); got != want {
		t.Fatal("the restarted control state differs from the state before the restart")
	}

	// (a) a snapshot larger than a record is the seed of a second store and restores byte for byte: its
	// control.db is filled from the seed, and the group's first start journals the whole snapshot.
	whole, _, err := again.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	second, err := control.OpenSeed(dir, whole)
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	other := reopen(dir)
	if got := canonicalControl(t, other); got != want {
		t.Fatal("the control state seeded from a snapshot larger than a record differs from its origin")
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	if got := canonicalControl(t, reopen(dir)); got != want {
		t.Fatal("the control state of the seeded store differs after its journal was read back")
	}
}
