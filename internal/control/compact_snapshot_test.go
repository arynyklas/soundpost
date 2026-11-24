// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// TestAContractedControlSnapshotNamesTheStateInsteadOfCarryingIt is the red test of the fail-stop of the
// live 2,000 records/s run (L2w20Admission15, D86): the journal record that follows a compaction of the
// control group held the whole control state (unsettled admission rows are ~1.2 KiB each: 141 MB at 115,000
// acknowledged requests, a data window of 4096 commands settles after ~8 minutes), base64 encoded twice,
// and the record is bounded (256 MiB): the first compaction past ~115,000 rows failed and the node stopped.
// The state of a contracted installation is control.db, so the snapshot the group cuts for itself names it
// (a revision and the seal of the stored state) and carries nothing of it; a snapshot sent to a peer, a
// seed and a backup are cut whole (Store.Snapshot) as before.
func TestAContractedControlSnapshotNamesTheStateInsteadOfCarryingIt(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(120)
	group := f.store.ReplicaGroup()
	cursorGroup := model.NewID()
	for i := range 60 {
		if err := admitAndFinalize(f, fmt.Sprintf("compact_series_%03d", i), model.Cursor{Group: cursorGroup, Index: model.Uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	var whole int
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := model.CanonicalJSON(st)
		whole = len(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
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
	raw, err := io.ReadAll(in)
	in.Close()
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		State []byte `json:"state"`
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	t.Logf("control state %d B canonical, snapshot envelope %d B, state in it %d B", whole, len(raw), len(envelope.State))
	if !bytes.HasPrefix(envelope.State, []byte(`{"compact":`)) {
		t.Fatalf("the control snapshot of a contracted installation carries %d B of state (%.60s...), want a compact state", len(envelope.State), envelope.State)
	}
	if len(envelope.State) > 1024 {
		t.Fatalf("a compact control state is %d B, want a revision and a seal", len(envelope.State))
	}
	if len(raw)-len(envelope.State) > whole {
		t.Fatalf("the snapshot envelope is %d B beside a state of %d B: it still carries the state", len(raw), len(envelope.State))
	}
}

// compactedControl is a control store whose journal was compacted onto a compact snapshot, closed, with the
// control.db file of an earlier revision kept beside it.
type compactedControl struct {
	f        *fenceFx
	earlier  string // a copy of control.db before the last admissions
	revision model.Revision
}

func newCompactedControl(t *testing.T) *compactedControl {
	t.Helper()
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(10)
	cursorGroup := model.NewID()
	admit := func(from, to int) {
		for i := from; i < to; i++ {
			if err := admitAndFinalize(f, fmt.Sprintf("restart_series_%03d", i), model.Cursor{Group: cursorGroup, Index: model.Uint64(i + 1)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	admit(0, 8)
	c := &compactedControl{f: f, earlier: filepath.Join(t.TempDir(), "control.db.earlier")}
	// bbolt takes a file lock: the copy is a consistent snapshot of the open store, written by the store.
	if err := f.store.CopyDatabaseForTest(c.earlier); err != nil {
		t.Fatal(err)
	}
	admit(8, 20)
	group := f.store.ReplicaGroup()
	cut, err := group.ReadIndex(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = group.CreateSnapshot(f.ctx, cut); err != nil {
		t.Fatal(err)
	}
	if _, err = group.CompactJournal(f.ctx); err != nil {
		t.Fatal(err)
	}
	if first, _ := group.JournalRange(); first <= 2 {
		t.Fatalf("control journal not truncated: first=%d", first)
	}
	c.revision = revisionOf(f)
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *compactedControl) reopen() (*control.Store, error) {
	store, err := control.Open(c.f.dir)
	if err != nil {
		return nil, err
	}
	if err = store.EnableSingle(c.f.ctx, filepath.Join(c.f.dir, "raft-control")); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

// requireRefusal checks the refusal of an open: a typed fault (corrupt) that names the two remedies.
func requireRefusal(t *testing.T, store *control.Store, err error, what string, namesRemedies bool) {
	t.Helper()
	if err == nil {
		store.Close()
		t.Fatalf("%s: the node started and would serve a state its journal does not vouch for", what)
	}
	var fault *model.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("%s: refused with %v, want a typed fault", what, err)
	}
	// The journal-open check (verifyCompact) names the two remedies; a control.db that is empty or whose seal
	// differs is already refused, typed and fail-closed, by the earlier consistency checks of Open.
	if namesRemedies && (fault.Code != model.Corrupt || !strings.Contains(fault.SafeDetail, "replace") || !strings.Contains(fault.SafeDetail, "restore")) {
		t.Fatalf("%s: refused with %v, want a typed corrupt fault that names replacing the node or restoring a backup", what, err)
	}
}

// A journal anchored on a compact snapshot restarts to the state in control.db and goes on committing.
func TestAControlJournalAnchoredOnACompactSnapshotRestartsOnItsOwnState(t *testing.T) {
	c := newCompactedControl(t)
	store, err := c.reopen()
	if err != nil {
		t.Fatalf("restart on a compact snapshot: %v", err)
	}
	defer store.Close()
	var after model.Revision
	if err = store.View(control.WithoutBooks(c.f.ctx), func(st control.State) error { after = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	if after < c.revision {
		t.Fatalf("revision %d after the restart, %d before", after, c.revision)
	}
	if err = store.Update(c.f.ctx, func(st *control.State) error {
		st.Quotas["after-restart"] = model.QuotaState{MaxBytes: 1}
		return nil
	}); err != nil {
		t.Fatalf("a restarted control group does not commit: %v", err)
	}
}

// The compact snapshot is a statement about control.db, so a control.db that cannot back it is refused with
// a typed fault, never replaced by an empty or an older state (D86): missing, older than the snapshot, or at
// the snapshot's revision with another seal.
func TestAControlJournalOnACompactSnapshotRefusesAControlDatabaseThatDoesNotBackIt(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		c := newCompactedControl(t)
		if err := os.Remove(filepath.Join(c.f.dir, "control.db")); err != nil {
			t.Fatal(err)
		}
		store, err := c.reopen()
		requireRefusal(t, store, err, "control.db missing", false)
	})
	t.Run("older", func(t *testing.T) {
		c := newCompactedControl(t)
		raw, err := os.ReadFile(c.earlier)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(c.f.dir, "control.db"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := c.reopen()
		requireRefusal(t, store, err, "control.db older than the snapshot", true)
	})
	t.Run("mismatched", func(t *testing.T) {
		c := newCompactedControl(t)
		db, err := bolt.Open(filepath.Join(c.f.dir, "control.db"), 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("control"))
			seal := bytes.Clone(b.Get([]byte("state_seal")))
			if len(seal) == 0 {
				return errors.New("the fixture has no state seal")
			}
			seal[0] ^= 0xff
			return b.Put([]byte("state_seal"), seal)
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
		store, err := c.reopen()
		requireRefusal(t, store, err, "control.db at the snapshot's revision with another seal", false)
	})
}
