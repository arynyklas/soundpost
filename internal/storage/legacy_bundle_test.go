// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// legacy is a sealed backup written by the code before 01.07-W1 (bundle version 1: slot snapshots
// that carry the whole command history, the full list of consumed reservations). The fixture was
// produced by the generator kept in .superpowers/sdd/approved-product/gen-legacy-bundle.go.txt
// against the tree at the parent of that change.
type legacy struct {
	Bundle   BackupBundle `json:"bundle"`
	Slots    [][]byte     `json:"slots"`
	AfterCut model.ID     `json:"after_cut"`
}

func loadLegacy(t *testing.T) legacy {
	t.Helper()
	f, err := os.Open("testdata/legacy_bundle_v1.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var l legacy
	if err = json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	if l.Bundle.Version != 1 || l.Bundle.Quota.Version != 1 || len(l.Bundle.Quota.Windows) != 0 || len(l.Slots) != 64 {
		t.Fatalf("fixture is not a version 1 bundle: version %d, evidence %d, %d windows, %d slots", l.Bundle.Version, l.Bundle.Quota.Version, len(l.Bundle.Quota.Windows), len(l.Slots))
	}
	return l
}

func (l legacy) open(slot uint16) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.Slots[slot])), nil
}

// Backups taken before the windowed format are still restorable: they are not refused, they are
// read in the form they were written in (whole-history snapshots, the complete consumed list), and
// the restored node's next cut is windowed.
func TestLegacyBundleVersion1StillRestores(t *testing.T) {
	l := loadLegacy(t)
	ctx := context.Background()
	cert, err := ReconcileQuota(l.Bundle)
	if err != nil {
		t.Fatalf("the sealed version 1 bundle no longer reconciles: %v", err)
	}
	if len(cert.Consumed) < 10 || len(cert.AddedAfterCut) != 1 || cert.AddedAfterCut[0] != l.AfterCut {
		t.Fatalf("certificate consumed=%d added=%v, want >=10 and the one created after the cut", len(cert.Consumed), cert.AddedAfterCut)
	}
	store, service, _, _ := fixture(t)
	restored, err := openRestoredEngine(t, t.TempDir(), service, store, l.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(ctx, raft, l.Bundle, l.open)
	})
	if err != nil {
		t.Fatalf("version 1 bundle refused: %v", err)
	}
	if restored.RestoreReady() == nil {
		t.Fatal("restored engine ready before quota reconciliation")
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatalf("certificate of a version 1 bundle refused by its own restore: %v", err)
	}
	var applied uint64
	for _, i := range restored.indexes {
		applied += i
	}
	var want uint64
	for _, s := range l.Bundle.Snapshots {
		want += uint64(s.Cursor.Index)
	}
	if applied != want || applied < 10 {
		t.Fatalf("restored %d commands, the bundle's cut holds %d", applied, want)
	}
	if _, err = restored.CreateSnapshots(ctx); err != nil {
		t.Fatalf("the restored node cannot cut its own snapshot: %v", err)
	}
	for slot := range uint16(64) {
		if restored.indexes[slot] == 0 {
			continue
		}
		cur, ok := restored.repl.groups[slot].Snapshots().Current()
		if !ok {
			t.Fatal("no snapshot after the cut")
		}
		if _, compact, err := compactState(cur); err != nil || !compact {
			t.Fatalf("slot %d: the cut after a legacy restore is not windowed (compact=%v err=%v)", slot, compact, err)
		}
	}
}

// The restore gate of a version 1 bundle still compares the evidence with the installed bytes.
func TestLegacyBundleTamperedEvidenceIsRefused(t *testing.T) {
	l := loadLegacy(t)
	ctx := context.Background()
	store, service, _, _ := fixture(t)
	try := func(b BackupBundle) error {
		_, err := openRestoredEngine(t, t.TempDir(), service, store, b.Identity, func(e *Engine, raft string) error {
			return e.InstallBackup(ctx, raft, b, l.open)
		})
		return err
	}
	if len(l.Bundle.Quota.Consumed) == 0 {
		t.Fatal("fixture has no consumed evidence")
	}
	forged := l.Bundle
	forged.Quota.Consumed = append([]ReservationEvidence(nil), l.Bundle.Quota.Consumed...)
	for i := range forged.Quota.Consumed {
		if _, known := forged.Cut.Reservations[forged.Quota.Consumed[i].ID.String()]; !known {
			forged.Quota.Consumed[i].Bytes += 7 // a charge control never held: only the bytes can refute it
		}
	}
	forged.Quota.Digest = forged.Quota.seal()
	forged.Digest = forged.seal()
	if _, err := ReconcileQuota(forged); err != nil {
		t.Fatalf("fixture: the forged bundle should be self-consistent: %v", err)
	}
	if err := try(forged); err == nil {
		t.Fatal("a version 1 bundle whose evidence the snapshots do not carry was installed")
	}
	relabelled := l.Bundle
	relabelled.Version = 2
	relabelled.Digest = relabelled.seal()
	if err := try(relabelled); err == nil {
		t.Fatal("a version 1 bundle relabelled as version 2 was installed")
	}
}
