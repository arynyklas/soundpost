// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"io"
	"testing"

	"soundpost/internal/model"
)

// restoreForged seals a real backup of the batches from mk, lets forge rewrite
// the bundle's quota evidence, reseals it with valid digests, and installs THAT
// bundle into a clean engine, so the pending-backup marker matches the forged
// bundle exactly (a forgery any weaker than this stops at the marker check and
// never reaches the series cross-check). installErr is the install's own refusal.
func restoreForged(t *testing.T, mk []maker, forge func(*BackupBundle)) (restored *Engine, forged BackupBundle, genuine QuotaReconciliation, installErr error) {
	t.Helper()
	store, service, credential, descriptor := typedFixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	for _, f := range mk {
		scope, b := f(store, service, credential, descriptor)
		if _, err = engine.Append(context.Background(), scope, b); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	backup, err := engine.BeginBackup(context.Background(), controlCut(t, engine, store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if genuine, err = ReconcileQuota(sealed.Bundle); err != nil {
		t.Fatal(err)
	}
	forged = sealed.Bundle
	forge(&forged)
	forged.Quota.Digest = forged.Quota.seal()
	forged.Digest = forged.seal()
	restored, installErr = openRestoredEngine(t, t.TempDir(), service, store, forged.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, forged, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	return restored, forged, genuine, installErr
}

func sameDigests(a, b map[string]model.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func isCorrupt(err error) bool { return err != nil && err.Error() == model.Fail(model.Corrupt).Error() }

// The Redacted/Retained fields of a bundle's quota evidence relax the restored
// index cross-check for batches that physical erasure rewrote. They must not be
// a way to hide series: a bundle that claims an UNERASED batch was redacted (and
// carries no Retained series, or fewer than the batch really holds) and is
// resealed with valid digests must still be refused, because the cross-check is
// against the restored index, which really holds those series.
//
// Which stage refuses is logged. The restoration is refused by the install, by
// the reconciliation, or, if both accept the forged evidence, by
// CommitQuotaReconciliation: the last is the check this test exists to pin, and
// the mutation run in the commit message shows it is reached.
func TestRestoreForgedRedactionEvidenceStaysCorrupt(t *testing.T) {
	forgeries := map[string]func(*BackupBundle){
		"redacted flag without a retained set": func(b *BackupBundle) {
			b.Quota.Consumed = append([]ReservationEvidence(nil), b.Quota.Consumed...)
			for i := range b.Quota.Consumed {
				b.Quota.Consumed[i].Redacted, b.Quota.Consumed[i].Retained = true, nil
			}
		},
		"redacted flag with an empty retained set": func(b *BackupBundle) {
			b.Quota.Consumed = append([]ReservationEvidence(nil), b.Quota.Consumed...)
			for i := range b.Quota.Consumed {
				b.Quota.Consumed[i].Redacted, b.Quota.Consumed[i].Retained = true, []string{}
			}
		},
	}
	for fname, forge := range forgeries {
		for mname, mk := range map[string][]maker{"metrics": {metricMaker(t)}, "mixed": {logMaker(t), metricMaker(t)}} {
			t.Run(fname+"/"+mname, func(t *testing.T) {
				restored, bundle, genuine, installErr := restoreForged(t, mk, forge)
				if installErr != nil {
					t.Logf("refused by the install: %v", installErr)
					return
				}
				cert, err := ReconcileQuota(bundle)
				if err != nil {
					t.Logf("refused by the reconciliation: %v", err)
					return
				}
				if sameDigests(cert.SeriesDigest, genuine.SeriesDigest) {
					t.Fatal("the forgery did not change the certificate: this test no longer exercises the relaxation")
				}
				err = restored.CommitQuotaReconciliation(context.Background(), cert)
				if !isCorrupt(err) {
					t.Fatalf("forged redaction evidence hid series from the restored index: %v, want corrupt", err)
				}
				t.Logf("refused by CommitQuotaReconciliation: %v", err)
				if restored.RestoreReady() == nil {
					t.Fatal("a forged reconciliation opened intake")
				}
			})
		}
	}
}
