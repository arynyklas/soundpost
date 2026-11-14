// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A batch of which SOME records were physically erased (an erased metric beside
// a kept metric and a kept log) is redacted to exactly the records that remain,
// and a backup of it installs and activates: the Retained list replaces the
// reservation's Series in the quota cross-check for the mixed case, not only for
// a batch erased whole. (09.06 review M-1; the 09.01x commit named it untested.)
func TestRestoreOfAPartiallyErasedBatchActivates(t *testing.T) {
	x := newEraseEnv(t)
	if err := x.store.BindAdmissionOwner(x.e); err != nil {
		t.Fatal(err)
	}
	x.appendMixed("MIXEDREDACT0f1e2d3c4b5a", bothDeadlines)
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := x.store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	backup, err := x.e.BeginBackup(context.Background(), controlCut(t, x.e, x.store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(sealed.Bundle.Quota.Consumed); n != 1 {
		t.Fatalf("%d consumed reservations, want the one mixed batch", n)
	}
	only := sealed.Bundle.Quota.Consumed[0]
	if !only.Redacted || len(only.Retained) != 1 {
		t.Fatalf("the mixed batch must be redacted to the one record that remains charged: redacted=%v retained=%d", only.Redacted, len(only.Retained))
	}
	restored, err := openRestoredEngine(t, t.TempDir(), x.a, x.store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("a restore of a bundle with a partially erased batch cannot activate: %v", err)
	}
	if err = restored.Close(); err != nil {
		t.Fatal(err)
	}
}
