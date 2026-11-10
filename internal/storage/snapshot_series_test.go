// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// logBatch is normalized() with a log record instead of a metric point.
func logBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	ctx := context.Background()
	src, err := a.SourceAuthority(ctx, c, true)
	if err != nil {
		t.Fatal(err)
	}
	res := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
	var row model.Record
	for _, r := range typedRows(res) {
		if r.Kind == model.Log {
			row = r
			break
		}
	}
	svc, err := policy.New(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := svc.ResolveSource(ctx, c, d.Project, d.Source, src.Policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	row.ID = model.NewID()
	n, err := policy.Normalize(grant, typedInput(t, d, src.Policy.Revision, row))
	if err != nil {
		t.Fatal(err)
	}
	n.Deadlines = []model.SignalDeadline{{Kind: model.Log, RetainUntil: 100}}
	scope, err := grant.Scope()
	if err != nil {
		t.Fatal(err)
	}
	if n.Reservation, err = store.ReserveAdmission(ctx, scope, n); err != nil {
		t.Fatal(err)
	}
	return scope, n
}

// restoreWith appends the batches from mk, seals a backup, and installs it into
// a clean engine. It returns the restored engine and the reconciliation certificate.
func restoreWith(t *testing.T, mk []func(*control.Store, *auth.Service, auth.SourceCredential, model.SourceDescriptor) (auth.Scope, model.NormalizedBatch)) (*Engine, QuotaReconciliation) {
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
	cert, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := openRestoredEngine(t, t.TempDir(), service, store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return restored, cert
}

func metricMaker(t *testing.T) func(*control.Store, *auth.Service, auth.SourceCredential, model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
	return func(s *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
		return normalized(t, s, a, c, d)
	}
}

func logMaker(t *testing.T) func(*control.Store, *auth.Service, auth.SourceCredential, model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
	return func(s *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
		return logBatch(t, s, a, c, d)
	}
}

type maker = func(*control.Store, *auth.Service, auth.SourceCredential, model.SourceDescriptor) (auth.Scope, model.NormalizedBatch)

func TestRestoreActivatesProjectWithBatchesAndNoMetricSeries(t *testing.T) {
	restored, cert := restoreWith(t, []maker{logMaker(t)})
	if len(cert.SeriesDigest) == 0 {
		t.Fatal("fixture: logs-only certificate carries no project entry")
	}
	if err := restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("logs-only restore must activate: %v", err)
	}
}

func TestRestoreActivatesMixedProject(t *testing.T) {
	restored, cert := restoreWith(t, []maker{logMaker(t), metricMaker(t)})
	if err := restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("mixed restore must activate: %v", err)
	}
}

func TestRestoreTamperedSeriesDigestStaysCorrupt(t *testing.T) {
	for name, mk := range map[string][]maker{"logs-only": {logMaker(t)}, "mixed": {logMaker(t), metricMaker(t)}, "metrics": {metricMaker(t)}} {
		t.Run(name, func(t *testing.T) {
			restored, cert := restoreWith(t, mk)
			bad := cert
			bad.SeriesDigest = map[string]model.Hash{}
			for k := range cert.SeriesDigest {
				bad.SeriesDigest[k] = model.HashCanonical([]byte("tampered"))
			}
			bad.Digest = bad.seal()
			if err := restored.CommitQuotaReconciliation(context.Background(), bad); !errors.Is(err, model.Fail(model.Corrupt)) && (err == nil || err.Error() != model.Fail(model.Corrupt).Error()) {
				t.Fatalf("tampered digest: %v, want corrupt", err)
			}
			extra := cert
			extra.SeriesDigest = map[string]model.Hash{"x:y": model.HashCanonical([]byte("phantom"))}
			for k, v := range cert.SeriesDigest {
				extra.SeriesDigest[k] = v
			}
			extra.Digest = extra.seal()
			if err := restored.CommitQuotaReconciliation(context.Background(), extra); err == nil {
				t.Fatal("phantom project digest accepted")
			}
			if restored.RestoreReady() == nil {
				t.Fatal("failed reconciliation opened intake")
			}
		})
	}
}

func TestRestoreEmptyProjectUnchanged(t *testing.T) {
	restored, cert := restoreWith(t, nil)
	if len(cert.SeriesDigest) != 0 {
		t.Fatalf("empty project certificate has %d entries", len(cert.SeriesDigest))
	}
	if err := restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("empty restore: %v", err)
	}
}

// A deletion that erases every record carrying a series must not leave the
// certificate demanding that series from the restored index.
func TestRestoreAfterErasingASeriesStillActivates(t *testing.T) {
	x := newEraseEnv(t)
	if err := x.store.BindAdmissionOwner(x.e); err != nil {
		t.Fatal(err)
	}
	x.appendRecords(model.NewID(), bothDeadlines, x.metric("gone_series", 5))
	x.appendRecords(model.NewID(), bothDeadlines, x.metric("kept_series", 500))
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
	restored, err := openRestoredEngine(t, t.TempDir(), x.a, x.store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("post-erasure restore must activate: %v", err)
	}
}

// A certificate that omits a project whose restored index holds metric series
// disagrees with the index and must stay corrupt.
func TestRestoreCertificateMissingProjectDigestStaysCorrupt(t *testing.T) {
	restored, cert := restoreWith(t, []maker{metricMaker(t)})
	bad := cert
	bad.SeriesDigest = map[string]model.Hash{}
	bad.Digest = bad.seal()
	err := restored.CommitQuotaReconciliation(context.Background(), bad)
	if err == nil || err.Error() != model.Fail(model.Corrupt).Error() {
		t.Fatalf("missing project digest: %v, want corrupt", err)
	}
}
