// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
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

// twoSeriesMaker builds a batch of two metric records of different names: it
// charges two series, so a forged Retained set can be a wrong NON-EMPTY subset
// of what the batch really holds (the one-series makers cannot express that).
func twoSeriesMaker(t *testing.T) maker {
	return func(store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
		t.Helper()
		ctx := context.Background()
		scope, err := a.SourceScope(ctx, c, false)
		if err != nil {
			t.Fatal(err)
		}
		src, err := a.SourceAuthority(ctx, c, true)
		if err != nil {
			t.Fatal(err)
		}
		resource := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
		record := func(name string) model.Record {
			return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}
		}
		// A batch is routed to one owner slot by its records' owner key (metric name
		// and labels, which is also the series identity), so two series in one batch
		// need two names whose slots collide: search for one.
		producer := model.NewID()
		first := record("requests")
		wantSlot, err := model.OwnerSlot(d.Org, d.Project, d.Source, producer, first)
		if err != nil {
			t.Fatal(err)
		}
		var second model.Record
		for i := 0; ; i++ {
			second = record(fmt.Sprintf("errors_%d", i))
			if slot, serr := model.OwnerSlot(d.Org, d.Project, d.Source, producer, second); serr != nil {
				t.Fatal(serr)
			} else if slot == wantSlot {
				break
			}
			if i > 100000 {
				t.Fatal("no second metric name routes to the first one's slot")
			}
		}
		b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: producer, ID: model.NewID(), PolicyRevision: src.Policy.Revision, Records: []model.Record{first, second}, RouteSlot: wantSlot}
		raw := mustJSON(t, b)
		n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(mustJSON(t, src.Policy)).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
		if n.Reservation, err = store.ReserveAdmission(ctx, scope, n); err != nil {
			t.Fatal(err)
		}
		if len(n.Reservation.Series) != 2 {
			t.Fatalf("setup: want a two-series charge, got %v", n.Reservation.Series)
		}
		return scope, n
	}
}

// forgeryRig is one sealed backup of a single two-series batch, with the
// control store it was taken from, so each case forges the SAME genuine bundle.
type forgeryRig struct {
	store   *control.Store
	service *auth.Service
	sealed  SealedBackup
	genuine QuotaReconciliation
	charged string // chargedState of the control store after the backup was sealed
}

func newForgeryRig(t *testing.T) forgeryRig {
	t.Helper()
	store, service, credential, descriptor := typedFixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	scope, b := twoSeriesMaker(t)(store, service, credential, descriptor)
	if _, err = engine.Append(context.Background(), scope, b); err != nil {
		t.Fatal(err)
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
	genuine, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	// A bundle of an unerased batch lists no reservation (its window is not Detail: control's cut
	// holds the consumed row and the window's charge digest proves it), so a forged Retained set
	// has to make the window Detail and list the reservation itself; forge does exactly that.
	if sealed.Bundle.Version != 2 || len(sealed.Bundle.Quota.Consumed) != 0 || len(sealed.Bundle.Cut.Reservations) != 1 {
		t.Fatalf("setup: want a version 2 bundle with one consumed reservation in the cut and none listed, got version %d, %d listed, %d in the cut", sealed.Bundle.Version, len(sealed.Bundle.Quota.Consumed), len(sealed.Bundle.Cut.Reservations))
	}
	for _, held := range sealed.Bundle.Cut.Reservations {
		if held.State != "consumed" || held.Cursor == nil || len(held.Series) != 2 {
			t.Fatalf("setup: want one consumed two-series reservation with a cursor, got %+v", held)
		}
	}
	return forgeryRig{store: store, service: service, sealed: sealed, genuine: genuine, charged: chargedState(t, store)}
}

// forge returns the genuine bundle in which the window of the one consumed batch is Detail and
// lists that batch's reservation evidence, with f applied to it, resealed with valid digests (a
// forgery any weaker stops at a digest check). The listing is what a bundle of an erased batch
// carries; the Series, bytes, hash and cursor stay the genuine ones, so the window's charge digest
// still matches and only the Redacted/Retained claim is false.
func (r forgeryRig) forge(f func(*ReservationEvidence)) BackupBundle {
	forged := r.sealed.Bundle
	forged.Quota.Windows = append([]WindowEvidence(nil), forged.Quota.Windows...)
	forged.Quota.Consumed = []ReservationEvidence{}
	for _, held := range forged.Cut.Reservations {
		ev := ReservationEvidence{ID: held.ID, Org: held.Org, Project: held.Project, Source: held.Source, Hash: held.Hash, Bytes: held.Bytes, Series: append([]string(nil), held.Series...), Cursor: *held.Cursor}
		f(&ev)
		forged.Quota.Consumed = append(forged.Quota.Consumed, ev)
		for i := range forged.Quota.Windows {
			if w := &forged.Quota.Windows[i]; w.Group == ev.Cursor.Group && (uint64(ev.Cursor.Index)-1)/w.Span == w.N {
				w.Detail = true
			}
		}
	}
	forged.Quota.Digest = forged.Quota.seal()
	forged.Digest = forged.seal()
	return forged
}

// install installs bundle's evidence with the genuine snapshots into dir.
func (r forgeryRig) install(t *testing.T, dir string, bundle BackupBundle) (*Engine, error) {
	t.Helper()
	return openRestoredEngine(t, dir, r.service, r.store, bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, r.sealed.Snapshots[slot]))), nil
		})
	})
}

// forgedRetained are the two Retained forgeries of an UNERASED two-series batch
// that the one-series cases in TestRestoreForgedRedactionEvidenceStaysCorrupt
// cannot express.
var forgedRetained = map[string]func(*ReservationEvidence){
	// the Redacted flag with no Retained set, and with an empty one: nothing is claimed to remain
	"redacted flag without a retained set": func(ev *ReservationEvidence) { ev.Redacted, ev.Retained = true, nil },
	"redacted flag with an empty retained set": func(ev *ReservationEvidence) {
		ev.Redacted, ev.Retained = true, []string{}
	},
	// the Retained set ADDS a series that is not in the charged Series set
	"retained adds a series outside the charged set": func(ev *ReservationEvidence) {
		ev.Redacted = true
		ev.Retained = append(append([]string(nil), ev.Series...), "forged-series-not-charged")
		sort.Strings(ev.Retained)
	},
	// the Retained set is a wrong non-empty subset of the series the batch really holds
	"retained is a wrong non-empty subset": func(ev *ReservationEvidence) {
		ev.Redacted = true
		ev.Retained = append([]string(nil), ev.Series[:1]...)
	},
}

// Layer 1: the install. ReconcileQuota ACCEPTS the forged evidence (it never
// compares Retained with Series, and the digests are valid), so the refusal
// comes from InstallBackup re-deriving the evidence from the installed snapshot
// bytes and comparing digests: a typed Corrupt, an engine that was never
// returned, a restore-pending marker left armed (a restart stays closed), no
// reconciliation certificate, and no charge moved in control.
func TestForgedRetainedSetIsRefusedByTheInstall(t *testing.T) {
	rig := newForgeryRig(t)
	for name, forge := range forgedRetained {
		t.Run(name, func(t *testing.T) {
			forged := rig.forge(forge)
			cert, err := ReconcileQuota(forged)
			if err != nil {
				t.Fatalf("the reconciliation layer was expected to accept the forged evidence (it is the install that refuses): %v", err)
			}
			if sameDigests(cert.SeriesDigest, rig.genuine.SeriesDigest) {
				t.Fatal("the forgery did not change the certificate: this test no longer exercises the relaxation")
			}
			dir := t.TempDir()
			restored, err := rig.install(t, dir, forged)
			if !isCorrupt(err) {
				t.Fatalf("install of forged Retained evidence: %v, want corrupt", err)
			}
			if restored != nil {
				t.Fatal("a refused install returned an engine")
			}
			if marker, rerr := os.ReadFile(filepath.Join(dir, restorePendingFile)); rerr != nil || strings.TrimSpace(string(marker)) != forged.Digest.String() {
				t.Fatalf("the restore-pending marker is not armed for the refused bundle: %v", rerr)
			}
			if _, serr := os.Stat(filepath.Join(dir, quotaCertFile)); !os.IsNotExist(serr) {
				t.Fatalf("a reconciliation certificate exists after a refused install: %v", serr)
			}
			if got := chargedState(t, rig.store); got != rig.charged {
				t.Fatalf("a refused install moved control's charge:\nbefore %s\nafter  %s", rig.charged, got)
			}
		})
	}
}

// Layer 2: CommitQuotaReconciliation, reached when the install's evidence check
// is not in the way (the GENUINE bundle is installed, so the restore-pending
// marker names it). A certificate computed from the forged evidence is refused as
// Corrupt twice over: bound to the forged backup it does not match the marker;
// re-bound to the installed backup (and resealed) its series digest does not
// match the series the restored project index really holds. Neither writes a
// certificate or opens intake, and the genuine certificate still activates the
// same engine afterwards (the refusals are not destructive and are due to the forgery).
func TestForgedRetainedCertificateIsRefusedByCommit(t *testing.T) {
	for name, forge := range forgedRetained {
		t.Run(name, func(t *testing.T) {
			rig := newForgeryRig(t)
			forged := rig.forge(forge)
			restored, err := rig.install(t, t.TempDir(), rig.sealed.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := ReconcileQuota(forged)
			if err != nil {
				t.Fatal(err)
			}
			if sameDigests(cert.SeriesDigest, rig.genuine.SeriesDigest) {
				t.Fatal("the forgery did not change the certificate: this test no longer exercises the cross-check")
			}
			refused := func(label string, c QuotaReconciliation) {
				t.Helper()
				if err := restored.CommitQuotaReconciliation(context.Background(), c); !isCorrupt(err) {
					t.Fatalf("%s: %v, want corrupt", label, err)
				}
				if !restored.snap.hold.Load() {
					t.Fatalf("%s: a forged reconciliation opened intake", label)
				}
				if _, serr := os.Stat(filepath.Join(restored.dir, quotaCertFile)); !os.IsNotExist(serr) {
					t.Fatalf("%s: a certificate was persisted: %v", label, serr)
				}
			}
			refused("certificate bound to the forged backup", cert)
			cert.Backup = rig.genuine.Backup
			cert.Digest = cert.seal()
			refused("certificate re-bound to the installed backup (series cross-check)", cert)
			if got := chargedState(t, rig.store); got != rig.charged {
				t.Fatalf("a refused commit moved control's charge:\nbefore %s\nafter  %s", rig.charged, got)
			}
			if err = restored.CommitQuotaReconciliation(context.Background(), rig.genuine); err != nil {
				t.Fatalf("the genuine certificate no longer activates the engine after the refusals: %v", err)
			}
			// (RestoreReady also waits for the deletion gate, which CommitQuotaReconciliation does
			// not own; the quota hold is the part it clears.)
			if restored.snap.hold.Load() {
				t.Fatal("the genuine certificate did not release the restore-quota hold")
			}
			if _, serr := os.Stat(filepath.Join(restored.dir, quotaCertFile)); serr != nil {
				t.Fatalf("the genuine certificate was not persisted: %v", serr)
			}
			if _, serr := os.Stat(filepath.Join(restored.dir, restorePendingFile)); !os.IsNotExist(serr) {
				t.Fatalf("the restore-pending marker survived the genuine certificate: %v", serr)
			}
		})
	}
}
