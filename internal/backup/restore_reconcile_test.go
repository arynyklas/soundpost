// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"context"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// stepRecorder is the restored side's activation with every step it takes written down in order, and
// the artifact reconciliation answering what the test says.
type stepRecorder struct {
	activation
	steps     *[]string
	retired   int
	reconcile error
}

func (s stepRecorder) RestoreDeletions(ctx context.Context, authority retention.Authority) error {
	*s.steps = append(*s.steps, "deletions")
	return s.activation.RestoreDeletions(ctx, authority)
}

func (s stepRecorder) ReconcileRetiredArtifacts(context.Context) (int, error) {
	*s.steps = append(*s.steps, "reconcile")
	return s.retired, s.reconcile
}

func (s stepRecorder) RestoreReady() error {
	*s.steps = append(*s.steps, "ready")
	return s.activation.RestoreReady()
}

func (l *live) activateRecording(t *testing.T, r *restored, retired int, reconcile error) ([]string, error, int) {
	t.Helper()
	var steps []string
	report, err := l.restorer(l.keys, l.dest).Activate(l.ctx, backup.DestinationRoot(r.root), stepRecorder{activation: activation{Engine: r.app.Storage, svc: r.svc, reconcile: r.app.ArtifactLifecycle.ReconcileRetired}, steps: &steps, retired: retired, reconcile: reconcile}, l.authority)
	return steps, err, report.ArtifactsRetired
}

// Restore activation retires, in the restored control state, every map whose retention is over
// (a backup older than the retirement brings the published intent back) after the deletions are
// restored and before the installation is declared ready; the count reaches the report the
// operator reads, and a failure of the step fails the activation before it is ready (review F-4 of
// the root pin sweep: deleting the call, or reordering it past RestoreReady, left the suite green).
func TestActivationRetiresLapsedArtifactsAfterDeletionsAndBeforeReady(t *testing.T) {
	l := newLiveWith(t, true)
	l.append(100, "kept")
	l.reconcile()
	before := l.mustBackup()
	root := l.newRoot()
	if _, err := l.restoreTo(root, before, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	steps, err, retired := l.activateRecording(t, r, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"deletions", "reconcile", "ready"}; !slices.Equal(steps, want) {
		t.Fatalf("activation steps %v, want %v", steps, want)
	}
	if retired != 7 {
		t.Fatalf("the report says %d artifacts retired, the step retired 7", retired)
	}
}

func TestAFailedArtifactReconciliationFailsTheActivationBeforeReady(t *testing.T) {
	l := newLiveWith(t, true)
	l.append(100, "kept")
	l.reconcile()
	before := l.mustBackup()
	root := l.newRoot()
	if _, err := l.restoreTo(root, before, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	boom := model.Fail(model.Unavailable)
	steps, err, _ := l.activateRecording(t, r, 0, boom)
	if code(err) != model.Unavailable {
		t.Fatalf("activation answered %v for a failed reconciliation, want the step's own failure", err)
	}
	if want := []string{"deletions", "reconcile"}; !slices.Equal(steps, want) {
		t.Fatalf("activation steps %v after a failed reconciliation, want %v (the installation must not be ready)", steps, want)
	}
}
