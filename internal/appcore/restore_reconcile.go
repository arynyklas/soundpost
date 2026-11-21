// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import "context"

// ReconcileRetiredArtifacts is the restore activation's artifact step (backup.Activation): a
// restore from a backup older than a retirement brings back published maps whose retention is
// already over, so they are retired again before the engine opens instead of staying readable
// until the next expiry pass (artifacts.Lifecycle.ReconcileRetired).
func (a *App) ReconcileRetiredArtifacts(ctx context.Context) (int, error) {
	return a.ArtifactLifecycle.ReconcileRetired(ctx)
}
