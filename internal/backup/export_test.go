// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"os"

	"github.com/arynyklas/soundpost/internal/model"
)

// ResignForTest re-authenticates a manifest a test edited, so the restore's
// content checks (not its MAC check) are what reject it.
func ResignForTest(m *BackupManifest, kek Key) error { return m.Sign(kek) }

// ControlStateForTest decrypts a backup and returns the control state it carries
// (the keys are unwrapped through the restorer's key provider, as a restore does).
func ControlStateForTest(ctx context.Context, r *Restorer, m BackupManifest) (model.ControlState, error) {
	deks, err := r.unwrap(ctx, m)
	if err != nil {
		return model.ControlState{}, err
	}
	defer func() {
		for _, k := range deks {
			clear(k)
		}
	}()
	dir, err := os.MkdirTemp("", "control-state-")
	if err != nil {
		return model.ControlState{}, err
	}
	defer os.RemoveAll(dir)
	staged, err := r.fetch(ctx, m, deks, dir)
	if err != nil {
		return model.ControlState{}, err
	}
	_, st, err := reassembleSeed(staged.controlState, staged.controlKeys)
	return st, err
}
