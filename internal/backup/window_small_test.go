// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import "github.com/arynyklas/soundpost/internal/storage"

// The backup suite cuts, seals, uploads and restores with windows of three commands, so the
// bundle format's per-window evidence is exercised with many windows (summarised and detail).
func init() { storage.SetSnapshotWindow(3) }
