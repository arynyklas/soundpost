// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

// The whole storage suite runs with windows of four commands, so every cut, install, evidence and
// restore test of the package exercises many windows (sealed, open and the boundary between them)
// instead of the single open window a production-sized window leaves a small test history in.
func init() { snapshotWindow = 4 }

// setMeasureWindow is the one call TestMeasureCutAndBackup needs that has no counterpart before the
// windowed format; the tree before it defines a no-op under this name.
func setMeasureWindow(n uint64) { snapshotWindow = n }
