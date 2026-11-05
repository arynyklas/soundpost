// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

// ResignForTest re-authenticates a manifest a test edited, so the restore's
// content checks (not its MAC check) are what reject it.
func ResignForTest(m *BackupManifest, kek Key) error { return m.Sign(kek) }
