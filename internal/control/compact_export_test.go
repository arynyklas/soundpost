// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import bolt "go.etcd.io/bbolt"

// CopyDatabaseForTest writes a consistent copy of control.db (a read transaction's view) to path. Test only.
func (s *Store) CopyDatabaseForTest(path string) error {
	return s.db.View(func(tx *bolt.Tx) error { return tx.CopyFile(path, 0o600) })
}
