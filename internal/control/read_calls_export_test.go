// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// ReadCallsForTest is how many ReadIndex rounds this voter's control group answered for its readers.
func (s *Store) ReadCallsForTest() uint64 { return s.repl.group.ReadCalls() }
