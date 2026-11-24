// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !soundpost_diag

package control

import "github.com/arynyklas/soundpost/internal/replica"

// registerDiag is the hook of a diagnostic build (diag_stats_on.go); the shipped binaries report nothing.
func (s *Store) registerDiag(*replica.Group, string) {}
