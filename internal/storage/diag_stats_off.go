// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !soundpost_diag

package storage

// registerDiag is the hook of a diagnostic build (diag_stats_on.go); the shipped binaries report nothing.
func (e *Engine) registerDiag(*replicatedEngine) {}
