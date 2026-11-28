// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !soundpost_diag

package storage

import "sync"

// engineMu is Engine.mu: a plain mutex. A diagnostic build counts how long it is held and waited for (engine_mu_on.go).
type engineMu = sync.Mutex
