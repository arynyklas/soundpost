// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package query

// The race detector multiplies CPU cost per operation, so stated CPU budgets
// are measured and logged but not asserted under -race.
const raceEnabled = true
