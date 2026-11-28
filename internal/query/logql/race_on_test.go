// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package logql

// The race detector multiplies CPU cost per operation (the accumulator budget of
// MaxAccumulatorRepetitions steps runs several times slower), so wall-clock bounds
// that are test choices rather than product budgets are measured and logged but not
// asserted under -race.
const raceEnabled = true
