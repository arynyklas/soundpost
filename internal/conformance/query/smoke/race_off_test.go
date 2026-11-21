//go:build !race

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

// raceEnabled reports whether the test binary carries the race detector, which
// slows the scenarios several fold and so changes wall-clock harness timings.
const raceEnabled = false
