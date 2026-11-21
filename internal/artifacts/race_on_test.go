// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package artifacts

// The race detector inflates allocation counters, so exact allocation bounds
// are not asserted under -race.
const raceEnabled = true
