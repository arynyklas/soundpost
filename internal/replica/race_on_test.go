// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package replica

// raceEnabled reports whether the test binary carries the race detector, which slows every goroutine several times
// over: a test that loads a group's lock with many proposers sees its tick wait for seconds.
const raceEnabled = true
