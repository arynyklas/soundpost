// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package httpapi_test

// The race detector slows the export pipeline about 30 times (measured: a busy-project export round
// takes 1.2-2.1 s without it and 36-50 s idle with it), so a wall-clock liveness budget is scaled
// with it; the test still fails on a hang.
const raceEnabled = true
