// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//go:build race

package appcore_test

// The race detector slows the parse of a 40000-symbol object past the 100 ms wall-clock bound of one artifact read
// (nativeperf.readFrameArtifact, pinned by nativeperf's timing tests), so a test that needs such an object read in
// full cannot hold under it; it runs in every build without the detector.
const raceEnabled = true
