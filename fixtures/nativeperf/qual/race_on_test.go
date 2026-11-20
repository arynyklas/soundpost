//go:build race

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

// raceDetectorOn is what the tests expect raceBuild to say: it comes from the build tag of this file, not from the constant under test.
const raceDetectorOn = true
