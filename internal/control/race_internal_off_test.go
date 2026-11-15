// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package control

// raceBuild is true when the race detector is built in (the in-package twin of raceEnabled).
const raceBuild = false
