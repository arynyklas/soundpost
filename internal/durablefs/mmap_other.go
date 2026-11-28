//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

// BoltInitialMmapSize is 0 off Linux: bolt extends the file to the size of the mapping on Windows, and the bolt files are not mapped
// ahead anywhere else the product does not run its gate (see mmap_linux.go).
const BoltInitialMmapSize = 0
