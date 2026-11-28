//go:build !unix

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "os"

// fileGID: there is no POSIX group on this platform (the mode check does not apply either).
func fileGID(os.FileInfo) (uint32, bool) { return 0, false }
