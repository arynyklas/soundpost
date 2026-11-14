//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"os"

	"golang.org/x/sys/unix"
)

// DropCachedPages asks the kernel to forget the clean cached pages of f, so the next read comes
// from the device. After a failed fsync the kernel marks the pages it could not write clean and
// keeps serving their content from memory: a process that restarts and reads the file is then
// shown bytes that may not be on the device at all. Dropping the clean pages first makes the
// journal verification read what the device holds. Pages still dirty stay (they are written
// back, and the sync that follows the verification fails if they cannot be). It is advice: an
// error is not a verification failure and is ignored, the verification itself decides.
func DropCachedPages(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
