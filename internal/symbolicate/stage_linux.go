//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

// StageMain is the staging half of a launch without clone3. It does nothing before it
// blocks on descriptor 3, the release pipe: no input is read, no file opened, no
// sandbox state touched. The parent moves this process into the limited cgroup and
// writes one 'G'; only then does it replace itself, through /proc/self/exe (the very
// image that was started, never a path looked up again), with the worker or probe
// vector. A closed pipe without the byte (parent gone or the launch aborted) or the
// ordinary five-second process bound ends it without running anything.
func StageMain(probe bool) int {
	time.AfterFunc(ProcessTimeout, func() { os.Exit(124) })
	release := os.NewFile(3, "release")
	if release == nil {
		return 70
	}
	var b [1]byte
	if _, e := io.ReadFull(release, b[:]); e != nil || b[0] != 'G' {
		return 70
	}
	release.Close()
	if markCloseOnExec() != nil {
		return 70
	}
	arg := workerArg
	if probe {
		arg = probeArg
	}
	syscall.Exec("/proc/self/exe", []string{os.Args[0], arg}, syscall.Environ())
	return 70
}

const (
	sysCloseRange     = 436 // the same number on amd64 and arm64
	closeRangeCloexec = 4   // CLOSE_RANGE_CLOEXEC
)

// markCloseOnExec makes every descriptor from 3 up close-on-exec, so the worker image
// starts with stdio only: whatever the parent left without close-on-exec (it is the
// parent's, not the worker's) vanishes at the exec. It marks instead of closing, so
// this process's own runtime keeps working until the exec itself. Without close_range
// (or when a filter refuses it) each /proc/self/fd entry is marked one by one; if
// neither works the launch fails rather than exec with inherited descriptors.
func markCloseOnExec() error {
	if _, _, e := syscall.RawSyscall(sysCloseRange, 3, uintptr(^uint32(0)), closeRangeCloexec); e == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil || n < 3 {
			continue
		}
		syscall.CloseOnExec(n) // the directory's own descriptor is already closed here; EBADF is fine
	}
	return nil
}
