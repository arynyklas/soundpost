//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"io"
	"os"
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
	arg := workerArg
	if probe {
		arg = probeArg
	}
	syscall.Exec("/proc/self/exe", []string{os.Args[0], arg}, syscall.Environ())
	return 70
}
