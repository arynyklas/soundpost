//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"golang.org/x/sys/unix"
	"runtime"
)

func probeOperation(kind ProbeKind) bool {
	switch kind {
	case ProbeFile:
		fd, e := unix.Open("/etc/passwd", unix.O_RDONLY, 0)
		if e == nil {
			unix.Close(fd)
		}
		return e == unix.EPERM
	case ProbeNetwork:
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if e == nil {
			unix.Close(fd)
		}
		return e == unix.EPERM
	case ProbeExec:
		return unix.Exec("/soundpost-denied-probe", []string{"/soundpost-denied-probe"}, nil) == unix.EPERM
	case ProbeMemory:
		var blocks [][]byte
		for {
			b := make([]byte, 1<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			blocks = append(blocks, b)
			runtime.KeepAlive(blocks)
		}
	case ProbeCPU, ProbeTimeout:
		var n uint64
		for {
			n = n*1664525 + 1013904223
			if n == 0 {
				runtime.Gosched()
			}
			runtime.KeepAlive(n)
		}
	}
	return false
}
