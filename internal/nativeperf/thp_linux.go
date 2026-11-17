//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import "syscall"

// DisableTransparentHugePages opts this process out of transparent huge pages: prctl(PR_SET_THP_DISABLE, 1). The helper
// calls it as its first action, before any significant allocation, so its resident size does not depend on the host's
// THP mode (on a host with "always" the Go heap sat on 2 MiB pages and the helper held about 7.7 MB more, D53). The
// setting is per process, is inherited by children, and needs no privilege. It is the only prctl the helper makes; the
// seccomp profile allows exactly this option with this argument.
func DisableTransparentHugePages() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 41, 1, 0); errno != 0 {
		return errno
	}
	return nil
}
