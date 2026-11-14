//go:build unix

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package estate

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the serve process in its own process group so Stop ends it and its children together.
func ownProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// terminateGroup sends SIGTERM (or SIGKILL when kill is set) to the serve process group.
func terminateGroup(cmd *exec.Cmd, kill bool) {
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	_ = syscall.Kill(-cmd.Process.Pid, sig)
}
