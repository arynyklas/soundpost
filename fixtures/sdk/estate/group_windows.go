//go:build windows

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package estate

import "os/exec"

// ownProcessGroup is a no-op on Windows: the fixture's serve process is ended directly.
func ownProcessGroup(*exec.Cmd) {}

// terminateGroup ends the serve process (Windows has no process-group signal; Kill is used for both).
func terminateGroup(cmd *exec.Cmd, _ bool) { _ = cmd.Process.Kill() }
