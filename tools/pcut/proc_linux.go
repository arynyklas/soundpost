// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import "syscall"

// processAlive reports whether a process with this id exists.
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
