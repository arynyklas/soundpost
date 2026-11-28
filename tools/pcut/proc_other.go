// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

// processAlive: the power-cut drill runs on Linux only; elsewhere the pid file alone is believed.
func processAlive(pid int) bool { return pid > 0 }
