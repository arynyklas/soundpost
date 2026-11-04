// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"soundpost/internal/symbolicate"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(64)
	}
	switch os.Args[1] {
	case "--worker-v1":
		os.Exit(symbolicate.WorkerMain())
	case "--probe-v1":
		os.Exit(symbolicate.ProbeMain())
	default:
		os.Exit(64)
	}
}
