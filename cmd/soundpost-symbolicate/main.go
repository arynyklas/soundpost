// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/arynyklas/soundpost/internal/symbolicate"
	"os"
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
	case "--stage-worker-v1":
		os.Exit(symbolicate.StageMain(false))
	case "--stage-probe-v1":
		os.Exit(symbolicate.StageMain(true))
	default:
		os.Exit(64)
	}
}
