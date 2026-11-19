//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// burner is the CPU-burning workload the native-helper container smoke profiles (tools/smoke/native_helper_container.go).
// It is a static, non-PIE Go executable with a GNU build ID (go build -ldflags "-B gobuildid"), so the operator policy can
// name it. One goroutine spins in soundpostHotLoop, which is the symbol the smoke expects the helper's samples to land in.
// It starts no thread after "ready": GOMAXPROCS is 1, the loop allocates nothing (no collection), and every runtime thread
// exists before "ready" is printed, because the helper ends a capture whose target creates or exits a thread.
package main

import (
	"os"
	"runtime"
	"time"
)

var sink uint64

//go:noinline
func soundpostHotLoop(value uint64) uint64 {
	for i := uint64(0); i < 100000; i++ {
		value ^= value << 7
		value ^= value >> 9
		value = value*6364136223846793005 + i
	}
	return value
}

func main() {
	runtime.GOMAXPROCS(1)
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		os.Exit(3)
	}
	value := uint64(7)
	for {
		value = soundpostHotLoop(value)
		sink = value
	}
}
