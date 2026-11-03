// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"soundpost/internal/nativeperf"
)

func main() {
	only := flag.Bool("probe-only", false, "probe without acquisition")
	pid := flag.Int("target-pid", 0, "authorized local process ID")
	flag.Parse()
	if !*only || *pid <= 0 {
		fmt.Fprintln(os.Stderr, "require --probe-only --target-pid with an authorized local PID")
		os.Exit(2)
	}
	var targets []nativeperf.Target
	if runtime.GOOS == "linux" {
		target, err := nativeperf.ResolveLocalTarget(*pid)
		if err != nil {
			fmt.Fprintln(os.Stderr, "target identity unavailable")
			os.Exit(1)
		}
		targets = []nativeperf.Target{target}
	}
	caps, err := nativeperf.Probe(context.Background(), targets)
	if caps.Validate() != nil {
		fmt.Fprintln(os.Stderr, "invalid capability evidence")
		os.Exit(1)
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(struct {
		Capabilities   nativeperf.Capabilities `json:"capabilities"`
		SamplesClaimed int                     `json:"samples_claimed"`
	}{Capabilities: caps}); encodeErr != nil {
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
