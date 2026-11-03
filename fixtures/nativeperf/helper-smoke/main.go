//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"soundpost/internal/nativeperf"
	"strings"
)

func main() {
	pid := flag.Uint("target-pid", 0, "operator-authorized process leader")
	scenarios := flag.String("scenario", "authorized,denied,expired,fd-cap,cancel", "comma separated scenarios")
	requestPath := flag.String("request", "/run/soundpost-perf/smoke-request.json", "operator-supplied JSON signed request (not a signing key)")
	flag.Parse()
	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "target-pid is required")
		os.Exit(2)
	}
	f, e := os.Open(*requestPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, "operator signed fixture request is required")
		os.Exit(2)
	}
	defer f.Close()
	var base nativeperf.CaptureRequest
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&base) != nil || len(base.Targets) != 1 || base.Targets[0].TGID != uint32(*pid) {
		fmt.Fprintln(os.Stderr, "fixture request target mismatch")
		os.Exit(2)
	}
	failed := false
	for _, scenario := range strings.Split(*scenarios, ",") {
		r := base
		ctx, cancel := context.WithCancel(context.Background())
		switch scenario {
		case "authorized":
		case "denied":
			r.Authorization.Signature = nil
		case "expired":
			r.Authorization.Expires = 1
		case "fd-cap":
			r.Config.RingBytes = nativeperf.MaxMemoryBytes
		case "cancel":
			cancel()
		default:
			fmt.Fprintln(os.Stderr, "unknown fixed scenario")
			os.Exit(2)
		}
		before, _ := os.ReadDir("/proc/self/fd")
		s, e := nativeperf.OpenAuthorized(ctx, r)
		if s != nil {
			s.Close()
		}
		cancel()
		after, _ := os.ReadDir("/proc/self/fd")
		status := "denied"
		if e == nil {
			status = "opened"
		}
		var capability *nativeperf.CapabilityError
		if errors.As(e, &capability) {
			status = string(capability.Status)
		}
		if errors.Is(e, nativeperf.ErrResources) {
			status = "resource_limit"
		}
		if errors.Is(e, nativeperf.ErrAcquisitionFailed) {
			status = "acquisition_failed"
		}
		if errors.Is(e, context.Canceled) {
			status = "cancelled"
		}
		ok := len(before) == len(after)
		if scenario == "authorized" {
			ok = ok && e == nil
		} else {
			ok = ok && e != nil
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"scenario": scenario, "status": status, "fd_before": len(before), "fd_after": len(after), "passed": ok, "samples_claimed": 0})
		if !ok {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
