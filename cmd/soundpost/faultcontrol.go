//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
)

// startFaultControl lets a browser harness remove shards under a running server. It exists only
// in builds tagged soundpost_faults and does nothing unless SOUNDPOST_FAULT_DIR names a directory:
// a file `close-groups` there holding comma-separated data slots (0-63) is consumed, those
// replica groups are closed (internal/storage CloseDataGroupsForDrill) and the outcome is written
// to `close-groups.result` ("ok N" or "error ...").
func startFaultControl(ctx context.Context, core *appcore.App) {
	dir := os.Getenv("SOUNDPOST_FAULT_DIR")
	if dir == "" {
		return
	}
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			path := filepath.Join(dir, "close-groups")
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			_ = os.Remove(path)
			var slots []int
			result := ""
			for _, part := range strings.Split(strings.TrimSpace(string(raw)), ",") {
				n, e := strconv.Atoi(strings.TrimSpace(part))
				if e != nil {
					result = "error bad slot"
					break
				}
				slots = append(slots, n)
			}
			if result == "" {
				closed, e := core.Storage.CloseDataGroupsForDrill(slots)
				if e != nil {
					result = fmt.Sprintf("error %v", e)
				} else {
					result = fmt.Sprintf("ok %d", closed)
				}
			}
			_ = os.WriteFile(filepath.Join(dir, "close-groups.result"), []byte(result), 0o600)
		}
	}()
}
