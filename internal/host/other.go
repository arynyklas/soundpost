// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows && !darwin

package host

import "time"

func newCollector() *collector {
	return &collector{now: time.Now, fsMethod: "none", read: func(_ *collector, g Group, _ HostPolicy) groupResult {
		return osUnsupported(g, "none")
	}}
}
