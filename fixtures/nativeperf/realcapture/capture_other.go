//go:build !linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package realcapture

import "context"

// BuildWorkload: native acquisition exists on Linux only (D10).
func BuildWorkload(ctx context.Context, source, dir string) (string, error) {
	return "", cannot("native acquisition is Linux only")
}

// Capture: native acquisition exists on Linux only (D10).
func Capture(ctx context.Context, req Request) (Result, error) {
	return Result{}, cannot("native acquisition is Linux only")
}
