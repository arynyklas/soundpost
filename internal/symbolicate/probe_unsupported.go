//go:build !linux || (!amd64 && !arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

func probeOperation(ProbeKind) bool { return false }
