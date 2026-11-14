//go:build !linux || (!amd64 && !arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

// StageMain: there is no native sandbox on this platform, so there is nothing to stage.
func StageMain(bool) int { return 70 }
