//go:build !linux || (!amd64 && !arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"errors"
	"os/exec"
)

func installSandbox() error { return errors.New("required Linux sandbox unavailable") }

type nativeGroup struct{}

func newNativeGroup(string) (*nativeGroup, error) {
	return nil, errors.New("required Linux cgroup sandbox unavailable")
}
func (*nativeGroup) configure(*exec.Cmd) error { return errors.New("unsupported sandbox") }
func (*nativeGroup) attach(int) error          { return errors.New("unsupported sandbox") }
func (*nativeGroup) cleanup()                  {}
func (*nativeGroup) oom() bool                 { return false }
