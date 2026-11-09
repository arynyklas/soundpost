// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !freebsd && !windows

package storage

// HostMeter is nil on platforms with no volume-usage API wired in. The caller
// binds the engine with BindPressureUnmetered, which admits intake and says so
// in PressureStatus, instead of failing every admission for a meter that can
// never answer.
func HostMeter() DiskMeter { return nil }
