// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package storage

import "soundpost/internal/model"

type statfsMeter struct{}

// StatfsMeter has no implementation on this platform; every sample fails, so
// a bound engine fails closed instead of guessing.
func StatfsMeter() DiskMeter { return statfsMeter{} }

func (statfsMeter) Usage(string) (DiskUsage, error) {
	return DiskUsage{}, model.Fail(model.Unsupported)
}
