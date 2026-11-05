// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package storage

import (
	"syscall"

	"soundpost/internal/model"
)

type statfsMeter struct{}

// StatfsMeter measures the volume holding dir with statfs(2).
func StatfsMeter() DiskMeter { return statfsMeter{} }

func (statfsMeter) Usage(dir string) (DiskUsage, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(dir, &s); err != nil {
		return DiskUsage{}, model.Fail(model.Unavailable)
	}
	total := uint64(s.Blocks) * uint64(s.Bsize)
	// Bavail is what unprivileged writers can still use; Bfree includes the root reserve.
	free := uint64(s.Bavail) * uint64(s.Bsize)
	if free > total {
		free = total
	}
	return DiskUsage{TotalBytes: total, UsedBytes: total - free}, nil
}
