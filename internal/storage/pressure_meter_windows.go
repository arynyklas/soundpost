// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package storage

import (
	"golang.org/x/sys/windows"

	"github.com/arynyklas/soundpost/internal/model"
)

type windowsMeter struct{}

// HostMeter measures the volume holding dir with GetDiskFreeSpaceExW. The free
// figure is the space available to the calling user (quota-aware), matching
// what statfs reports as available to unprivileged writers on Unix.
func HostMeter() DiskMeter { return windowsMeter{} }

func (windowsMeter) Usage(dir string) (DiskUsage, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return DiskUsage{}, model.Fail(model.Unavailable)
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err != nil {
		return DiskUsage{}, model.Fail(model.Unavailable)
	}
	if avail > total {
		avail = total
	}
	return DiskUsage{TotalBytes: total, UsedBytes: total - avail}, nil
}
