// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package host

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func newCollector() *collector {
	return &collector{
		procRoot:  "/proc",
		sysRoot:   "/sys",
		statfs:    linuxStatfs,
		isCgroup2: linuxIsCgroup2,
		exempt:    linuxProcExempt,
		now:       time.Now,
		fsMethod:  "statfs",
		read:      procfsRead,
	}
}

// linuxStatfs converts block counts using f_frsize (the unit statvfs uses),
// falling back to f_bsize on filesystems that do not report it.
func linuxStatfs(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	unit := uint64(st.Frsize)
	if unit == 0 {
		unit = uint64(st.Bsize)
	}
	return fsStat{
		Size:      uint64(st.Blocks) * unit,
		Free:      uint64(st.Bfree) * unit,
		Avail:     uint64(st.Bavail) * unit,
		Files:     uint64(st.Files),
		FilesFree: uint64(st.Ffree),
	}, nil
}

func linuxIsCgroup2(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}
	return int64(st.Type) == int64(unix.CGROUP2_SUPER_MAGIC), nil
}

// linuxProcExempt is true for root (CAP_SYS_PTRACE is assumed) and for members
// of the hidepid exemption group. A root agent without CAP_SYS_PTRACE inside a
// container can still see a partial list; the doc states this limit.
func linuxProcExempt(gid int, hasGID bool) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if !hasGID {
		return false
	}
	if os.Getegid() == gid {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}
