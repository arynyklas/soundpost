// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package host

import (
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file is compiled and vetted for darwin but has not been run: the
// project has no macOS machine.

func newCollector() *collector {
	return &collector{now: time.Now, statfs: darwinStatfs, fsMethod: "statfs", read: darwinRead}
}

func darwinRead(c *collector, g Group, p HostPolicy) groupResult {
	switch g {
	case GroupCPU:
		// CPU tick counters need Mach host_statistics, which needs cgo.
		return failure(g, "mach_host_statistics", StatusUnsupported, ReasonRequiresCgo)
	case GroupMemory:
		return darwinMemory()
	case GroupLoad:
		return darwinLoad()
	case GroupFilesystem:
		return c.readFilesystem(p)
	case GroupProcessCount:
		return darwinProcessCount()
	}
	return osUnsupported(g, "none")
}

// loadavgFromSysctl decodes struct loadavg {uint32 ldavg[3]; long fscale}.
func loadavgFromSysctl(b []byte) ([3]float64, bool) {
	var out [3]float64
	if len(b) < 24 {
		return out, false
	}
	scale := int64(uint64(b[16]) | uint64(b[17])<<8 | uint64(b[18])<<16 | uint64(b[19])<<24 |
		uint64(b[20])<<32 | uint64(b[21])<<40 | uint64(b[22])<<48 | uint64(b[23])<<56)
	if scale <= 0 {
		return out, false
	}
	for i := range out {
		v := uint32(b[i*4]) | uint32(b[i*4+1])<<8 | uint32(b[i*4+2])<<16 | uint32(b[i*4+3])<<24
		out[i] = float64(v) / float64(scale)
	}
	return out, true
}

func darwinLoad() groupResult {
	const m = "sysctl_vm_loadavg"
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupLoad, m, s, r)
	}
	l, ok := loadavgFromSysctl(b)
	if !ok {
		return failure(GroupLoad, m, StatusUnknown, ReasonParseFailed)
	}
	return supported(GroupLoad, m,
		sample("host_load_average", "1", "gauge", l[0], "window", "1m"),
		sample("host_load_average", "1", "gauge", l[1], "window", "5m"),
		sample("host_load_average", "1", "gauge", l[2], "window", "15m"))
}

func darwinPageSize() (uint64, error) {
	if v, err := unix.SysctlUint64("hw.pagesize"); err == nil {
		return v, nil
	}
	v, err := unix.SysctlUint32("hw.pagesize")
	return uint64(v), err
}

// darwinMemory reports total and free only; there is no cgo-free "available".
func darwinMemory() groupResult {
	const m = "sysctl_hw_memsize"
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupMemory, m, s, r)
	}
	pages, err := unix.SysctlUint32("vm.page_free_count")
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupMemory, m, s, r)
	}
	ps, err := darwinPageSize()
	if err != nil || ps == 0 {
		return failure(GroupMemory, m, StatusUnknown, ReasonReadFailed)
	}
	return supported(GroupMemory, m,
		sample("host_memory_bytes", "bytes", "gauge", float64(total), "state", "total"),
		sample("host_memory_bytes", "bytes", "gauge", float64(uint64(pages)*ps), "state", "free"))
}

// darwinProcessCount uses only the length of kern.proc.all.
func darwinProcessCount() groupResult {
	const m = "sysctl_kern_proc_all"
	b, err := unix.SysctlRaw("kern.proc.all")
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupProcessCount, m, s, r)
	}
	size := int(unsafe.Sizeof(unix.KinfoProc{}))
	if size == 0 || len(b)%size != 0 {
		return failure(GroupProcessCount, m, StatusUnknown, ReasonParseFailed)
	}
	return supported(GroupProcessCount, m, sample("host_processes_total", "1", "gauge", float64(len(b)/size)))
}

func darwinStatfs(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	unit := uint64(st.Bsize)
	return fsStat{
		Size: st.Blocks * unit, Free: st.Bfree * unit, Avail: st.Bavail * unit,
		Files: st.Files, FilesFree: st.Ffree,
	}, nil
}
