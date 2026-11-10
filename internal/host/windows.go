// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package host

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes    = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryState = kernel32.NewProc("GlobalMemoryStatusEx")
)

func newCollector() *collector {
	return &collector{now: time.Now, statfs: windowsStatfs, fsMethod: "win32_get_disk_free_space_ex", read: windowsRead}
}

func windowsRead(c *collector, g Group, p HostPolicy) groupResult {
	switch g {
	case GroupCPU:
		return windowsCPU()
	case GroupMemory:
		return windowsMemory()
	case GroupFilesystem:
		return c.readFilesystem(p)
	case GroupProcessCount:
		return windowsProcessCount()
	case GroupLoad:
		return osUnsupported(g, "none")
	}
	return osUnsupported(g, "none")
}

func filetimeSeconds(f windows.Filetime) float64 {
	return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7
}

// windowsCPU reports cumulative system times; kernel time includes idle, so
// system is kernel minus idle.
func windowsCPU() groupResult {
	const m = "win32_system_times"
	var idle, kernel, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return failure(GroupCPU, m, StatusUnknown, ReasonReadFailed)
	}
	idleS, kernelS := filetimeSeconds(idle), filetimeSeconds(kernel)
	if kernelS < idleS {
		return failure(GroupCPU, m, StatusUnknown, ReasonParseFailed)
	}
	return supported(GroupCPU, m,
		sample("host_cpu_seconds_total", "seconds", "counter", filetimeSeconds(user), "mode", "user"),
		sample("host_cpu_seconds_total", "seconds", "counter", kernelS-idleS, "mode", "system"),
		sample("host_cpu_seconds_total", "seconds", "counter", idleS, "mode", "idle"),
		sample("host_cpu_logical_count", "1", "gauge", float64(runtime.NumCPU())))
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func windowsMemory() groupResult {
	const m = "win32_global_memory_status"
	st := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, _ := procGlobalMemoryState.Call(uintptr(unsafe.Pointer(&st)))
	if r == 0 || st.TotalPhys == 0 {
		return failure(GroupMemory, m, StatusUnknown, ReasonReadFailed)
	}
	return supported(GroupMemory, m,
		sample("host_memory_bytes", "bytes", "gauge", float64(st.TotalPhys), "state", "total"),
		sample("host_memory_bytes", "bytes", "gauge", float64(st.AvailPhys), "state", "available"))
}

// windowsProcessCount asks only for PIDs; no process is opened.
func windowsProcessCount() groupResult {
	const m = "win32_enum_processes"
	size := 1024
	for size <= 1<<22 {
		pids := make([]uint32, size)
		var needed uint32
		if err := windows.EnumProcesses(pids, &needed); err != nil {
			s, r := statusFor(err)
			return failure(GroupProcessCount, m, s, r)
		}
		if int(needed/4) < size {
			return supported(GroupProcessCount, m, sample("host_processes_total", "1", "gauge", float64(needed/4)))
		}
		size *= 2
	}
	return failure(GroupProcessCount, m, StatusUnknown, ReasonReadFailed)
}

func windowsStatfs(path string) (fsStat, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fsStat{}, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return fsStat{}, err
	}
	return fsStat{Size: total, Free: free, Avail: avail}, nil
}
