//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	capIPCLock           = 14
	rlimitMemlock        = 8 // RLIMIT_MEMLOCK; package syscall does not export it
	defaultPerfMlockKB   = 516
	perfMlockKBPath      = "/proc/sys/kernel/perf_event_mlock_kb"
	perfEventParanoiPath = "/proc/sys/kernel/perf_event_paranoid"
	selfStatusPath       = "/proc/self/status"
)

// perfLockBytes is the most perf ring memory the kernel will let this process map: every perf ring (the data area
// plus its metadata page) is locked memory, charged first against the per-user perf_event_mlock_kb allowance (the
// kernel multiplies it by the number of online CPUs) and then against RLIMIT_MEMLOCK. When both are exhausted mmap
// fails with EPERM, which the capture would otherwise report as an opaque acquisition failure after the perf events
// were opened (measured on an 8-CPU VM at the default 8 MiB RLIMIT_MEMLOCK: the 48th ring of 256 KiB failed, so a
// 64-thread target, which needs 16.6 MiB of rings, could never be mapped). Zero means the kernel imposes no such bound
// (RLIMIT_MEMLOCK infinite, CAP_IPC_LOCK held, or perf_event_paranoid -1), or that the limits cannot be read and the
// kernel stays the judge. The figure is the kernel's linear allowance; the kernel additionally charges cumulative
// overage per mapping, so a very small RLIMIT_MEMLOCK can still refuse a mapping this bound admits (the mmap error is
// then reported as a resource limit as well).
func perfLockBytes(onlineCPUs uint64) uint64 {
	var limit syscall.Rlimit
	if syscall.Getrlimit(rlimitMemlock, &limit) != nil {
		return 0
	}
	paranoid, e := readTrimmedInt(perfEventParanoiPath)
	if e != nil || paranoid <= -1 || holdsIPCLock(selfStatusPath) {
		return 0
	}
	return lockBytesFrom(limit.Cur, readPerfMlockKB(), onlineCPUs)
}

// lockBytesFrom combines the RLIMIT_MEMLOCK soft limit with the per-user perf allowance (perfKB per online CPU are
// free, the rest must fit the rlimit). Infinity means unbounded.
func lockBytesFrom(memlock, perfKB, onlineCPUs uint64) uint64 {
	if memlock == ^uint64(0) {
		return 0
	}
	allowance := perfKB * 1024 * max(onlineCPUs, 1)
	total := memlock + allowance
	if total < memlock || perfKB != 0 && allowance/perfKB < 1024 { // overflow: effectively unbounded
		return 0
	}
	if total == 0 {
		return 1 // a zero limit and zero allowance must still refuse, not read as "unbounded"
	}
	return total
}

func readPerfMlockKB() uint64 {
	n, e := readTrimmedInt(perfMlockKBPath)
	if e != nil || n < 0 {
		return defaultPerfMlockKB
	}
	return uint64(n)
}

func readTrimmedInt(path string) (int64, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0, e
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// holdsIPCLock reports whether CAP_IPC_LOCK is in the process's effective set (it bypasses the RLIMIT_MEMLOCK check).
func holdsIPCLock(statusPath string) bool {
	b, e := os.ReadFile(statusPath)
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			v, e := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
			return e == nil && v&(1<<capIPCLock) != 0
		}
	}
	return false
}

// mmapFailure classifies a failed perf ring mmap. EPERM is the kernel refusing locked memory (RLIMIT_MEMLOCK and the
// per-user perf allowance are exhausted): a resource limit the operator can raise, not an opaque acquisition failure.
// Anything else keeps the generic event error. (The privacy audit allowlists only the reviewed errno symbols, so ENOMEM
// is deliberately not named here.)
func mmapFailure(e error) error {
	if errors.Is(e, syscall.EPERM) {
		return ErrResources
	}
	return &CapabilityError{Error, ReasonEvent}
}
