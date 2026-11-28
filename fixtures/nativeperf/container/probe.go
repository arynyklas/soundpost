//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// reasonNoParanoidLevel3 is the whole reason of a paranoid-level-3 scenario on a kernel the probe proved does not
// enforce that level; it is matched exactly. reasonLevel3Unknown is the distinct reason when the probe could not tell:
// that never exempts anything.
const (
	reasonNoParanoidLevel3 = "kernel_lacks_paranoid_level3"
	reasonLevel3Unknown    = "level3_probe_inconclusive"
)

type level3Outcome int

const (
	level3Enforced level3Outcome = iota
	level3NotEnforced
	level3Unknown
)

// level3Verdict decides from two unprivileged perf_event_open attempts whether this kernel enforces
// kernel.perf_event_paranoid=3. Level 3 ("perf_event_open needs CAP_SYS_ADMIN") is a Debian/Android patch, not upstream:
// a vanilla kernel accepts the value 3 and still answers like level 2. control is the attempt at level 2, at3 the
// attempt at level 3. Enforced: the attempt at 3 was refused with EACCES/EPERM while the control was allowed.
// NotEnforced (conclusive): the control at level 2 AND the attempt at level 3 both succeeded. Anything else (no control,
// control failed, unexpected errno) is Unknown.
func level3Verdict(controlKnown bool, control, at3 error) (level3Outcome, string) {
	refused := func(err error) bool { return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) }
	if controlKnown && control != nil {
		return level3Unknown, "the control attempt at level 2 failed too (" + control.Error() + "): the probe cannot tell"
	}
	if refused(at3) {
		return level3Enforced, ""
	}
	if at3 == nil {
		if !controlKnown {
			return level3Unknown, "no level-2 control attempt was made (--keep-paranoid): an allowed open at level 3 is not conclusive"
		}
		return level3NotEnforced, "an unprivileged user-space-only perf_event_open was allowed at both level 2 and kernel.perf_event_paranoid=3"
	}
	return level3Unknown, "the attempt at level 3 failed with " + at3.Error() + ", not a permission refusal"
}

// probeUnprivilegedOpen opens a user-space-only software CPU-clock event on the calling process as an unprivileged uid
// (a locked OS thread that gave up root; the thread is never unlocked, so the runtime discards it).
func probeUnprivilegedOpen() error {
	res := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESGID, 65534, 65534, 65534); e != 0 {
			res <- fmt.Errorf("setresgid: %w", e)
			return
		}
		if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESUID, 65534, 65534, 65534); e != 0 {
			res <- fmt.Errorf("setresuid: %w", e)
			return
		}
		var attr [128]byte
		*(*uint32)(unsafe.Pointer(&attr[0])) = 1                   // PERF_TYPE_SOFTWARE
		*(*uint32)(unsafe.Pointer(&attr[4])) = 128                 // size
		*(*uint64)(unsafe.Pointer(&attr[8])) = 0                   // PERF_COUNT_SW_CPU_CLOCK
		*(*uint64)(unsafe.Pointer(&attr[40])) = 1<<5 | 1<<6 | 1<<0 // disabled, exclude_kernel, exclude_hv
		fd, _, e := syscall.RawSyscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr[0])), 0, ^uintptr(0), ^uintptr(0), 0, 0)
		runtime.KeepAlive(&attr)
		if e != 0 {
			res <- e
			return
		}
		_ = syscall.Close(int(fd))
		res <- nil
	}()
	return <-res
}

// probeLevel3 measures whether the running kernel enforces perf_event_paranoid=3. It writes the sysctl only for the two
// attempts and puts the host's value back (keepParanoid: it never writes and judges the attempt at the host's own level).
func (h *harness) probeLevel3() (level3Outcome, string) {
	return level3Verdict(h.probeAttempts())
}

func (h *harness) probeAttempts() (controlKnown bool, control, at3 error) {
	if h.keepParanoid {
		return false, nil, probeUnprivilegedOpen()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	defer func() { _ = os.WriteFile(paranoidFile, []byte(strconv.Itoa(h.paranoid)), 0o644) }()
	if err := os.WriteFile(paranoidFile, []byte("2"), 0o644); err != nil {
		return true, err, nil
	}
	control = probeUnprivilegedOpen()
	if err := os.WriteFile(paranoidFile, []byte("3"), 0o644); err != nil {
		return true, control, err
	}
	return true, control, probeUnprivilegedOpen()
}
