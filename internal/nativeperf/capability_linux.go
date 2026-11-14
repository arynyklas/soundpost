//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Independently authored from perf_event_open(2). Size 64 is VER0;
// this disabled open does not acquire or persist any ring/sample bytes.
type perfProbeAttr struct {
	Type       uint32
	Size       uint32
	Config     uint64
	Frequency  uint64
	SampleType uint64
	ReadFormat uint64
	Flags      uint64
	Wakeup     uint32
	BPType     uint32
	Config1    uint64
}

func probeOpen(typ uint32, config uint64, pid, cpu int) error {
	a := perfProbeAttr{Type: typ, Size: 64, Config: config, Frequency: 99, SampleType: 1 | 2 | 4 | 32, Flags: 1 | 1<<5 | 1<<6 | 1<<10}
	if typ == 2 {
		a.Frequency = 1
		a.SampleType = 4
		a.Flags = 1
	}
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&a)), uintptr(pid), uintptr(cpu), ^uintptr(0), 8, 0)
	if errno != 0 {
		return errno
	}
	return syscall.Close(int(fd))
}
func probeStatus(err error) (Status, Reason) {
	if err == nil {
		return Supported, ""
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return Denied, ReasonPermission
	}
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.EINVAL) {
		return Unsupported, ReasonEvent
	}
	return Error, ReasonEvent
}
func Probe(ctx context.Context, targets []Target) (Capabilities, error) {
	c := Capabilities{Arch: runtime.GOARCH, Config: "unmeasured", CPU: Unsupported, OffCPU: Unsupported, RunqueueSplit: Unsupported, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, Reasons: []Reason{ReasonUnmeasured}}
	c.Permissions.CPUEventOpen = Unsupported
	c.Permissions.SchedulerEventOpen = Unsupported
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if err := validateTargets(targets); err != nil {
		return c, err
	}
	if b, e := os.ReadFile("/proc/sys/kernel/osrelease"); e == nil {
		c.Kernel = strings.TrimSpace(string(b))
	}
	if b, e := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); e == nil {
		if n, e := strconv.Atoi(strings.TrimSpace(string(b))); e == nil {
			c.Permissions.PerfEventParanoid = &n
		}
	}
	if b, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				c.Permissions.EffectiveCapabilities = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			}
		}
	}
	c.CPU = Supported
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		if t.CgroupID != 0 {
			c.CPU = Unsupported
			c.Reasons = append(c.Reasons, ReasonAcquisition)
			return c, &CapabilityError{Unsupported, ReasonAcquisition}
		}
		actual, e := ResolveLocalTarget(int(t.TGID))
		if e != nil || actual.PIDNamespace != t.PIDNamespace || actual.ProcessStart != t.ProcessStart {
			return c, ErrInvalid
		}
		s, r := probeStatus(probeOpen(1, 0, int(t.TGID), -1))
		if s != Supported {
			c.CPU = s
			c.Reasons = append(c.Reasons, r)
			break
		}
	}
	c.Permissions.CPUEventOpen = c.CPU
	c.OffCPU = Supported
	if !schedulerPIDsAttributable() {
		// Tracepoint records carry init-namespace PIDs; outside the initial PID
		// namespace no authorized task can ever match, so a session would
		// succeed and stay empty. Report it instead of a false capability.
		c.OffCPU = Unsupported
		c.Reasons = append(c.Reasons, ReasonEvent)
	}
	for _, event := range []string{"sched_switch", "sched_wakeup", "sched_wakeup_new"} {
		if c.OffCPU != Supported {
			break
		}
		if err := ctx.Err(); err != nil {
			return c, err
		}
		id, e := tracepointID(event)
		if e != nil {
			c.OffCPU = Unsupported
			c.Reasons = append(c.Reasons, ReasonTraceFS)
			break
		}
		s, r := probeStatus(probeOpen(2, id, -1, 0))
		if s != Supported {
			c.OffCPU = s
			c.Reasons = append(c.Reasons, r)
			break
		}
	}
	c.Permissions.SchedulerEventOpen = c.OffCPU
	c.RunqueueSplit = Unsupported
	c.Reasons = append(c.Reasons, ReasonAcquisition)
	// Even successful opens do not prove correlation or actual frame/thread coverage.
	if c.CPU != Supported {
		return c, &CapabilityError{c.CPU, reasonFor(c.CPU)}
	}
	if c.OffCPU != Supported {
		return c, &CapabilityError{c.OffCPU, reasonFor(c.OffCPU)}
	}
	return c, nil
}
func reasonFor(s Status) Reason {
	if s == Denied {
		return ReasonPermission
	}
	return ReasonEvent
}
func tracepointID(event string) (uint64, error) {
	for _, root := range []string{"/sys/kernel/tracing/events/sched/", "/sys/kernel/debug/tracing/events/sched/"} {
		b, e := os.ReadFile(root + event + "/id")
		if e != nil {
			continue
		}
		id, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if e == nil && id > 0 {
			return id, nil
		}
	}
	return 0, ErrInvalid
}
func Open(ctx context.Context, targets []Target, cfg Config) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return openLocalSession(ctx, targets, cfg)
}

// ResolveLocalTarget reads identity metadata only, never process memory or command
// content. stat's comm field is skipped in place and never exported or logged.
// Linux amd64/arm64 expose /proc starttime in USER_HZ=100 ticks.
func ResolveLocalTarget(pid int) (Target, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return Target{}, ErrInvalid
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return Target{}, &CapabilityError{Unsupported, ReasonPlatform}
	}
	base := "/proc/" + strconv.Itoa(pid)
	link, e := os.Readlink(base + "/ns/pid")
	if e != nil {
		if d := permissionDenied(e); d != nil {
			return Target{}, d
		}
		return Target{}, ErrInvalid
	}
	if !strings.HasPrefix(link, "pid:[") || !strings.HasSuffix(link, "]") {
		return Target{}, ErrInvalid
	}
	ns, e := strconv.ParseUint(link[5:len(link)-1], 10, 64)
	if e != nil {
		return Target{}, ErrInvalid
	}
	b, e := os.ReadFile(base + "/stat")
	if e != nil {
		if d := permissionDenied(e); d != nil {
			return Target{}, d
		}
		return Target{}, ErrInvalid
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return Target{}, ErrInvalid
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return Target{}, ErrInvalid
	}
	ticks, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil || ticks == 0 || ticks > ^uint64(0)/10000000 {
		return Target{}, ErrInvalid
	}
	status, e := os.ReadFile(base + "/status")
	if e != nil {
		return Target{}, ErrInvalid
	}
	tgid := uint64(0)
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			tgid, e = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")), 10, 32)
			if e != nil {
				return Target{}, ErrInvalid
			}
		}
	}
	if tgid != uint64(pid) {
		return Target{}, fmt.Errorf("%w: target must be a process leader", ErrInvalid)
	}
	t := Target{PIDNamespace: model.Uint64(ns), TGID: uint32(tgid), ProcessStart: model.MonoNano(ticks * 10000000)}
	return t, t.Validate()
}

// initPIDNamespaceInode is PROC_PID_INIT_INO, the inode of the initial PID namespace.
const initPIDNamespaceInode = 0xEFFFFFFC

// schedulerPIDsAttributable reports whether this process runs in the initial
// PID namespace, the only one in which sched_switch/sched_wakeup raw PIDs equal
// the PIDs of the authorized targets.
func schedulerPIDsAttributable() bool {
	info, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Ino == initPIDNamespaceInode
}

// permissionDenied maps EACCES/EPERM to the typed permission denial, so a target
// the caller may not inspect is never reported as an identity or generation change.
func permissionDenied(err error) error {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return &CapabilityError{Denied, ReasonPermission}
	}
	return nil
}
