//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const sysfsCPU = "/sys/devices/system/cpu"

// formatCPUList renders a CPU set the way the kernel prints /sys/devices/system/cpu/online ("0-7", "0-2,4").
func formatCPUList(cpus []uint32) string {
	var b strings.Builder
	for i := 0; i < len(cpus); {
		j := i
		for j+1 < len(cpus) && cpus[j+1] == cpus[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if j == i {
			fmt.Fprintf(&b, "%d", cpus[i])
		} else {
			fmt.Fprintf(&b, "%d-%d", cpus[i], cpus[j])
		}
		i = j + 1
	}
	return b.String()
}

// parseCPUList parses the kernel's CPU list syntax ("0-7", "0-2,4") into an ascending list.
func parseCPUList(text string) ([]uint32, error) {
	text = strings.TrimSpace(text)
	var cpus []uint32
	for _, part := range strings.Split(text, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.ParseUint(lo, 10, 32)
		if err != nil || a > 1023 {
			return nil, fmt.Errorf("cpu list %q", text)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(hi, 10, 32); err != nil || b < a || b > 1023 {
				return nil, fmt.Errorf("cpu list %q", text)
			}
		}
		for c := a; c <= b; c++ {
			if n := len(cpus); n > 0 && cpus[n-1] >= uint32(c) {
				return nil, fmt.Errorf("cpu list %q is not ascending", text)
			}
			cpus = append(cpus, uint32(c))
		}
	}
	return cpus, nil
}

// readOnline is the kernel's online set, as the text it printed and as an ascending list.
func readOnline() (string, []uint32, error) {
	raw, err := os.ReadFile(sysfsCPU + "/online")
	if err != nil {
		return "", nil, err
	}
	text := strings.TrimSpace(string(raw))
	cpus, err := parseCPUList(text)
	return text, cpus, err
}

// pickCPU is the CPU the harness takes offline: the highest online CPU that is not cpu0 and has an online switch.
// cpu0 is never chosen: on some platforms it cannot be offlined at all and it is where the boot work lives.
func pickCPU(online []uint32, want int, hasSwitch func(cpu uint32) bool) (uint32, error) {
	if len(online) < 2 {
		return 0, errors.New("fewer than two CPUs are online: offlining one would leave the host without a CPU")
	}
	if want >= 0 {
		if want == 0 {
			return 0, errors.New("cpu0 is never taken offline")
		}
		for _, c := range online {
			if int(c) == want {
				if !hasSwitch(c) {
					return 0, fmt.Errorf("cpu%d has no online switch", want)
				}
				return c, nil
			}
		}
		return 0, fmt.Errorf("cpu%d is not online", want)
	}
	for i := len(online) - 1; i >= 0; i-- {
		if online[i] != 0 && hasSwitch(online[i]) {
			return online[i], nil
		}
	}
	return 0, errors.New("no online CPU other than cpu0 has an online switch")
}

func cpuSwitchPath(cpu uint32) string { return fmt.Sprintf("%s/cpu%d/online", sysfsCPU, cpu) }

func hasSwitch(cpu uint32) bool {
	_, err := os.Stat(cpuSwitchPath(cpu))
	return err == nil
}

// hotplugger takes one CPU offline and back, and puts it back on any exit path: the deferred restore of main, the
// signal handler, and the caller's final check. restore is idempotent.
type hotplugger struct {
	mu  sync.Mutex
	cpu uint32
}

func (h *hotplugger) write(value string) error {
	path := cpuSwitchPath(h.cpu)
	if err := os.WriteFile(path, []byte(value+"\n"), 0); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) != value {
		return fmt.Errorf("cpu%d online switch reads %q after writing %q", h.cpu, strings.TrimSpace(string(raw)), value)
	}
	return nil
}

func (h *hotplugger) offline() error { h.mu.Lock(); defer h.mu.Unlock(); return h.write("0") }
func (h *hotplugger) online() error  { h.mu.Lock(); defer h.mu.Unlock(); return h.write("1") }

// restore brings the CPU back when it is offline.
func (h *hotplugger) restore() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, err := os.ReadFile(cpuSwitchPath(h.cpu))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return nil
	}
	return h.write("1")
}

// pinThreads sets the CPU affinity of every thread of pid to exactly cpu. The harness runs as root, and the target
// runs as root too, so no capability beyond the opt-in is used.
func pinThreads(pid int, cpu uint32) (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0, err
	}
	var mask [16]uint64
	if int(cpu) >= len(mask)*64 {
		return 0, errors.New("cpu number beyond the affinity mask")
	}
	mask[cpu/64] = 1 << (cpu % 64)
	pinned := 0
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if _, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(tid), unsafe.Sizeof(mask), uintptr(unsafe.Pointer(&mask[0]))); errno != 0 {
			return pinned, fmt.Errorf("sched_setaffinity(%d): %v", tid, errno)
		}
		pinned++
	}
	return pinned, nil
}

// runningOn reports whether any thread of pid is in the running state on cpu right now (/proc/<tid>/stat: state and the
// last CPU). It is the harness' own ground truth that the target really executes on the CPU.
func runningOn(pid int, cpu uint32) bool {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/stat", pid, entry.Name()))
		if err != nil {
			continue
		}
		state, processor, ok := parseStat(string(raw))
		if ok && state == 'R' && processor == cpu {
			return true
		}
	}
	return false
}

// parseStat reads the state and the processor (field 39) of one /proc/<pid>/stat line; the command name may contain
// spaces and parentheses, so fields are counted after the last ')'.
func parseStat(line string) (state byte, processor uint32, ok bool) {
	end := strings.LastIndexByte(line, ')')
	if end < 0 || end+2 >= len(line) {
		return 0, 0, false
	}
	fields := strings.Fields(line[end+2:])
	// fields[0] is field 3 (state); field 39 is fields[36]
	if len(fields) < 37 || len(fields[0]) != 1 {
		return 0, 0, false
	}
	n, err := strconv.ParseUint(fields[36], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return fields[0][0], uint32(n), true
}
