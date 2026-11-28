// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// The gate's host shape (decision D90): the server runs in its own cgroup v2 scope whose effective CPU set is exactly 8 CPUs, whose
// memory.max is between 15,000 MiB and 16 GiB (the page cache is charged to it) and which has no swap, with GOMAXPROCS 8, on the larger
// gate VM. The harness starts the product with
//
//	systemd-run --scope -p AllowedCPUs=0-7 -p MemoryMax=16G -p MemorySwapMax=0
//
// (systemd-run replaces itself with the command, so the process id is the product's) and refuses to go on unless the scope it
// reads back from /sys/fs/cgroup says the same.
const (
	scopeCPUs       = 8
	scopeMemMinKiB  = 15000 * 1024
	scopeMemMaxKiB  = 16 * 1024 * 1024
	scopeGomaxprocs = 8
)

// CgroupFacts are the limits of the cgroup v2 the server process runs in: the raw trimmed contents of the controller files.
type CgroupFacts struct {
	Path        string `json:"cgroup_path,omitempty"`            // the process's cgroup, from /proc/<pid>/cgroup
	CPUsEff     string `json:"cgroup_cpus_effective,omitempty"`  // cpuset.cpus.effective
	MemoryMax   string `json:"cgroup_memory_max,omitempty"`      // memory.max: decimal bytes or "max"
	MemorySwapM string `json:"cgroup_memory_swap_max,omitempty"` // memory.swap.max: decimal bytes or "max"
}

// cgroupRoot is where cgroup v2 is mounted; a variable of the tests.
var cgroupRoot = "/sys/fs/cgroup"

// cgroupPathOf is the cgroup v2 path of a process ("0::/system.slice/x.scope"), "" when the process has none or the host is on v1.
func cgroupPathOf(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

func cgroupFile(path, name string) string {
	return firstLine(cgroupRoot + path + "/" + name)
}

func cgroupFileAll(path, name string) string {
	raw, err := os.ReadFile(cgroupRoot + path + "/" + name)
	if err != nil {
		return ""
	}
	return string(raw)
}

// readCgroup reads the limits of the cgroup the process is in.
func readCgroup(pid int) CgroupFacts {
	p := cgroupPathOf(pid)
	if p == "" {
		return CgroupFacts{}
	}
	return CgroupFacts{Path: p, CPUsEff: cgroupFile(p, "cpuset.cpus.effective"), MemoryMax: cgroupFile(p, "memory.max"), MemorySwapM: cgroupFile(p, "memory.swap.max")}
}

// cpuListCount is the number of CPUs of a kernel CPU list ("0-3,8,10-11").
func cpuListCount(list string) (int, error) {
	n := 0
	for _, part := range strings.Split(strings.TrimSpace(list), ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return 0, fmt.Errorf("bad CPU list %q", list)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return 0, fmt.Errorf("bad CPU list %q", list)
			}
		}
		n += b - a + 1
	}
	return n, nil
}

// checkScope returns what is wrong with a scope against the host shape of D90, nil when it is the shape.
func (c CgroupFacts) checkScope() error {
	if c.Path == "" || c.Path == "/" {
		return fmt.Errorf("the server is not in a cgroup v2 scope of its own (cgroup %q)", c.Path)
	}
	n, err := cpuListCount(c.CPUsEff)
	if err != nil || n != scopeCPUs {
		return fmt.Errorf("cpuset.cpus.effective of %s is %q: the gate needs exactly %d CPUs", c.Path, c.CPUsEff, scopeCPUs)
	}
	mem, err := strconv.ParseInt(c.MemoryMax, 10, 64)
	if err != nil || mem < scopeMemMinKiB*1024 || mem > scopeMemMaxKiB*1024 {
		return fmt.Errorf("memory.max of %s is %q: the gate needs a number of bytes between 15,000 MiB and 16 GiB", c.Path, c.MemoryMax)
	}
	if c.MemorySwapM != "0" {
		return fmt.Errorf("memory.swap.max of %s is %q: the gate needs 0 (no swap)", c.Path, c.MemorySwapM)
	}
	return nil
}

// processGomaxprocs is the GOMAXPROCS the process was started with (/proc/<pid>/environ), 0 when it cannot be read or is not set.
func processGomaxprocs(pid int) int {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return 0
	}
	for _, kv := range strings.Split(string(raw), "\x00") {
		if v, ok := strings.CutPrefix(kv, "GOMAXPROCS="); ok {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return 0
}

// scopeSeq makes the name of every scope the harness starts unique (a restart starts a new one).
var scopeSeq atomic.Int64

// scopeCommand is the command that runs `soundpost serve` (args after the binary) in a new scope.
func scopeCommand(cpus, memoryMax, unit, bin string, serve []string) (string, []string) {
	args := []string{"--scope", "--quiet", "--collect", "--unit=" + unit,
		"-p", "AllowedCPUs=" + cpus, "-p", "MemoryMax=" + memoryMax, "-p", "MemorySwapMax=0", "--", bin}
	return "systemd-run", append(args, serve...)
}
