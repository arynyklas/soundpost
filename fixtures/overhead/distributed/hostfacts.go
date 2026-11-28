// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// HostFacts are the facts about a host a result is bound to: numbers and closed words, never a host name or address.
type HostFacts struct {
	HostID       string `json:"host_id"` // first 16 hex of sha256(machine-id): stable, reveals nothing
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Kernel       string `json:"kernel"`
	LogicalCPUs  int    `json:"logical_cpus"`
	MemTotalKiB  int64  `json:"mem_total_kib"`
	Gomaxprocs   int    `json:"gomaxprocs"`
	CpusAllowed  string `json:"cpus_allowed,omitempty"`
	DataFS       string `json:"data_dir_filesystem,omitempty"`
	BlockDevice  string `json:"block_device_model,omitempty"`
	DataOnTmpfs  bool   `json:"data_dir_on_tmpfs"`
	Load1AtStart string `json:"load_average_at_start,omitempty"`
	// CgroupFacts are the limits of the cgroup v2 scope the server process runs in (the gate's host shape, decision D90).
	CgroupFacts
}

func firstLine(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
}

// hostFacts reads this host's identity facts. dataDir, when set, is the directory whose filesystem is described.
func hostFacts(dataDir string, gomaxprocs int) HostFacts {
	h := HostFacts{OS: runtime.GOOS, Arch: runtime.GOARCH, Kernel: firstLine("/proc/sys/kernel/osrelease"), LogicalCPUs: runtime.NumCPU(), Gomaxprocs: gomaxprocs}
	sum := sha256.Sum256([]byte(firstLine("/etc/machine-id")))
	h.HostID = hex.EncodeToString(sum[:8])
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(l, "MemTotal:"); ok {
				h.MemTotalKiB, _ = strconv.ParseInt(strings.Fields(v)[0], 10, 64)
			}
		}
	}
	h.CpusAllowed = cpusAllowed(os.Getpid())
	h.Load1AtStart = strings.Fields(firstLine("/proc/loadavg") + " ")[0]
	if dataDir != "" {
		if out, err := exec.Command("stat", "-f", "-c", "%T", dataDir).Output(); err == nil {
			h.DataFS = strings.TrimSpace(string(out))
			h.DataOnTmpfs = h.DataFS == "tmpfs" || h.DataFS == "ramfs"
		}
	}
	// the first non-removable block device's model: a virtual disk says so (QEMU HARDDISK), it is a limit of the result.
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "sd") || strings.HasPrefix(e.Name(), "vd") || strings.HasPrefix(e.Name(), "nvme") {
				if m := firstLine(fmt.Sprintf("/sys/block/%s/device/model", e.Name())); m != "" {
					h.BlockDevice = m
					break
				}
			}
		}
	}
	return h
}
