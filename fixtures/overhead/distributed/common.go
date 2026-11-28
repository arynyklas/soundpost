// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Plan is what the generators and verifiers need to reach and address the estate. It carries credentials: it is written 0600 and is
// never part of the evidence.
type Plan struct {
	Config    Config       `json:"config"`
	Nodes     []PlanNode   `json:"nodes"`
	Sources   []PlanSource `json:"sources"`
	Readers   []PlanReader `json:"readers"`
	StartedAt int64        `json:"provisioned_unix_ms"`
}

// PlanNode is one voter: the public HTTPS address the SDKs and readers use and the harness control endpoint of its agent.
type PlanNode struct {
	ID           uint64 `json:"id"`
	Addr         string `json:"addr"`
	Control      string `json:"control"`
	ControlToken string `json:"control_token"`
}

// PlanSource is the credential of one project's SDK source.
type PlanSource struct {
	Project    int    `json:"project"`
	Credential string `json:"credential"`
}

// PlanReader is the read token of one organization's read-only user (all of the org's projects).
type PlanReader struct {
	Org   int    `json:"org"`
	Token string `json:"token"`
}

// Sample is one monitor sample of a node's server process: numbers only. The field names are the ones of the single-host harness
// (the qualify runner reads t_ms, pid, rss_kib, hwm_kib, data_bytes, io_write_bytes, utime_ticks, stime_ticks, load1), plus the link
// counters of the host's non-loopback interfaces and the CPU the scope has used.
type Sample struct {
	TMS         int64    `json:"t_ms"`
	PID         int      `json:"pid"`
	RSSKiB      int64    `json:"rss_kib"`
	HWMKiB      int64    `json:"hwm_kib"`
	Threads     int64    `json:"threads"`
	FDs         int      `json:"fds"`
	IOWrite     uint64   `json:"io_write_bytes"`
	IORead      uint64   `json:"io_read_bytes"`
	IOWChar     uint64   `json:"io_wchar"`
	UTime       uint64   `json:"utime_ticks"`
	STime       uint64   `json:"stime_ticks"`
	CPUBusy     []uint64 `json:"cpu_busy_ticks"`
	CPUTotal    []uint64 `json:"cpu_total_ticks"`
	MemAvailKiB int64    `json:"mem_available_kib"`
	Load1       float64  `json:"load1"`
	DataBytes   int64    `json:"data_bytes,omitempty"`
	FSUsedPct   float64  `json:"data_fs_used_percent,omitempty"`
	CgMemKiB    int64    `json:"cgroup_memory_current_kib,omitempty"`
	CgOOMKill   uint64   `json:"cgroup_oom_kill,omitempty"`
	CgCPUUsec   uint64   `json:"cgroup_cpu_usage_usec,omitempty"`
	NetRxBytes  uint64   `json:"net_rx_bytes"`
	NetTxBytes  uint64   `json:"net_tx_bytes"`
}

// Event is one lifecycle event of a node (start, kill, restart) with its measured durations.
type Event struct {
	TMS       int64        `json:"t_ms"`
	Node      uint64       `json:"node"`
	Event     string       `json:"event"`
	Mode      string       `json:"mode,omitempty"`
	PIDBefore int          `json:"pid_before,omitempty"`
	PIDAfter  int          `json:"pid_after,omitempty"`
	Exit      string       `json:"exit,omitempty"`
	StopMS    int64        `json:"stop_ms,omitempty"`
	ReadyMS   int64        `json:"ready_ms,omitempty"`
	DownMS    int64        `json:"down_ms,omitempty"`
	Cpus      string       `json:"cpus_allowed,omitempty"`
	Note      string       `json:"note,omitempty"`
	Cgroup    *CgroupFacts `json:"cgroup,omitempty"`
}

func now() int64 { return time.Now().UnixMilli() }

// activePID is the exact process id of the soundpost this harness started on this host (0 when none runs): a failing harness ends it
// rather than leave an orphan on the host.
var activePID atomic.Int64

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "distributed: FAIL: "+f+"\n", a...)
	if p := activePID.Load(); p != 0 {
		syscall.Kill(int(p), syscall.SIGKILL)
	}
	os.Exit(1)
}

func must(err error, what string) {
	if err != nil {
		fatalf("%s: %v", what, err)
	}
}

func readProcStatus(pid int) (rss, hwm, threads int64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "VmRSS:":
			rss = v
		case "VmHWM:":
			hwm = v
		case "Threads:":
			threads = v
		}
	}
	return
}

func readProcIO(pid int) (write, read, wchar uint64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		switch k {
		case "write_bytes":
			write = n
		case "read_bytes":
			read = n
		case "wchar":
			wchar = n
		}
	}
	return
}

func readProcCPU(pid int) (utime, stime uint64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return
	}
	f := strings.Fields(s[i+1:])
	if len(f) > 13 {
		utime, _ = strconv.ParseUint(f[11], 10, 64)
		stime, _ = strconv.ParseUint(f[12], 10, 64)
	}
	return
}

func readSystem() (busy, total []uint64, memAvail int64, load1 float64) {
	if raw, err := os.ReadFile("/proc/stat"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			f := strings.Fields(l)
			if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
				continue
			}
			var v [8]uint64
			var sum uint64
			for i := range v {
				v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
				sum += v[i]
			}
			busy = append(busy, sum-v[3]-v[4]) // all but idle and iowait
			total = append(total, sum)
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(l, "MemAvailable:"); ok {
				memAvail, _ = strconv.ParseInt(strings.Fields(v)[0], 10, 64)
			}
		}
	}
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		load1, _ = strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	}
	return
}

// readNet is the sum of the received and transmitted bytes of every interface of the host except the loopback.
func readNet() (rx, tx uint64) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		name, rest, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx, tx = rx+r, tx+t
	}
	return
}

// fsUsedPercent is the used share of the file system holding dir, as df reports it (what the product's disk-pressure levels are about).
func fsUsedPercent(dir string) float64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil || st.Blocks == 0 {
		return 0
	}
	used := st.Blocks - st.Bfree
	return 100 * float64(used) / float64(used+st.Bavail)
}

func dirBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}
