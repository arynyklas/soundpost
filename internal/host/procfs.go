// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procfs parsing is OS-neutral file reading so the same code runs against
// fixtures on any platform; linux.go supplies the real roots and syscalls.

const (
	maxRead  = 1 << 20
	userHZ   = 100.0
	methodSt = "procfs_stat"
)

var errTooLarge = errors.New("source larger than read bound")

// readBounded reads at most 1 MiB; a larger source is treated as unreadable
// rather than silently truncated.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRead {
		return nil, errTooLarge
	}
	return b, nil
}

func procfsRead(c *collector, g Group, p HostPolicy) groupResult {
	switch g {
	case GroupCPU:
		return c.procCPU()
	case GroupMemory:
		return c.procMemory()
	case GroupLoad:
		return c.procLoad()
	case GroupFilesystem:
		return c.readFilesystem(p)
	case GroupProcessCount:
		return c.procCount()
	case GroupCgroup:
		return c.procCgroup()
	}
	return failure(g, "none", StatusUnsupported, ReasonOSUnsupported)
}

var cpuModes = [...]string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

func (c *collector) procCPU() groupResult {
	b, err := readBounded(filepath.Join(c.procRoot, "stat"))
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupCPU, methodSt, s, r)
	}
	bad := failure(GroupCPU, methodSt, StatusUnknown, ReasonParseFailed)
	var agg []string
	logical := 0
	rest := string(b)
	for rest != "" {
		line, tail, terminated := strings.Cut(rest, "\n")
		rest = tail
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "cpu":
			// A kernel always terminates the line; a missing newline means truncation.
			if !terminated {
				return bad
			}
			agg = fields[1:]
		case strings.HasPrefix(fields[0], "cpu") && allDigits(fields[0][3:]):
			logical++
		}
	}
	if len(agg) < 4 {
		return bad
	}
	var samples []Sample
	for i, mode := range cpuModes {
		if i >= len(agg) {
			break
		}
		ticks, err := strconv.ParseUint(agg[i], 10, 64)
		if err != nil {
			return bad
		}
		samples = append(samples, sample("host_cpu_seconds_total", "seconds", "counter", float64(ticks)/userHZ, "mode", mode))
	}
	if len(agg) > len(cpuModes) {
		for _, f := range agg[len(cpuModes):] {
			if _, err := strconv.ParseUint(f, 10, 64); err != nil {
				return bad
			}
		}
	}
	if logical > 0 {
		samples = append(samples, sample("host_cpu_logical_count", "1", "gauge", float64(logical)))
	}
	return supported(GroupCPU, methodSt, samples...)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (c *collector) procLoad() groupResult {
	const m = "procfs_loadavg"
	b, err := readBounded(filepath.Join(c.procRoot, "loadavg"))
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupLoad, m, s, r)
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return failure(GroupLoad, m, StatusUnknown, ReasonParseFailed)
	}
	var samples []Sample
	for i, w := range [...]string{"1m", "5m", "15m"} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return failure(GroupLoad, m, StatusUnknown, ReasonParseFailed)
		}
		samples = append(samples, sample("host_load_average", "1", "gauge", v, "window", w))
	}
	return supported(GroupLoad, m, samples...)
}

func (c *collector) procMemory() groupResult {
	const m = "procfs_meminfo"
	b, err := readBounded(filepath.Join(c.procRoot, "meminfo"))
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupMemory, m, s, r)
	}
	// field order is the emission order
	type field struct{ key, state string }
	fields := []field{
		{"MemTotal", "total"}, {"MemAvailable", "available"}, {"MemFree", "free"},
		{"Buffers", "buffers"}, {"Cached", "cached"}, {"SwapTotal", "swap_total"}, {"SwapFree", "swap_free"},
	}
	wanted := map[string]bool{}
	for _, f := range fields {
		wanted[f.key] = true
	}
	kb := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok || !wanted[key] {
			continue
		}
		parts := strings.Fields(rest)
		if len(parts) != 2 || parts[1] != "kB" {
			return failure(GroupMemory, m, StatusUnknown, ReasonParseFailed)
		}
		v, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || v > math.MaxUint64/1024 {
			return failure(GroupMemory, m, StatusUnknown, ReasonParseFailed)
		}
		kb[key] = v
	}
	for _, req := range []string{"MemTotal", "MemAvailable", "MemFree"} {
		if _, ok := kb[req]; !ok {
			return failure(GroupMemory, m, StatusUnknown, ReasonParseFailed)
		}
	}
	var samples []Sample
	for _, f := range fields {
		if v, ok := kb[f.key]; ok {
			samples = append(samples, sample("host_memory_bytes", "bytes", "gauge", float64(v*1024), "state", f.state))
		}
	}
	return supported(GroupMemory, m, samples...)
}

// procCount lists /proc directory NAMES only; no per-process file is opened.
func (c *collector) procCount() groupResult {
	const m = "procfs_dirnames"
	mi, err := readBounded(filepath.Join(c.procRoot, "self", "mountinfo"))
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupProcessCount, m, s, r)
	}
	restricted, gid, hasGID, found := procMountVisibility(string(mi))
	if !found {
		return failure(GroupProcessCount, m, StatusUnknown, ReasonParseFailed)
	}
	if restricted && !c.exempt(gid, hasGID) {
		return failure(GroupProcessCount, m, StatusUnknown, ReasonProcessVisibility)
	}
	d, err := os.Open(c.procRoot)
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupProcessCount, m, s, r)
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		s, r := statusFor(err)
		return failure(GroupProcessCount, m, s, r)
	}
	n := 0
	for _, name := range names {
		if allDigits(name) {
			n++
		}
	}
	return supported(GroupProcessCount, m, sample("host_processes_total", "1", "gauge", float64(n)))
}

// procMountVisibility inspects the last "/proc" proc mount in mountinfo.
func procMountVisibility(mountinfo string) (restricted bool, gid int, hasGID, found bool) {
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 6 || len(f) < sep+4 || f[4] != "/proc" || f[sep+1] != "proc" {
			continue
		}
		found, restricted, hasGID, gid = true, false, false, 0
		for _, opts := range []string{f[5], f[sep+3]} {
			for _, o := range strings.Split(opts, ",") {
				switch k, v, _ := strings.Cut(o, "="); k {
				case "hidepid":
					if v != "0" && v != "off" {
						restricted = true
					}
				case "gid":
					if n, err := strconv.Atoi(v); err == nil {
						gid, hasGID = n, true
					}
				}
			}
		}
	}
	return
}

const cgroupMethod = "cgroup2_files"

func (c *collector) procCgroup() groupResult {
	b, err := readBounded(filepath.Join(c.procRoot, "self", "cgroup"))
	if err != nil {
		return cgroupError(err)
	}
	mount := filepath.Join(c.sysRoot, "fs", "cgroup")
	ok, err := c.isCgroup2(mount)
	if err != nil {
		return cgroupError(err)
	}
	if !ok {
		return failure(GroupCgroup, cgroupMethod, StatusUnsupported, ReasonCgroupV2Required)
	}
	rel, found, valid := unifiedCgroupPath(string(b))
	if !found {
		return failure(GroupCgroup, cgroupMethod, StatusUnsupported, ReasonCgroupV2Required)
	}
	if !valid {
		return failure(GroupCgroup, cgroupMethod, StatusUnknown, ReasonParseFailed)
	}
	dir := filepath.Join(mount, filepath.FromSlash(rel))

	read := func(name string) (string, bool, *groupResult) {
		data, err := readBounded(filepath.Join(dir, name))
		switch {
		case err == nil:
			return strings.TrimSpace(string(data)), true, nil
		case errors.Is(err, os.ErrNotExist):
			return "", false, nil
		}
		s, r := statusFor(err)
		f := failure(GroupCgroup, cgroupMethod, s, r)
		return "", false, &f
	}
	bad := failure(GroupCgroup, cgroupMethod, StatusUnknown, ReasonParseFailed)
	var samples []Sample
	uintFile := func(name string) (uint64, bool, *groupResult) {
		s, present, f := read(name)
		if f != nil || !present {
			return 0, false, f
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false, &bad
		}
		return v, true, nil
	}
	// limit: "max" means unlimited and emits nothing.
	limitFile := func(name string) (uint64, bool, *groupResult) {
		s, present, f := read(name)
		if f != nil || !present || s == "max" {
			return 0, false, f
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false, &bad
		}
		return v, true, nil
	}

	cpu, present, f := read("cpu.stat")
	if f != nil {
		return *f
	}
	if present {
		var user, system uint64
		var haveU, haveS bool
		for _, line := range strings.Split(cpu, "\n") {
			k, v, _ := strings.Cut(line, " ")
			if k != "user_usec" && k != "system_usec" {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return bad
			}
			if k == "user_usec" {
				user, haveU = n, true
			} else {
				system, haveS = n, true
			}
		}
		if !haveU || !haveS {
			return bad
		}
		samples = append(samples,
			sample("host_cgroup_cpu_seconds_total", "seconds", "counter", float64(user)/1e6, "mode", "user"),
			sample("host_cgroup_cpu_seconds_total", "seconds", "counter", float64(system)/1e6, "mode", "system"))
	}
	if v, ok, f := uintFile("memory.current"); f != nil {
		return *f
	} else if ok {
		samples = append(samples, sample("host_cgroup_memory_bytes", "bytes", "gauge", float64(v), "state", "current"))
	}
	if v, ok, f := limitFile("memory.max"); f != nil {
		return *f
	} else if ok {
		samples = append(samples, sample("host_cgroup_memory_bytes", "bytes", "gauge", float64(v), "state", "limit"))
	}
	if v, ok, f := uintFile("memory.swap.current"); f != nil {
		return *f
	} else if ok {
		samples = append(samples, sample("host_cgroup_memory_bytes", "bytes", "gauge", float64(v), "state", "swap_current"))
	}
	ev, present, f := read("memory.events")
	if f != nil {
		return *f
	}
	if present {
		for _, line := range strings.Split(ev, "\n") {
			k, v, _ := strings.Cut(line, " ")
			if k != "oom_kill" {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return bad
			}
			samples = append(samples, sample("host_cgroup_memory_oom_kills_total", "1", "counter", float64(n)))
		}
	}
	if v, ok, f := uintFile("pids.current"); f != nil {
		return *f
	} else if ok {
		samples = append(samples, sample("host_cgroup_pids", "1", "gauge", float64(v), "state", "current"))
	}
	if v, ok, f := limitFile("pids.max"); f != nil {
		return *f
	} else if ok {
		samples = append(samples, sample("host_cgroup_pids", "1", "gauge", float64(v), "state", "limit"))
	}
	if len(samples) == 0 {
		return failure(GroupCgroup, cgroupMethod, StatusUnsupported, ReasonNotPresent)
	}
	return supported(GroupCgroup, cgroupMethod, samples...)
}

// cgroupError maps a failure on the structural sources (self/cgroup, mount):
// absent means this host has no usable cgroup tree, not that data is missing.
func cgroupError(err error) groupResult {
	if errors.Is(err, os.ErrNotExist) {
		return failure(GroupCgroup, cgroupMethod, StatusUnsupported, ReasonNotPresent)
	}
	s, r := statusFor(err)
	return failure(GroupCgroup, cgroupMethod, s, r)
}

// unifiedCgroupPath extracts the agent's own cgroup v2 path ("0::/path") as a
// clean slash path without a leading slash. It rejects any ".." element.
func unifiedCgroupPath(self string) (rel string, found, valid bool) {
	for _, line := range strings.Split(self, "\n") {
		p, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		p = strings.TrimSuffix(p, " (deleted)")
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
			return "", true, false
		}
		var parts []string
		for _, e := range strings.Split(p, "/") {
			switch e {
			case "", ".":
			case "..":
				return "", true, false
			default:
				parts = append(parts, e)
			}
		}
		return strings.Join(parts, "/"), true, true
	}
	return "", false, false
}
