// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCPUListCount(t *testing.T) {
	for list, want := range map[string]int{"0-7": 8, "0": 1, "0-3,8,10-11": 7, "0-15\n": 16} {
		if got, err := cpuListCount(list); err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", list, got, err, want)
		}
	}
	for _, bad := range []string{"", "a", "3-1", "0-", "-2"} {
		if _, err := cpuListCount(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The scope of the gate (D90) is exactly 8 CPUs, a memory.max between 15,000 MiB and 16 GiB and no swap; every other shape is refused.
func TestCheckScopeIsTheD90Shape(t *testing.T) {
	ok := CgroupFacts{Path: "/system.slice/soundpost-server-1-1.scope", CPUsEff: "0-7", MemoryMax: "17179869184", MemorySwapM: "0"}
	if err := ok.checkScope(); err != nil {
		t.Fatalf("the gate shape was refused: %v", err)
	}
	lowest := ok
	lowest.MemoryMax = "15728640000" // 15,000 MiB
	if err := lowest.checkScope(); err != nil {
		t.Fatalf("15,000 MiB was refused: %v", err)
	}
	for name, mut := range map[string]func(*CgroupFacts){
		"no cgroup":          func(c *CgroupFacts) { c.Path = "" },
		"the root cgroup":    func(c *CgroupFacts) { c.Path = "/" },
		"4 CPUs":             func(c *CgroupFacts) { c.CPUsEff = "0-3" },
		"16 CPUs":            func(c *CgroupFacts) { c.CPUsEff = "0-15" },
		"no cpuset file":     func(c *CgroupFacts) { c.CPUsEff = "" },
		"unlimited memory":   func(c *CgroupFacts) { c.MemoryMax = "max" },
		"memory over 16 GiB": func(c *CgroupFacts) { c.MemoryMax = "17179869185" },
		"memory 14,999 MiB":  func(c *CgroupFacts) { c.MemoryMax = "15726591999" },
		"swap allowed":       func(c *CgroupFacts) { c.MemorySwapM = "max" },
		"swap file missing":  func(c *CgroupFacts) { c.MemorySwapM = "" },
	} {
		c := ok
		mut(&c)
		if err := c.checkScope(); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}

// The harness starts the product with systemd-run --scope and the three properties of D90, and nothing between systemd-run and the
// product (the process id the harness signals is the product's).
func TestScopeCommand(t *testing.T) {
	name, args := scopeCommand("0-7", "16G", "u.scope", "/b/soundpost", []string{"serve", "--mode=single"})
	want := []string{"--scope", "--quiet", "--collect", "--unit=u.scope", "-p", "AllowedCPUs=0-7", "-p", "MemoryMax=16G", "-p", "MemorySwapMax=0", "--", "/b/soundpost", "serve", "--mode=single"}
	if name != "systemd-run" || !reflect.DeepEqual(args, want) {
		t.Fatalf("%s %v", name, args)
	}
}

// The result carries the scope under the names the qualify runner reads, beside the existing keys.
func TestHostFactsCarryTheScope(t *testing.T) {
	h := HostFacts{Gomaxprocs: 8, CpusAllowed: "0-7", LogicalCPUs: 16, CgroupFacts: CgroupFacts{Path: "/system.slice/x.scope", CPUsEff: "0-7", MemoryMax: "17179869184", MemorySwapM: "0"}}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"cgroup_path": "/system.slice/x.scope", "cgroup_cpus_effective": "0-7", "cgroup_memory_max": "17179869184", "cgroup_memory_swap_max": "0", "gomaxprocs": float64(8), "cpus_allowed": "0-7", "logical_cpus": float64(16)} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	var back HostFacts
	if err = json.Unmarshal(raw, &back); err != nil || back.CgroupFacts != h.CgroupFacts {
		t.Fatalf("round trip: %+v %v", back.CgroupFacts, err)
	}
}

// readCgroup reads the raw, trimmed controller files of the process's cgroup under the cgroup mount.
func TestReadCgroupReadsTheControllerFiles(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	var path string
	for _, l := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			path = p
		}
	}
	if path == "" {
		t.Skip("cgroup v1 host")
	}
	root := t.TempDir()
	dir := filepath.Join(root, path)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"cpuset.cpus.effective": "0-7\n", "memory.max": "17179869184\n", "memory.swap.max": "0\n"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := cgroupRoot
	cgroupRoot = root
	defer func() { cgroupRoot = old }()
	got := readCgroup(os.Getpid())
	if got.Path != path || got.CPUsEff != "0-7" || got.MemoryMax != "17179869184" || got.MemorySwapM != "0" {
		t.Fatalf("%+v", got)
	}
}
