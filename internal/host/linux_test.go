// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package host

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func realCollect(t *testing.T, p HostPolicy) (HostBatch, Capabilities) {
	t.Helper()
	b, caps, err := Collect(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return b, caps
}

func spin(d time.Duration, workers int) {
	var wg sync.WaitGroup
	deadline := time.Now().Add(d)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := uint64(1)
			for time.Now().Before(deadline) {
				for i := 0; i < 20000; i++ {
					x = x*6364136223846793005 + 1442695040888963407
				}
			}
			if x == 42 { // keep the loop observable to the compiler
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()
}

func sum(b HostBatch, name string, skip ...string) float64 {
	total := 0.0
outer:
	for _, s := range b.Samples {
		if s.Name != name {
			continue
		}
		for _, l := range s.Labels {
			for _, x := range skip {
				if l.Value == x {
					continue outer
				}
			}
		}
		total += s.Value
	}
	return total
}

func TestRealHostCPULoadDelta(t *testing.T) {
	p := HostPolicy{Allow: []Group{GroupCPU, GroupCgroup}}
	before, caps := realCollect(t, p)
	mustCap(t, caps, GroupCPU, "", StatusSupported, ReasonNone)
	t0 := time.Now()
	workers := min(runtime.NumCPU(), 4)
	spin(500*time.Millisecond, workers)
	after, _ := realCollect(t, p)
	wall := time.Since(t0).Seconds()

	busy := func(b HostBatch) float64 { return sum(b, "host_cpu_seconds_total", "idle", "iowait") }
	total := func(b HostBatch) float64 { return sum(b, "host_cpu_seconds_total") }
	busyDelta := busy(after) - busy(before)
	// Each worker burns ~0.5 CPU-seconds; demand only a quarter of the ideal.
	if want := 0.125 * float64(workers); busyDelta < want {
		t.Fatalf("busy CPU delta %.3fs, want at least %.3fs for %d spinning workers", busyDelta, want, workers)
	}
	var cpus float64
	for _, s := range after.Samples {
		if s.Name == "host_cpu_logical_count" {
			cpus = s.Value
		}
	}
	if cpus < float64(runtime.NumCPU()) {
		t.Fatalf("logical count %v below runtime.NumCPU %d", cpus, runtime.NumCPU())
	}
	if got, ideal := total(after)-total(before), wall*cpus; got < 0.5*ideal || got > 1.5*ideal {
		t.Fatalf("all-mode delta %.2fs inconsistent with wall %.2fs x %v cpus = %.2fs", got, wall, cpus, ideal)
	}
	if busy(after) < busy(before) {
		t.Fatal("counter went backwards")
	}

	if c, _ := caps.Find(GroupCgroup, ""); c.Status == StatusSupported {
		cg := func(b HostBatch) float64 { return sum(b, "host_cgroup_cpu_seconds_total") }
		if d := cg(after) - cg(before); d < 0.125*float64(workers) {
			t.Fatalf("cgroup CPU delta %.3fs too small for %d spinning workers", d, workers)
		}
	} else if c.Reason != ReasonCgroupV2Required && c.Reason != ReasonNotPresent {
		t.Fatalf("cgroup %+v", c)
	}
}

func TestRealHostFilesystemChange(t *testing.T) {
	dir := t.TempDir()
	p := HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{{Alias: "scratch", Path: dir}}}
	read := func() map[string]float64 {
		b, caps := realCollect(t, p)
		mustCap(t, caps, GroupFilesystem, "scratch", StatusSupported, ReasonNone)
		return values(b)
	}
	before := read()
	f, err := os.Create(filepath.Join(dir, "blob"))
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i*7 + 1)
	}
	for range 16 {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	after := read()

	free := "host_filesystem_bytes{mount=scratch,state=free,}"
	avail := "host_filesystem_bytes{mount=scratch,state=available,}"
	size := "host_filesystem_bytes{mount=scratch,state=size,}"
	if before[size] == 0 || after[size] != before[size] {
		t.Fatalf("size changed or is zero: %v -> %v", before[size], after[size])
	}
	if d := before[free] - after[free]; d < 2<<20 {
		t.Fatalf("free bytes fell by %.0f after a 16 MiB write, want at least 2 MiB", d)
	}
	if d := before[avail] - after[avail]; d < 2<<20 {
		t.Fatalf("available bytes fell by %.0f after a 16 MiB write, want at least 2 MiB", d)
	}
	if after[avail] > after[free] || after[free] > after[size] {
		t.Fatalf("inconsistent: avail %v free %v size %v", after[avail], after[free], after[size])
	}
	if tot, ok := after["host_filesystem_inodes{mount=scratch,state=total,}"]; ok && tot != before["host_filesystem_inodes{mount=scratch,state=total,}"] {
		t.Fatal("inode total changed")
	}

	// Real error mapping, with the path absent from the capability.
	missing := filepath.Join(dir, "no-such-dir-xyz")
	_, caps := realCollect(t, HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{{Alias: "gone", Path: missing}}})
	mustCap(t, caps, GroupFilesystem, "gone", StatusUnknown, ReasonNotPresent)
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		_, caps = realCollect(t, HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{{Alias: "locked", Path: filepath.Join(locked, "inner")}}})
		mustCap(t, caps, GroupFilesystem, "locked", StatusDenied, ReasonPermission)
	}
}

func TestRealHostProcessCountRises(t *testing.T) {
	p := HostPolicy{Allow: []Group{GroupProcessCount}}
	count := func() float64 {
		b, caps := realCollect(t, p)
		mustCap(t, caps, GroupProcessCount, "", StatusSupported, ReasonNone)
		return values(b)["host_processes_total{}"]
	}
	base := count()
	if base < 1 {
		t.Fatalf("process count %v", base)
	}
	var cmds []*exec.Cmd
	t.Cleanup(func() {
		for _, c := range cmds {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	for range 5 {
		c := exec.Command("sleep", "30")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	var got float64
	for i := 0; i < 50; i++ {
		if got = count(); got-base >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got-base < 5 {
		t.Fatalf("count rose from %v to %v after starting 5 processes", base, got)
	}
	for _, c := range cmds {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	cmds = nil
	if after := count(); after > got-5+3 {
		t.Fatalf("count %v did not fall after killing 5 processes (was %v)", after, got)
	}
}

func TestRealHostMemoryLoadAndPrivacy(t *testing.T) {
	b, caps := realCollect(t, HostPolicy{Allow: []Group{GroupMemory, GroupLoad, GroupCgroup}})
	mustCap(t, caps, GroupMemory, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupLoad, "", StatusSupported, ReasonNone)
	v := values(b)

	// Independent read of the same kernel files.
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			total, _ = strconv.ParseUint(strings.Fields(rest)[0], 10, 64)
		}
	}
	if got := v["host_memory_bytes{state=total,}"]; got != float64(total*1024) || total == 0 {
		t.Fatalf("total %v, /proc/meminfo says %d kB", got, total)
	}
	if v["host_memory_bytes{state=available,}"] > v["host_memory_bytes{state=total,}"] || v["host_memory_bytes{state=available,}"] <= 0 {
		t.Fatalf("available %v vs total %v", v["host_memory_bytes{state=available,}"], v["host_memory_bytes{state=total,}"])
	}
	la, _ := os.ReadFile("/proc/loadavg")
	one, _ := strconv.ParseFloat(strings.Fields(string(la))[0], 64)
	if d := v["host_load_average{window=1m,}"] - one; d > 2 || d < -2 {
		t.Fatalf("1m load %v vs /proc/loadavg %v", v["host_load_average{window=1m,}"], one)
	}

	if c, _ := caps.Find(GroupCgroup, ""); c.Status == StatusSupported {
		if v["host_cgroup_pids{state=current,}"] < 1 {
			t.Fatalf("cgroup pids.current %v", v["host_cgroup_pids{state=current,}"])
		}
		self, _ := os.ReadFile("/proc/self/cgroup")
		line, _, _ := strings.Cut(strings.TrimPrefix(string(self), "0::"), "\n")
		j, _ := json.Marshal(b.Samples)
		if strings.Trim(line, "/") != "" && strings.Contains(string(j), strings.Trim(line, "/")) {
			t.Fatalf("cgroup path %q leaked into samples", line)
		}
	}
}
