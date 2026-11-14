// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package host

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
			if x == 42 {
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()
}

func TestRealWindowsCPUMemoryAndUnsupported(t *testing.T) {
	p := HostPolicy{Allow: AllGroups()}
	before, caps := realCollect(t, p)
	mustCap(t, caps, GroupCPU, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupMemory, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupProcessCount, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupLoad, "", StatusUnsupported, ReasonOSUnsupported)
	mustCap(t, caps, GroupCgroup, "", StatusUnsupported, ReasonOSUnsupported)
	mustCap(t, caps, GroupFilesystem, "", StatusDenied, ReasonNoTarget)
	for _, prefix := range []string{"host_load", "host_cgroup", "host_filesystem"} {
		if hasPrefix(before, prefix) {
			t.Fatalf("samples for unsupported group %s", prefix)
		}
	}
	v := values(before)
	total, avail := v["host_memory_bytes{state=total,}"], v["host_memory_bytes{state=available,}"]
	if total < 1<<28 || avail <= 0 || avail > total {
		t.Fatalf("memory total %v available %v", total, avail)
	}
	if v["host_cpu_logical_count{}"] != float64(runtime.NumCPU()) {
		t.Fatalf("logical cpus %v, runtime says %d", v["host_cpu_logical_count{}"], runtime.NumCPU())
	}

	t0 := time.Now()
	workers := min(runtime.NumCPU(), 4)
	spin(500*time.Millisecond, workers)
	after, _ := realCollect(t, p)
	wall := time.Since(t0).Seconds()
	busy := func(b HostBatch) float64 { return sum(b, "host_cpu_seconds_total", "idle") }
	total2 := func(b HostBatch) float64 { return sum(b, "host_cpu_seconds_total") }
	if d := busy(after) - busy(before); d < 0.125*float64(workers) {
		t.Fatalf("busy CPU delta %.3fs for %d spinning workers", d, workers)
	}
	ideal := wall * float64(runtime.NumCPU())
	if got := total2(after) - total2(before); got < 0.5*ideal || got > 1.5*ideal {
		t.Fatalf("all-mode delta %.2fs inconsistent with wall x cpus = %.2fs", got, ideal)
	}
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

func TestRealWindowsFilesystemChange(t *testing.T) {
	dir := t.TempDir() // the test run points TMP/TEMP at X: because C: is full
	if filepath.VolumeName(dir) == "C:" {
		t.Skipf("temp directory is on C: (full); run with TMP/TEMP on X:")
	}
	p := HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{{Alias: "scratch", Path: dir}}}
	read := func() map[string]float64 {
		b, caps := realCollect(t, p)
		mustCap(t, caps, GroupFilesystem, "scratch", StatusSupported, ReasonNone)
		if hasPrefix(b, "host_filesystem_inodes") {
			t.Fatal("Windows reports no inode counts; none may be emitted")
		}
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
		t.Fatalf("size %v -> %v", before[size], after[size])
	}
	if d := before[free] - after[free]; d < 2<<20 {
		t.Fatalf("free fell by %.0f, want at least 2 MiB", d)
	}
	if d := before[avail] - after[avail]; d < 2<<20 {
		t.Fatalf("available fell by %.0f, want at least 2 MiB", d)
	}
	_, caps := realCollect(t, HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{{Alias: "gone", Path: filepath.Join(dir, "no-such-dir")}}})
	mustCap(t, caps, GroupFilesystem, "gone", StatusUnknown, ReasonNotPresent)
}

func TestRealWindowsProcessCountRises(t *testing.T) {
	p := HostPolicy{Allow: []Group{GroupProcessCount}}
	count := func() float64 {
		b, _ := realCollect(t, p)
		return values(b)["host_processes_total{}"]
	}
	base := count()
	var cmds []*exec.Cmd
	t.Cleanup(func() {
		for _, c := range cmds {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	for range 5 {
		c := exec.Command("ping", "-n", "30", "127.0.0.1")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	var got float64
	for i := 0; i < 100; i++ {
		if got = count(); got-base >= 5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("count rose from %v to %v after starting 5 processes", base, got)
}
