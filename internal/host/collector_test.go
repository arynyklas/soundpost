// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
)

const fixtureDir = "../../tools/fixtures/host"

var fixedNow = time.Unix(1_700_000_000, 123)

// secretPath stands in for an operator path with an identity in it; it must
// never appear in any output.
func secretPath() string {
	if runtime.GOOS == "windows" {
		return `X:\customer-acme\payroll-secret`
	}
	return "/var/lib/customer-acme/payroll-secret"
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fixtureEnv struct {
	proc, sys, cg string
	c             *collector
	stats         map[string]fsStat
	errs          map[string]error
	cgroup2       bool
}

func newFixtureEnv(t *testing.T) *fixtureEnv {
	t.Helper()
	root := t.TempDir()
	copyTree(t, fixtureDir, root)
	e := &fixtureEnv{
		proc:    filepath.Join(root, "proc"),
		sys:     filepath.Join(root, "cgroup"),
		stats:   map[string]fsStat{},
		errs:    map[string]error{},
		cgroup2: true,
	}
	e.cg = filepath.Join(e.sys, "fs", "cgroup", "system.slice", "agent.service")
	e.c = &collector{
		procRoot: e.proc,
		sysRoot:  e.sys,
		statfs: func(p string) (fsStat, error) {
			if err := e.errs[p]; err != nil {
				return fsStat{}, err
			}
			if st, ok := e.stats[p]; ok {
				return st, nil
			}
			return fsStat{}, &fs.PathError{Op: "statfs", Path: p, Err: fs.ErrNotExist}
		},
		isCgroup2: func(string) (bool, error) { return e.cgroup2, nil },
		exempt:    func(int, bool) bool { return false },
		now:       func() time.Time { return fixedNow },
		fsMethod:  "statfs",
		read:      procfsRead,
	}
	return e
}

func (e *fixtureEnv) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *fixtureEnv) remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, c *collector, p HostPolicy) (HostBatch, Capabilities) {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	b, caps, err := c.collect(context.Background(), p)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return b, caps
}

func allowAll(fsTargets ...FilesystemTarget) HostPolicy {
	return HostPolicy{Allow: AllGroups(), Filesystems: fsTargets}
}

func key(s Sample) string {
	var b strings.Builder
	b.WriteString(s.Name + "{")
	for _, l := range s.Labels {
		b.WriteString(l.Name + "=" + l.Value + ",")
	}
	b.WriteString("}")
	return b.String()
}

func values(b HostBatch) map[string]float64 {
	m := map[string]float64{}
	for _, s := range b.Samples {
		m[key(s)] = s.Value
	}
	return m
}

func hasPrefix(b HostBatch, prefix string) bool {
	for _, s := range b.Samples {
		if strings.HasPrefix(s.Name, prefix) {
			return true
		}
	}
	return false
}

func mustCap(t *testing.T, caps Capabilities, g Group, scope string, st Status, r Reason) Capability {
	t.Helper()
	c, ok := caps.Find(g, scope)
	if !ok {
		t.Fatalf("no capability for %s/%q in %+v", g, scope, caps)
	}
	if c.Status != st || c.Reason != r {
		t.Fatalf("%s/%q = %s/%q, want %s/%q", g, scope, c.Status, c.Reason, st, r)
	}
	return c
}

func assertValues(t *testing.T, got, want map[string]float64) {
	t.Helper()
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("missing sample %s", k)
		} else if g != w {
			t.Errorf("%s = %v, want %v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected sample %s = %v", k, got[k])
		}
	}
}

func TestHostFixtureExactValues(t *testing.T) {
	e := newFixtureEnv(t)
	e.stats[secretPath()] = fsStat{Size: 100 * 4096, Free: 40 * 4096, Avail: 30 * 4096, Files: 5000, FilesFree: 4000}
	b, caps := run(t, e.c, allowAll(FilesystemTarget{Alias: "data", Path: secretPath()}))
	want := map[string]float64{
		"host_cpu_seconds_total{mode=user,}":    20,
		"host_cpu_seconds_total{mode=nice,}":    1,
		"host_cpu_seconds_total{mode=system,}":  10,
		"host_cpu_seconds_total{mode=idle,}":    900,
		"host_cpu_seconds_total{mode=iowait,}":  5,
		"host_cpu_seconds_total{mode=irq,}":     0.5,
		"host_cpu_seconds_total{mode=softirq,}": 0.25,
		"host_cpu_seconds_total{mode=steal,}":   0.1,
		"host_cpu_logical_count{}":              2,

		"host_load_average{window=1m,}":  0.52,
		"host_load_average{window=5m,}":  1.25,
		"host_load_average{window=15m,}": 3.5,

		"host_memory_bytes{state=total,}":      8192000 * 1024,
		"host_memory_bytes{state=available,}":  4096000 * 1024,
		"host_memory_bytes{state=free,}":       1024000 * 1024,
		"host_memory_bytes{state=buffers,}":    256 * 1024,
		"host_memory_bytes{state=cached,}":     2048000 * 1024,
		"host_memory_bytes{state=swap_total,}": 2097152 * 1024,
		"host_memory_bytes{state=swap_free,}":  1048576 * 1024,

		"host_filesystem_bytes{mount=data,state=size,}":      100 * 4096,
		"host_filesystem_bytes{mount=data,state=free,}":      40 * 4096,
		"host_filesystem_bytes{mount=data,state=available,}": 30 * 4096,
		"host_filesystem_inodes{mount=data,state=total,}":    5000,
		"host_filesystem_inodes{mount=data,state=free,}":     4000,

		"host_processes_total{}": 3,

		"host_cgroup_cpu_seconds_total{mode=user,}":     3,
		"host_cgroup_cpu_seconds_total{mode=system,}":   2,
		"host_cgroup_memory_bytes{state=current,}":      52428800,
		"host_cgroup_memory_bytes{state=limit,}":        104857600,
		"host_cgroup_memory_bytes{state=swap_current,}": 4096,
		"host_cgroup_memory_oom_kills_total{}":          3,
		"host_cgroup_pids{state=current,}":              12,
	}
	assertValues(t, values(b), want)
	if b.At != model.UnixNano(fixedNow.UnixNano()) {
		t.Fatalf("At = %d", b.At)
	}
	for _, s := range b.Samples {
		wantType, wantUnit := "gauge", "1"
		switch {
		case strings.HasSuffix(s.Name, "_seconds_total"):
			wantType, wantUnit = "counter", "seconds"
		case strings.HasSuffix(s.Name, "_oom_kills_total"):
			wantType = "counter"
		case strings.HasSuffix(s.Name, "_bytes"):
			wantUnit = "bytes"
		}
		if s.Type != wantType || s.Unit != wantUnit {
			t.Errorf("%s: type/unit = %s/%s, want %s/%s", s.Name, s.Type, s.Unit, wantType, wantUnit)
		}
		if err := s.Labels.Validate(); err != nil {
			t.Errorf("%s labels: %v", s.Name, err)
		}
	}
	wantMethods := map[Group]string{GroupCPU: "procfs_stat", GroupMemory: "procfs_meminfo", GroupLoad: "procfs_loadavg",
		GroupFilesystem: "statfs", GroupProcessCount: "procfs_dirnames", GroupCgroup: "cgroup2_files"}
	if len(caps) != len(AllGroups()) {
		t.Fatalf("caps = %+v", caps)
	}
	for i, g := range AllGroups() {
		c := mustCap(t, caps, g, map[bool]string{true: "data"}[g == GroupFilesystem], StatusSupported, ReasonNone)
		if c.Method != wantMethods[g] || caps[i].Group != g {
			t.Errorf("%s: method %q (order %v)", g, c.Method, caps[i].Group)
		}
	}
}

func TestHostCapabilityMissingIsUnknown(t *testing.T) {
	e := newFixtureEnv(t)
	e.remove(t, filepath.Join(e.proc, "meminfo"))
	e.write(t, filepath.Join(e.proc, "stat"), "cpu  2000 100")
	e.write(t, filepath.Join(e.proc, "self", "mountinfo"),
		"25 1 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw,hidepid=invisible,gid=1001\n")
	e.cgroup2 = false
	e.write(t, filepath.Join(e.proc, "self", "cgroup"), "12:cpu,cpuacct:/foo\n1:name=systemd:/foo\n")
	b, caps := run(t, e.c, allowAll())

	mustCap(t, caps, GroupMemory, "", StatusUnknown, ReasonNotPresent)
	mustCap(t, caps, GroupCPU, "", StatusUnknown, ReasonParseFailed)
	mustCap(t, caps, GroupProcessCount, "", StatusUnknown, ReasonProcessVisibility)
	mustCap(t, caps, GroupCgroup, "", StatusUnsupported, ReasonCgroupV2Required)
	mustCap(t, caps, GroupLoad, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupFilesystem, "", StatusDenied, ReasonNoTarget)
	for _, prefix := range []string{"host_memory", "host_cpu", "host_processes_total", "host_cgroup", "host_filesystem"} {
		if hasPrefix(b, prefix) {
			t.Errorf("samples exist for a group without data: %s", prefix)
		}
	}
	if len(b.Samples) != 3 {
		t.Errorf("only the three load samples may exist, got %d", len(b.Samples))
	}
	for _, s := range b.Samples {
		if s.Value == 0 {
			t.Errorf("zero sample %s", key(s))
		}
	}

	// A policy denying a group is denied by policy with no samples.
	e = newFixtureEnv(t)
	b, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupCPU}})
	for _, g := range AllGroups()[1:] {
		mustCap(t, caps, g, "", StatusDenied, ReasonPolicy)
	}
	mustCap(t, caps, GroupCPU, "", StatusSupported, ReasonNone)
	for _, s := range b.Samples {
		if !strings.HasPrefix(s.Name, "host_cpu") {
			t.Errorf("sample from a denied group: %s", s.Name)
		}
	}
	b, caps = run(t, e.c, HostPolicy{})
	if len(b.Samples) != 0 || len(caps) != 6 {
		t.Fatalf("empty allow list: %d samples %d caps", len(b.Samples), len(caps))
	}
	for _, c := range caps {
		if c.Status != StatusDenied || c.Reason != ReasonPolicy {
			t.Errorf("%+v", c)
		}
	}
}

func TestHostUnreadableCgroupFileIsDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not make a file unreadable")
	}
	e := newFixtureEnv(t)
	if err := os.Chmod(filepath.Join(e.cg, "memory.current"), 0); err != nil {
		t.Fatal(err)
	}
	b, caps := run(t, e.c, allowAll())
	mustCap(t, caps, GroupCgroup, "", StatusDenied, ReasonPermission)
	if hasPrefix(b, "host_cgroup") {
		t.Fatal("cgroup samples emitted although a file was unreadable")
	}
	if !hasPrefix(b, "host_cpu") {
		t.Fatal("unrelated group lost")
	}
}

func TestHostProcfsFailureModes(t *testing.T) {
	type tc struct {
		name   string
		mutate func(e *fixtureEnv, t *testing.T)
		g      Group
		st     Status
		r      Reason
		prefix string
	}
	proc := func(e *fixtureEnv, p ...string) string { return filepath.Join(append([]string{e.proc}, p...)...) }
	cases := []tc{
		{"stat missing", func(e *fixtureEnv, t *testing.T) { e.remove(t, proc(e, "stat")) }, GroupCPU, StatusUnknown, ReasonNotPresent, "host_cpu"},
		{"stat without aggregate line", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "stat"), "cpu0 1 2 3 4 5 6 7 8\nintr 1\n")
		}, GroupCPU, StatusUnknown, ReasonParseFailed, "host_cpu"},
		{"stat non numeric", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "stat"), "cpu  2000 x 1000 90000\ncpu0 1 2 3 4\n")
		}, GroupCPU, StatusUnknown, ReasonParseFailed, "host_cpu"},
		{"stat too few fields", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "stat"), "cpu  2000 100 1000\ncpu0 1 2 3\n")
		}, GroupCPU, StatusUnknown, ReasonParseFailed, "host_cpu"},
		{"meminfo lacks MemAvailable", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "meminfo"), "MemTotal: 100 kB\nMemFree: 50 kB\nBuffers: 1 kB\n")
		}, GroupMemory, StatusUnknown, ReasonParseFailed, "host_memory"},
		{"meminfo wrong unit", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "meminfo"), "MemTotal: 100 MB\nMemFree: 50 kB\nMemAvailable: 60 kB\n")
		}, GroupMemory, StatusUnknown, ReasonParseFailed, "host_memory"},
		{"loadavg missing", func(e *fixtureEnv, t *testing.T) { e.remove(t, proc(e, "loadavg")) }, GroupLoad, StatusUnknown, ReasonNotPresent, "host_load"},
		{"loadavg garbage", func(e *fixtureEnv, t *testing.T) { e.write(t, proc(e, "loadavg"), "abc def\n") }, GroupLoad, StatusUnknown, ReasonParseFailed, "host_load"},
		{"loadavg negative", func(e *fixtureEnv, t *testing.T) { e.write(t, proc(e, "loadavg"), "-1 0 0 1/1 1\n") }, GroupLoad, StatusUnknown, ReasonParseFailed, "host_load"},
		{"mountinfo missing", func(e *fixtureEnv, t *testing.T) { e.remove(t, proc(e, "self", "mountinfo")) }, GroupProcessCount, StatusUnknown, ReasonNotPresent, "host_processes_total"},
		{"mountinfo without proc mount", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "mountinfo"), "22 1 0:20 / /sys rw - sysfs sysfs rw\n")
		}, GroupProcessCount, StatusUnknown, ReasonParseFailed, "host_processes_total"},
		{"hidepid=2", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "mountinfo"), "25 1 0:23 / /proc rw,relatime - proc proc rw,hidepid=2\n")
		}, GroupProcessCount, StatusUnknown, ReasonProcessVisibility, "host_processes_total"},
		{"hidepid=noaccess in mount options", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "mountinfo"), "25 1 0:23 / /proc rw,relatime,hidepid=noaccess - proc proc rw\n")
		}, GroupProcessCount, StatusUnknown, ReasonProcessVisibility, "host_processes_total"},
		{"hidepid=ptraceable", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "mountinfo"), "25 1 0:23 / /proc rw - proc proc rw,hidepid=ptraceable\n")
		}, GroupProcessCount, StatusUnknown, ReasonProcessVisibility, "host_processes_total"},
		{"later proc mount shadows earlier", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "mountinfo"),
				"25 1 0:23 / /proc rw - proc proc rw\n40 1 0:41 / /proc rw - proc proc rw,hidepid=1\n")
		}, GroupProcessCount, StatusUnknown, ReasonProcessVisibility, "host_processes_total"},
		{"self cgroup missing", func(e *fixtureEnv, t *testing.T) { e.remove(t, proc(e, "self", "cgroup")) }, GroupCgroup, StatusUnsupported, ReasonNotPresent, "host_cgroup"},
		{"cgroup path traversal", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "cgroup"), "0::/system.slice/../../../../etc\n")
		}, GroupCgroup, StatusUnknown, ReasonParseFailed, "host_cgroup"},
		{"hybrid without cgroup2 mount", func(e *fixtureEnv, t *testing.T) { e.cgroup2 = false }, GroupCgroup, StatusUnsupported, ReasonCgroupV2Required, "host_cgroup"},
		{"cgroup2 mount but no unified line", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "cgroup"), "4:memory:/foo\n")
		}, GroupCgroup, StatusUnsupported, ReasonCgroupV2Required, "host_cgroup"},
		{"cgroup directory absent", func(e *fixtureEnv, t *testing.T) {
			e.write(t, proc(e, "self", "cgroup"), "0::/does/not/exist\n")
		}, GroupCgroup, StatusUnsupported, ReasonNotPresent, "host_cgroup"},
		{"cpu.stat lacks system_usec", func(e *fixtureEnv, t *testing.T) {
			e.write(t, filepath.Join(e.cg, "cpu.stat"), "usage_usec 1\nuser_usec 1\n")
		}, GroupCgroup, StatusUnknown, ReasonParseFailed, "host_cgroup"},
		{"memory.current garbage", func(e *fixtureEnv, t *testing.T) {
			e.write(t, filepath.Join(e.cg, "memory.current"), "lots\n")
		}, GroupCgroup, StatusUnknown, ReasonParseFailed, "host_cgroup"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFixtureEnv(t)
			c.mutate(e, t)
			b, caps := run(t, e.c, allowAll())
			mustCap(t, caps, c.g, "", c.st, c.r)
			if hasPrefix(b, c.prefix) {
				t.Fatalf("samples emitted for failed group %s", c.g)
			}
		})
	}
}

func TestHostOldKernelFieldsAreSkippedNotZeroed(t *testing.T) {
	e := newFixtureEnv(t)
	e.write(t, filepath.Join(e.proc, "stat"), "cpu  10 0 20 30\n")
	e.write(t, filepath.Join(e.proc, "meminfo"), "MemTotal: 100 kB\nMemFree: 50 kB\nMemAvailable: 60 kB\n")
	b, caps := run(t, e.c, HostPolicy{Allow: []Group{GroupCPU, GroupMemory}})
	mustCap(t, caps, GroupCPU, "", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupMemory, "", StatusSupported, ReasonNone)
	assertValues(t, values(b), map[string]float64{
		"host_cpu_seconds_total{mode=user,}":   0.1,
		"host_cpu_seconds_total{mode=nice,}":   0,
		"host_cpu_seconds_total{mode=system,}": 0.2,
		"host_cpu_seconds_total{mode=idle,}":   0.3,
		"host_memory_bytes{state=total,}":      100 * 1024,
		"host_memory_bytes{state=free,}":       50 * 1024,
		"host_memory_bytes{state=available,}":  60 * 1024,
	})
}

func TestHostProcessCountNamesOnly(t *testing.T) {
	e := newFixtureEnv(t)
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		// A numeric directory the agent cannot open must still be counted from its name alone.
		d := filepath.Join(e.proc, "777")
		if err := os.Mkdir(d, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
		b, caps := run(t, e.c, HostPolicy{Allow: []Group{GroupProcessCount}})
		mustCap(t, caps, GroupProcessCount, "", StatusSupported, ReasonNone)
		assertValues(t, values(b), map[string]float64{"host_processes_total{}": 4})
	}
	for _, opt := range []string{"hidepid=0", "hidepid=off"} {
		e.write(t, filepath.Join(e.proc, "self", "mountinfo"), "25 1 0:23 / /proc rw - proc proc rw,"+opt+"\n")
		_, caps := run(t, e.c, HostPolicy{Allow: []Group{GroupProcessCount}})
		mustCap(t, caps, GroupProcessCount, "", StatusSupported, ReasonNone)
	}
	// Exempt via the mount's gid option: partial visibility does not apply.
	var sawGID int
	var sawHas bool
	e.c.exempt = func(gid int, has bool) bool { sawGID, sawHas = gid, has; return true }
	e.write(t, filepath.Join(e.proc, "self", "mountinfo"), "25 1 0:23 / /proc rw - proc proc rw,hidepid=2,gid=1001\n")
	b, caps := run(t, e.c, HostPolicy{Allow: []Group{GroupProcessCount}})
	mustCap(t, caps, GroupProcessCount, "", StatusSupported, ReasonNone)
	if sawGID != 1001 || !sawHas {
		t.Fatalf("exemption saw gid %d/%v", sawGID, sawHas)
	}
	if v := values(b)["host_processes_total{}"]; v < 3 {
		t.Fatalf("count = %v", v)
	}
	e.c.exempt = func(gid int, has bool) bool { return has && gid == 4242 }
	_, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupProcessCount}})
	mustCap(t, caps, GroupProcessCount, "", StatusUnknown, ReasonProcessVisibility)
}

func TestHostCgroupLimitsAndOptionalFiles(t *testing.T) {
	e := newFixtureEnv(t)
	e.write(t, filepath.Join(e.cg, "memory.max"), "max\n")
	e.write(t, filepath.Join(e.cg, "pids.max"), "4096\n")
	e.remove(t, filepath.Join(e.cg, "memory.swap.current"))
	e.write(t, filepath.Join(e.cg, "memory.events"), "low 0\nhigh 0\nmax 7\noom 2\n")
	b, caps := run(t, e.c, HostPolicy{Allow: []Group{GroupCgroup}})
	mustCap(t, caps, GroupCgroup, "", StatusSupported, ReasonNone)
	assertValues(t, values(b), map[string]float64{
		"host_cgroup_cpu_seconds_total{mode=user,}":   3,
		"host_cgroup_cpu_seconds_total{mode=system,}": 2,
		"host_cgroup_memory_bytes{state=current,}":    52428800,
		"host_cgroup_pids{state=current,}":            12,
		"host_cgroup_pids{state=limit,}":              4096,
	})

	// A nested cgroup namespace root resolves to the mount itself.
	e = newFixtureEnv(t)
	e.write(t, filepath.Join(e.proc, "self", "cgroup"), "0::/\n")
	e.write(t, filepath.Join(e.sys, "fs", "cgroup", "pids.current"), "1\n")
	b, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupCgroup}})
	mustCap(t, caps, GroupCgroup, "", StatusSupported, ReasonNone)
	assertValues(t, values(b), map[string]float64{"host_cgroup_pids{state=current,}": 1})

	// The cgroup path in /proc/self/cgroup must not escape to other trees.
	e = newFixtureEnv(t)
	e.write(t, filepath.Join(e.proc, "self", "cgroup"), "0::/system.slice/agent.service (deleted)\n")
	_, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupCgroup}})
	mustCap(t, caps, GroupCgroup, "", StatusSupported, ReasonNone)
}

func TestHostFilesystemAliasOnlyAndErrors(t *testing.T) {
	e := newFixtureEnv(t)
	sec := secretPath()
	other := filepath.Join(filepath.Dir(sec), "other-secret")
	denied := filepath.Join(filepath.Dir(sec), "denied-secret")
	gone := filepath.Join(filepath.Dir(sec), "gone-secret")
	broken := filepath.Join(filepath.Dir(sec), "broken-secret")
	e.stats[sec] = fsStat{Size: 1 << 30, Free: 1 << 29, Avail: 1 << 28, Files: 0, FilesFree: 0}
	e.stats[other] = fsStat{Size: 1 << 20, Free: 1 << 10, Avail: 1 << 9, Files: 64, FilesFree: 8}
	e.errs[denied] = &fs.PathError{Op: "statfs", Path: denied, Err: fs.ErrPermission}
	e.errs[gone] = &fs.PathError{Op: "statfs", Path: gone, Err: fs.ErrNotExist}
	e.errs[broken] = &fs.PathError{Op: "statfs", Path: broken, Err: errors.New("input/output error")}
	p := HostPolicy{Allow: []Group{GroupFilesystem}, Filesystems: []FilesystemTarget{
		{Alias: "data", Path: sec}, {Alias: "scratch", Path: other}, {Alias: "locked", Path: denied},
		{Alias: "gone", Path: gone}, {Alias: "flaky", Path: broken},
	}}
	b, caps := run(t, e.c, p)
	mustCap(t, caps, GroupFilesystem, "data", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupFilesystem, "scratch", StatusSupported, ReasonNone)
	mustCap(t, caps, GroupFilesystem, "locked", StatusDenied, ReasonPermission)
	mustCap(t, caps, GroupFilesystem, "gone", StatusUnknown, ReasonNotPresent)
	mustCap(t, caps, GroupFilesystem, "flaky", StatusUnknown, ReasonReadFailed)
	var order []string
	for _, c := range caps {
		if c.Group == GroupFilesystem {
			order = append(order, c.Scope)
		}
	}
	if strings.Join(order, ",") != "data,scratch,locked,gone,flaky" {
		t.Fatalf("scope order %v", order)
	}
	// Filesystems that do not report inodes get no fake zero inode sample.
	assertValues(t, values(b), map[string]float64{
		"host_filesystem_bytes{mount=data,state=size,}":         1 << 30,
		"host_filesystem_bytes{mount=data,state=free,}":         1 << 29,
		"host_filesystem_bytes{mount=data,state=available,}":    1 << 28,
		"host_filesystem_bytes{mount=scratch,state=size,}":      1 << 20,
		"host_filesystem_bytes{mount=scratch,state=free,}":      1 << 10,
		"host_filesystem_bytes{mount=scratch,state=available,}": 1 << 9,
		"host_filesystem_inodes{mount=scratch,state=total,}":    64,
		"host_filesystem_inodes{mount=scratch,state=free,}":     8,
	})

	res := testResource()
	recs, err := b.Records(res)
	if err != nil {
		t.Fatal(err)
	}
	capRecs, err := caps.Records(res, b.At, time.Minute, testDomain(), "test-build")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"samples": b.Samples, "caps": caps, "metric records": recs, "capability records": capRecs} {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		text := string(j) + fmt.Sprintf("%+v", v)
		for _, p := range []string{sec, other, denied, gone, broken, "customer-acme", "payroll-secret", strings.ReplaceAll(sec, `\`, `\\`)} {
			if strings.Contains(text, p) {
				t.Errorf("%s leak a path fragment %q", name, p)
			}
		}
	}

	_, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupFilesystem}})
	if len(caps) != 6 {
		t.Fatalf("filesystem with no target must stay one scope-less capability, got %d caps", len(caps))
	}
	mustCap(t, caps, GroupFilesystem, "", StatusDenied, ReasonNoTarget)
}

func TestHostPolicyValidateBoundaries(t *testing.T) {
	abs := "/data"
	if runtime.GOOS == "windows" {
		abs = `X:\data`
	}
	many := func(n int) []FilesystemTarget {
		var out []FilesystemTarget
		for i := range n {
			out = append(out, FilesystemTarget{Alias: fmt.Sprintf("fs%d", i), Path: abs})
		}
		return out
	}
	long32 := "a" + strings.Repeat("b", 31)
	cases := []struct {
		name string
		p    HostPolicy
		ok   bool
	}{
		{"empty", HostPolicy{}, true},
		{"all groups", HostPolicy{Allow: AllGroups()}, true},
		{"unknown group", HostPolicy{Allow: []Group{"cpu", "gpu"}}, false},
		{"empty group name", HostPolicy{Allow: []Group{""}}, false},
		{"duplicate group", HostPolicy{Allow: []Group{GroupCPU, GroupCPU}}, false},
		{"alias ok", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a_1", Path: abs}}}, true},
		{"alias 32 chars", HostPolicy{Filesystems: []FilesystemTarget{{Alias: long32, Path: abs}}}, true},
		{"alias 33 chars", HostPolicy{Filesystems: []FilesystemTarget{{Alias: long32 + "c", Path: abs}}}, false},
		{"alias empty", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "", Path: abs}}}, false},
		{"alias uppercase", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "Data", Path: abs}}}, false},
		{"alias digit first", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "1data", Path: abs}}}, false},
		{"alias dash", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a-b", Path: abs}}}, false},
		{"alias slash", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a/b", Path: abs}}}, false},
		{"alias newline", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a\n", Path: abs}}}, false},
		{"duplicate alias", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: abs}, {Alias: "a", Path: abs}}}, false},
		{"empty path", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: ""}}}, false},
		{"relative path", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: "data/dir"}}}, false},
		{"dot path", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: "."}}}, false},
		{"NUL path", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: abs + "\x00x"}}}, false},
		{"16 filesystems", HostPolicy{Filesystems: many(16)}, true},
		{"17 filesystems", HostPolicy{Filesystems: many(17)}, false},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			struct {
				name string
				p    HostPolicy
				ok   bool
			}{"drive relative", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: `X:data`}}}, false},
			struct {
				name string
				p    HostPolicy
				ok   bool
			}{"unc", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: `\\srv\share`}}}, false},
			struct {
				name string
				p    HostPolicy
				ok   bool
			}{"slash drive", HostPolicy{Filesystems: []FilesystemTarget{{Alias: "a", Path: `X:/data`}}}, true})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			if c.ok && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if !c.ok {
				var f *model.Fault
				if !errors.As(err, &f) || f.Code != model.Invalid {
					t.Fatalf("want Invalid fault, got %v", err)
				}
			}
		})
	}
}

func testResource() model.Resource {
	return model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "host-a"}
}

func sourcePolicyFor(res model.Resource, mounts ...string) model.SourcePolicy {
	return model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured",
		Kinds:     []model.Kind{model.Metric, model.CapabilityKind},
		Resources: model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
		Labels: map[string][]string{
			"mode":   {"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"},
			"window": {"1m", "5m", "15m"},
			"state": {"total", "available", "free", "buffers", "cached", "swap_total", "swap_free",
				"size", "current", "limit", "swap_current"},
			"mount": mounts,
		},
		RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.CapabilityKind: 30},
		MaxBytes:      1 << 20, MaxSeries: 1000,
	}
}

func TestHostRecordsPassModelValidation(t *testing.T) {
	e := newFixtureEnv(t)
	e.stats[secretPath()] = fsStat{Size: 1 << 30, Free: 1 << 29, Avail: 1 << 28, Files: 100, FilesFree: 10}
	b, caps := run(t, e.c, allowAll(FilesystemTarget{Alias: "data", Path: secretPath()}))
	res := testResource()
	pol := sourcePolicyFor(res, "data")
	if err := model.ValidateSourcePolicy(pol); err != nil {
		t.Fatal(err)
	}
	recs, err := b.Records(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(b.Samples) || len(recs) == 0 {
		t.Fatalf("%d records for %d samples", len(recs), len(b.Samples))
	}
	ids := map[model.ID]bool{}
	for i, r := range recs {
		if ids[r.ID] {
			t.Fatal("record IDs not unique")
		}
		ids[r.ID] = true
		if err := model.ValidateRecord(&recs[i], pol); err != nil {
			t.Fatalf("%s: %v", key(b.Samples[i]), err)
		}
		m := r.Payload.Metric
		if r.Kind != model.Metric || r.ObservedAt != b.At || m.SampleKind != "float" || m.Name != b.Samples[i].Name ||
			m.Unit != b.Samples[i].Unit || m.Type != b.Samples[i].Type || uint64(*m.Value) != math.Float64bits(b.Samples[i].Value) {
			t.Fatalf("record %d does not carry its sample: %+v", i, m)
		}
	}
	// The allow-list is what makes admission work: an unlisted alias is refused.
	strict := sourcePolicyFor(res)
	for i := range recs {
		if recs[i].Payload.Metric.Name == "host_filesystem_bytes" {
			if model.ValidateRecord(&recs[i], strict) == nil {
				t.Fatal("alias outside the source label allow-list was admitted")
			}
			break
		}
	}

	at := model.UnixNano(fixedNow.UnixNano())
	capRecs, err := caps.Records(res, at, 90*time.Second, model.ClockDomain{Host: model.NewID()}, "build-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(capRecs) != 6 {
		t.Fatalf("%d capability records", len(capRecs))
	}
	for i := range capRecs {
		if err := model.ValidateRecord(&capRecs[i], pol); err != nil {
			t.Fatalf("capability %d: %v", i, err)
		}
		c := capRecs[i].Payload.Capability
		if c.Status != "supported" || c.Reason != "ok" || c.Expires != at+model.UnixNano(90*time.Second) ||
			c.Runtime != "soundpost-agent" || c.Version != "1" || c.OS != runtime.GOOS || c.Arch != runtime.GOARCH ||
			c.Signal != model.Metric || c.Coverage != (model.Coverage{Frames: "complete", Threads: "complete", Workers: "complete", Tasks: "complete"}) {
			t.Fatalf("capability record %+v", c)
		}
	}

	// Status vocabulary: unknown -> error, others verbatim, coverage only complete when supported.
	e = newFixtureEnv(t)
	e.remove(t, filepath.Join(e.proc, "meminfo"))
	e.cgroup2 = false
	_, caps = run(t, e.c, HostPolicy{Allow: []Group{GroupMemory, GroupCgroup, GroupFilesystem}})
	capRecs, err = caps.Records(res, at, time.Minute, model.ClockDomain{}, "build-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][3]string{}
	for i := range capRecs {
		if err := model.ValidateRecord(&capRecs[i], pol); err != nil {
			t.Fatal(err)
		}
		c := capRecs[i].Payload.Capability
		got[c.Method] = [3]string{c.Status, c.Reason, c.Coverage.Frames}
	}
	want := map[string][3]string{
		"memory:procfs_meminfo": {"error", "not_present", "unknown"},
		"cgroup:cgroup2_files":  {"unsupported", "cgroup_v2_required", "unknown"},
		"filesystem:statfs":     {"denied", "no_target_configured", "unknown"},
		"cpu:policy":            {"denied", "policy", "unknown"},
		"load:policy":           {"denied", "policy", "unknown"},
		"process_count:policy":  {"denied", "policy", "unknown"},
	}
	// the wire capability has no group field: the method alone must tell the
	// groups apart, so every record carries a distinct group-qualified method
	if len(got) != len(capRecs) || len(got) != len(want) {
		t.Errorf("capability methods are not unique per group: %d distinct for %d records: %v", len(got), len(capRecs), got)
	}
	for m, w := range want {
		if got[m] != w {
			t.Errorf("method %s: %v, want %v", m, got[m], w)
		}
	}

	// A group with several filesystem scopes is only supported when all are.
	mixed := Capabilities{
		{Group: GroupFilesystem, Scope: "a", Status: StatusSupported, Method: "statfs"},
		{Group: GroupFilesystem, Scope: "b", Status: StatusDenied, Reason: ReasonPermission, Method: "statfs"},
	}
	capRecs, err = mixed.Records(res, at, time.Minute, model.ClockDomain{}, "b")
	if err != nil || len(capRecs) != 1 || capRecs[0].Payload.Capability.Status != "denied" || capRecs[0].Payload.Capability.Reason != "permission_denied" {
		t.Fatalf("mixed scopes: %v %+v", err, capRecs)
	}
	if _, err := caps.Records(res, at, 0, model.ClockDomain{}, "b"); err == nil {
		t.Fatal("zero ttl accepted")
	}
	if _, err := (HostBatch{Samples: []Sample{{Name: "x", Value: math.NaN(), Unit: "1", Type: "gauge"}}}).Records(res); err == nil {
		t.Fatal("NaN sample accepted")
	}
	if _, err := (HostBatch{Samples: []Sample{{Name: "x", Labels: model.Labels{{Name: "b", Value: "1"}, {Name: "a", Value: "1"}}, Unit: "1", Type: "gauge"}}}).Records(res); err == nil {
		t.Fatal("unsorted labels accepted")
	}
}

func TestHostCollectContextAndPolicyErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, caps, err := Collect(ctx, HostPolicy{Allow: []Group{GroupCPU}})
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Cancelled || len(b.Samples) != 0 || caps != nil {
		t.Fatalf("cancelled: %v %v %v", err, b, caps)
	}
	_, _, err = Collect(context.Background(), HostPolicy{Allow: []Group{"nope"}})
	if !errors.As(err, &f) || f.Code != model.Invalid {
		t.Fatalf("invalid policy: %v", err)
	}

	// Cancellation that lands while a group is being read discards the pass.
	e := newFixtureEnv(t)
	ctx, cancel = context.WithCancel(context.Background())
	inner := e.c.read
	e.c.read = func(c *collector, g Group, p HostPolicy) groupResult {
		if g == GroupMemory {
			cancel()
		}
		return inner(c, g, p)
	}
	_, _, err = e.c.collect(ctx, allowAll())
	if !errors.As(err, &f) || f.Code != model.Cancelled {
		t.Fatalf("mid-pass cancel: %v", err)
	}
}

func TestHostGroupOrderAndFind(t *testing.T) {
	want := []Group{"cpu", "memory", "load", "filesystem", "process_count", "cgroup"}
	got := AllGroups()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("AllGroups = %v", got)
	}
	e := newFixtureEnv(t)
	_, caps := run(t, e.c, allowAll())
	var order []Group
	for _, c := range caps {
		order = append(order, c.Group)
	}
	if !sort.SliceIsSorted(order, func(i, j int) bool { return indexOf(order[i]) < indexOf(order[j]) }) {
		t.Fatalf("capability order %v", order)
	}
	if _, ok := caps.Find(GroupCPU, "x"); ok {
		t.Fatal("Find matched a wrong scope")
	}
}

func indexOf(g Group) int {
	for i, x := range AllGroups() {
		if x == g {
			return i
		}
	}
	return -1
}

func testDomain() model.ClockDomain {
	return model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}
}
