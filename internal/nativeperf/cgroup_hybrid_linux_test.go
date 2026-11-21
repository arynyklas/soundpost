//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const hybridMountinfo = `22 28 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
31 22 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
32 31 0:27 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
33 31 0:28 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
34 31 0:29 /user.slice/c /sys/fs/cgroup/sub\040dir rw,relatime shared:12 - cgroup2 cgroup2 rw
35 31 0:30 / /sys/fs/cgroup/odd\040name rw,relatime shared:13 - cgroup2 cgroup2 rw
`

func TestParseCgroup2MountsFindsOnlyHierarchyRoots(t *testing.T) {
	got := parseCgroup2Mounts([]byte(hybridMountinfo))
	want := []string{"/sys/fs/cgroup/unified", "/sys/fs/cgroup/odd name"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cgroup2 mounts = %q, want %q (a v1 cgroup mount, a tmpfs and a cgroup2 mount rooted at a sub-cgroup are not hierarchy roots)", got, want)
	}
	order := cgroup2MountOrder([]string{"/x", "/sys/fs/cgroup/unified", "/sys/fs/cgroup", "/y"})
	if !reflect.DeepEqual(order, []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified", "/x", "/y"}) {
		t.Fatalf("mount preference order = %q", order)
	}
}

// On a hybrid (v1 + v2) host the "0::/path" hierarchy is mounted at /sys/fs/cgroup/unified and /sys/fs/cgroup is a tmpfs: the
// identity must be the inode of the real cgroup directory under the cgroup2 mount, found through mountinfo, never a failure
// and never an inode of some other filesystem.
func TestCgroupIdentityResolvesUnderTheRealCgroup2Mount(t *testing.T) {
	info, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		t.Skip("mountinfo unreadable")
	}
	// found independently of the code under test: the first mountinfo line whose filesystem type is cgroup2 and whose root is "/"
	var mounts []string
	for _, line := range strings.Split(string(info), "\n") {
		head, tail, ok := strings.Cut(line, " - ")
		fields := strings.Fields(head)
		if ok && strings.HasPrefix(tail, "cgroup2 ") && len(fields) >= 5 && fields[3] == "/" {
			mounts = append(mounts, fields[4])
		}
	}
	if len(mounts) == 0 {
		t.Skip("NOT run: no cgroup v2 hierarchy mounted")
	}
	raw, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		t.Fatal(e)
	}
	path := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "0::/") {
			path = strings.TrimPrefix(line, "0::")
		}
	}
	if path == "" {
		t.Skip("NOT run: the process has no cgroup v2 membership line")
	}
	st, e := os.Stat(filepath.Join(mounts[0], path))
	if e != nil {
		t.Skipf("NOT run: cgroup directory not visible in this mount namespace: %v", e)
	}
	want := st.Sys().(*syscall.Stat_t).Ino
	got, e := ResolveCgroupID(os.Getpid())
	if e != nil || got != want {
		t.Fatalf("ResolveCgroupID = %d, %v; the cgroup directory under %s has inode %d", got, e, mounts[0], want)
	}
	if fd, e := openCgroup2Root(); e != nil {
		t.Fatal(e)
	} else {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(fd, &fs) != nil || uint64(fs.Type) != cgroup2SuperMagic {
			t.Fatal("the opened hierarchy root is not a cgroup2 filesystem")
		}
		syscall.Close(fd)
	}
}
