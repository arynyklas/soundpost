//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// cgroup2SuperMagic is CGROUP2_SUPER_MAGIC (statfs f_type).
const cgroup2SuperMagic = 0x63677270

// parseCgroup2Mounts returns the mount points of cgroup2 filesystems that expose the root of their hierarchy
// (mountinfo root "/"), in mountinfo order. A cgroup2 mount whose root is a sub-cgroup is skipped: the "0::/path" line of
// /proc/<pid>/cgroup is relative to the reader's cgroup namespace root, so it cannot be resolved under such a mount.
func parseCgroup2Mounts(mountinfo []byte) []string {
	var out []string
	for _, line := range strings.Split(string(mountinfo), "\n") {
		head, tail, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(head)
		after := strings.Fields(tail)
		if len(fields) < 5 || len(after) < 1 || after[0] != "cgroup2" || fields[3] != "/" {
			continue
		}
		out = append(out, unescapeMountField(fields[4]))
	}
	return out
}

// unescapeMountField decodes the \ooo octal escapes mountinfo uses for space, tab, newline and backslash.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, e := strconv.ParseUint(s[i+1:i+4], 8, 8); e == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// cgroup2MountOrder prefers the pure-v2 location, then the unified mount of a hybrid (v1+v2) host, then any other
// cgroup2 mount in mountinfo order.
func cgroup2MountOrder(mounts []string) []string {
	var first, second, rest []string
	for _, m := range mounts {
		switch m {
		case "/sys/fs/cgroup":
			first = append(first, m)
		case "/sys/fs/cgroup/unified":
			second = append(second, m)
		default:
			rest = append(rest, m)
		}
	}
	return append(append(first, second...), rest...)
}

// openCgroup2Root opens the root of the cgroup v2 hierarchy as this process sees it: pure v2 at /sys/fs/cgroup, the
// unified mount of a hybrid host, or a container's own cgroup2 mount. The candidates are the mountinfo entries whose
// filesystem type is cgroup2 (the privacy audit of the acquisition path allows no statfs), so a tmpfs or v1 directory at
// another path is never walked.
func openCgroup2Root() (int, error) {
	info, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil || len(info) > 4<<20 {
		return -1, ErrAuthorization
	}
	for _, mount := range cgroup2MountOrder(parseCgroup2Mounts(info)) {
		fd, e := syscall.Open(mount, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e == nil {
			return fd, nil
		}
	}
	return -1, ErrAuthorization
}

// ResolveCgroupID returns the identity (cgroup v2 directory inode) Target.CgroupID is compared with for the process pid:
// the "0::/path" line of /proc/<pid>/cgroup resolved, component by component without following symlinks, under this
// process's cgroup2 mount. It is empty-handed (ErrAuthorization) on a host with no cgroup v2 hierarchy.
func ResolveCgroupID(pid int) (uint64, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return 0, ErrInvalid
	}
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if e != nil || len(b) > 65536 {
		return 0, ErrInvalid
	}
	return cgroupIdentity(b)
}
