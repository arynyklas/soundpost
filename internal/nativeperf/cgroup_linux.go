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

// ancestorMount is a cgroup2 mount whose mountinfo root is only ".." segments: a mount of an ANCESTOR of this
// process's cgroup namespace root (a kubelet's read-only hostPath of /sys/fs/cgroup inside a pod, whose cgroup
// namespace is private). depth is the number of those segments, the levels between the mount's root and this
// process's cgroup.
type ancestorMount struct {
	dir   string
	depth int
}

// parseCgroup2AncestorMounts returns the cgroup2 mounts whose root is "/.." repeated: nothing else is an ancestor mount.
func parseCgroup2AncestorMounts(mountinfo []byte) []ancestorMount {
	var out []ancestorMount
	for _, line := range strings.Split(string(mountinfo), "\n") {
		head, tail, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(head)
		after := strings.Fields(tail)
		if len(fields) < 5 || len(after) < 1 || after[0] != "cgroup2" {
			continue
		}
		depth, only := 0, true
		for _, part := range strings.Split(strings.TrimPrefix(fields[3], "/"), "/") {
			if part != ".." {
				only = false
				break
			}
			depth++
		}
		if only && depth > 0 && depth <= maxAncestorDepth {
			out = append(out, ancestorMount{dir: unescapeMountField(fields[4]), depth: depth})
		}
	}
	return out
}

const (
	maxAncestorDepth   = 8
	maxAncestorEntries = 8192 // directories visited while locating this process's own cgroup below the mount
)

const openDir = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// locateOwnCgroup finds, below the mount directory fd, the directory depth levels down whose inode is own: the kernel's
// identity of this process's cgroup, read from the own cgroup2 mount. It returns the names on the way. Only directories are
// entered, nothing is followed, and at most maxAncestorEntries directories are opened.
func locateOwnCgroup(fd, depth int, own uint64, budget *int) ([]string, bool) {
	if depth == 0 {
		var st syscall.Stat_t
		ok := syscall.Fstat(fd, &st) == nil && st.Ino == own
		syscall.Close(fd)
		return nil, ok
	}
	dir := os.NewFile(uintptr(fd), "cgroup")
	defer dir.Close() // closes fd
	entries, e := dir.ReadDir(-1)
	if e != nil {
		return nil, false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if *budget--; *budget < 0 {
			return nil, false
		}
		child, e := syscall.Openat(fd, entry.Name(), openDir, 0)
		if e != nil {
			continue
		}
		names, ok := locateOwnCgroup(child, depth-1, own, budget)
		if ok {
			return append([]string{entry.Name()}, names...), true
		}
	}
	return nil, false
}

// resolveRelativeCgroup resolves the cgroup path of a process as read in a PRIVATE cgroup namespace: "/../" repeated n
// times and a tail below that ancestor, relative to this process's own cgroup. The mount is an ancestor mount depth
// levels above this process's cgroup (own is that cgroup's inode, read from the own cgroup2 mount). The directory chain from
// the mount down to this process's cgroup is found by inode, so no name is taken on trust; the result is the kernel
// inode of the target's cgroup, which the operator policy compares exactly like a path resolved in the host namespace.
func resolveRelativeCgroup(path string, anc ancestorMount, own uint64) (uint64, error) {
	if anc.dir == "" || anc.depth <= 0 || anc.depth > maxAncestorDepth {
		return 0, ErrAuthorization
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	up := 0
	for up < len(parts) && parts[up] == ".." {
		up++
	}
	tail := parts[up:]
	if up > anc.depth {
		return 0, ErrAuthorization
	}
	for _, part := range tail {
		if part == ".." || part == "." {
			return 0, ErrAuthorization
		}
	}
	root, e := syscall.Open(anc.dir, openDir, 0)
	if e != nil {
		return 0, ErrAuthorization
	}
	budget := maxAncestorEntries
	// locateOwnCgroup consumes its descriptor chain; open the mount again for the walk to the target (the shipped
	// seccomp profile has no dup)
	walk, e := syscall.Open(anc.dir, openDir, 0)
	if e != nil {
		syscall.Close(root)
		return 0, ErrAuthorization
	}
	names, ok := locateOwnCgroup(root, anc.depth, own, &budget)
	if !ok {
		syscall.Close(walk)
		return 0, ErrAuthorization
	}
	fd := walk
	for _, part := range append(append([]string{}, names[:anc.depth-up]...), tail...) {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, openDir, 0)
		syscall.Close(fd)
		if e != nil {
			return 0, ErrAuthorization
		}
		fd = next
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if e := syscall.Fstat(fd, &st); e != nil {
		return 0, ErrAuthorization
	}
	return st.Ino, nil
}

// privateNamespaceCgroupIdentity is cgroupIdentity for a path that starts with "..": this process is in a private cgroup
// namespace. It needs an ancestor mount (read-only hostPath of the cgroup2 root) and its own cgroup2 mount to read its
// own cgroup's inode; without either it is refused exactly as before.
func privateNamespaceCgroupIdentity(path string) (uint64, error) {
	info, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil || len(info) > 4<<20 {
		return 0, ErrAuthorization
	}
	mounts := parseCgroup2AncestorMounts(info)
	if len(mounts) == 0 {
		return 0, ErrAuthorization
	}
	rootFd, e := openCgroup2Root()
	if e != nil {
		return 0, e
	}
	var st syscall.Stat_t
	e = syscall.Fstat(rootFd, &st)
	syscall.Close(rootFd)
	if e != nil {
		return 0, ErrAuthorization
	}
	for _, m := range mounts {
		if id, e := resolveRelativeCgroup(path, m, st.Ino); e == nil {
			return id, nil
		}
	}
	return 0, ErrAuthorization
}
