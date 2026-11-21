//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402): the cgroup v2 root and the component-wise resolution of a target's cgroup
// path, against a /proc/self/mountinfo and a /proc/<pid>/cgroup of the test's own (private mount namespace, root; skips,
// loudly, without).

const cgroupRootChildEnv = "MUT0402_CGROUP_ROOT_CHILD"

func TestCgroupRootAndPathResolutionAgainstAMountinfoOfTheTestsOwn(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCgroupRootChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), cgroupRootChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "CGROUPROOT SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "CGROUPROOT SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "CGROUPROOT FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "CGROUPROOT DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

func TestCgroupRootChild(t *testing.T) {
	if os.Getenv(cgroupRootChildEnv) == "" {
		t.Skip("helper of TestCgroupRootAndPathResolutionAgainstAMountinfoOfTheTestsOwn")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("CGROUPROOT SKIP: cannot make the mount tree private:", err)
		return
	}
	dir := t.TempDir()
	fail := func(format string, args ...any) { fmt.Printf("CGROUPROOT FAIL "+format+"\n", args...) }
	root := filepath.Join(dir, "cgroot")
	for _, d := range []string{"b/c", "empty"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Symlink("b", filepath.Join(root, "link"))
	os.WriteFile(filepath.Join(root, "file"), nil, 0o644)
	ino := func(rel string) uint64 {
		st, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return st.Sys().(*syscall.Stat_t).Ino
	}
	n := 0
	bind := func(path, content string) func() {
		n++
		file := filepath.Join(dir, fmt.Sprintf("f%d", n))
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(file, path, "", syscall.MS_BIND, ""); err != nil {
			fmt.Println("CGROUPROOT SKIP: cannot bind a file over", path+":", err)
			os.Exit(0)
		}
		return func() { syscall.Unmount(path, syscall.MNT_DETACH) }
	}
	mountinfo := "/proc/self/mountinfo"
	line := func(point string) string { return "36 25 0:30 / " + point + " rw - cgroup2 cgroup2 rw\n" }

	// openCgroup2Root: the first usable candidate, never a path that is not a cgroup2 mount
	check := func(name, content string, want int, wantErr error) {
		defer bind(mountinfo, content)()
		fd, e := openCgroup2Root()
		if fd >= 0 {
			defer syscall.Close(fd)
		}
		switch {
		case wantErr != nil && (!errors.Is(e, wantErr) || fd != -1):
			fail("%s: fd %d, %v, want -1 and %v", name, fd, e, wantErr)
		case wantErr == nil && (e != nil || fd < 0):
			fail("%s: fd %d, %v", name, fd, e)
		}
		if wantErr == nil && fd >= 0 {
			var st syscall.Stat_t
			if syscall.Fstat(fd, &st) != nil || st.Ino != uint64(want) {
				fail("%s: opened inode %d, want %d", name, st.Ino, want)
			}
		}
	}
	rootIno := int(ino("."))
	check("one cgroup2 mount", line(root), rootIno, nil)
	check("the first candidate is not there, the second is", line(filepath.Join(dir, "missing"))+line(root), rootIno, nil)
	if st, err := os.Stat("/sys/fs/cgroup"); err == nil {
		check("the pure-v2 location is tried before a mount listed earlier", line(root)+line("/sys/fs/cgroup"), int(st.Sys().(*syscall.Stat_t).Ino), nil)
	}
	check("no cgroup2 mount", "36 25 0:30 / /x rw - tmpfs tmpfs rw\n", 0, ErrAuthorization)
	check("a cgroup2 mount that does not exist", line(filepath.Join(dir, "missing")), 0, ErrAuthorization)
	check("a cgroup2 mount that is a file", line(filepath.Join(root, "file")), 0, ErrAuthorization)
	pad := func(base string, total int) string { return base + strings.Repeat("x", total-len(base)-1) + "\n" }
	check("mountinfo of exactly 4 MiB", pad(line(root), 4<<20), rootIno, nil)
	check("mountinfo of 4 MiB and a byte", pad(line(root), 4<<20+1), 0, ErrAuthorization)

	// cgroupIdentity / ResolveCgroupID: the inode of the directory the "0::/path" line names under that root
	func() {
		defer bind(mountinfo, line(root))()
		for _, tc := range []struct {
			name string
			path string
			want uint64
			err  error
		}{
			{"the root", "0::/\n", ino("."), nil},
			{"one component", "0::/empty\n", ino("empty"), nil},
			{"two components", "0::/b/c\n", ino("b/c"), nil},
			{"empty components are skipped", "0::/b//c\n", ino("b/c"), nil},
			{"a trailing slash", "0::/b/c/\n", ino("b/c"), nil},
			{"v1 lines before the unified one", "12:cpu:/x\n0::/b\n", ino("b"), nil},
			{"a component that does not exist", "0::/missing\n", 0, syscall.ENOENT},
			{"a missing component behind a real one", "0::/b/missing\n", 0, syscall.ENOENT},
			{"a symlink is not followed", "0::/link\n", 0, syscall.ENOTDIR},
			{"a file is not a directory", "0::/file\n", 0, syscall.ENOTDIR},
			{"a dot component", "0::/b/./c\n", 0, ErrAuthorization},
			{"a dot-dot component", "0::/b/../c\n", 0, ErrAuthorization},
			{"no unified line", "12:cpu:/x\n", 0, ErrAuthorization},
			{"a relative unified line", "0::b\n", 0, ErrAuthorization},
		} {
			got, e := cgroupIdentity([]byte(tc.path))
			switch {
			case tc.err == nil && (e != nil || got != tc.want):
				fail("cgroupIdentity %s: %d %v, want %d", tc.name, got, e, tc.want)
			case tc.err != nil && (!errors.Is(e, tc.err) || got != 0):
				fail("cgroupIdentity %s: %d %v, want 0 and %v", tc.name, got, e, tc.err)
			}
		}
		// the file of a process: exactly 65536 bytes are read, one more is refused
		cgroup := "/proc/" + strconv.Itoa(os.Getpid()) + "/cgroup"
		padded := func(total int) string { return pad("0::/b/c\n", total)[:total-1] + "\n" }
		for _, tc := range []struct {
			total int
			ok    bool
		}{{65536, true}, {65537, false}} {
			func() {
				defer bind(cgroup, padded(tc.total))()
				got, e := ResolveCgroupID(os.Getpid())
				switch {
				case tc.ok && (e != nil || got != ino("b/c")):
					fail("ResolveCgroupID of a %d-byte cgroup file: %d %v", tc.total, got, e)
				case !tc.ok && (!errors.Is(e, ErrInvalid) || got != 0):
					fail("ResolveCgroupID of a %d-byte cgroup file: %d %v, want ErrInvalid", tc.total, got, e)
				}
			}()
		}
	}()
	// no cgroup2 hierarchy: the resolution is refused with the root's error, not answered with a zero inode
	func() {
		defer bind(mountinfo, "36 25 0:30 / /x rw - tmpfs tmpfs rw\n")()
		if got, e := cgroupIdentity([]byte("0::/b\n")); !errors.Is(e, ErrAuthorization) || got != 0 {
			fail("cgroupIdentity without a cgroup2 mount: %d %v, want 0 and ErrAuthorization", got, e)
		}
	}()
	// checkNSpid with no /proc/self/ns/pid to read: unproven, not a panic and not a pass
	if err := syscall.Mount("tmpfs", "/proc/self/ns", "tmpfs", 0, ""); err == nil {
		if e := checkNSpid([]byte("NSpid:\t5\n"), 5, 1); !errors.Is(e, ErrPIDNamespaceUnproven) {
			fail("checkNSpid without /proc/self/ns/pid: %v, want ErrPIDNamespaceUnproven", e)
		}
		syscall.Unmount("/proc/self/ns", syscall.MNT_DETACH)
	}
	fmt.Println("CGROUPROOT DONE")
}
